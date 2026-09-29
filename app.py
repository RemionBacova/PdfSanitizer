"""
Rebuilds an untrusted PDF into a safe one.

This exists as a separate service so that a parser with a long CVE history never runs in
the same process as the API's token signing and database credentials. It holds no data,
owns no permissions and has no network egress: if a malformed document ever achieves
execution inside qpdf, there is nothing here to take and nowhere to go.

The approach is disarm-and-reconstruct rather than detect-and-allow. Everything that could
carry behaviour is removed unconditionally, the file is rebuilt from what survives, and the
result is then re-parsed and refused if anything dangerous is still reachable. Trusting the
rebuild without checking it would be the weak point, so the check is the actual control.
"""

import hmac
import io
import logging
import os

import pikepdf
from flask import Flask, Response, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sanitizer")

MAX_BYTES = int(os.environ.get("MAX_BYTES", 10 * 1024 * 1024))
MAX_PAGES = int(os.environ.get("MAX_PAGES", 20))

# Catalog entries that can carry or trigger behaviour.
ROOT_KEYS = ("/OpenAction", "/AA", "/Names", "/AcroForm", "/Outlines", "/Metadata")
PAGE_KEYS = ("/Annots", "/AA")

# Annotation actions that reach outside the document. /URI is stripped along with the rest
# of the annotations: a menu has no need of clickable links, and a link is how a PDF phones
# home with the address of everyone who opens it.
ACTIVE_ACTIONS = {
    "/Launch", "/URI", "/SubmitForm", "/ImportData",
    "/GoToR", "/GoToE", "/JavaScript", "/Movie", "/Sound", "/RichMedia",
}


def _valid_keys():
    """
    Accepts a set of labelled keys so one environment can be revoked without re-keying the
    others. Format: "label1:secret1,label2:secret2", or a bare secret for a single key.
    """
    raw = os.environ.get("API_KEYS", "")
    keys = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        label, _, secret = entry.partition(":")
        if secret:
            keys[label] = secret
        else:
            keys["default"] = label
    return keys


def _authenticate(provided):
    """Constant-time comparison against every configured key, so neither the secret nor
    which key matched can be recovered by timing."""
    if not provided:
        return None
    matched = None
    for label, secret in _valid_keys().items():
        if hmac.compare_digest(provided, secret):
            matched = label
    return matched


def _sanitize(data):
    """Strip behaviour, rebuild, and garbage-collect anything left unreferenced."""
    with pikepdf.open(io.BytesIO(data)) as pdf:
        for key in ROOT_KEYS:
            if key in pdf.Root:
                del pdf.Root[key]

        for page in pdf.pages:
            for key in PAGE_KEYS:
                if key in page:
                    del page[key]

        if "/Info" in pdf.trailer:
            del pdf.trailer["/Info"]

        page_count = len(pdf.pages)

        # Drops orphaned objects so nothing dangerous lingers in the bytes even unreferenced.
        pdf.remove_unreferenced_resources()

        out = io.BytesIO()
        pdf.save(
            out,
            linearize=True,
            compress_streams=True,
            object_stream_mode=pikepdf.ObjectStreamMode.generate,
        )
        return out.getvalue(), page_count


def _find_threats(data):
    """Re-parse the rebuilt file and report anything a viewer could still act on."""
    found = []
    with pikepdf.open(io.BytesIO(data)) as pdf:
        root = pdf.Root
        for key in ("/OpenAction", "/AA"):
            if key in root:
                found.append("catalog" + key)

        if "/Names" in root:
            for key in ("/JavaScript", "/EmbeddedFiles"):
                if key in root.Names:
                    found.append("Names" + key)

        if "/AcroForm" in root:
            if "/XFA" in root.AcroForm:
                found.append("AcroForm/XFA")
            if root.AcroForm.get("/Fields"):
                found.append("AcroForm/Fields")

        for index, page in enumerate(pdf.pages):
            if "/AA" in page:
                found.append("page%d/AA" % index)
            for annot in (page.get("/Annots") or []):
                action = annot.get("/A", {}).get("/S")
                if action is not None and str(action) in ACTIVE_ACTIONS:
                    found.append("page%d/Annot%s" % (index, action))

        if pdf.trailer.get("/Info"):
            found.append("Info-metadata")
        if "/Metadata" in root:
            found.append("XMP-metadata")
    return found


@app.get("/health")
def health():
    return jsonify(status="ok", keys=len(_valid_keys()))


@app.post("/")
def sanitize():
    keys = _valid_keys()
    if not keys:
        log.error("API_KEYS is not set; refusing every request.")
        return jsonify(error="not_configured"), 503

    # Authenticate before touching the body, so an unauthenticated flood costs almost nothing.
    label = _authenticate(request.headers.get("X-Api-Key", ""))
    if label is None:
        return jsonify(error="unauthorized"), 401

    declared = request.content_length
    if declared is not None and declared > MAX_BYTES:
        return jsonify(error="too_large", maxBytes=MAX_BYTES), 413

    data = request.get_data(cache=False)
    if not data:
        return jsonify(error="empty"), 400
    if len(data) > MAX_BYTES:
        return jsonify(error="too_large", maxBytes=MAX_BYTES), 413
    if not data.startswith(b"%PDF-"):
        return jsonify(error="not_a_pdf"), 415

    try:
        cleaned, page_count = _sanitize(data)
    except Exception as exc:
        log.warning("rebuild failed for key=%s: %s", label, exc)
        return jsonify(error="unreadable"), 422

    if page_count > MAX_PAGES:
        return jsonify(error="too_many_pages", pages=page_count, maxPages=MAX_PAGES), 422

    threats = _find_threats(cleaned)
    if threats:
        # The rebuild is expected to remove all of this. If something survived, refuse the
        # document rather than trying to clean it again.
        log.error("verification failed for key=%s: %s", label, threats)
        return jsonify(error="active_content", details=threats), 422

    log.info("ok key=%s pages=%d in=%d out=%d", label, page_count, len(data), len(cleaned))
    return Response(
        cleaned,
        mimetype="application/pdf",
        headers={"X-Page-Count": str(page_count)},
    )
