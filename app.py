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

import base64
import hmac
import io
import logging
import os
import zlib

import pikepdf
from flask import Flask, Response, jsonify, request

MAX_BYTES = int(os.environ.get("MAX_BYTES", 10 * 1024 * 1024))
MAX_PAGES = int(os.environ.get("MAX_PAGES", 20))

# Looking for unused resources makes qpdf read every content stream whole into memory, and
# Flate expands about 1000x: a 2 MB upload measured past 3 GB. This caps the decoded size of
# all content streams together, checked before qpdf reads them. Real menus stay far below it.
MAX_CONTENT_BYTES = int(os.environ.get("MAX_CONTENT_BYTES", 64 * 1024 * 1024))

app = Flask(__name__)
# Refuse an oversized body before reading it, including a chunked one with no Content-Length.
app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sanitizer")

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


class Refused(Exception):
    """The document is refused before it is rebuilt; carries the JSON answer."""

    def __init__(self, **answer):
        super().__init__(answer.get("error"))
        self.answer = answer


def _filters(stream):
    value = stream.get("/Filter")
    if value is None:
        return []
    if isinstance(value, pikepdf.Array):
        return [str(f) for f in value]
    return [str(value)]


def _ascii85(raw):
    body = raw.split(b"~>", 1)[0]
    return base64.a85decode(body, ignorechars=b" \t\n\r\f\v\0")


def _ascii_hex(raw):
    digits = bytes(c for c in raw.split(b">", 1)[0] if c not in b" \t\n\r\f\0")
    if len(digits) % 2:
        digits += b"0"
    return bytes.fromhex(digits.decode("ascii"))


_TEXT_DECODERS = {"/ASCII85Decode": _ascii85, "/ASCIIHexDecode": _ascii_hex}


def _content_streams(pdf):
    """Every stream qpdf parses as page content: page contents, form XObjects and tiling
    patterns. Found by type across the whole file so inherited resources are not missed."""
    for page in pdf.pages:
        contents = page.obj.get("/Contents")
        if isinstance(contents, pikepdf.Stream):
            yield contents
        elif isinstance(contents, pikepdf.Array):
            yield from (c for c in contents if isinstance(c, pikepdf.Stream))
    for obj in pdf.objects:
        if isinstance(obj, pikepdf.Stream) and (
            obj.get("/Subtype") == pikepdf.Name.Form or obj.get("/PatternType") == 1
        ):
            yield obj


def _check_content_size(pdf):
    """Decode content streams just far enough to know they fit in MAX_CONTENT_BYTES, a megabyte
    at a time and discarding the output, so the check itself never holds the expansion."""
    seen = set()
    total = 0
    for stream in _content_streams(pdf):
        if stream.objgen in seen:
            continue
        seen.add(stream.objgen)
        filters = _filters(stream)
        raw = stream.read_raw_bytes()
        # Text encodings in front only ever shrink the data, so they are undone here first.
        while filters and filters[0] in _TEXT_DECODERS:
            try:
                raw = _TEXT_DECODERS[filters[0]](raw)
            except ValueError:
                raise Refused(error="unreadable")
            filters = filters[1:]
        if not filters:
            total += len(raw)
        elif filters == ["/FlateDecode"]:
            inflater = zlib.decompressobj()
            pending = raw
            try:
                while pending and total <= MAX_CONTENT_BYTES:
                    total += len(inflater.decompress(pending, 1024 * 1024))
                    pending = inflater.unconsumed_tail
            except zlib.error:
                pass  # damaged data: qpdf decides what it can still read
        else:
            # Other filters (LZW, RunLength, chains) can expand just as far and cannot be measured
            # here without decoding them whole. Real content streams use Flate or nothing.
            raise Refused(error="unsupported_encoding", filters=filters)
        if total > MAX_CONTENT_BYTES:
            raise Refused(error="content_too_large", maxContentBytes=MAX_CONTENT_BYTES)


def _sanitize(data):
    """Strip behaviour, rebuild, and garbage-collect anything left unreferenced."""
    with pikepdf.open(io.BytesIO(data)) as pdf:
        # Both limits are checked before any rebuilding work is spent on the document.
        page_count = len(pdf.pages)
        if page_count > MAX_PAGES:
            raise Refused(error="too_many_pages", pages=page_count, maxPages=MAX_PAGES)
        _check_content_size(pdf)

        for key in ROOT_KEYS:
            if key in pdf.Root:
                del pdf.Root[key]

        for page in pdf.pages:
            for key in PAGE_KEYS:
                if key in page:
                    del page[key]

        if "/Info" in pdf.trailer:
            del pdf.trailer["/Info"]

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
    except Refused as refused:
        log.warning("refused for key=%s: %s", label, refused.answer)
        return jsonify(**refused.answer), 422
    except Exception as exc:
        log.warning("rebuild failed for key=%s: %s", label, exc)
        return jsonify(error="unreadable"), 422

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
