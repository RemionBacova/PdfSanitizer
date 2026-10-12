# PDF Sanitizer

Rebuilds an untrusted PDF into a safe one. Used by `RewardSystem.API` before a retailer's
menu or price list is ever stored or served.

## Why it is a separate service

Parsing a hostile PDF inside the API would put a parser with a long CVE history in the same
process as JWT signing and database credentials. Here it runs alone, as an identity with no
IAM roles, holding no data. A compromise gets an attacker a container that can do nothing.

## What it removes

Unconditionally, then verifies:

| removed | why |
|---|---|
| `/OpenAction`, `/AA` | run JavaScript on open and on close |
| `/Names` → `/JavaScript`, `/EmbeddedFiles` | scripts and attached payloads |
| `/AcroForm` (incl. `/XFA`) | form submission and phone-home |
| `/Annots` | `/Launch`, `/URI` and friends — this is the tracker vector |
| `/Outlines`, `/Metadata`, `/Info` | metadata leaking author, software and local paths |
| unreferenced objects | so nothing lingers in the bytes even unreachable |

Page content, text, images and fonts are preserved. **Hyperlinks inside the PDF stop
working** — that is the point, and worth telling retailers.

The rebuilt file is re-parsed and refused if anything dangerous survived. The verification,
not the rebuild, is the actual control.

## Library choice

`pikepdf` (MPL-2.0) over `libqpdf` (Apache-2.0). Ghostscript and MuPDF were both rejected:
they are AGPL, owned by the same vendor, and MuPDF's `scrub()` was measured leaving
`/OpenAction`, `/AA`, `/Names` and an intact XFA stream in place.

## API

```
POST /            X-Api-Key: <secret>      body: application/pdf
  200  cleaned PDF, header X-Page-Count
  401  bad or missing key        (checked before the body is read)
  413  over MAX_BYTES
  415  not a PDF
  422  unreadable / too many pages / content too large when decoded /
       unsupported content encoding / active content survived
  503  API_KEYS not set

GET /health
```

Callers must fail closed: treat any non-200 as a refusal and never fall back to the original.

## Environment

| var | default | |
|---|---|---|
| `API_KEYS` | — | `label:secret[,label:secret]`. Required; no keys means refuse everything. |
| `MAX_BYTES` | 10485760 | |
| `MAX_PAGES` | 20 | Checked before the rebuild. |
| `MAX_CONTENT_BYTES` | 67108864 | Decoded size of all page content streams together, measured before qpdf reads them: Flate expands ~1000x, so a 2 MB file can decode to GBs. |

## Deploy

```bash
./setup-service-account.sh                  # once
API_KEYS="all:<key from appsettings>" ./deploy.sh
```

Then set `Menu:SanitizerUrl` in the API to the printed URL.

## Hardening still to do

- **Block egress.** The container makes no outbound calls, but nothing enforces that yet.
  Needs a Serverless VPC Access connector with `--vpc-egress=all-traffic` into a network
  whose firewall denies outbound. This is what makes a qpdf compromise a dead end.
- **Move `API_KEYS` to Secret Manager** rather than an environment variable.
- **Per-environment keys** instead of one shared value.

## Cost

`--max-instances 3` is the control that bounds exposure. The key stops casual use; the
instance cap stops the bill. Scale-to-zero means it costs nothing idle.
