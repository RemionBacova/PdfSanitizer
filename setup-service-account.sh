#!/usr/bin/env bash
# Creates the identity the sanitizer runs as.
#
# It is granted NOTHING on purpose. The service receives bytes and returns bytes; it reads no
# database, no bucket and no secret. If a malformed document ever achieves execution inside
# qpdf, the identity it inherits can do nothing.
set -euo pipefail

PROJECT="${PROJECT:-reward-run-432209}"
SA="pdf-sanitizer"

gcloud iam service-accounts create "$SA" \
  --project "$PROJECT" \
  --display-name "PDF sanitizer (no permissions by design)" \
  --description "Runs the menu PDF rebuild service. Intentionally has no IAM roles." \
  || echo "service account already exists, continuing"

echo "done: ${SA}@${PROJECT}.iam.gserviceaccount.com (no roles granted, as intended)"
