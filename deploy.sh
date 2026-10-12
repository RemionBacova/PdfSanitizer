#!/usr/bin/env bash
# Deploys the PDF sanitizer to Cloud Run.
#
# Builds from source with Cloud Build, so no local Docker push is needed.
# Re-run to deploy a new revision; traffic moves once the revision is healthy.
set -euo pipefail

PROJECT="${PROJECT:-reward-run-432209}"
REGION="${REGION:-europe-west1}"
SERVICE="${SERVICE:-pdf-sanitizer}"

# Must match Menu:SanitizerApiKey in the API's appsettings.
# Format "label:secret[,label:secret...]" so one environment can be revoked alone.
API_KEYS="${API_KEYS:?set API_KEYS, e.g. all:<key from appsettings>}"

gcloud run deploy "$SERVICE" \
  --project "$PROJECT" \
  --region "$REGION" \
  --source . \
  --platform managed \
  --no-allow-unauthenticated \
  --set-env-vars "API_KEYS=${API_KEYS},MAX_BYTES=10485760,MAX_PAGES=20" \
  --memory 512Mi \
  --cpu 1 \
  --concurrency 4 \
  --timeout 60s \
  --min-instances 0 \
  --max-instances 3 \
  --service-account "pdf-sanitizer@${PROJECT}.iam.gserviceaccount.com"

echo
echo "URL:"
gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" \
  --format 'value(status.url)'
