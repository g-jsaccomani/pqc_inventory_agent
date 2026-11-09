#!/usr/bin/env bash
# ==============================================================================
# Cloud Run Deployment Script for PQC Enterprise Workspace Portal
# Mounts gs://pqc-inventory-agent-cd06-pqc-agent-staging at /data so that
# pqc_sessions.db and calibration-history.jsonl persist permanently across restarts.
# ==============================================================================
set -euo pipefail

PROJECT_ID="${1:-pqc-inventory-agent-cd06}"
LOCATION="${2:-us-central1}"
SERVICE_NAME="${3:-pqc-inventory-agent}"
BUCKET_NAME="${PROJECT_ID}-pqc-agent-staging"
ARGOLIS_ACCOUNT="${ARGOLIS_ACCOUNT:-admin@jsaccomani.altostrat.com}"

if [[ -z "${CLOUDSDK_PYTHON:-}" && -x "$(pwd)/.venv/bin/python" ]]; then
  export CLOUDSDK_PYTHON="$(pwd)/.venv/bin/python"
fi

# On corporate gMacs, unset internal BeyondCorp/CBA variables so gcloud authenticates
# against external Argolis (admin@jsaccomani.altostrat.com) instead of forcing @google.com SSO.
unset CLOUDSDK_INTERNAL_USER
unset CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE
unset CLOUDSDK_CONTEXT_AWARE_USE_ECP_HTTP_PROXY
unset CLOUDSDK_CONTEXT_AWARE_USE_MTLS_FOR_GRPC
unset CLOUDSDK_CONTEXT_AWARE_CERTIFICATE_CONFIG_FILE_PATH
unset GOOGLE_API_CERTIFICATE_CONFIG
unset GOOGLE_AUTH_WEBAUTHN_PLUGIN

export CLOUDSDK_CONFIG="${CLOUDSDK_CONFIG:-$HOME/.config/gcloud-argolis}"
mkdir -p "${CLOUDSDK_CONFIG}"

echo "=================================================================="
echo "🔐 Verifying Argolis authentication (${ARGOLIS_ACCOUNT})"
echo "   CLOUDSDK_CONFIG : ${CLOUDSDK_CONFIG}"
echo "=================================================================="

TOKEN_EMAIL=""
if TOK=$(CLOUDSDK_CORE_DISABLE_PROMPTS=1 gcloud auth print-access-token "${ARGOLIS_ACCOUNT}" 2>/dev/null); then
  TOKEN_EMAIL=$(curl -s "https://oauth2.googleapis.com/tokeninfo?access_token=${TOK}" | grep -o '"email": *"[^"]*"' | head -n1 | cut -d'"' -f4 || true)
fi

if [[ "${TOKEN_EMAIL}" != "${ARGOLIS_ACCOUNT}" ]]; then
  echo "⚠️  Active token is '${TOKEN_EMAIL:-expired/missing}' (expected '${ARGOLIS_ACCOUNT}')."
  rm -f "${CLOUDSDK_CONFIG}/credentials.db" "${CLOUDSDK_CONFIG}/access_tokens.db"
  rm -rf "${CLOUDSDK_CONFIG}/legacy_credentials/${ARGOLIS_ACCOUNT}"
  echo "👉 Open the URL below in your Argolis Chrome window (${ARGOLIS_ACCOUNT}) and paste the verification code:"
  gcloud auth login "${ARGOLIS_ACCOUNT}" --no-launch-browser
fi

echo "=================================================================="
echo "🚀 Deploying ${SERVICE_NAME} to Cloud Run (${LOCATION})"
echo "   Project      : ${PROJECT_ID}"
echo "   Account      : ${ARGOLIS_ACCOUNT}"
echo "   GCS Volume   : gs://${BUCKET_NAME} -> /data"
echo "   Session DB   : sqlite:///data/pqc_sessions.db"
echo "=================================================================="

gcloud run deploy "${SERVICE_NAME}" \
  --source . \
  --account="${ARGOLIS_ACCOUNT}" \
  --project="${PROJECT_ID}" \
  --region="${LOCATION}" \
  --allow-unauthenticated \
  --execution-environment=gen2 \
  --memory=2Gi \
  --cpu=2 \
  --timeout=600 \
  --add-volume="name=pqc-data,type=cloud-storage,bucket=${BUCKET_NAME}" \
  --add-volume-mount="volume=pqc-data,mount-path=/data" \
  --set-env-vars="GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=global,GCP_ORGANIZATION_ID=31564119954,GCP_ORGANIZATION_NAME=jsaccomani.altostrat.com,PQC_AGENT_MODEL=gemini-3.1-pro-preview-customtools,PQC_SIMULATION_MODE=FALSE,SESSION_DB_URL=sqlite:///data/pqc_sessions.db,PQC_ARTIFACT_BUCKET=gs://${BUCKET_NAME},PQC_CALIBRATION_STORE_PATH=/data/calibration-history.jsonl"

