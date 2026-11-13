#!/usr/bin/env bash
# ==============================================================================
# Automated Setup and Deployment Script for Vertex AI Agent Engine (GCP)
# Usage: ./scripts/setup_and_deploy_vertex.sh <PROJECT_ID> [REGION]
# ==============================================================================
set -euo pipefail

PROJECT_ID="${1:-$(gcloud config get-value project 2>/dev/null || true)}"
LOCATION="${2:-us-central1}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "❌ Error: Please provide the GCP Project ID. Example:"
  echo "   ./scripts/setup_and_deploy_vertex.sh pqc-inventory-agent-cd06 us-central1"
  exit 1
fi

STAGING_BUCKET="gs://${PROJECT_ID}-pqc-agent-staging"

echo "=================================================================="
echo "🚀 Preparing PQC Inventory Agent Deployment to Vertex AI"
echo "   Project : ${PROJECT_ID}"
echo "   Region  : ${LOCATION}"
echo "   Bucket  : ${STAGING_BUCKET}"
echo "=================================================================="

echo "[1/4] Configuring active project and ADC quota project..."
gcloud config set project "${PROJECT_ID}"
gcloud auth application-default set-quota-project "${PROJECT_ID}" || true

echo "[2/4] Enabling required Google Cloud APIs (Vertex AI, Cloud KMS, Cloud Asset Inventory, Storage)..."
gcloud services enable \
  aiplatform.googleapis.com \
  cloudkms.googleapis.com \
  cloudasset.googleapis.com \
  storage.googleapis.com \
  --project="${PROJECT_ID}"

echo "[3/4] Granting IAM roles to the Vertex AI Reasoning Engine Service Agent..."
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")
RE_SA="service-${PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com"

for ROLE in "roles/cloudkms.viewer" "roles/cloudasset.viewer" "roles/aiplatform.user"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${RE_SA}" \
    --role="${ROLE}" \
    --condition=None \
    --quiet >/dev/null 2>&1 || true
done

echo "[4/5] Packaging and deploying to Vertex AI Agent Engine..."
.venv/bin/python main.py deploy \
  --project="${PROJECT_ID}" \
  --location="${LOCATION}" \
  --staging-bucket="${STAGING_BUCKET}"

echo "[5/5] Deploying Gemini Enterprise Workspace Portal to Cloud Run with GCS Volume Mount (/data)..."
BUCKET_NAME="${PROJECT_ID}-pqc-agent-staging"
# Security posture of the deployed portal (see pqc_agent/auth_guard.py):
# - PQC_ALLOW_UNVERIFIED_SIGNIN=false : sign-in requires a verified Google credential (no email-only sign-in).
# - PQC_ENABLE_ADK_DEV_UI=false       : no ADK DevServer (/dev-ui, /dev/apps/*/builder/save, /dev/apps/*/deploy/*).
# - PQC_ENABLE_ADK_API=false          : ADK-native REST routes (/list-apps, /apps/..., /run, /run_sse) return 404.
# - No wildcard CORS (PQC_ALLOWED_ORIGINS unset => same-origin portal only).
# Optional: PQC_AUTH_SECRET_SECRET=<Secret Manager secret name> injects the session HMAC key (recommended), and
# PQC_IAP_AUDIENCE=<IAP audience> when the service sits behind Cloud IAP (only verified IAP JWTs are trusted).
EXTRA_DEPLOY_FLAGS=()
if [[ -n "${PQC_AUTH_SECRET_SECRET:-}" ]]; then
  EXTRA_DEPLOY_FLAGS+=("--set-secrets=PQC_AUTH_SECRET=${PQC_AUTH_SECRET_SECRET}:latest")
fi
PQC_IAP_AUDIENCE="${PQC_IAP_AUDIENCE:-/projects/${PROJECT_NUMBER}/locations/${LOCATION}/services/agentic-pqc}"
IAP_ENV=",PQC_IAP_AUDIENCE=${PQC_IAP_AUDIENCE}"

gcloud beta run deploy agentic-pqc \
  --source . \
  --project="${PROJECT_ID}" \
  --region="${LOCATION}" \
  --allow-unauthenticated \
  --no-iap \
  --execution-environment=gen2 \
  --min-instances=1 \
  --max-instances=1 \
  --memory=16Gi \
  --cpu=8 \
  --no-cpu-throttling \
  --cpu-boost \
  --timeout=600 \
  --add-volume="name=pqc-data,type=cloud-storage,bucket=${BUCKET_NAME}" \
  --add-volume-mount="volume=pqc-data,mount-path=/data" \
  --set-env-vars="GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=global,GCP_ORGANIZATION_ID=31564119954,GCP_ORGANIZATION_NAME=jsaccomani.altostrat.com,PQC_AGENT_MODEL=gemini-3.1-pro-preview-customtools,PQC_SIMULATION_MODE=FALSE,SESSION_DB_URL=sqlite:///data/pqc_sessions.db,PQC_ARTIFACT_BUCKET=gs://${BUCKET_NAME},PQC_CALIBRATION_STORE_PATH=/data/calibration-history.jsonl,PQC_ALLOW_UNVERIFIED_SIGNIN=false,PQC_ENABLE_ADK_DEV_UI=false,PQC_ENABLE_ADK_API=false${IAP_ENV}" \
  ${EXTRA_DEPLOY_FLAGS[@]+"${EXTRA_DEPLOY_FLAGS[@]}"}

