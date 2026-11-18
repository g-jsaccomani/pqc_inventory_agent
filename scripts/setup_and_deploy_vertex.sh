#!/usr/bin/env bash
# ==============================================================================
# Automated Setup and Deployment Script for Vertex AI Agent Engine + Cloud Run
# Usage:
#   PQC_CLOUD_SQL_CONNECTION_NAME=<proj>:<region>:<inst> \
#   PQC_KMS_KEY_NAME=projects/<proj>/locations/<region>/keyRings/<kr>/cryptoKeys/<key> \
#   ./scripts/setup_and_deploy_vertex.sh <PROJECT_ID> [REGION]
# ==============================================================================
set -euo pipefail

PROJECT_ID="${1:-$(gcloud config get-value project 2>/dev/null || true)}"
LOCATION="${2:-us-central1}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "❌ Error: Please provide the GCP Project ID. Example:"
  echo "   ./scripts/setup_and_deploy_vertex.sh pqc-inventory-agent-cd06 us-central1"
  exit 1
fi

CLOUD_SQL_INSTANCE="${PQC_CLOUD_SQL_CONNECTION_NAME:-}"
DB_NAME="${PQC_DB_NAME:-pqc_workspace}"
DB_USER="${PQC_DB_USER:-pqc_app}"
PQC_DB_PASSWORD_SECRET="${PQC_DB_PASSWORD_SECRET:-pqc-db-password}"
PQC_AUTH_SECRET_SECRET="${PQC_AUTH_SECRET_SECRET:-pqc-session-secret}"
KMS_KEY_NAME="${PQC_KMS_KEY_NAME:-}"

if [[ -z "${CLOUD_SQL_INSTANCE}" || -z "${KMS_KEY_NAME}" ]]; then
  echo "❌ Error: Both PQC_CLOUD_SQL_CONNECTION_NAME and PQC_KMS_KEY_NAME must be set."
  echo "   SQLite and GCS FUSE (/data) are prohibited in production."
  exit 1
fi

STAGING_BUCKET="gs://${PROJECT_ID}-pqc-agent-staging"
BUCKET_NAME="${PROJECT_ID}-pqc-agent-staging"

echo "=================================================================="
echo "🚀 Preparing PQC Inventory Agent Deployment (Vertex AI + Cloud SQL)"
echo "   Project   : ${PROJECT_ID}"
echo "   Region    : ${LOCATION}"
echo "   Cloud SQL : ${CLOUD_SQL_INSTANCE}"
echo "   Bucket    : ${STAGING_BUCKET} (object storage only)"
echo "=================================================================="

echo "[1/5] Configuring active project and ADC quota project..."
gcloud config set project "${PROJECT_ID}"
gcloud auth application-default set-quota-project "${PROJECT_ID}" || true

echo "[2/5] Enabling required Google Cloud APIs..."
gcloud services enable \
  aiplatform.googleapis.com \
  cloudkms.googleapis.com \
  cloudasset.googleapis.com \
  storage.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  --project="${PROJECT_ID}"

echo "[3/5] Granting least-privilege IAM roles to Reasoning Engine & Cloud Run Service Accounts..."
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")
RE_SA="service-${PROJECT_NUMBER}@gcp-sa-aiplatform-re.iam.gserviceaccount.com"
COMPUTE_SA="${PQC_RUNTIME_SERVICE_ACCOUNT:-${PROJECT_NUMBER}-compute@developer.gserviceaccount.com}"
ORG_ID="${GCP_ORGANIZATION_ID:-31564119954}"

for SA_EMAIL in "${RE_SA}" "${COMPUTE_SA}"; do
  for ROLE in "roles/cloudkms.viewer" "roles/cloudasset.viewer" "roles/compute.viewer" "roles/privateca.auditor" "roles/serviceusage.serviceUsageConsumer" "roles/aiplatform.user" "roles/cloudsql.client"; do
    gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
      --member="serviceAccount:${SA_EMAIL}" \
      --role="${ROLE}" \
      --condition=None \
      --quiet >/dev/null 2>&1 || true
  done
  for ROLE in "roles/cloudasset.viewer" "roles/cloudkms.viewer" "roles/resourcemanager.organizationViewer" "roles/compute.viewer" "roles/privateca.auditor" "roles/certificatemanager.viewer" "roles/orgpolicy.policyViewer"; do
    gcloud organizations add-iam-policy-binding "${ORG_ID}" \
      --member="serviceAccount:${SA_EMAIL}" \
      --role="${ROLE}" \
      --condition=None \
      --quiet >/dev/null 2>&1 || true
  done
done

gcloud kms keys add-iam-policy-binding "${KMS_KEY_NAME}" \
  --member="serviceAccount:${COMPUTE_SA}" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" \
  --quiet >/dev/null 2>&1 || true

for SECRET_NAME in "${PQC_AUTH_SECRET_SECRET}" "${PQC_DB_PASSWORD_SECRET}"; do
  gcloud secrets add-iam-policy-binding "${SECRET_NAME}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet >/dev/null 2>&1 || true
done

echo "[4/5] Packaging and deploying to Vertex AI Agent Engine..."
.venv/bin/python main.py deploy \
  --project="${PROJECT_ID}" \
  --location="${LOCATION}" \
  --staging-bucket="${STAGING_BUCKET}"

echo "[5/5] Deploying Gemini Enterprise Workspace Portal to Cloud Run with Cloud SQL PostgreSQL..."
PQC_IAP_AUDIENCE="${PQC_IAP_AUDIENCE:-/projects/${PROJECT_NUMBER}/locations/${LOCATION}/services/agentic-pqc}"
IAP_ENV=",PQC_IAP_AUDIENCE=${PQC_IAP_AUDIENCE}"

gcloud beta run deploy agentic-pqc \
  --source . \
  --project="${PROJECT_ID}" \
  --region="${LOCATION}" \
  --no-allow-unauthenticated \
  --iap \
  --execution-environment=gen2 \
  --min-instances=1 \
  --max-instances=10 \
  --memory=16Gi \
  --cpu=8 \
  --no-cpu-throttling \
  --cpu-boost \
  --timeout=600 \
  --add-cloudsql-instances="${CLOUD_SQL_INSTANCE}" \
  --set-secrets="PQC_AUTH_SECRET=${PQC_AUTH_SECRET_SECRET}:latest,PQC_DB_PASSWORD=${PQC_DB_PASSWORD_SECRET}:latest" \
  --set-env-vars="PQC_PRODUCTION_MODE=true,GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=global,GCP_ORGANIZATION_ID=31564119954,GCP_ORGANIZATION_NAME=jsaccomani.altostrat.com,PQC_AGENT_MODEL=gemini-3.1-pro-preview-customtools,PQC_SIMULATION_MODE=FALSE,PQC_CLOUD_SQL_CONNECTION_NAME=${CLOUD_SQL_INSTANCE},PQC_DB_NAME=${DB_NAME},PQC_DB_USER=${DB_USER},PQC_KMS_KEY_NAME=${KMS_KEY_NAME},PQC_ARTIFACT_BUCKET=gs://${BUCKET_NAME},PQC_ALLOW_UNVERIFIED_SIGNIN=false,PQC_ENABLE_ADK_DEV_UI=false,PQC_ENABLE_ADK_API=false,PQC_ENABLE_GIS_JAVASCRIPT_CLIENT=false${IAP_ENV}"
