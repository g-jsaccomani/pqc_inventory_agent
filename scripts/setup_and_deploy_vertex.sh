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

echo "[4/4] Packaging and deploying to Vertex AI Agent Engine..."
.venv/bin/python main.py deploy \
  --project="${PROJECT_ID}" \
  --location="${LOCATION}" \
  --staging-bucket="${STAGING_BUCKET}"
