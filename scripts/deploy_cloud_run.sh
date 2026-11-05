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

echo "=================================================================="
echo "🚀 Deploying ${SERVICE_NAME} to Cloud Run (${LOCATION})"
echo "   Project      : ${PROJECT_ID}"
echo "   GCS Volume   : gs://${BUCKET_NAME} -> /data"
echo "   Session DB   : sqlite:///data/pqc_sessions.db"
echo "=================================================================="

gcloud run deploy "${SERVICE_NAME}" \
  --source . \
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
