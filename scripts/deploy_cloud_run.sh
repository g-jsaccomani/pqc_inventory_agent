#!/usr/bin/env bash
# ==============================================================================
# Cloud Run Deployment Script for PQC Enterprise Workspace Portal
# - Transactional persistence: Cloud SQL for PostgreSQL (--add-cloudsql-instances)
# - Secrets: Secret Manager (--set-secrets for PQC_AUTH_SECRET & PQC_DB_PASSWORD)
# - Delegated Credential Wrapping: Cloud KMS symmetric KEK (PQC_KMS_KEY_NAME)
# - Object storage only: Cloud Storage (PQC_ARTIFACT_BUCKET; NO GCS FUSE /data)
# ==============================================================================
set -euo pipefail

PROJECT_ID="${1:-pqc-inventory-agent-cd06}"
LOCATION="${2:-us-central1}"
SERVICE_NAME="${3:-agentic-pqc}"
BUCKET_NAME="${PROJECT_ID}-pqc-agent-staging"
ARGOLIS_ACCOUNT="${ARGOLIS_ACCOUNT:-admin@jsaccomani.altostrat.com}"

CLOUD_SQL_INSTANCE="${PQC_CLOUD_SQL_CONNECTION_NAME:-}"
DB_NAME="${PQC_DB_NAME:-pqc_workspace}"
DB_USER="${PQC_DB_USER:-pqc_app}"
PQC_DB_PASSWORD_SECRET="${PQC_DB_PASSWORD_SECRET:-pqc-db-password}"
PQC_AUTH_SECRET_SECRET="${PQC_AUTH_SECRET_SECRET:-pqc-session-secret}"
KMS_KEY_NAME="${PQC_KMS_KEY_NAME:-}"

if [[ -z "${CLOUD_SQL_INSTANCE}" ]]; then
  echo "❌ Error: PQC_CLOUD_SQL_CONNECTION_NAME (<project>:<region>:<instance>) is required for Cloud Run deployment."
  echo "   SQLite and GCS FUSE (/data) are prohibited in production."
  exit 1
fi

if [[ -z "${KMS_KEY_NAME}" ]]; then
  echo "❌ Error: PQC_KMS_KEY_NAME (projects/.../locations/.../keyRings/.../cryptoKeys/...) is required in production"
  echo "   for Cloud KMS AES-256-GCM envelope encryption of delegated credentials."
  exit 1
fi

if [[ -z "${CLOUDSDK_PYTHON:-}" && -x "$(pwd)/.venv/bin/python" ]]; then
  export CLOUDSDK_PYTHON="$(pwd)/.venv/bin/python"
fi

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
  TOKEN_EMAIL=$(curl -s --cacert /etc/ssl/cert.pem --max-time 10 "https://oauth2.googleapis.com/tokeninfo?access_token=${TOK}" | grep -o '"email": *"[^"]*"' | head -n1 | cut -d'"' -f4 || true)
fi

if [[ "${TOKEN_EMAIL}" != "${ARGOLIS_ACCOUNT}" ]]; then
  echo "⚠️  Active token is '${TOKEN_EMAIL:-expired/missing}' (expected '${ARGOLIS_ACCOUNT}')."
  rm -f "${CLOUDSDK_CONFIG}/credentials.db" "${CLOUDSDK_CONFIG}/access_tokens.db"
  rm -rf "${CLOUDSDK_CONFIG}/legacy_credentials/${ARGOLIS_ACCOUNT}"
  echo "👉 Open the URL below in your Argolis Chrome window (${ARGOLIS_ACCOUNT}) and paste the verification code:"
  gcloud auth login "${ARGOLIS_ACCOUNT}" --no-launch-browser
fi

PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --account="${ARGOLIS_ACCOUNT}" --format="value(projectNumber)")
RUNTIME_SA="serviceAccount:${PQC_RUNTIME_SERVICE_ACCOUNT:-${PROJECT_NUMBER}-compute@developer.gserviceaccount.com}"
ORG_ID="${GCP_ORGANIZATION_ID:-31564119954}"
LAB_FOLDER_ID="${PQC_LAB_FOLDER_ID:-534285347409}"

echo "=================================================================="
echo "🛡️ Onboarding Least-Privilege IAM Roles for ${RUNTIME_SA}"
echo "   Organization : organizations/${ORG_ID}"
echo "   Host Project : projects/${PROJECT_ID}"
echo "   Cloud SQL    : ${CLOUD_SQL_INSTANCE}"
echo "   KMS KEK      : ${KMS_KEY_NAME}"
echo "=================================================================="
for ROLE in \
  "roles/cloudasset.viewer" \
  "roles/cloudkms.viewer" \
  "roles/resourcemanager.organizationViewer" \
  "roles/compute.viewer" \
  "roles/privateca.auditor" \
  "roles/certificatemanager.viewer" \
  "roles/orgpolicy.policyViewer"; do
  gcloud organizations add-iam-policy-binding "${ORG_ID}" \
    --account="${ARGOLIS_ACCOUNT}" \
    --member="${RUNTIME_SA}" \
    --role="${ROLE}" \
    --condition=None \
    --format="none" --quiet >/dev/null 2>&1 || true
done

for ROLE in \
  "roles/viewer" \
  "roles/iam.securityReviewer" \
  "roles/cloudasset.viewer" \
  "roles/cloudkms.viewer" \
  "roles/compute.viewer" \
  "roles/privateca.auditor"; do
  gcloud resource-manager folders add-iam-policy-binding "${LAB_FOLDER_ID}" \
    --account="${ARGOLIS_ACCOUNT}" \
    --member="${RUNTIME_SA}" \
    --role="${ROLE}" \
    --condition=None \
    --format="none" --quiet >/dev/null 2>&1 || true
done

for ROLE in \
  "roles/cloudasset.viewer" \
  "roles/cloudkms.viewer" \
  "roles/compute.viewer" \
  "roles/privateca.auditor" \
  "roles/serviceusage.serviceUsageConsumer" \
  "roles/aiplatform.user" \
  "roles/cloudsql.client"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --account="${ARGOLIS_ACCOUNT}" \
    --member="${RUNTIME_SA}" \
    --role="${ROLE}" \
    --condition=None \
    --format="none" --quiet >/dev/null 2>&1 || true
done

# Grant key-scoped encrypt/decrypt ONLY on the dedicated portal DEK-wrapping KMS CryptoKey (never org-wide!)
gcloud kms keys add-iam-policy-binding "${KMS_KEY_NAME}" \
  --account="${ARGOLIS_ACCOUNT}" \
  --member="${RUNTIME_SA}" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" \
  --format="none" --quiet >/dev/null 2>&1 || true

gcloud services enable secretmanager.googleapis.com sqladmin.googleapis.com --account="${ARGOLIS_ACCOUNT}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true

if ! gcloud secrets describe "${PQC_AUTH_SECRET_SECRET}" --account="${ARGOLIS_ACCOUNT}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  python3 -c "import secrets; print(secrets.token_urlsafe(48), end='')" | \
    gcloud secrets create "${PQC_AUTH_SECRET_SECRET}" --account="${ARGOLIS_ACCOUNT}" --project="${PROJECT_ID}" --replication-policy="automatic" --data-file=-
fi

for SECRET_NAME in "${PQC_AUTH_SECRET_SECRET}" "${PQC_DB_PASSWORD_SECRET}"; do
  gcloud secrets add-iam-policy-binding "${SECRET_NAME}" \
    --account="${ARGOLIS_ACCOUNT}" \
    --project="${PROJECT_ID}" \
    --member="${RUNTIME_SA}" \
    --role="roles/secretmanager.secretAccessor" \
    --format="none" || true
done

SECRET_MAPPINGS="PQC_AUTH_SECRET=${PQC_AUTH_SECRET_SECRET}:latest,PQC_DB_PASSWORD=${PQC_DB_PASSWORD_SECRET}:latest"
if [[ -n "${PQC_GOOGLE_OAUTH_CLIENT_SECRET_NAME:-}" ]]; then
  gcloud secrets add-iam-policy-binding "${PQC_GOOGLE_OAUTH_CLIENT_SECRET_NAME}" \
    --account="${ARGOLIS_ACCOUNT}" \
    --project="${PROJECT_ID}" \
    --member="${RUNTIME_SA}" \
    --role="roles/secretmanager.secretAccessor" \
    --format="none" || true
  SECRET_MAPPINGS="${SECRET_MAPPINGS},PQC_GOOGLE_OAUTH_CLIENT_SECRET=${PQC_GOOGLE_OAUTH_CLIENT_SECRET_NAME}:latest"
fi

PQC_IAP_AUDIENCE="${PQC_IAP_AUDIENCE:-/projects/${PROJECT_NUMBER}/locations/${LOCATION}/services/${SERVICE_NAME}}"
IAP_ENV=",PQC_IAP_AUDIENCE=${PQC_IAP_AUDIENCE}"

OAUTH_CLIENT_ENV=""
if [[ -n "${PQC_GOOGLE_OAUTH_CLIENT_ID:-}" ]]; then
  OAUTH_CLIENT_ENV=",PQC_GOOGLE_OAUTH_CLIENT_ID=${PQC_GOOGLE_OAUTH_CLIENT_ID}"
fi

IAP_FLAGS=("--no-allow-unauthenticated" "--iap")
if [[ "${PQC_ENABLE_CLOUD_IAP:-true}" == "false" ]]; then
  IAP_FLAGS=("--allow-unauthenticated" "--no-iap")
fi

MIGRATION_JOB_NAME="${SERVICE_NAME}-db-migrate"

echo "=================================================================="
echo "🗄️  Running Explicit Single-Task Alembic Schema Migration (${MIGRATION_JOB_NAME})"
echo "   Target Cloud SQL : ${CLOUD_SQL_INSTANCE} (DB=${DB_NAME}, user=${DB_USER})"
echo "   Concurrency      : tasks=1, max-retries=0 (PostgreSQL advisory lock enforced)"
echo "=================================================================="

gcloud beta run jobs deploy "${MIGRATION_JOB_NAME}" \
  --source . \
  --account="${ARGOLIS_ACCOUNT}" \
  --project="${PROJECT_ID}" \
  --region="${LOCATION}" \
  --execution-environment=gen2 \
  --tasks=1 \
  --max-retries=0 \
  --task-timeout=300s \
  --set-cloudsql-instances="${CLOUD_SQL_INSTANCE}" \
  --set-secrets="${SECRET_MAPPINGS}" \
  --set-env-vars="PQC_PRODUCTION_MODE=true,PQC_CLOUD_SQL_CONNECTION_NAME=${CLOUD_SQL_INSTANCE},PQC_DB_NAME=${DB_NAME},PQC_DB_USER=${DB_USER}" \
  --command="python" \
  --args="scripts/run_db_migrations.py,--require-postgres"

gcloud beta run jobs execute "${MIGRATION_JOB_NAME}" \
  --account="${ARGOLIS_ACCOUNT}" \
  --project="${PROJECT_ID}" \
  --region="${LOCATION}" \
  --wait

echo "=================================================================="
echo "🚀 Deploying ${SERVICE_NAME} to Cloud Run (${LOCATION})"
echo "   Project       : ${PROJECT_ID}"
echo "   Cloud SQL     : ${CLOUD_SQL_INSTANCE} (DB=${DB_NAME}, user=${DB_USER})"
echo "   GCS Artifacts : gs://${BUCKET_NAME} (object storage only; no FUSE mount)"
echo "   KMS Envelope  : ${KMS_KEY_NAME}"
echo "   Scaling       : min=${MIN_INSTANCES:-1}, max=${MAX_INSTANCES:-10}, concurrency=${CONCURRENCY:-80}"
echo "   AuthFlags     : ${IAP_FLAGS[*]}"
echo "=================================================================="

gcloud beta run deploy "${SERVICE_NAME}" \
  --source . \
  --account="${ARGOLIS_ACCOUNT}" \
  --project="${PROJECT_ID}" \
  --region="${LOCATION}" \
  "${IAP_FLAGS[@]}" \
  --execution-environment=gen2 \
  --min-instances="${MIN_INSTANCES:-1}" \
  --max-instances="${MAX_INSTANCES:-10}" \
  --concurrency="${CONCURRENCY:-80}" \
  --memory="${MEMORY:-16Gi}" \
  --cpu="${CPU:-8}" \
  --no-cpu-throttling \
  --cpu-boost \
  --timeout=600 \
  --add-cloudsql-instances="${CLOUD_SQL_INSTANCE}" \
  --set-secrets="${SECRET_MAPPINGS}" \
  --set-env-vars="PQC_PRODUCTION_MODE=true,GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=global,GCP_ORGANIZATION_ID=31564119954,GCP_ORGANIZATION_NAME=jsaccomani.altostrat.com,PQC_AGENT_MODEL=gemini-3.1-pro-preview-customtools,PQC_SIMULATION_MODE=FALSE,PQC_CLOUD_SQL_CONNECTION_NAME=${CLOUD_SQL_INSTANCE},PQC_DB_NAME=${DB_NAME},PQC_DB_USER=${DB_USER},PQC_KMS_KEY_NAME=${KMS_KEY_NAME},PQC_ARTIFACT_BUCKET=gs://${BUCKET_NAME},PQC_ALLOW_UNVERIFIED_SIGNIN=false,PQC_ENABLE_ADK_DEV_UI=false,PQC_ENABLE_ADK_API=false,PQC_ENABLE_GIS_JAVASCRIPT_CLIENT=false${IAP_ENV}${OAUTH_CLIENT_ENV}"

IAP_OAUTH_CLIENT_ID="${IAP_OAUTH_CLIENT_ID:-}"
if [[ "${PQC_ENABLE_CLOUD_IAP:-true}" != "false" ]] && [[ -n "${IAP_OAUTH_CLIENT_ID:-}" ]] && \
   gcloud secrets describe "iap-external-oauth-secret" --account="${ARGOLIS_ACCOUNT}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  OAUTH_SEC=$(gcloud secrets versions access latest --secret="iap-external-oauth-secret" --account="${ARGOLIS_ACCOUNT}" --project="${PROJECT_ID}")
  URLS_JSON=$(gcloud run services describe "${SERVICE_NAME}" --account="${ARGOLIS_ACCOUNT}" --project="${PROJECT_ID}" --region="${LOCATION}" --format="value(metadata.annotations['run.googleapis.com/urls'])")
  TMP_IAP_YAML=$(mktemp)
  chmod 600 "${TMP_IAP_YAML}"
  URLS_JSON="${URLS_JSON}" CID="${IAP_OAUTH_CLIENT_ID}" CSEC="${OAUTH_SEC}" python3 - "${TMP_IAP_YAML}" <<'PY'
import json, os, sys, urllib.parse
hosts = [urllib.parse.urlparse(u).hostname for u in json.loads(os.environ.get("URLS_JSON") or "[]") if urllib.parse.urlparse(u).hostname]
lines = [
    "accessSettings:",
    "  allowedDomainsSettings:",
    "    enable: true",
    "    domains:",
    *[f'      - "{h}"' for h in hosts],
    "  oauthSettings:",
    f'    clientId: "{os.environ["CID"]}"',
    f'    clientSecret: "{os.environ["CSEC"]}"',
]
open(sys.argv[1], "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
  unset OAUTH_SEC
  gcloud iap settings set "${TMP_IAP_YAML}" --project="${PROJECT_ID}" --account="${ARGOLIS_ACCOUNT}" >/dev/null
  gcloud iap settings set "${TMP_IAP_YAML}" --project="${PROJECT_ID}" --resource-type=cloud-run --region="${LOCATION}" --service="${SERVICE_NAME}" --account="${ARGOLIS_ACCOUNT}" >/dev/null
  rm -f "${TMP_IAP_YAML}"
fi
