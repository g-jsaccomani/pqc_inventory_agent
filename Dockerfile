FROM python:3.12-slim

WORKDIR /app

# Install official Google Cloud CLI (gcloud) for read-only control-plane diagnostics
RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
       | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
       > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && apt-get update && apt-get install -y --no-install-recommends \
       google-cloud-cli \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/exports

# Production posture:
# - Authoritative transactional persistence MUST be Cloud SQL for PostgreSQL
#   (injected via DATABASE_URL or PQC_CLOUD_SQL_CONNECTION_NAME + Secret Manager PQC_DB_PASSWORD).
# - Production fails closed if PostgreSQL, PQC_AUTH_SECRET, or PQC_KMS_KEY_NAME is missing.
# - Cloud Storage (PQC_ARTIFACT_BUCKET) is used strictly for object/artifact storage, never SQLite/FUSE.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PQC_PRODUCTION_MODE=true \
    GOOGLE_GENAI_USE_VERTEXAI=TRUE \
    GOOGLE_CLOUD_PROJECT=pqc-inventory-agent-cd06 \
    GOOGLE_CLOUD_LOCATION=global \
    GCP_ORGANIZATION_ID=31564119954 \
    GCP_ORGANIZATION_NAME=jsaccomani.altostrat.com \
    PQC_AGENT_MODEL=gemini-3.1-pro-preview-customtools \
    PQC_SIMULATION_MODE=FALSE \
    PQC_ARTIFACT_BUCKET=gs://pqc-inventory-agent-cd06-pqc-agent-staging \
    PQC_ALLOW_UNVERIFIED_SIGNIN=false \
    PQC_ENABLE_ADK_DEV_UI=false \
    PQC_ENABLE_ADK_API=false \
    PQC_ENABLE_GIS_JAVASCRIPT_CLIENT=false

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY alembic.ini .
COPY migrations ./migrations
COPY pqc_agent ./pqc_agent
COPY tools ./tools
COPY scripts/run_db_migrations.py ./scripts/run_db_migrations.py
COPY scripts/migrate_sqlite_to_postgres.py ./scripts/migrate_sqlite_to_postgres.py
COPY main.py .
RUN chmod 0755 /app/scripts/run_db_migrations.py /app/scripts/migrate_sqlite_to_postgres.py

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
