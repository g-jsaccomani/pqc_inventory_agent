FROM python:3.12-slim

WORKDIR /app

# Install official Google Cloud CLI (gcloud) for the Antigravity-style CLI & Dynamic Credential Bridge
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

RUN mkdir -p /data /app/data /app/exports

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOOGLE_GENAI_USE_VERTEXAI=TRUE \
    GOOGLE_CLOUD_PROJECT=pqc-inventory-agent-cd06 \
    GOOGLE_CLOUD_LOCATION=global \
    GCP_ORGANIZATION_ID=31564119954 \
    GCP_ORGANIZATION_NAME=jsaccomani.altostrat.com \
    PQC_AGENT_MODEL=gemini-3.1-pro-preview-customtools \
    PQC_SIMULATION_MODE=FALSE \
    SESSION_DB_URL=sqlite:///data/pqc_sessions.db \
    PQC_ARTIFACT_BUCKET=gs://pqc-inventory-agent-cd06-pqc-agent-staging \
    PQC_CALIBRATION_STORE_PATH=/data/calibration-history.jsonl \
    PQC_ALLOW_UNVERIFIED_SIGNIN=false \
    PQC_ENABLE_ADK_DEV_UI=false \
    PQC_ENABLE_ADK_API=false

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pqc_agent ./pqc_agent
COPY tools ./tools
COPY main.py .

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]

