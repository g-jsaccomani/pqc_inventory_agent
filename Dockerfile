FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GOOGLE_GENAI_USE_VERTEXAI=TRUE \
    GOOGLE_CLOUD_PROJECT=pqc-inventory-agent-cd06 \
    GOOGLE_CLOUD_LOCATION=global \
    GCP_ORGANIZATION_ID=31564119954 \
    GCP_ORGANIZATION_NAME=jsaccomani.altostrat.com \
    PQC_AGENT_MODEL=gemini-3.1-pro-preview-customtools \
    PQC_SIMULATION_MODE=AUTO


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pqc_agent ./pqc_agent
COPY tools ./tools
COPY main.py .

EXPOSE 8080

CMD ["adk", "web", ".", "--host", "0.0.0.0", "--port", "8080"]
