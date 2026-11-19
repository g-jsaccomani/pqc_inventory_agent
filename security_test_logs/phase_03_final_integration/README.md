# Phase 3 Final Live Integration Validation — Evidence Directory

This directory records the completed live integration validation evidence, chronological execution log, regression verification totals, cleanup verification, and final sign-off checkpoint for branch `security-hardening/phase-03-runtime-resilience`.

## Final Status
- **Gate A — Live PostgreSQL 16 Persistence:** **`PASS`** (`1 passed, 0 failed` in `150.30s` against PostgreSQL 16.15)
- **Gate B — Live Vertex AI Gemini Turn:** **`PASS`** (`1 passed, 0 failed` in `6.52s` against `gemini-3.1-pro-preview-customtools` on `global`)
- **Gate C — Cloud Build Docker Non-Root & Read-Only Runtime:** **`PASS`** (`2 passed, 0 failed` in `16.31s`, Build ID `605c784d-6949-4891-bfd0-0ba519a6c68d`, valid for tested source revision `9027888484b37581c3433be3bc5917454930d4d1`)
- **Full Safe Local Suite / Phase 3 Suites:** **`343 passed, 0 failed, 4 skipped`** (`61.82s`) / **`261 passed, 0 failed, 1 skipped`** (`10.07s`)
- **Phase 3 Readiness:** **`READY FOR FINAL SIGN-OFF`**

## Directory Contents
- [PHASE_03_FINAL_INTEGRATION_REPORT.md](./PHASE_03_FINAL_INTEGRATION_REPORT.md) — Executive summary, gate matrix, regression verification totals, cleanup confirmation, and **`READY FOR FINAL SIGN-OFF`** determination.
- [postgresql_validation.md](./postgresql_validation.md) — Detailed **`PASS`** evidence, safety guard verification, runner notes, and cleanup confirmation for `tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration`.
- [vertex_ai_validation.md](./vertex_ai_validation.md) — Detailed **`PASS`** evidence, real Vertex AI model/token telemetry, timeout/cost controls, and immediate ADC revocation verification for `tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry`.
- [EXECUTION_CHECKPOINT.md](./EXECUTION_CHECKPOINT.md) — Verified commit lineage, gate statuses, regression totals, Cloud Build reference, and final readiness checkpoint.
- [EXECUTION_LOG.md](./EXECUTION_LOG.md) — Chronological UTC execution log covering preflight, authorization, live runs, deviations, regression suites, and cleanup verification.

## Related Validated Evidence
- Cloud Build live Docker non-root (`UID/GID 10001`) and `--read-only` root filesystem validation (**`PASS`**, `2 passed, 0 failed, 0 skipped`, Build ID `605c784d-6949-4891-bfd0-0ba519a6c68d`): [GCP_CLOUD_BUILD_DOCKER_VALIDATION.md](../cloud_build_validation/GCP_CLOUD_BUILD_DOCKER_VALIDATION.md)

## Reproducing Live Validation Safely

### 1. Live PostgreSQL 16 Persistence Integration
Execute only against an authorized, dedicated, disposable PostgreSQL 16 database whose name matches `^pqc_test_[a-zA-Z0-9_]+$` (never production or shared databases):

```bash
PQC_ALLOW_DESTRUCTIVE_TEST_DB=true \
PQC_TEST_POSTGRES_URL="postgresql+psycopg://<TEST_DB_USER>:<EPHEMERAL_TEST_PASSWORD>@127.0.0.1:<LOOPBACK_MTLS_PORT>/pqc_test_<name>" \
  .venv/bin/pytest -v -rs \
  tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration
```

### 2. Live Vertex AI Gemini Turn Integration
Execute only with temporary isolated Application Default Credentials targeting an authorized non-production validation project with `aiplatform.googleapis.com` enabled:

```bash
PQC_LIVE_LLM_TEST=1 \
GOOGLE_CLOUD_PROJECT="<VALIDATION_GCP_PROJECT>" \
GOOGLE_CLOUD_LOCATION="global" \
GOOGLE_GENAI_USE_VERTEXAI="TRUE" \
PQC_AGENT_MODEL="gemini-3.1-pro-preview-customtools" \
PQC_AGENT_THINKING_LEVEL="MEDIUM" \
PQC_VERTEX_TIMEOUT_SECONDS=60 \
PQC_AGENT_TURN_TIMEOUT_SECONDS=90 \
GOOGLE_APPLICATION_CREDENTIALS="<ISOLATED_ADC_CREDENTIALS_PATH>" \
  .venv/bin/pytest -v -rs \
  tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry
```
