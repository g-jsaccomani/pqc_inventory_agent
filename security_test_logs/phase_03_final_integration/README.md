# Phase 3 Final Live Integration Validation — Evidence Directory

This directory records the inspection, eligibility analysis, safety verification, execution results, and regression totals for the Phase 3 final live integration validation gate on branch `security-hardening/phase-03-runtime-resilience`.

## Directory Contents
- [PHASE_03_FINAL_INTEGRATION_REPORT.md](./PHASE_03_FINAL_INTEGRATION_REPORT.md) — Executive summary, gate matrix (`PASS` / `FAIL` / `BLOCKED` / `NOT RUN`), regression test totals, remaining blockers, and explicit readiness recommendation.
- [postgresql_validation.md](./postgresql_validation.md) — Code/fixture inspection, destructive-operation safety review, prerequisite audit, and exact `BLOCKED` record for the live PostgreSQL 16 persistence test (`tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration`).
- [vertex_ai_validation.md](./vertex_ai_validation.md) — Code/fixture inspection, read-only environment and ADC authorization audit, and exact `BLOCKED` record for the live Vertex AI Gemini test (`tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry`).

## Related Validated Evidence
- Cloud Build live Docker non-root (`UID/GID 10001`) and `--read-only` root filesystem validation (`PASS`, Build ID `605c784d-6949-4891-bfd0-0ba519a6c68d`): [GCP_CLOUD_BUILD_DOCKER_VALIDATION.md](../cloud_build_validation/GCP_CLOUD_BUILD_DOCKER_VALIDATION.md)

## Rerunning Once Prerequisites Are Authorized

### 1. Live PostgreSQL 16 Persistence Integration
Only against an authorized, dedicated, disposable PostgreSQL 16 database whose name matches `^pqc_test_[a-zA-Z0-9_]+$` (never production or shared databases):

```bash
PQC_ALLOW_DESTRUCTIVE_TEST_DB=true \
PQC_TEST_POSTGRES_URL="postgresql+psycopg://<test_user>:<test_password>@127.0.0.1:<port>/pqc_test_validation" \
  .venv/bin/pytest -v -rs \
  tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration
```

### 2. Live Vertex AI Gemini Turn Integration
Only with authorized Application Default Credentials targeting a dedicated test project with `aiplatform.googleapis.com` enabled:

```bash
PQC_LIVE_LLM_TEST=1 \
GOOGLE_CLOUD_PROJECT="<authorized-test-project-id>" \
GOOGLE_CLOUD_LOCATION="global" \
GOOGLE_GENAI_USE_VERTEXAI="TRUE" \
  .venv/bin/pytest -v -rs \
  tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry
```
