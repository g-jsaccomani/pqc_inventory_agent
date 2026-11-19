# Vertex AI / Gemini Live Integration Validation Record

## 1. Target Test Identification
- **Prompt Reference:** `tests/test_pqc_inventory.py::test_live_vertex_ai_gemini_turn`
- **Actual Repository Pytest Node ID:** `tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry` *(lines 974–981)*
- **Validation Timestamp (UTC):** `2026-11-19T15:11:33Z` – `2026-11-19T15:16:15Z`
- **Environment Classification:** Dedicated authorized test environment required (must not rely on unauthorized platform/runtime projects or mutate APIs/IAM).
- **Status:** **`BLOCKED`**
- **Execution Command Attempted:** *None — live execution intentionally withheld because mandatory API enablement, ADC authorization, and dedicated test environment prerequisites were not satisfied.*
- **Duration:** `N/A` *(not executed)*

---

## 2. Pre-Execution Code & Safety Inspection

### Implementation & Fixtures
- Test function `test_live_vertex_gemini_turn_reports_model_telemetry` (`tests/test_pqc_inventory.py`, lines 974–981) is skipped unless `PQC_LIVE_LLM_TEST == "1"`.
- Invokes `main.run_adk_agent_turn("In one sentence, what does ML-KEM standardize? Do not call tools.")` and asserts:
  - `result["status"] == "OK"`
  - `result["served_by"]["models_used"]` is non-empty
  - `result["served_by"]["prompt_tokens"] > 0`
- Shared `tests/conftest.py` isolates local state during test runs (`PQC_MODEL_VERIFICATION_ON_STARTUP=false`, temporary SQLite `SESSION_DB_URL`, empty `PQC_ARTIFACT_BUCKET`, temporary `PQC_DATA_DIR`, default `GOOGLE_CLOUD_LOCATION=global`).
- `main.run_adk_agent_turn()` runs a local in-process Google ADK `Runner` with Phase 3 resilience controls (`pqc_agent/resilience.py` turn timeout, per-model circuit breaker, bounded transient retry) and issues a single direct Vertex AI `generate_content` call via `google-genai` using Application Default Credentials (`google.auth.default()`).

### Side-Effect & Cleanup Analysis
- **External Side Effects:** Stateless read-only Vertex AI model inference (`generate_content`); does not invoke Cloud Run services, Vertex AI Agent Engine endpoints, Cloud SQL, or Cloud KMS, and creates no cloud resources.
- **Local Side Effects:** Persists one synthetic ADK session/event in `tests/conftest.py`'s temporary SQLite directory (`pqc-tests-*`), cleaned up outside repository files; no repository files are modified.

### Required Environment Variables & Cloud Prerequisites
- `PQC_LIVE_LLM_TEST=1`
- `GOOGLE_GENAI_USE_VERTEXAI=TRUE`
- `GOOGLE_CLOUD_PROJECT` pointing to an authorized dedicated test project where `aiplatform.googleapis.com` is already enabled
- `GOOGLE_CLOUD_LOCATION` (e.g., `global` for Gemini 3.x / `us-central1` or `global` per model availability)
- Working Application Default Credentials (`google.auth.default()`) or workload identity authorized for `aiplatform.endpoints.predict` and `serviceusage.services.use` on that target project, with the configured Gemini Pro model (`PQC_AGENT_MODEL` / `DEFAULT_MODEL`) available.

---

## 3. Read-Only Prerequisite Audit & Exact Blocking Reasons

All checks were strictly read-only (`gcloud ... --quiet` and Cloud Resource Manager `:testIamPermissions`; zero API enablements, zero IAM edits, zero inference calls):

1. **Dedicated Validation Project (`pqc-inventory-agent-validation`):**
   - `aiplatform.googleapis.com` is **disabled** (only `cloudbuild.googleapis.com` is enabled).
   - Active Application Default Credentials (`google.auth.default()`) returned **empty permissions (`[]`)** for `aiplatform.endpoints.predict` and `serviceusage.services.use`.
   - Enabling `aiplatform.googleapis.com` or granting IAM roles is prohibited without explicit authorization.
2. **Existing Non-Production Lab Project (with `aiplatform.googleapis.com` Enabled):**
   - Although `aiplatform.googleapis.com` is enabled on the non-production lab project, active Application Default Credentials (`google.auth.default()`) returned **empty permissions (`[]`)** for `aiplatform.endpoints.predict` and `serviceusage.services.use`, and no ADC credentials file exists for the separate lab CLI identity.
   - Generating or reconfiguring ADC credentials interactively or modifying IAM bindings is out of scope without explicit authorization.
3. **Existing Local `.env` Default Project (`tier: platform`):**
   - The local `.env` points to a platform runtime project (`tier: platform`) that hosts a deployed Cloud Run service (`run.googleapis.com` enabled) and a configured Vertex AI Agent Engine resource rather than a dedicated validation environment.
   - Additionally, active ADC has no quota project (`quota_project_id=None`) and lacks `serviceusage.services.use` on that project.
   - Executing live integration tests against a non-validation platform project without explicit authorization violates the dedicated test environment and production-isolation guardrails.

---

## 4. Cleanup Confirmation & Sanitized Evidence
- **Cleanup Required:** None (no Vertex AI inference request was sent, no API was enabled, no IAM role or credential file was modified).
- **Offline Phase 3 Resilience Confirmation:** All 7 automated Phase 3.4 Vertex AI timeout, bounded retry, and per-model circuit breaker tests in `tests/test_phase3_vertex_resilience.py` **PASSED** during the regression run, while `tests/test_pqc_inventory.py:974` reported:
  ```text
  SKIPPED [1] tests/test_pqc_inventory.py:974: Set PQC_LIVE_LLM_TEST=1 with Vertex AI access to run.
  ```
