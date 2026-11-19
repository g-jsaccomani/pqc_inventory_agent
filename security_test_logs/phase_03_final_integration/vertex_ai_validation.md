# Vertex AI / Gemini Live Integration Validation Record

## 1. Target Test Identification
- **Prompt Reference:** `tests/test_pqc_inventory.py::test_live_vertex_ai_gemini_turn`
- **Actual Repository Pytest Node ID:** `tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry` *(lines 974–981)*
- **Tested Source Code Commit SHA:** `57a904f40196d013007052146ac6303278ec583f`
- **Validation Timestamp (UTC):** `2026-11-19T15:11:33Z` – `2026-11-19T15:16:15Z`
- **Environment Classification:** Dedicated authorized test environment required (must not target unrelated runtime workloads or mutate APIs/IAM).
- **Status:** **`BLOCKED`**
- **Execution Command Attempted:** *None — live execution intentionally withheld because mandatory dedicated-environment API enablement and credential authorization prerequisites were not satisfied.*
- **Duration:** `N/A` *(not executed)*

---

## 2. Pre-Execution Code & Safety Inspection

### Implementation & Fixtures
- Test function `test_live_vertex_gemini_turn_reports_model_telemetry` (`tests/test_pqc_inventory.py`, lines 974–981) is skipped unless `PQC_LIVE_LLM_TEST == "1"`.
- Invokes `main.run_adk_agent_turn("In one sentence, what does ML-KEM standardize? Do not call tools.")` and asserts:
  - `result["status"] == "OK"`
  - `result["served_by"]["models_used"]` is non-empty
  - `result["served_by"]["prompt_tokens"] > 0`
- Shared `tests/conftest.py` isolates local test state (`PQC_MODEL_VERIFICATION_ON_STARTUP=false`, temporary SQLite `SESSION_DB_URL`, empty `PQC_ARTIFACT_BUCKET`, temporary `PQC_DATA_DIR`, default `GOOGLE_CLOUD_LOCATION=global`).
- `main.run_adk_agent_turn()` runs a local in-process Google ADK `Runner` with Phase 3 resilience controls (`pqc_agent/resilience.py` turn timeout, per-model circuit breaker, bounded transient retry) and issues a single direct Vertex AI `generate_content` call via `google-genai` using Application Default Credentials (`google.auth.default()`).

### Side-Effect & Cleanup Analysis
- **External Side Effects:** Stateless read-only Vertex AI model inference (`generate_content`); creates no cloud resources and does not invoke unrelated external services.
- **Local Side Effects:** Persists one synthetic ADK session/event in `tests/conftest.py`'s temporary directory (`pqc-tests-*`), isolated from repository files; no repository files are modified.

### Required Environment Variables & Cloud Prerequisites
- `PQC_LIVE_LLM_TEST=1`
- `GOOGLE_GENAI_USE_VERTEXAI=TRUE`
- `GOOGLE_CLOUD_PROJECT` pointing to an authorized dedicated test project where `aiplatform.googleapis.com` is already enabled
- `GOOGLE_CLOUD_LOCATION` (e.g., `global` or a supported Gemini Pro region per model availability)
- Working Application Default Credentials (`google.auth.default()`) or workload identity authorized for Vertex AI prediction on that dedicated test project, with the configured Gemini Pro model (`PQC_AGENT_MODEL` / `DEFAULT_MODEL`) available.

---

## 3. Prerequisite Audit & Blocking Reasons

All checks were strictly read-only, and zero unauthorized infrastructure or credential changes were performed:

1. **No Authorized Dedicated Test Environment Ready for Vertex AI:**
   - No dedicated test project currently satisfies all mandatory execution criteria simultaneously (Vertex AI API `aiplatform.googleapis.com` enabled, working Application Default Credentials or workload identity authorized for Vertex AI inference on that project, and explicit authorization for live model execution).
2. **Strict Isolation from Unrelated Workloads:**
   - Execution against unrelated or non-validation runtime projects is excluded to avoid touching or coupling validation to unrelated workloads.
3. **No Unauthorized Cloud or Credential Changes Performed:**
   - Enabling APIs, granting IAM roles, creating service accounts, modifying organization policies, or reconfiguring credentials is prohibited without explicit authorization. Consequently, live execution was withheld and remains **`BLOCKED`**.

---

## 4. Cleanup Confirmation & Sanitized Evidence
- **Cleanup Required:** None (no Vertex AI inference request was sent, no API was enabled, and no IAM role, service account, or credential file was modified).
- **Offline Phase 3 Resilience Confirmation:** All 7 automated Phase 3.4 Vertex AI timeout, bounded retry, and per-model circuit breaker tests in `tests/test_phase3_vertex_resilience.py` **PASSED** during the regression run (`261 passed, 0 failed, 1 skipped` across Phase 3 suites in `10.67s`), while `tests/test_pqc_inventory.py:974` reported:
  ```text
  SKIPPED [1] tests/test_pqc_inventory.py:974: Set PQC_LIVE_LLM_TEST=1 with Vertex AI access to run.
  ```
