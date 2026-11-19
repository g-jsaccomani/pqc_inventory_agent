# Vertex AI / Gemini Live Integration Validation Record

## 1. Target Test Identification
- **Prompt Reference:** `tests/test_pqc_inventory.py::test_live_vertex_ai_gemini_turn`
- **Actual Repository Pytest Node ID:** `tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry` *(lines 974–981)*
- **Tested Branch `HEAD` SHA:** `ff9287681d5c38560e03142ee4e12e0c0e2b0e5f` *(source revision `9027888484b37581c3433be3bc5917454930d4d1`)*
- **Execution Window (UTC):** `2026-11-19T17:07:19Z` – `2026-11-19T17:07:28Z`
- **Environment Category:** Live Vertex AI Gemini API in an authorized non-production validation project (`<VALIDATION_GCP_PROJECT>`, `aiplatform.googleapis.com` pre-enabled)
- **Model Configuration Used:** Repository canonical default `gemini-3.1-pro-preview-customtools` (`PQC_AGENT_THINKING_LEVEL=MEDIUM`, `GOOGLE_CLOUD_LOCATION=global`, `GOOGLE_GENAI_USE_VERTEXAI=TRUE`)
- **Status:** **`PASS`**
- **Exit Code:** `0`
- **Duration:** `6.52s`

---

## 2. Authorization, Cost & Safety Controls Applied
1. **Explicit Human Approval:** Executed only after explicit human approval of Option A (existing non-production validation project where `aiplatform.googleapis.com` was already enabled) and temporary isolated user Application Default Credentials (ADC).
2. **Zero API, IAM, or Service Account Mutations:**
   - Zero APIs enabled or modified (`aiplatform.googleapis.com` verified already enabled via read-only `gcloud services list`).
   - Zero IAM policy changes; zero service accounts or service account keys created or downloaded.
   - Verified pre-execution via read-only `projects:testIamPermissions` that the isolated user ADC principal held `aiplatform.endpoints.predict` and `serviceusage.services.use` on `<VALIDATION_GCP_PROJECT>`.
3. **Minimal Cost & Explicit Timeouts:**
   - Exactly **one (1)** single-sentence Gemini inference request was executed (`"In one sentence, what does ML-KEM standardize? Do not call tools."`).
   - Zero retries triggered, zero loops or benchmarks executed.
   - Explicit Phase 3 resilience timeouts enforced (`PQC_VERTEX_TIMEOUT_SECONDS=60`, `PQC_AGENT_TURN_TIMEOUT_SECONDS=90`).
   - No local mock or fake model was used (`FakeModelForTests` in `tests/conftest.py` only registers `r"fake-.*"`).

---

## 3. Sanitized Execution Command & Observed Telemetry

### Sanitized Command
```bash
PQC_LIVE_LLM_TEST=1 \
GOOGLE_GENAI_USE_VERTEXAI=TRUE \
GOOGLE_CLOUD_PROJECT="<VALIDATION_GCP_PROJECT>" \
GOOGLE_CLOUD_LOCATION="global" \
PQC_AGENT_MODEL="gemini-3.1-pro-preview-customtools" \
PQC_AGENT_THINKING_LEVEL="MEDIUM" \
PQC_VERTEX_TIMEOUT_SECONDS=60 \
PQC_AGENT_TURN_TIMEOUT_SECONDS=90 \
GOOGLE_APPLICATION_CREDENTIALS="<ISOLATED_ADC_CREDENTIALS_PATH>" \
  .venv/bin/pytest -v -rs \
  tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry
```

### Sanitized Verification Output & Live Model Telemetry
*(Non-sensitive model telemetry was passively observed during the single test run without altering assertions, model selection, or API calls.)*

```text
VERTEX_TEST_START_UTC=2026-11-19T17:07:19Z
collected 1 item

tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry
[LIVE_VERTEX_TELEMETRY] {"observed_utc": "2026-11-19T17:07:27Z", "llm_call_count": 1, "models_used": ["gemini-3.1-pro-preview-customtools"], "agents_involved": ["pqc_inventory_agent"], "prompt_tokens": 3197, "output_tokens": 53, "thinking_tokens": 74, "error_count": 0, "errors": []}
PASSED

======================== 1 passed, 38 warnings in 6.52s ========================
VERTEX_TEST_EXIT_CODE=0
VERTEX_TEST_END_UTC=2026-11-19T17:07:28Z
```

### Observed Telemetry Breakdown
| Telemetry Field | Observed Value |
| :--- | :--- |
| **Requested / Served Model ID** | `gemini-3.1-pro-preview-customtools` |
| **Vertex AI Location** | `global` |
| **Thinking Level** | `MEDIUM` |
| **LLM Call Count** | `1` |
| **Agents Involved** | `["pqc_inventory_agent"]` |
| **Prompt Tokens** | `3197` |
| **Output Tokens** | `53` |
| **Thinking Tokens** | `74` |
| **Total Tokens** | `3324` |
| **Error Count** | `0` |
| **Turn Latency (pytest wall)** | `6.52s` |

---

## 4. Assertions Verified Against Live Vertex AI
1. `result["status"] == "OK"` (no fallback, no error envelope, circuit breaker remained closed).
2. `result["served_by"]["models_used"]` was non-empty and reported real Vertex AI model `gemini-3.1-pro-preview-customtools`.
3. `result["served_by"]["prompt_tokens"] > 0` (`3197`), with real non-zero `output_tokens` (`53`) and `thinking_tokens` (`74`).
4. Phase 3.4 HTTP timeout (`build_vertex_http_options`), turn deadline enforcement (`PQC_AGENT_TURN_TIMEOUT_SECONDS`), and per-model circuit breaker (`VertexCircuitBreaker`) operated cleanly end-to-end with real `google-genai` Vertex AI transport.

---

## 5. Credential Setup Note & Post-Run Cleanup Verification
- **Setup Note:** An initial interactive browser OAuth sign-in (`17:03:43Z` – `17:03:58Z`) selected an unintended browser profile without permissions on `<VALIDATION_GCP_PROJECT>` (caught immediately by read-only `testIamPermissions` before any inference call). Re-authenticating with the authorized isolated validation account (`17:05:07Z` – `17:06:19Z`) attached quota project `<VALIDATION_GCP_PROJECT>` and confirmed `aiplatform.endpoints.predict` + `serviceusage.services.use` prior to running the single live turn.
- **Cleanup Verified (`2026-11-19T17:08:06Z`):**
  - Revoked temporary isolated user ADC via `gcloud auth application-default revoke --quiet` (`Credentials revoked.`).
  - Confirmed temporary isolated ADC file removed from disk, leaving the default `~/.config/gcloud/` profile untouched.
  - Deleted temporary read-only scratch telemetry observer script (`SCRATCH_HELPERS_REMOVED=OK`).
  - Zero cloud resources created; zero APIs or IAM bindings modified.
