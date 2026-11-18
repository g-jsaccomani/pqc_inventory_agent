# Phase 3.1 (`P3-01`) — Test Execution & Verification Results

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Baseline `main` Commit SHA:** `62f7247b52effc3f3cf2086a86f06071eea1b6fc`
- **Exact Starting Commit SHA:** `90ddf8fd08dc3b0e50d54176f44c267330493854`
- **Final Commit:** Direct child of `90ddf8fd08dc3b0e50d54176f44c267330493854` (`fix(security): harden outbound egress and gcloud execution`; exact self-SHA inspectable via `git rev-parse HEAD`)

---

## 1. Complete Manifest of Changed & Added Files (`P3-01`)

| File Path | Change Type | Purpose |
| :--- | :---: | :--- |
| [pqc_agent/egress_guard.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/egress_guard.py) | **Added** | Centralized `safe_urlopen()` enforcing HTTPS-only, exact Google OAuth/OIDC allowlist, IP-literal & metadata/private IP blocking, single-lookup DNS pinning with TLS SNI/cert verification, disabled redirects, finite timeouts, `64 KiB` bounded streaming reads, and secret redaction. |
| [pqc_agent/workspace_server.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py) | **Modified** | Replaced all 4 direct `urllib.request.urlopen()` calls (`L510`, `L564`, `L604`, `L1322`) with `egress_guard.safe_urlopen()`, scrubbed tokens from OAuth error messages, and added `ConfigDict(extra="forbid")` on `GcloudCommandPayload`. |
| [pqc_agent/credential_service.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/credential_service.py) | **Modified** | Replaced `urllib.request.urlopen()` in `_default_oauth_refresh_exchange()` (`L236`) with `egress_guard.safe_urlopen()`. |
| [pqc_agent/auth_guard.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/auth_guard.py) | **Modified** | Hardened `_CertCachingRequest` JWKS retrieval (`L420-L539`) to route all certificate fetches through `egress_guard.safe_urlopen()` (`GOOGLE_JWKS_ALLOWED_HOSTS`, `64 KiB` cap, no redirects, verified TLS, finite timeout) while preserving `google.auth.transport.requests.Request` compatibility. |
| [tools/gcloud_bridge.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcloud_bridge.py) | **Modified** | Replaced verb-only `validate_gcloud_command()` with structured command/flag grammar & typed value validators; added `build_sanitized_gcloud_env()` scrubbing `CLOUDSDK_API_ENDPOINT_OVERRIDES_*` and proxy vars; eliminated confused-deputy `access_token` -> server ADC fallback; enforced fail-closed mode normalization and credential resolution. |
| [tests/test_phase3_egress_security.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_phase3_egress_security.py) | **Added** | `181` deterministic unit, DNS-pinning, adversarial `gcloud`, legitimate regression, OAuth integration, and confused-deputy test cases (`0` skipped). |
| [security_test_logs/phase_03_1_p3_01/EXECUTION_CHECKPOINT.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/security_test_logs/phase_03_1_p3_01/EXECUTION_CHECKPOINT.md) | **Added** | Stage 0 preconditions & execution checkpoint. |
| [security_test_logs/phase_03_1_p3_01/TEST_RESULTS.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/security_test_logs/phase_03_1_p3_01/TEST_RESULTS.md) | **Added** | Complete test execution commands, counts, exit codes, and skip documentation. |
| [security_test_logs/phase_03_1_p3_01/ADVERSARIAL_TESTS.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/security_test_logs/phase_03_1_p3_01/ADVERSARIAL_TESTS.md) | **Added** | Detailed adversarial SSRF, redirect, DNS rebinding, `gcloud` flag smuggling, and confused-deputy test outcomes. |
| [security_test_logs/phase_03_1_p3_01/SECURITY_REVIEW.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/security_test_logs/phase_03_1_p3_01/SECURITY_REVIEW.md) | **Added** | Stage 5 security review, remaining non-`urlopen` SDK egress inventory, and deferred Phase 3 risks. |

---

## 2. Executed Test Commands, Counts, and Exit Codes

| Execution Step | Exact Command | Collected | Passed | Failed | Skipped | Duration | Exit Code |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **1. Pre-Change Baseline Suite** | `.venv/bin/pytest -v` | `85` | `82` | `0` | `3` | `50.07s` | `0` |
| **2. Dedicated `P3-01` Security Suite** | `.venv/bin/pytest tests/test_phase3_egress_security.py -v` | `181` | `181` | `0` | `0` | `2.5s` | `0` |
| **3. Bytecode Syntax Verification** | `.venv/bin/python -m compileall -q main.py pqc_agent tools tests` | — | — | — | — | `< 1.0s` | `0` |
| **4. Complete Repository Suite** | `.venv/bin/pytest -v -rs` | `266` | `263` | `0` | `3` | `61.65s` | `0` |
| **5. Whitespace & Patch Hygiene** | `git diff --check` | — | — | — | — | `< 0.2s` | `0` |

---

## 3. Skipped Tests & Environment Limitations

Zero (`0`) tests in `tests/test_phase3_egress_security.py` were skipped (`181/181 PASSED`).

The `3` skipped tests in the full `266`-test repository run are pre-existing Phase 1–2 live-infrastructure integration tests gated by environment availability:

1. `tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration`
   - **Reason:** Requires a disposable live PostgreSQL 16 target (`PQC_TEST_POSTGRES_URL`) and explicit `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true` opt-in.
2. `tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry`
   - **Reason:** Opt-in live Vertex AI Gemini API test (`PQC_LIVE_LLM_TEST=1`); disabled in hermetic test runs.
3. `tests/test_pre_merge_hotfix.py::test_pre_merge_01_live_docker_build_and_container_smoke`
   - **Reason:** `BLOCKED: Docker CLI/daemon is not installed in this workstation environment.`

**Validation Blocked by Environment Limitations for `P3-01`:**
- Live Cloud Run Serverless VPC Egress / Cloud NAT / Metadata Server (`169.254.169.254`) network-level integration testing was not executed because `PHASE03` explicitly prohibits deploying to GCP or modifying production infrastructure; all metadata-IP, redirect, DNS-rebinding, and `gcloud` subprocess boundaries were verified deterministically via local mocks/fakes.
