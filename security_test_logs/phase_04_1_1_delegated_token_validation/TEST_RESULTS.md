# Phase 4.1.1 — Verification & Regression Test Results

**Branch:** `security-hardening/phase-04-scope-isolation`
**Base Revision (`origin/main`):** `7f91cae13060b8fb8ceed9ac689981527c00df9f`
**Pre-4.1.1 HEAD:** `36dec313551c158a1e01abb4e11e8a384d5575a7`
**Execution Environment:** Local Python `3.12.13` (`.venv`, `pytest 9.1.1`). All Phase 4.1.1 tests mock identity providers, Google Cloud SDK clients (`AssetServiceClient`, `KeyManagementServiceClient`, `SslPoliciesClient`, `RegionSslPoliciesClient`), `google.auth.default`, and `subprocess.run`. No GCP resources, Cloud SQL databases, Vertex AI endpoints, or Docker daemons were invoked.

## Result Provenance & Cloud-Safety Scope

- All counts below are recorded local workstation runs executed on 2026-11-19 against the working-tree source and test files prior to committing. No automated GitHub Actions / CI check exists in this repository at this revision.
- As previously documented in Phase 4.1 (`security_test_logs/phase_04_1_scope_isolation/TEST_RESULTS.md`), the full-suite output includes the pre-existing `google.auth` warning on 9 `tests/test_pqc_inventory.py` tests where local Cloud SDK ADC files exist on disk; outbound network traffic was not instrumented during the full-suite run, while the 15 targeted Phase 4.1.1 tests enforce an explicit `google.auth.default` tripwire and assert `0` calls.

## 1. Targeted Phase 4.1.1 Security Suite

Command:
```bash
.venv/bin/pytest -v -rs tests/test_phase4_delegated_token_validation.py
```

Observed Result: **`15 passed, 0 failed, 0 skipped`** (`3.40s`, exit `0`).

| Test Case | Requirement Verified | Outcome |
|---|---|---|
| `test_01_delegated_token_auth_with_server_bound_project_scope` | Req 1 — Delegated-token auth auto-binds server project (`PQC_ALLOWED_PROJECTS`); all 5 collectors succeed on explicit & `"default"` scope with `oauth2.Credentials(expiry, quota_project_id)`; partial-policy org bypass returns `403` / `UNAUTHORIZED_RESOURCE_SCOPE` with 0 extra SDK/ADC calls. | **PASS** |
| `test_02_delegated_token_auth_with_server_bound_organization_scope` | Req 2 — Delegated-token auth auto-binds server org (`PQC_ALLOWED_ORGANIZATIONS`); all 5 collectors succeed on explicit & `"org"` scope; partial-policy project bypass returns `403` / `UNAUTHORIZED_RESOURCE_SCOPE` with 0 extra SDK/ADC calls. | **PASS** |
| `test_03_missing_organization_and_project_scope_fails_closed` | Req 3 — Unscoped delegated token fails closed with `UNAUTHORIZED_RESOURCE_SCOPE (MISSING_AUTHORIZED_SCOPE)` across all 5 collectors; `/api/sessions` returns `""` (not `organizations/`); production (`K_SERVICE`) blocks `POST /api/connection` self-binding (`403`) and tampered DB rows; 0 SDK/ADC calls. | **PASS** |
| `test_04_client_cannot_override_server_bound_scope_via_any_request_payload` | Req 4 — Client override attempts across `/api/connection`, `/api/chat` (JSON & FormData), `/api/sessions`, `/api/auth/tool-consent`, `/api/auth/oauth/authorize`, `PqcOAuth3LOPlugin`, and all 5 collectors fail closed (`403` / `SCOPE_AUTHORIZATION_DENIED` / `UNAUTHORIZED_RESOURCE_SCOPE`); omitted `/api/chat` scope inherits server project; 0 SDK/ADC calls. | **PASS** |
| `test_05_cross_tenant_organization_access_denied` | Req 5 — Alice cannot read Bob's live or cached org (`organizations/222222222222`) via `/api/connection`, `/api/chat`, `/api/sessions`, `/api/gcloud`, or any collector, nor inject Bob's verified Google token via `/api/auth/tool-consent` (`403`); 0 Bob key leaks, 0 subprocess/SDK/ADC calls. | **PASS** |
| `test_06_cross_tenant_project_access_denied` | Req 6 — Alice cannot read Bob's live or cached project (`projects/tenant-b-proj-02`) via `/api/connection`, `/api/chat`, `/api/sessions`, `/api/gcloud`, or any collector; 0 Bob key leaks, 0 subprocess/SDK/ADC calls. | **PASS** |
| `test_07_expired_revoked_and_invalid_delegated_tokens_never_create_sdk_clients` | Req 7 — Invalid login token (`401`), malformed tokens (`400 ACCESS_TOKEN_INVALID`), `expires_in <= 0` (`ACCESS_TOKEN_EXPIRED`), expired DB credential (`ACCESS_TOKEN_REQUIRED`), and post-logout revoked token (`ACCESS_TOKEN_REQUIRED`) fail closed with 0 SDK/ADC calls. | **PASS** |
| `test_08_unauthorized_scope_after_existing_connection_established_is_denied` | Req 8 — After establishing org `111111111111` (without env policies), attempting to re-bind org `222222222222` or pivot to `projects/tenant-b-proj-02` via `POST /api/connection` returns `403`, DB remains locked, and `/api/chat`, `/api/sessions`, and all 5 collectors deny foreign scopes with 0 SDK/ADC calls. | **PASS** |
| `test_09_scope_revocation_after_cache_population_blocks_all_collectors_and_apis` | Req 9 — Revoking Alice's scopes in `PQC_TENANT_SCOPE_POLICY` after warming `_SCAN_CACHE` across all 5 collectors immediately clears `GET /api/connection`, rejects `/api/chat` & `/api/sessions` (`403`), and causes all 5 collectors to fail closed with `UNAUTHORIZED_RESOURCE_SCOPE` (0 cached leaks, 0 SDK/ADC calls). | **PASS** |
| `test_10_no_sdk_client_creation_on_any_denied_request` | Req 10 — Hard SDK tripwires confirm 0 `AssetServiceClient`, `KeyManagementServiceClient`, `SslPoliciesClient`, `RegionSslPoliciesClient`, and `google.auth.default` calls across unauth, missing-token, unauthorized/malformed scopes, and standalone `_fetch_compute_pq_key_exchange()`. | **PASS** |
| `test_11_no_ambient_adc_fallback_under_any_delegated_failure` | Req 11 — With `GOOGLE_APPLICATION_CREDENTIALS` planted, tampered DB `mode='adc'` fails closed (`ADC_UNAUTHORIZED`, 0 ADC calls) and CAI `403 PERMISSION_DENIED` on delegated token runs once with user `oauth2.Credentials` and 0 ambient ADC retries. | **PASS** |
| `test_12_authorized_administrator_adc_mode_regression` | Req 12 — `PQC_ADMIN_EMAILS` + `PQC_ALLOWED_ORGANIZATIONS` succeeds in ADC mode (`client_kwargs={}`) on allowlisted org and denies non-allowlisted org/project (`UNAUTHORIZED_RESOURCE_SCOPE` / `403`, 0 extra SDK calls). | **PASS** |
| `test_13_explicit_demo_and_simulation_mode_regression` | Req 13 — `demo-pqc-project` and `PQC_SIMULATION_MODE=TRUE` return `SIMULATED_DEMO_DATASET` with `simulation_notice` across all 5 collectors, scorecard, and CBOM with 0 live SDK/ADC calls. | **PASS** |
| `test_14_scorecard_and_cyclonedx_workflows_under_authorized_delegated_access` | Req 14 — Project-bound & org-bound delegated tenants produce `COMPLETE` scorecard (KMS + TLS + Compute `SslPoliciesClient` with delegated credentials + BYOK) and CycloneDX v1.6 CBOM; unauthorized scope fails closed (`COLLECTION_FAILED` / `UNAUTHORIZED_RESOURCE_SCOPE`, 0 extra SDK/ADC calls). | **PASS** |
| `test_15_oauth_3lo_pkce_callback_enforces_server_bound_scope_and_midflow_revocation` | End-to-end 3LO PKCE `/api/auth/oauth/authorize` -> `/api/auth/oauth/callback` binds server project scope and succeeds in KMS collector; revoking scope mid-flow causes callback to fail closed (`403 UNAUTHORIZED_RESOURCE_SCOPE`). | **PASS** |

## 2. Regression Suites

| Suite / Command | Observed Result | Notes |
|---|---|---|
| `.venv/bin/pytest -q -rs tests/test_phase4_scope_isolation.py` | **`9 passed, 0 skipped, 0 failed`** (`1.25s`) | All Phase 4.1 scope isolation & AST literal checks green. |
| `.venv/bin/pytest -q -rs tests/test_auth_hardening.py tests/test_phase1_distributed_auth.py` | **`40 passed, 0 skipped, 0 failed`** (`5.10s`) | All Phase 1 auth hardening & distributed OAuth tests green. |
| `.venv/bin/pytest -q -rs tests/test_pqc_inventory.py tests/test_phase3_scorecard_correctness.py` | **`34 passed, 1 skipped, 0 failed`** (`11.09s`) | 1 skip: `test_live_vertex_gemini_turn_reports_model_telemetry` (requires `PQC_LIVE_LLM_TEST=1`, prohibited in Phase 4.1.1). |
| `.venv/bin/pytest -q -rs tests/test_phase3_adc_authorization.py` | **`41 passed, 0 skipped, 0 failed`** (`4.66s`) | All Phase 3.1 ADC & tenant scope authorization tests green. |
| `.venv/bin/pytest -q -rs tests/test_phase3_egress_security.py` | **`181 passed, 0 skipped, 0 failed`** (`1.86s`) | All Phase 3.1 SSRF/egress/gcloud hardening tests green. |
| `.venv/bin/pytest -q -rs` (Full Safe Local Suite) | **`367 passed, 4 skipped, 0 failed`** (`63.57s`) | 4 skips: 1 live PostgreSQL (`PQC_TEST_POSTGRES_URL`), 1 live Vertex AI (`PQC_LIVE_LLM_TEST=1`), 2 Docker daemon (`Docker CLI/daemon is not installed in this workstation environment`). All 4 skips are prohibited out-of-scope live/daemon tests. |

## 3. Initial Failure Encountered & Resolved During Validation

- **First run of `tests/test_phase4_delegated_token_validation.py`:** `11 passed, 1 failed` (`test_03_missing_organization_and_project_scope_fails_closed`).
  - **Cause:** Switching `K_SERVICE="pqc-inventory-agent"` mid-test triggered Phase 2's fail-closed Cloud KMS envelope guard (`PQC_KMS_KEY_NAME` unset in production) when `get_gcp_connection_config()` decrypted the stored token.
  - **Fix:** Attached an explicit in-memory `LocalHkdfKekWrapper` to `app.state.credential_service._explicit_wrapper` inside `test_03` before setting `K_SERVICE`, simulating a production instance with KMS configured while isolating the missing tenant scope policy test. Re-run passed cleanly (`15 passed, 0 failed, 0 skipped`).

## 4. Static Hygiene & Secret / Sensitive-Identifier Verification

| Check | Command | Outcome |
|---|---|---|
| Bytecode compilation | `.venv/bin/python -m compileall -q pqc_agent tools tests main.py` | Recorded in `EXECUTION_LOG.md` (verified before commit). |
| Diff hygiene | `git diff --check` | Recorded in `EXECUTION_LOG.md` (verified before commit). |
| Secret & sensitive-identifier scan | Automated regex scan over `git diff 36dec31...` and all new Phase 4.1.1 files | Recorded in `EXECUTION_LOG.md` (verified before commit). |
