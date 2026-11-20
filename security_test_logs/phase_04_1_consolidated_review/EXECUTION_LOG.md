# Phase 4.1 — Consolidated Security Review Execution Log

## 1. Precondition Gate Verification (All 7 Passed)
- Confirmed repository `g-jsaccomani/pqc_inventory_agent` on branch `security-hardening/phase-04-scope-isolation`.
- Confirmed `HEAD` == `40506e06385490cea16094aecf49bfc6f091f13e`.
- Confirmed `main` and `origin/main` == `7f91cae13060b8fb8ceed9ac689981527c00df9f`.
- Confirmed PR #3 (`https://github.com/g-jsaccomani/pqc_inventory_agent/pull/3`) is `OPEN`, targets `main`, and contains exactly the 4 expected Phase 4.1 commits (`5f325a5`, `36dec31`, `f8a05b1`, `40506e0`).
- Confirmed working tree clean (no modified tracked files).

## 2. Integrated End-to-End Security Audit
Audited all four commits together across the entire repository (`tools/gcloud_bridge.py`, `tools/gcp_inventory.py`, `tools/pqc_detectors.py`, `tools/quantum_engine.py`, `pqc_agent/workspace_server.py`, `pqc_agent/portal_ui.py`, `pqc_agent/auth_guard.py`, `pqc_agent/auth_store.py`, `pqc_agent/credential_service.py`, `main.py`). Identified 7 confirmed security/isolation defects (`CR-01` through `CR-07`):
- `CR-01` [HIGH]: Missing `user_id` ownership binding silently skipped in `_active_tenant_default_scope()` and `authorize_gcp_scope()` (`if conn_uid is not None:`), and unchecked in `resolve_authorized_tenant_scope()`.
- `CR-02` [HIGH]: Arbitrary non-email identities and production/HTTP unauthenticated contexts misclassified as unauthenticated CLI helpers and given `DEFAULT_ORGANIZATION_ID`; HTTP middleware did not reset tenant ContextVars on request entry/exit.
- `CR-03` [HIGH]: `_SCAN_CACHE` keyed on collidable 10-char `access_token_preview`, fell back to shared `"unconfigured"` on error, lacked scope-policy fingerprinting, mixed live/sim prefixes, and lacked lock synchronization.
- `CR-04` [HIGH]: `portal_ui.py`, `workspace_server.py` (`build_oauth_authorize_uri`, `GET /api/sessions/{id}`), and `auth_store.py` (`upsert_session_metadata`) hardcoded `"31564119954"` and `"pqc-inventory-agent-cd06"`, breaking delegated-token onboarding for project-bound/unbound portal users without `POST /api/connection`.
- `CR-05` [MEDIUM]: Unauthenticated startup background thread `_warm_inventory_cache()` invoked all 5 collectors against `organizations/{DEFAULT_ORGANIZATION_ID}` on boot.
- `CR-06` [MEDIUM]: Standalone `_fetch_compute_pq_key_exchange()` swallowed `PermissionError` via `except Exception: return None`.
- `CR-07` [MEDIUM]: `PqcOAuth3LOPlugin.before_tool_callback()` allowed unauthenticated `inv_uid` and unbound omitted scopes through to consent cards; `_resolve_and_authorize_request_scope()` returned `""` on empty `raw` + empty `active_uri` even when `allow_unbound_non_scan=False`.

## 3. Surgical Remediations Applied
- `tools/gcloud_bridge.py`: Added `UNAUTHENTICATED_CLI_IDENTITIES`, `_CURRENT_EXECUTION_CONTEXT`, `classify_execution_context()`, `enter_http_request_tenant_context()`, `exit_http_request_tenant_context()`; tightened `_is_authenticated_email_identity()`; required mandatory matching non-empty string `user_id` ownership in `resolve_authorized_tenant_scope()` and `authorize_gcp_scope()`; passed explicit `"user_id": uid` from `get_gcp_connection_config()`.
- `tools/gcp_inventory.py`: Added `_SCAN_CACHE_LOCK` and fail-closed `_live_cache_partition()` (SHA-256 credential digest + SHA-256 authorized-scope fingerprint, zero `"unconfigured"` live fallback, segregated `sim:` namespace); updated `_active_tenant_default_scope()` to use `classify_execution_context()` and require mandatory matching `conn["user_id"]`; threaded `simulated=True` / `client_kwargs=client_kwargs` through all 3 collectors.
- `tools/pqc_detectors.py`: Added `except PermissionError: raise` in `_fetch_compute_pq_key_exchange()` and threaded `simulated=True` / `client_kwargs=client_kwargs` through both collectors.
- `pqc_agent/workspace_server.py`: Isolated & reset HTTP/WebSocket tenant ContextVars in `_AuthStoreContextMiddleware`; removed `_warm_inventory_cache()`; removed hardcoded `organizations/31564119954` in `build_oauth_authorize_uri()` and `GET /api/sessions/{id}`; hardened `_resolve_and_authorize_request_scope()` and `PqcOAuth3LOPlugin.before_tool_callback()` for unauthenticated identities and unbound omitted scopes.
- `pqc_agent/auth_store.py`: Removed hardcoded `organizations/31564119954` fallback in `upsert_session_metadata()`.
- `pqc_agent/portal_ui.py`: Removed all hardcoded `31564119954` and `pqc-inventory-agent-cd06` defaults; added `currentActiveScopeUri` + `getActiveTenantScopeUri()` so sign-in, session creation, OAuth popups, consent cards, and `/api/chat` bind seamlessly to server-assigned org/project/folder scopes without requiring `POST /api/connection`.
- `tests/test_phase4_consolidated_security_review.py`: Added 23 deterministic security regression tests covering all 20 required verification criteria and `CR-01`–`CR-07`.
- `tests/test_phase4_delegated_token_validation.py` & `tests/test_phase3_adc_authorization.py`: Aligned 2 existing assertions with stricter fail-closed `PermissionError` (`_fetch_compute_pq_key_exchange`) and `SCOPE_AUTHORIZATION_DENIED` (unbound `organizations/31564119954` in `PqcOAuth3LOPlugin`).

## 4. Controlled Validation Runs
- Stage 1 (`test_phase4_consolidated_security_review.py`): `23 passed`, exit `0`.
- Stage 2 (`test_phase4_scope_isolation.py`): `9 passed`, exit `0`.
- Stage 3 (`test_phase4_delegated_token_validation.py`): `15 passed`, exit `0`.
- Stage 4 (`test_phase4_fail_closed_scope_resolution.py`): `29 passed`, exit `0`.
- Stage 5 (`test_phase3_adc_authorization.py` + `test_phase3_egress_security.py`): `222 passed`, exit `0`.
- Stage 6 (`test_auth_hardening.py` + `test_phase1_distributed_auth.py` + `test_phase2_persistence_and_credentials.py` + `test_pqc_inventory.py`): `76 passed, 2 skipped`, exit `0`.
- Stage 7 (`tests/` full safe local suite): `419 passed, 4 skipped`, exit `0`.
- `python -m compileall -q pqc_agent tools tests main.py`: exit `0`.
- `git diff --check`: exit `0`.
- Secret & operational identifier scan: `CLEAN (0 matches)`, exit `0`.
