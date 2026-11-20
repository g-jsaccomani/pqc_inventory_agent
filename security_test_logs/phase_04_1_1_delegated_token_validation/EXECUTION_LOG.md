# Phase 4.1.1 — Execution Log

## 1. Mandatory Git Preconditions (2026-11-19)

- Verified remote `origin` via `git fetch origin`.
- Confirmed exact commit SHAs:
  - `main`: `7f91cae13060b8fb8ceed9ac689981527c00df9f` (matches expected base)
  - `security-hardening/phase-04-scope-isolation~1`: `5f325a5be161fc204efdc36d4c59a09559494e62` (matches expected Phase 4.1 implementation commit)
  - `security-hardening/phase-04-scope-isolation` & `origin/security-hardening/phase-04-scope-isolation`: `36dec313551c158a1e01abb4e11e8a384d5575a7` (matches expected Phase 4.1 docs commit)
- Confirmed PR #3 (`OPEN`, `https://github.com/g-jsaccomani/pqc_inventory_agent/pull/3`, base `main`, head `36dec313551c158a1e01abb4e11e8a384d5575a7`).
- Checked out `security-hardening/phase-04-scope-isolation` with clean tracked working tree.

## 2. Security Investigation

- Inspected `pqc_agent/workspace_server.py`, `pqc_agent/credential_service.py`, `pqc_agent/auth_store.py`, `pqc_agent/portal_ui.py`, `tools/gcloud_bridge.py`, `tools/gcp_inventory.py`, `tools/pqc_detectors.py`, `main.py`, and existing auth/Phase 3/Phase 4.1 test suites.
- Confirmed baseline regression health (`108 passed, 1 skipped` across `test_phase4_scope_isolation.py`, `test_phase3_adc_authorization.py`, `test_pqc_inventory.py`, `test_auth_hardening.py`).
- Identified:
  1. Compatibility gap: delegated-token logins left `organization_id=""` / `project_id=""` even when server policy (`PQC_ALLOWED_PROJECTS`, `PQC_ALLOWED_ORGANIZATIONS`, `PQC_TENANT_SCOPE_POLICY`) granted an unambiguous scope; `/api/sessions` fabricated `organizations/`, `/api/chat` defaulted to `organizations/31564119954`, and `_resolve_scope()` fell back to `DEFAULT_ORGANIZATION_ID`.
  2. `V-4.1.1-01` (Critical): partial server policy bypass (`PQC_ALLOWED_PROJECTS` alone left `has_org_restriction=False`, permitting arbitrary org self-binding, and symmetrically for org-only/folder-only policies).
  3. `V-4.1.1-02` (High): production self-binding via `POST /api/connection` when no server policy is set, and post-binding scope mutation/pivoting on established connections.
  4. `V-4.1.1-03` (High): unvalidated client scope parameters in `/api/chat`, `/api/sessions`, `/api/auth/oauth/authorize`, `/api/auth/oauth/callback`, `/api/auth/tool-consent`, and `PqcOAuth3LOPlugin`; missing `verified_email == uid` check on `/api/auth/tool-consent` (`verify_with_google=True`).
  5. `V-4.1.1-04` (Medium): `store_delegated_token(..., expires_in<=0)` silently substituted 3600s TTL; malformed token syntax not rejected; `oauth2.credentials.Credentials` omitted `expiry`.
  6. `V-4.1.1-05` (Medium): `_fetch_compute_pq_key_exchange()` called bare `_get_client_kwargs()` without a scope; `_resolve_scope()` substituted `DEFAULT_ORGANIZATION_ID` for unbound authenticated tenants.

## 3. Targeted Remediation Edits

- `tools/gcloud_bridge.py`:
  - Added `_ServerScopePolicy.has_any_restriction`, normalized `projects/` prefixes in `_load_server_scope_policy()`, added `resolve_server_bound_defaults()`, and auto-bound unambiguous server-authorized scopes in `_default_connection_template()` and `set_gcp_connection_config()`.
  - Hardened `resolve_authorized_tenant_scope()`, `set_gcp_connection_config()`, and `get_gcp_connection_config()` to enforce unified server policies across all scope types, fail closed in production without server policy, prevent mutation/pivoting of already-bound non-admin scopes, and expose `active_scope_uri`, `scope_bound_by_server`, and `authorized_scope`.
  - Added `_validate_delegated_access_token_syntax()` and TTL validation before DB writes; updated `get_active_gcp_credentials()` to load directly from `EncryptedDatabaseCredentialService`, verify syntax, and pass UTC `expiry` to `oauth2.credentials.Credentials`.
  - Updated `authorize_gcp_scope()` to emit explicit `UNAUTHORIZED_RESOURCE_SCOPE (MISSING_AUTHORIZED_SCOPE)` actionable errors when a tenant has no authorized scope.
- `pqc_agent/credential_service.py`:
  - Rejected malformed tokens (`ACCESS_TOKEN_INVALID`) and `expires_in <= 0` (`ACCESS_TOKEN_EXPIRED`) in `store_delegated_token()`.
- `tools/gcp_inventory.py`:
  - Added `_active_tenant_default_scope()` so symbolic/default scope tokens resolve to the authenticated tenant's bound org/project/folder or `("UNBOUND", "", "")` (never silently substituting `DEFAULT_ORGANIZATION_ID`).
- `tools/pqc_detectors.py`:
  - Threaded authorized `client_kwargs` into `_fetch_compute_pq_key_exchange()` from `collect_tls_policies()` and enforced `scope_uri=f"projects/{project_id}"` on standalone invocations.
- `pqc_agent/workspace_server.py`:
  - Added `_resolve_and_authorize_request_scope()` and enforced it across `/api/chat`, `/api/sessions`, `/api/auth/oauth/authorize`, `/api/auth/oauth/callback`, `/api/auth/tool-consent`, and `PqcOAuth3LOPlugin`.
  - Enforced `verified_email == uid` in `/api/auth/tool-consent` (`verify_with_google=True`), suppressed consent cards on scope/ADC denials in `after_tool_callback`, and mapped `ValueError`/`PermissionError` cleanly to HTTP `400`/`403` in `_complete_signin`, `/api/auth/tool-consent`, and `/api/auth/oauth/callback`.

## 4. Test Execution & Remediation

- Regression sanity check after source edits (`test_phase4_scope_isolation.py`, `test_phase3_adc_authorization.py`, `test_pqc_inventory.py`, `test_auth_hardening.py`): `108 passed, 1 skipped, 0 failed` (`16.12s`).
- Created `tests/test_phase4_delegated_token_validation.py`.
- Run 1 (12 combined tests): `11 passed, 1 failed` — `test_03` raised `RuntimeError` because toggling `K_SERVICE` activated Phase 2's fail-closed `PQC_KMS_KEY_NAME` requirement. Fixed test fixture by attaching an explicit in-memory `LocalHkdfKekWrapper` before setting `K_SERVICE`.
- Run 2 (12 combined tests): `12 passed, 0 failed` (`3.09s`).
- Split combined tests (`5/6` and `10/11`) into 1-to-1 tests and added `test_15` (3LO PKCE callback scope binding & mid-flow revocation) -> 15 tests total.
- Run 3 (targeted suite): `.venv/bin/pytest -v -rs tests/test_phase4_delegated_token_validation.py` -> **`15 passed, 0 failed, 0 skipped`** (`3.40s`).
- Per-suite regressions:
  - `tests/test_phase4_scope_isolation.py`: **`9 passed, 0 skipped, 0 failed`** (`1.25s`)
  - `tests/test_auth_hardening.py tests/test_phase1_distributed_auth.py`: **`40 passed, 0 skipped, 0 failed`** (`5.10s`)
  - `tests/test_pqc_inventory.py tests/test_phase3_scorecard_correctness.py`: **`34 passed, 1 skipped, 0 failed`** (`11.09s`)
  - `tests/test_phase3_adc_authorization.py`: **`41 passed, 0 skipped, 0 failed`** (`4.66s`)
  - `tests/test_phase3_egress_security.py`: **`181 passed, 0 skipped, 0 failed`** (`1.86s`)
- Full safe local suite: `.venv/bin/pytest -q -rs` -> **`367 passed, 4 skipped, 0 failed`** (`63.57s`).

## 5. Hygiene, Compilation & Secret Scan

- Executed `.venv/bin/python -m compileall -q pqc_agent tools tests main.py` -> PASS (exit 0).
- Executed `git diff --check` -> PASS (exit 0).
- Executed automated secret and sensitive-identifier scan across all changed/added Phase 4.1.1 files -> PASS (0 findings).
- Reviewed complete `git diff` prior to commit `fix(security): validate delegated token scope binding` on branch `security-hardening/phase-04-scope-isolation`.
