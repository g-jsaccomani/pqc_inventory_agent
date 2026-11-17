# Phase 1 Verification Report — OAuth and Authentication Hardening (P0)

## 1. Phase Identification
- **Phase:** Phase 1 — OAuth and authentication (`P0`)
- **Branch:** `security-hardening/2026-11`
- **Parent / Baseline Commit SHA:** `91efa40` (`chore(security): add master remediation plan and baseline test report`)

## 2. Files Created or Modified
- `pqc_agent/auth_guard.py` (modified)
- `pqc_agent/workspace_server.py` (modified)
- `pqc_agent/portal_ui.py` (modified)
- `tests/test_auth_hardening.py` (modified)
- `security_test_logs/phase_01_oauth/REPORT.md` (created)

## 3. Remediated Vulnerabilities & Controls Implemented

### H1 — Wildcard `postMessage` OAuth Token Leak & Popup Receiver Validation
- **Server-side popup origin validation:** Added `_allowed_popup_origins(request)` and `_resolve_validated_popup_origin(request, candidate_origin)` in `pqc_agent/workspace_server.py`. `/api/auth/bridge` now rejects missing, wildcard (`*`), malformed, or untrusted origins with HTTP `400`.
- **Removal of wildcard `postMessage('*')`:** Replaced `window.opener.postMessage(msg, '*')` in `/api/auth/bridge` with explicit origin targeting (`window.opener.postMessage(msg, targetOrigin)`), and changed the bridge to complete sign-in via `POST /api/auth/google` (`credentials: 'include'`) before posting status-only completion (`PQC_SIGNIN_COMPLETE`).
- **Removal of credentials/tokens from popup `postMessage` payloads:** Added `_sanitize_popup_postmessage_payload()` to strip `token`, `access_token`, `id_token`, `refresh_token`, `google_access_token`, `session_token`, and `code` from `_oauth_popup_result_html()`, `_OAUTH_IMPLICIT_CALLBACK_HTML`, and `/api/auth/oauth/authorize` before serializing any popup payload.
- **Strict opener receiver verification (`pqc_agent/portal_ui.py`):** Tracked `activeAuthPopupWindow` across popup sign-in flows and updated `window.addEventListener("message", ...)` to require `event.origin === window.location.origin`, `Boolean(activeAuthPopupWindow && event.source === activeAuthPopupWindow)`, and `!hasForbiddenPopupCredentialFields(event.data)`. The receiver consumes `activeAuthPopupWindow = null` on receipt and refreshes session state from the server (`loadCurrentTenantUser()`).

### H2 — `localStorage` Session Token Exposure, Cookie Hardening, CSRF, Rotation & Revocation
- **Removed `localStorage` session token storage:** Removed all `localStorage.getItem("pqc_session_token")` and `localStorage.setItem("pqc_session_token", ...)` reads/writes from `pqc_agent/portal_ui.py` and `pqc_agent/workspace_server.py`, and stripped `token` fields from `pqc_saved_accounts` UI metadata.
- **`HttpOnly; SameSite=Lax; Secure` session & account-switcher cookies:** Session authentication uses `pqc_session_token` (`HttpOnly`, `SameSite=Lax`, `Secure` on HTTPS/production) and multi-account switching uses the server-managed `HttpOnly` `pqc_account_jar` cookie (`POST /api/auth/switch-account`).
- **CSRF & Origin/Referer/Sec-Fetch-Site protection:** Added `derive_csrf_token()` / `verify_csrf_token()` in `pqc_agent/auth_guard.py` and `_enforce_csrf_and_origin()` in `pqc_agent/workspace_server.py`. All cookie-authenticated state-changing `/api/*` requests (`POST`, `PUT`, `PATCH`, `DELETE`) enforce same-origin `Origin`/`Referer`/`Sec-Fetch-Site` headers and validate `X-PQC-CSRF-Token` against the active session token. `portal_ui.py` automatically attaches `X-PQC-CSRF-Token` on same-origin mutating `fetch` calls.
- **Session rotation (`jti`) and server-side logout revocation:** Added unique `jti` claims to `sign_tenant_session_token()`, rotated session tokens on login/fixation, and implemented server-side token revocation (`revoke_tenant_session_token()`, `is_tenant_session_token_revoked()`, persisted to `pqc_revoked_tokens.json`) enforced on `/api/auth/logout` and during session verification.

### A1 — OAuth 2.0 PKCE (`S256`), OIDC `nonce`, Expiry, and `redirect_uri` Enforcement
- **PKCE (`S256`):** Added `generate_pkce_pair()` and `compute_pkce_challenge()` in `pqc_agent/auth_guard.py`. `/api/auth/oauth/signin` and `/api/auth/oauth/authorize` emit `code_challenge` + `code_challenge_method=S256`, bind `code_verifier` inside the signed single-use OAuth state token, and pass `code_verifier` during `/api/auth/oauth/callback` token exchange (`_exchange_oauth_code()`).
- **OIDC `nonce` & ID token expiry:** Generated and bound `oidc_nonce` into the signed OAuth state token and authorization request (`nonce`), and enforced exact `nonce` matching and `exp` validation in `_verify_google_oauth_or_id_token()`.
- **Strict `redirect_uri` validation:** Added `_validate_oauth_redirect_uri()` to enforce exact match against the canonical callback URL on `/api/auth/oauth/signin`, `/api/auth/oauth/authorize`, and `/api/auth/oauth/callback`, rejecting open redirects and mismatched callback URIs with HTTP `400`.

### A2 & A3 — Production Fail-Closed `PQC_AUTH_SECRET`, Key Rotation, and IAP Audience Enforcement
- **Fail-closed `PQC_AUTH_SECRET` in production:** Updated `load_or_create_hmac_secret()` in `pqc_agent/auth_guard.py` and `_validate_production_auth_configuration()` in `pqc_agent/workspace_server.py` to raise `RuntimeError` when `is_production_environment()` is true (`K_SERVICE`, `PQC_PRODUCTION_MODE=true`, or `PQC_ENV=production`) and `PQC_AUTH_SECRET` / `PQC_AUTH_SECRET_FILE` is missing or shorter than 32 characters.
- **Zero-downtime secret rotation:** Added `PQC_AUTH_SECRET_PREVIOUS` / `PQC_AUTH_SECRET_PREVIOUS_FILE` support (`load_previous_hmac_secrets()`) so `verify_signed_payload()` verifies active tokens across key rotations while signing new tokens with the primary secret.
- **Production IAP audience enforcement:** Updated `verify_iap_jwt()` to fail closed in production when `PQC_IAP_AUDIENCE` is unset, and to verify `claims["aud"] == expected_audience` and token expiration (`exp`) when fallback claims decoding is used.
- **Workstation auto-gcloud opt-in:** Restricted `_try_workstation_auto_gcloud_token()` so it is disabled in production and requires explicit `PQC_AUTO_WORKSTATION_GCLOUD_AUTH=true` in local development.

## 4. Exact Commands Executed & Actual Test Results

### Command 1: Full Pytest Suite (including Phase 1 Regression Tests)
```bash
.venv/bin/pytest -q
```
- **Result:** `58 passed, 1 skipped` (30 passed in `tests/test_auth_hardening.py` including 5 new Phase 1 regression tests; 28 passed, 1 skipped in `tests/test_pqc_inventory.py`).

### Command 2: Bytecode Compilation & Static Diff Hygiene Check
```bash
.venv/bin/python -m compileall -q pqc_agent tools tests && git diff --check
```
- **Result:** Exit code `0` (no syntax errors, no whitespace or conflict markers).

## 5. Manual Staging Validation Still Required
- Verify Cloud Run deployment with Secret Manager-backed `PQC_AUTH_SECRET` (>= 32 bytes) and `PQC_IAP_AUDIENCE` configured.
- Verify end-to-end Google OAuth popup sign-in in a real browser against staging to confirm `event.source === activeAuthPopupWindow` and `HttpOnly; Secure; SameSite=Lax` cookie persistence across page reloads and multi-tab storage sync.

## 6. Residual Risks & Follow-Up Items
- Revoked session `jti` entries are persisted to local/workspace storage (`pqc_revoked_tokens.json`, capped to recent entries); multi-instance horizontal scaling in Cloud Run should back this store with shared state or short token TTLs.
- Phase 2 (`P0` SSRF and network egress hardening) remains pending execution.
