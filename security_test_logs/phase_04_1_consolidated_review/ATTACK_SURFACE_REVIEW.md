# Phase 4.1 — End-to-End Attack Surface Review

## 1. Integrated Trust Boundary Walkthrough

```text
HTTP Request (IAP JWT / Signed Session Cookie + CSRF)
  │
  ├─ 1. _AuthStoreContextMiddleware [workspace_server.py]
  │      ├─ Binds per-instance DistributedAuthStore & EncryptedDatabaseCredentialService
  │      ├─ enter_http_request_tenant_context(): initializes ContextVars as ("sec-architect", "unverified")
  │      └─ finally: exit_http_request_tenant_context() resets ContextVars (0 cross-request bleed)
  │
  ├─ 2. IdentityResolver / activate_request_tenant_user() [auth_guard.py, workspace_server.py]
  │      ├─ Verifies signed IAP JWT or HMAC-signed session cookie against shared DB revocation table
  │      ├─ Ignores untrusted headers (X-PQC-User-Id, X-Goog-Authenticated-User-Email)
  │      └─ Promotes ContextVar to ("authenticated", verified_email) ONLY on valid email identity
  │
  ├─ 3. Portal UI & API Onboarding [portal_ui.py, workspace_server.py]
  │      ├─ GET /api/connection returns server-bound active_scope_uri & authorized_scope (no POST /api/connection required)
  │      ├─ Portal UI uses getActiveTenantScopeUri() (zero hardcoded 31564119954 or internal project IDs)
  │      └─ POST /api/sessions, POST /api/chat, /api/auth/oauth/*, PqcOAuth3LOPlugin validate scope via _resolve_and_authorize_request_scope()
  │
  ├─ 4. Scope Resolution [tools/gcp_inventory.py::_active_tenant_default_scope() / _resolve_scope()]
  │      ├─ Calls classify_execution_context() (rejects arbitrary non-email strings, prod placeholders, HTTP unverified)
  │      ├─ Enforces mandatory non-empty conn["user_id"] == active_uid ownership binding
  │      └─ Any exception, malformed payload, missing binding, or mismatch -> ("UNBOUND", "", "") (NEVER DEFAULT_ORGANIZATION_ID)
  │
  ├─ 5. Scope & Credential Authorization [tools/gcp_inventory.py::_get_client_kwargs()]  <-- RUNS BEFORE CACHE & SDK
  │      ├─ authorize_gcp_scope(scope_uri):
  │      │    ├─ Authenticated email check & cross-tenant override denial
  │      │    ├─ Raw & effective DB mode == "adc" -> authorize_adc_mode(uid) (default-deny PQC_ADMIN_EMAILS)
  │      │    ├─ Mandatory conn["user_id"] == uid ownership binding (rejects missing/None/empty/mismatched)
  │      │    └─ Unified resolve_authorized_tenant_scope() (server policy across ALL 3 dims; prod fails closed without policy; default-deny folders)
  │      └─ get_active_gcp_credentials():
  │           ├─ Loads KMS-envelope-encrypted delegated token from DB (verifies AAD, ownership, non-revoked, non-expired)
  │           ├─ Validates token syntax & constructs oauth2.credentials.Credentials(..., expiry=...)
  │           └─ Zero fallback to google.auth.default() on any failure
  │
  ├─ 6. Cache Partitioning [tools/gcp_inventory.py::_cache_get() / _cache_put()]  <-- RUNS AFTER AUTHZ
  │      ├─ Guarded by _SCAN_CACHE_LOCK (thread-safe)
  │      ├─ Simulated demo data isolated under sim:
  │      └─ Live data partitioned by live:<uid>:<sha256(token)|imp:hash|adc>:<sha256(authorized_scope)> (zero "unconfigured" fallback)
  │
  └─ 7. Cloud SDK & CAI Execution [tools/gcp_inventory.py, tools/pqc_detectors.py]
         ├─ _cai_search_all_resources(): strict single-scope query, zero fallback scopes, propagates original exception
         └─ _fetch_compute_pq_key_exchange(): reuses authorized client_kwargs; standalone propagates PermissionError
```

---

## 2. Attack Scenarios & Verified Outcomes

| # | Attack Scenario | Entry Point / Vector | Expected & Verified Outcome |
| :-: | :--- | :--- | :--- |
| A1 | **Missing `user_id` ownership injection** | Connection mapping `{"organization_id": "222222222222"}` (missing/`None`/empty/`int` `user_id`) supplied to `_active_tenant_default_scope`, `resolve_authorized_tenant_scope`, or `authorize_gcp_scope` | **DENIED (`CR-01`):** Returns `("UNBOUND", "", "")` in scope resolution; raises `PermissionError("UNAUTHORIZED_RESOURCE_SCOPE: Tenant connection ownership binding (user_id) is missing or mismatched.")` in authorization. `0` SDK/ADC/CAI/cache calls. |
| A2 | **Non-email identity misclassification** | Non-email identifier (`corp-admin`, `tenant-42`, `service-worker`, `admin`, `guest`, `a@@b.example`, `alice @tenant.example`) or `sec-architect` in production / HTTP context | **DENIED (`CR-02`):** `classify_execution_context()` returns `("invalid", "")`; `_active_tenant_default_scope()` returns `("UNBOUND", "", "")` (never `DEFAULT_ORGANIZATION_ID`); all 5 collectors fail closed with `UNAUTHENTICATED_EXECUTION_CONTEXT`. `0` SDK/ADC/CAI/cache calls. |
| A3 | **HTTP ContextVar bleed across requests** | Authenticated Tenant A completes HTTP request; subsequent unauthenticated or Tenant B request arrives | **MITIGATED (`CR-02`):** `_AuthStoreContextMiddleware` enters unverified context and resets both `_CURRENT_USER_ID` and `_CURRENT_EXECUTION_CONTEXT` in `finally:`. Outer/subsequent context never retains Tenant A. |
| A4 | **Delegated token preview collision on `_SCAN_CACHE`** | Attacker/rotated token shares first 6 and last 4 characters with prior token (`ya29.A...ZZZZ`) | **MITIGATED (`CR-03`):** Live cache partitions use 32-hex SHA-256 of the full credential token plus 16-hex SHA-256 of `authorized_scope`. Different tokens never collide; scope changes segregate cached entries immediately. |
| A5 | **Post-revocation / post-expiration cache replay** | Tenant warms `_SCAN_CACHE` across all 5 collectors, then token is revoked or expires | **DENIED:** `_get_client_kwargs()` runs before `_cache_get()`, validates token non-revoked/non-expired in DB, and fails closed with `ACCESS_TOKEN_REQUIRED`. `0` cache reads, `0` SDK/ADC/CAI calls. |
| A6 | **Cross-tenant concurrent scan race** | 20 concurrent threads interleave Tenant A and Tenant B scans over shared `_SCAN_CACHE` | **ISOLATED (`CR-03`):** `_SCAN_CACHE_LOCK` + per-thread `ContextVar` + tenant/token/scope partition yields 0 cross-tenant leaks across all 20 concurrent tasks. |
| A7 | **Client-supplied foreign scope override via Portal/API** | Tenant A (server-bound to `projects/tenant-a-proj-01`) submits `scope="organizations/222222222222"` or `"organizations/31564119954"` to `/api/sessions`, `/api/chat`, `/api/connection`, `/api/auth/oauth/authorize`, or `PqcOAuth3LOPlugin` | **DENIED (`CR-04`, `CR-07`):** HTTP `403` across API endpoints; `SCOPE_AUTHORIZATION_DENIED` in `PqcOAuth3LOPlugin` before consent card or tool execution; Portal UI never fabricates `"organizations/31564119954"`. |
| A8 | **Standalone Compute SSL policy bypass** | Direct call `_fetch_compute_pq_key_exchange("victim-proj-99", "global", "ssl-pol")` without `client_kwargs` | **DENIED (`CR-06`):** Calls `_get_client_kwargs(scope_uri="projects/victim-proj-99")`, propagates `PermissionError("UNAUTHORIZED_RESOURCE_SCOPE...")` (no longer swallowed to `None`). `0` `SslPoliciesClient`/`RegionSslPoliciesClient` instantiations. |
| A9 | **Unauthenticated startup warmup / ambient ADC** | App starts with `verify_models_on_startup=True` or unauthorized user requests `mode="adc"` | **MITIGATED (`CR-05`):** Startup warmup thread removed; `0` background collector invocations on boot; non-admin `adc` rejected with `ADC_UNAUTHORIZED`; `0` `google.auth.default()` calls. |
| A10 | **Partial server policy / production self-binding** | `PQC_ALLOWED_PROJECTS` set without `PQC_ALLOWED_ORGANIZATIONS`, or production without any server policy | **DENIED:** Unified `server_policy.has_any_restriction` default-denies unmentioned dimensions; production without server policy returns empty sets for non-admin users. |
| A11 | **CAI org failure silent lab fallback** | CAI `search_all_resources` fails on `organizations/<id>` | **DENIED:** `DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES` deleted; `_cai_search_all_resources()` makes exactly 1 query for the requested scope and propagates the original error untouched. |
