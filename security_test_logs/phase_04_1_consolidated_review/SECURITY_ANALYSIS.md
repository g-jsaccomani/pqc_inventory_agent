# Phase 4.1 — Consolidated Security Analysis & Findings

## 1. Files and Functions Inspected

| Module | Functions / Components Audited |
| :--- | :--- |
| `tools/gcloud_bridge.py` | `_CURRENT_USER_ID`, `normalize_user_id()`, `_is_authenticated_email_identity()`, `set_current_tenant_user()`, `get_current_tenant_user()`, `is_adc_authorized_user()`, `authorize_adc_mode()`, `set_gcp_connection_config()`, `get_gcp_connection_config()`, `get_active_gcp_credentials()`, `clear_user_access_token()`, `resolve_authorized_tenant_scope()`, `authorize_gcp_scope()`, `authorize_gcloud_command_scope()` |
| `tools/gcp_inventory.py` | `_get_client_kwargs()`, `_SCAN_CACHE`, `_cache_scope_prefix()`, `_cache_get()`, `_cache_put()`, `_active_tenant_default_scope()`, `_active_tenant_org_id()`, `_resolve_scope()`, `_cai_search_all_resources()`, `_discover_kms_targets_via_cai()`, `collect_kms_inventory()`, `collect_workload_evidence()`, `discover_all_crypto_assets()`, `compute_pqc_scorecard()`, `export_cyclonedx_cbom()` |
| `tools/pqc_detectors.py` | `_fetch_compute_pq_key_exchange()`, `collect_tls_policies()`, `_discover_key_rings_via_cai()`, `collect_kms_import_jobs()` |
| `tools/quantum_engine.py` | `run_quantum_cryptanalysis_simulation()` |
| `pqc_agent/workspace_server.py` | `build_oauth_authorize_uri()`, `_resolve_and_authorize_request_scope()`, `PqcOAuth3LOPlugin.before_tool_callback()`, `PqcOAuth3LOPlugin.after_tool_callback()`, `_AuthStoreContextMiddleware`, `_warm_inventory_cache()`, `/api/auth/google`, `/api/auth/auto`, `/api/auth/switch`, `/api/auth/oauth/authorize`, `/api/auth/oauth/callback`, `/api/auth/tool-consent`, `/api/sessions`, `/api/sessions/{id}`, `/api/chat`, `/api/connection`, `/api/gcloud` |
| `pqc_agent/portal_ui.py` | Sidebar & modal defaults (`sidebar-conn-summary`, `conn-org-input`, `conn-proj-input`, `gcloud-cmd-input`), `applyConnectionConfigToUI()`, `updateHeaderConnectionBadge()`, `saveConnectionConfig()`, `openOAuth3LOPopup()`, `buildOAuthConsentCardHtml()`, `createNewSession()`, `downloadMarkdownReport()`, `runLabPrompt()`, `sendChatMessage()` |
| `pqc_agent/auth_guard.py` | `IdentityResolver.resolve()`, `bind_user_id()`, `verify_iap_jwt()`, `verify_google_oidc_id_token()`, `AdkRouteGuardMiddleware` |
| `pqc_agent/auth_store.py` | `upsert_session_metadata()`, `get_user_connection()`, `upsert_user_connection()` |
| `pqc_agent/credential_service.py` | `store_delegated_token()`, `load_delegated_token()`, `revoke_delegated_tokens()`, `resolve_dek_wrapper()` |
| `main.py` | `run_adk_agent_turn()`, `run_tools_smoke_test()`, CLI entry points (`serve`, `ask`, `tools`, `cbom`, `deploy`) |

---

## 2. Confirmed Findings by Severity & Remediations Implemented

### High Severity Findings

#### `CR-01` [HIGH] — Missing `user_id` Ownership Binding Silently Bypassed in Scope Resolution & Authorization
- **Locations:** `tools/gcp_inventory.py::_active_tenant_default_scope()`, `tools/gcloud_bridge.py::authorize_gcp_scope()`, `tools/gcloud_bridge.py::resolve_authorized_tenant_scope()`.
- **Defect:** Both `_active_tenant_default_scope()` and `authorize_gcp_scope()` guarded tenant ownership validation with `if conn_uid is not None:`. Any connection mapping omitting `"user_id"` or setting `"user_id": None` silently bypassed ownership validation, allowing an unbound or foreign connection mapping (e.g., `{"organization_id": "222222222222"}`) to be accepted for an authenticated tenant. `resolve_authorized_tenant_scope()` also did not verify `conn_cfg.get("user_id")`.
- **Remediation:**
  - Enforced mandatory non-empty string ownership matching (`isinstance(conn_uid, str) and bool(conn_uid.strip()) and normalize_user_id(conn_uid) == uid`) across `resolve_authorized_tenant_scope()`, `authorize_gcp_scope()`, and `_active_tenant_default_scope()`.
  - Explicitly included `"user_id": uid` when `get_gcp_connection_config()` delegates to `resolve_authorized_tenant_scope()`.
  - Missing, `None`, empty, whitespace, non-string, or mismatched `user_id` now fails closed (`("UNBOUND", "", "")` in scope resolution; `PermissionError("UNAUTHORIZED_RESOURCE_SCOPE: Tenant connection ownership binding (user_id) is missing or mismatched.")` in authorization).

#### `CR-02` [HIGH] — Non-Email Identity Misclassification & Cross-Request ContextVar Isolation
- **Locations:** `tools/gcloud_bridge.py` (`_CURRENT_USER_ID`, `set_current_tenant_user`, `_is_authenticated_email_identity`), `tools/gcp_inventory.py::_active_tenant_default_scope()`, `pqc_agent/workspace_server.py::_AuthStoreContextMiddleware`.
- **Defect:**
  1. `_active_tenant_default_scope()` classified ANY non-email string lacking `"@"` (e.g. `"corp-admin"`, `"tenant-42"`, `"service-worker"`, `"admin"`) as an unauthenticated CLI/test helper and returned `DEFAULT_ORGANIZATION_ID` — even in production environments (`K_SERVICE` / `PQC_PRODUCTION_MODE=true`) and inside HTTP request contexts.
  2. `_AuthStoreContextMiddleware` did not initialize or reset `_CURRENT_USER_ID` per HTTP/WebSocket request, leaving unauthenticated HTTP requests with the default CLI classification and risking ContextVar bleed on request exit.
  3. `_is_authenticated_email_identity()` accepted malformed strings with multiple `@` signs or embedded whitespace (e.g. `"a@@b.example"`, `"alice @tenant.example"`).
- **Remediation:**
  - Implemented explicit execution-context classification in `tools/gcloud_bridge.py`: `UNAUTHENTICATED_CLI_IDENTITIES = frozenset({DEFAULT_TENANT_USER_ID, "default"})`, `_CURRENT_EXECUTION_CONTEXT` (`"authenticated"` | `"unauthenticated_cli"` | `"unverified"`), and `classify_execution_context()`.
  - `"unauthenticated_cli"` is returned **exclusively** when all four hold: non-production environment, active identity in `UNAUTHENTICATED_CLI_IDENTITIES`, explicit `_CURRENT_EXECUTION_CONTEXT == "unauthenticated_cli"`, and not an email identity. Arbitrary non-email strings, malformed emails, production unauthenticated contexts, and unauthenticated HTTP requests classify as `"invalid"` and fail closed as `("UNBOUND", "", "")`.
  - Added `enter_http_request_tenant_context()` / `exit_http_request_tenant_context()` in `_AuthStoreContextMiddleware` (`try ... finally:`) so every HTTP/WebSocket request starts `"unverified"` and restores outer ContextVars cleanly on exit.
  - Tightened `_is_authenticated_email_identity()` to require `isinstance(user_id, str)`, `norm.count("@") == 1`, no whitespace, and non-empty local/domain parts.

#### `CR-03` [HIGH] — Weak `_SCAN_CACHE` Key Prefix (`access_token_preview`), Silent `"unconfigured"` Bucket, Missing Scope-Fingerprint Segregation & Missing Locking
- **Locations:** `tools/gcp_inventory.py` (`_SCAN_CACHE`, `_cache_scope_prefix`, `_cache_get`, `_cache_put`, all 3 collectors), `tools/pqc_detectors.py` (all 2 collectors).
- **Defect:**
  1. `_cache_scope_prefix()` keyed `access_token` entries using `access_token_preview` (first 6 + last 4 chars), permitting distinct rotated/re-consented tokens sharing prefix/suffix to collide on cached entries.
  2. Exceptions inside `_cache_scope_prefix()` silently fell back to a shared `"unconfigured"` bucket.
  3. Cache keys did not include the tenant's active authorized scope policy, nor were simulated entries isolated under a dedicated namespace, nor was `_SCAN_CACHE` guarded by a lock for concurrent threads.
- **Remediation:**
  - Added `_SCAN_CACHE_LOCK = threading.RLock()`.
  - Replaced live cache keying with fail-closed `_live_cache_partition(client_kwargs)` that requires authenticated identity + ownership-verified connection + **SHA-256 digest of the active credential token** (`hashlib.sha256(token).hexdigest()[:32]`) + **SHA-256 fingerprint of the sorted authorized scope map** (`live:<uid>:<cred_part>:<scope_sig>`).
  - Eliminated any `"unconfigured"` fallback for live queries: if live partitioning fails, `_cache_get()` returns `None` and `_cache_put()` skips writing.
  - Segregated demo/simulation entries strictly under `sim:` (`simulated=True`), threaded `client_kwargs` through all 5 live collectors.

#### `CR-04` [HIGH] — Hardcoded `"31564119954"` / Operational Project Defaults in Portal UI & Backend Session/OAuth Paths Breaking Delegated Onboarding
- **Locations:** `pqc_agent/portal_ui.py` (lines 1696, 1976, 1982, 2009, 3101, 3252, 3355, 3570, 3593, 3625), `pqc_agent/workspace_server.py` (`build_oauth_authorize_uri`, `GET /api/sessions/{session_id}`), `pqc_agent/auth_store.py` (`upsert_session_metadata`).
- **Defect:**
  1. `portal_ui.py` pre-populated `#conn-org-input` with `"31564119954"` and `#conn-proj-input` with `"pqc-inventory-agent-cd06"`, and fell back to `|| "31564119954"` in `sendChatMessage()`, `createNewSession()`, `openOAuth3LOPopup()`, `buildOAuthConsentCardHtml()`, `runLabPrompt()`, and `downloadMarkdownReport()`. Any project-bound or unbound delegated-token user who signed in and used chat (without running `POST /api/connection` for an org) sent `scope="organizations/31564119954"`, failing with HTTP `403 UNAUTHORIZED_RESOURCE_SCOPE`.
  2. `build_oauth_authorize_uri()` injected `scope=organizations/31564119954` when `target_scope` was empty; `auth_store.upsert_session_metadata()` persisted `"organizations/31564119954"` into PostgreSQL when `scope` was empty; `GET /api/sessions/{session_id}` returned `"organizations/31564119954"` as default.
- **Remediation:**
  - Removed all hardcoded `"31564119954"` and `"pqc-inventory-agent-cd06"` defaults from `pqc_agent/portal_ui.py`, `pqc_agent/workspace_server.py`, and `pqc_agent/auth_store.py`.
  - Tracked server-bound `currentActiveScopeUri` (`cfg.active_scope_uri`) in `portal_ui.py` via `getActiveTenantScopeUri()`, omitting `scope` when unbound so server-side `_resolve_and_authorize_request_scope()` automatically resolves the tenant's authorized org/project/folder scope without requiring `POST /api/connection`.

---

### Medium Severity Findings

#### `CR-05` [MEDIUM] — Unauthenticated Startup Cache Warmup Invoking Collectors Against `DEFAULT_ORGANIZATION_ID`
- **Location:** `pqc_agent/workspace_server.py` (`_warm_inventory_cache()` in `create_workspace_app()`).
- **Defect:** On every startup with `verify_models_on_startup=True`, a background daemon thread spawned 5 worker threads invoking all live collectors against `organizations/{DEFAULT_ORGANIZATION_ID}` without any authenticated tenant context.
- **Remediation:** Removed `_warm_inventory_cache()` completely while preserving Vertex AI model catalog background verification (`registry_obj.start_background_verification()`).

#### `CR-06` [MEDIUM] — Standalone `_fetch_compute_pq_key_exchange()` Swallowed `PermissionError`
- **Location:** `tools/pqc_detectors.py::_fetch_compute_pq_key_exchange()`.
- **Defect:** The broad `except Exception: return None` handler swallowed `PermissionError` raised by `_get_client_kwargs(scope_uri=f"projects/{project_id}")` on standalone unauthorized invocations instead of failing closed.
- **Remediation:** Added explicit `except PermissionError: raise` before `except Exception: return None`.

#### `CR-07` [MEDIUM] — `PqcOAuth3LOPlugin.before_tool_callback()` Allowed Unauthenticated Identities and Unbound Omitted Tool Scopes Through to Consent Cards
- **Location:** `pqc_agent/workspace_server.py` (`PqcOAuth3LOPlugin.before_tool_callback()` and `_resolve_and_authorize_request_scope()`).
- **Defect:** `before_tool_callback()` did not reject unauthenticated `inv_uid` values before fetching connection state or emitting consent cards, and skipped scope authorization whenever `raw_tool_scope` was omitted (or when `allow_unbound_non_scan=True` was passed). `_resolve_and_authorize_request_scope()` also returned `""` when both `raw` and `active_uri` were empty even with `allow_unbound_non_scan=False`.
- **Remediation:**
  - Rejected unauthenticated `inv_uid` immediately with `SCOPE_AUTHORIZATION_DENIED` (`UNAUTHENTICATED_EXECUTION_CONTEXT`).
  - Enforced `_resolve_and_authorize_request_scope(..., allow_unbound_non_scan=False)` on non-`execute_gcloud_command` protected tools, and updated `_resolve_and_authorize_request_scope()` to invoke `authorize_gcp_scope("", user_id=uid)` when both `raw` and `active_uri` are empty and `allow_unbound_non_scan=False`.

---

## 3. Remaining Architectural Limitations (Documented Explicitly)

1. **Legacy `DEFAULT_ORGANIZATION_ID` Parameter Defaults Outside Active Enforcement Boundary:** `DEFAULT_ORGANIZATION_ID` remains on tool function signature defaults (`tools/gcp_inventory.py`, `tools/pqc_detectors.py`, `tools/quantum_engine.py`), CLI `--scope` defaults (`main.py`), system prompt guidance (`pqc_agent/agent.py`), and pre-Phase-2 JSON migration fallback (`pqc_agent/migration_tool.py`). Every live execution path still passes through `authorize_gcp_scope()` and fails closed unless the caller is explicitly authorized for that scope. Full removal of legacy default-org constants from CLI/prompt/migration layers belongs to a subsequent multi-tenant configuration cleanup phase.
2. **Offline Mocked Verification Only:** Live GCP CAI/KMS/Compute APIs, Cloud SQL PostgreSQL, Cloud KMS live key wrapping, Vertex AI, and Cloud Run deployment were **not** executed during this review (prohibited by Section 6). Live staging validation remains required before production rollout.
3. **In-Memory `_SCAN_CACHE` Scope:** `_SCAN_CACHE` is process-local (segregated by tenant, SHA-256 credential digest, and authorized-scope fingerprint). In multi-instance Cloud Run deployments, each instance maintains its own isolated cache; revocation and scope-policy enforcement occur authoritatively against the shared DB/policy **before** `_cache_get()` is ever reached.
