# Phase 3.1 (`P3-01` P0 Hotfix) — Independent Security Architecture Review

- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Phase:** `3.1 — P3-01 Outbound SSRF & Egress Controls (P0 Hotfix: ADC Authorization & Tenant Isolation)`

---

## 1. Root Cause Analysis

During the independent Phase 3.1 security review, five related privilege-boundary gaps remained around server-side Application Default Credentials (ADC), tenant scope enforcement, and `gcloud` binary resolution:

1. **Unrestricted ADC Selection & Defaulting (`P0`):**
   - `set_gcp_connection_config()`, `_default_connection_template()`, and `auth_store.UserConnectionRecord` allowed any authenticated user to select or default into `mode="adc"`, causing `execute_gcloud_command()` and GCP Python SDK collectors to run with the Cloud Run Service Account's ambient IAM permissions.
2. **Automatic "Auto-Heal" Transitions to ADC (`P0`):**
   - `_is_builtin_demo_scope()` in `pqc_agent/workspace_server.py` automatically switched users from `mode="access_token"` (when no delegated token was present) to `mode="adc"` across four paths: `PqcOAuth3LOPlugin.before_tool_callback()`, `GET /api/auth/me`, `POST /api/auth/auto`, and `POST /api/chat`.
3. **Default-Open Service Account Impersonation & SDK Exception Fallback (`P0/P1`):**
   - `validate_impersonated_service_account()` enforced `PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS` only when the env var was non-empty (default-open when unset), and `tools/gcp_inventory.py:_get_client_kwargs()` caught all `Exception`s (including `PermissionError`) and returned `{}` (which caused Google Cloud Python SDK clients to fall back to ambient server ADC).
4. **Missing Independent Resource Scope Authorization on `gcloud` Execution (`P0`):**
   - `validate_gcloud_command()` enforced read-only verbs and safe flags, but `execute_gcloud_command()` did not verify that target `--project`, `--organization`, `--folder`, `--scope`, positional hierarchy arguments, or embedded `projects/...` / `organizations/...` / `folders/...` / `@<proj>.iam.gserviceaccount.com` resource references belonged to the caller's authorized tenant scope, and permitted unscoped commands (`projects list`, `organizations list`, `storage buckets describe`).
5. **`PATH`-Dependent `gcloud` Binary Lookup (`P1`):**
   - `_resolve_gcloud_binary()` called `shutil.which("gcloud")` first and expanded `~/google-cloud-sdk/bin/gcloud`, while `_try_workstation_auto_gcloud_token()` invoked bare `"gcloud"` with inherited `PATH`.

---

## 2. Attack Surface & Authorization Boundary Changes

| Boundary | Previous Behavior | Hardened Hotfix Behavior |
| :--- | :--- | :--- |
| **Default Connection State** (`auth_store.py`, `gcloud_bridge.py`, `portal_ui.py`) | Defaulted new users to `mode="adc"`, `organization_id="31564119954"`, `project_id="pqc-inventory-agent-cd06"`. | Defaults non-admin users to `mode="access_token"`, `organization_id=""`, `project_id=""`. |
| **HTTP API Boundary** (`POST /api/connection`, `POST /api/chat`) | Accepted `mode="adc"` from any authenticated user; `/api/chat` auto-switched empty `access_token` to `adc` on demo scope. | Explicitly enforces `authorize_adc_mode(uid)` and `validate_impersonated_service_account(..., user_id=uid)`, returning HTTP `403` before model lookup or DB persistence. |
| **Service & Credential Layer** (`set_gcp_connection_config`, `get_gcp_connection_config`, `get_active_gcp_credentials`, `build_sanitized_gcloud_env`, `_get_client_kwargs`) | Trusted stored/requested `mode="adc"`; `_get_client_kwargs` swallowed `PermissionError` into `{}`. | Enforces `authorize_adc_mode()` at every layer, sanitizes unauthorized stored `adc` rows on read, blocks tampered DB rows on credential/subprocess execution, and re-raises `PermissionError` in `_get_client_kwargs()`. |
| **Automatic ADC / Demo Logic** (`workspace_server.py`) | `_is_builtin_demo_scope()` triggered silent `set_gcp_connection_config(mode="adc")` across 4 paths and suppressed 3LO consent cards. | `_is_builtin_demo_scope()` deleted completely; all 4 automatic ADC paths and consent-suppression checks removed. |
| **Service Account Impersonation** (`validate_impersonated_service_account`) | Allowed any `<sa>@<proj>.iam.gserviceaccount.com` when `PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS` was unset. | **Default-deny** when `PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS` is unset; supports global entries and principal-bound rules (`user@domain=sa@...`, `@domain=@proj.iam.gserviceaccount.com`). |
| **Independent Tenant Scope Authorizer** (`authorize_gcloud_command_scope`) | Relied solely on read-only command grammar. | Requires authenticated email identity; resolves per-user scope from `PQC_TENANT_SCOPE_POLICY` / `PQC_ALLOWED_PROJECTS` / `PQC_ALLOWED_ORGANIZATIONS` / `PQC_ALLOWED_FOLDERS` and tenant binding; rejects unscoped commands and out-of-scope flags, positional IDs, resource URIs, and SA emails; pins `--project=<authorized_project>` when omitted. |
| **Executable Resolution** (`resolve_trusted_gcloud_binary`, `validate_gcloud_executable_path`) | `shutil.which("gcloud")` + `~/google-cloud-sdk/bin/gcloud` + inherited `PATH`. | Zero `shutil.which` or `~` usage; validates candidate slot in `TRUSTED_GCLOUD_PATHS`, canonical `realpath` prefix in `TRUSTED_GCLOUD_REALPATH_PREFIXES`, executable bit, non-world-writable binary & parent directory (`!S_IWOTH`), `shell=False`, and pinned `PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`. |

---

## 3. ADC Policy & Tenant Isolation Guarantees

1. **ADC Policy (`is_adc_authorized_user` / `authorize_adc_mode`):**
   - Backed exclusively by the existing server-side `auth_guard.admin_emails()` (`PQC_ADMIN_EMAILS` environment variable).
   - **Default-deny in all environments** (including when `K_SERVICE` is unset): if `PQC_ADMIN_EMAILS` is empty or does not contain the caller's verified normalized email, ADC activation and execution are unconditionally rejected with `PermissionError("ADC_UNAUTHORIZED: ...")` / HTTP `403`.
   - Zero client-controlled inputs (`user_id`, `project_id`, `organization_id`, `scope`, `session_id`, `X-PQC-*`, `X-Goog-Authenticated-User-Email` without IAP JWT verification) or demo scope constants (`31564119954`, `pqc-inventory-agent-cd06`) can grant ADC eligibility.
2. **Tenant & Resource Scope Isolation (`resolve_authorized_tenant_scope` / `authorize_gcloud_command_scope`):**
   - Every `execute_gcloud_command()` call requires an authenticated email identity (`UNAUTHENTICATED_EXECUTION_CONTEXT` otherwise).
   - Operators can enforce strict server-side multi-tenant boundaries via `PQC_TENANT_SCOPE_POLICY` (JSON map of `user@domain` / `@domain` -> `{projects, organizations, folders}`) and/or `PQC_ALLOWED_PROJECTS`, `PQC_ALLOWED_ORGANIZATIONS`, `PQC_ALLOWED_FOLDERS` (supporting `principal=resource` rules).
   - Even when operator env policies are not set, commands remain restricted to the caller's own configured `project_id` / `organization_id` (and never unscoped global enumeration).
   - Unscoped hierarchy/global commands (`gcloud projects list`, `gcloud organizations list`, `gcloud storage buckets describe`) are removed from `_COMMAND_POLICIES` so global GCP namespace enumeration is impossible.

---

## 4. Repository-Wide Security Audit Verification

| Audit Item | Inspection Scope & Result | Status |
| :--- | :--- | :---: |
| Every assignment of `mode="adc"` or equivalent | Audited across `pqc_agent/` and `tools/`. Removed from `auth_store.py`, `workspace_server.py` (all 4 auto-heal sites), and `portal_ui.py` defaults. Remaining references in `gcloud_bridge.py` are gated behind `is_adc_authorized_user()` / `authorize_adc_mode()`. Legacy Phase 2 one-time JSON migration rows (`migration_tool.py`) are neutralized at read/exec time by `get_gcp_connection_config()`, `get_active_gcp_credentials()`, and `execute_gcloud_command()`. | **PASS** |
| Every automatic ADC activation path | `_is_builtin_demo_scope()` completely deleted; verified `/api/chat`, `/api/auth/me`, `/api/auth/auto`, and `PqcOAuth3LOPlugin` never auto-switch to `adc`. | **PASS** |
| Every invocation of `execute_gcloud_command()` | Registered on ADK agents (`pqc_agent/agent.py`, gated by `PqcOAuth3LOPlugin` in `PROTECTED_GCP_TOOLS`) and `POST /api/gcloud` (`workspace_server.py`); enforces identity, ADC/impersonation authz, independent scope validation, sanitized env, and validated binary path internally so direct calls cannot bypass policy. | **PASS** |
| Every `gcloud` subprocess invocation | Only two sites exist in production code: `tools/gcloud_bridge.py:execute_gcloud_command` (`subprocess.run(..., shell=False)`) and local-dev opt-in `pqc_agent/workspace_server.py:_try_workstation_auto_gcloud_token` (`_subprocess.check_output([gcloud_bin, ...])`). Both now use `resolve_trusted_gcloud_binary()` and `TRUSTED_SUBPROCESS_PATH`. | **PASS** |
| Every use of `shutil.which()` for `gcloud` | Zero occurrences in `pqc_agent/` or `tools/` (`shutil` import removed from `tools/gcloud_bridge.py`; only `tests/test_pre_merge_hotfix.py` uses `shutil.which("docker")` for test skip gating). | **PASS** |
| Every path that persists or restores credential configuration | `set_gcp_connection_config`, `get_gcp_connection_config`, `get_active_gcp_credentials`, `build_sanitized_gcloud_env`, and `gcp_inventory._get_client_kwargs` all enforce caller identity and fail-closed authorization. | **PASS** |

---

## 5. Regression Analysis & Residual Risks

- **Preserved Phase 3.1 Controls:** `pqc_agent/egress_guard.py` (`safe_urlopen`, HTTPS-only, Google host allowlist, DNS/IP private/metadata blocking, redirect rejection, bounded reads, finite timeouts, verified TLS), strict `gcloud` command/flag allowlists, and zero `access_token` -> ADC fallback all pass `181/181` tests in `tests/test_phase3_egress_security.py`.
- **Full Regression Suite:** `304 passed, 0 failed, 3 skipped` (all 3 skips are pre-existing environment-gated live PostgreSQL / live Vertex AI / Docker tests).
- **Residual Risks & Operational Guidance:**
  1. **IAM Enforcement on Delegated 3LO Tokens:** When an external user supplies their own 3LO `access_token` without operator-defined `PQC_TENANT_SCOPE_POLICY` / `PQC_ALLOWED_*`, Google Cloud IAM enforces resource permissions on that user's own Google identity, while `authorize_gcloud_command_scope()` enforces isolation to the user's configured scope and blocks unscoped global queries. Multi-tenant enterprise operators should additionally configure `PQC_TENANT_SCOPE_POLICY` to pin permitted orgs/projects/folders server-side.
  2. **Trusted System Paths on Custom Hosts:** `TRUSTED_GCLOUD_PATHS` covers standard Cloud Run / Debian / Ubuntu / Alpine / macOS system SDK paths (`/usr/bin/gcloud`, `/usr/local/bin/gcloud`, `/usr/lib/google-cloud-sdk/bin/gcloud`, `/google-cloud-sdk/bin/gcloud`, `/opt/google-cloud-sdk/bin/gcloud`, `/opt/homebrew/bin/gcloud`). Non-standard per-user home installations (`~/google-cloud-sdk`) are intentionally rejected to prevent writable-directory binary substitution.
  3. **Prompt-Injection Data Envelope Isolation (`P3-05`):** Structural untrusted-data framing for uploaded artifacts and GCP resource labels remains scheduled for `P3-05` per the Phase 3 roadmap, though even under prompt injection an agent can no longer escalate to server ADC or query out-of-scope projects/orgs/folders via `execute_gcloud_command()`.

---

## 6. Final Security Assessment

**PASS (P0 Remediated).** Unauthorized external and non-administrative users cannot select, persist, default into, auto-switch into, or indirectly consume server Application Default Credentials or unapproved service-account impersonation across any HTTP endpoint, chat workflow, ADK plugin callback, or direct Python function call. Every `gcloud` execution is bound to an authenticated identity, independently scope-authorized, isolated from `PATH` hijacking, and verified by automated adversarial tests.
