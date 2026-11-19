# Phase 3.1 (`P3-01` P0 Hotfix) — ADC Authorization & Tenant Isolation Checkpoint

- **Repository:** `g-jsaccomani/pqc_inventory_agent` (`https://github.com/g-jsaccomani/pqc_inventory_agent.git`)
- **Target Branch:** `security-hardening/phase-03-runtime-resilience`
- **Baseline `main` Commit SHA:** `62f7247b52effc3f3cf2086a86f06071eea1b6fc` (untouched)
- **Initial `HEAD` Commit SHA:** `44e6cd4c7192b89af3f0e61c2e6a69dc23cf16d9` (`fix(security): harden outbound egress and gcloud execution`)
- **Hotfix Commit Message:** `fix(security): enforce trusted ADC authorization boundaries` (parent: `44e6cd4c7192b89af3f0e61c2e6a69dc23cf16d9`; final commit SHA recorded in git history & final delivery report)

---

## 1. Mandatory Preconditions Verification

| # | Precondition | Verification Result | Status |
| :---: | :--- | :--- | :---: |
| 1 | Current branch is `security-hardening/phase-03-runtime-resilience` | Verified via `git branch --show-current` | **PASS** |
| 2 | Working tree is clean | Verified via `git status --short --branch` (`git diff` empty before edits; untracked root prompt file `PHASE03` left untouched & unstaged) | **PASS** |
| 3 | Record current `HEAD` SHA | `44e6cd4c7192b89af3f0e61c2e6a69dc23cf16d9` | **PASS** |
| 4 | Existing Phase 3.1 implementation & logs present | Verified `pqc_agent/egress_guard.py`, `tests/test_phase3_egress_security.py`, and all 4 files under `security_test_logs/phase_03_1_p3_01/` | **PASS** |
| 5 | Preserve existing Phase 3.1 commits & `main` | No reset, rebase, amend, merge, or modification to `main` (`62f7247b52effc3f3cf2086a86f06071eea1b6fc`) | **PASS** |

---

## 2. Confirmed P0 Vulnerabilities Remediated

1. **Unrestricted External User Activation & Defaulting of Server ADC (`mode="adc"`):**
   - Eliminated default-ADC creation in `pqc_agent/auth_store.py`, `tools/gcloud_bridge.py`, and `pqc_agent/portal_ui.py`; enforced default-deny server-side admin check (`PQC_ADMIN_EMAILS` via `auth_guard.admin_emails()`) at both HTTP endpoints (`POST /api/connection`, `POST /api/chat` -> HTTP `403`) and inside every credential/config/execution service function (`set_gcp_connection_config`, `get_gcp_connection_config`, `get_active_gcp_credentials`, `build_sanitized_gcloud_env`, `execute_gcloud_command`, `tools/gcp_inventory._get_client_kwargs`).
2. **Automatic "Auto-Heal" Escalation to Server ADC (`_is_builtin_demo_scope`):**
   - Deleted `_is_builtin_demo_scope()` completely from `pqc_agent/workspace_server.py` and removed all 4 automatic ADC transitions (`PqcOAuth3LOPlugin.before_tool_callback`, `GET /api/auth/me`, `POST /api/auth/auto`, `POST /api/chat`) plus consent-card suppression in `PqcOAuth3LOPlugin.after_tool_callback`.
3. **Default-Open Impersonation & SDK Exception Fallback to Ambient ADC:**
   - Made `validate_impersonated_service_account()` strictly default-deny when `PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS` is unset, added principal-bound allowlist support (`user@domain=sa@...`), and fixed `tools/gcp_inventory._get_client_kwargs()` to re-raise `PermissionError` rather than returning `{}`.
4. **Missing Independent Tenant & Resource Scope Enforcement on `gcloud` Execution:**
   - Added `resolve_authorized_tenant_scope()` and independent `authorize_gcloud_command_scope()` in `tools/gcloud_bridge.py` enforcing authenticated identity and tenant-specific project, organization, and folder boundaries across flags (`--project`, `--organization`, `--folder`, `--scope`, `--billing-project`, `--impersonate-service-account`), positional hierarchy IDs, embedded resource URIs (`projects/...`, `organizations/...`, `folders/...`), and service account emails, while removing unscoped commands (`projects list`, `organizations list`, `storage buckets describe`).
5. **Untrusted `PATH` Executable Resolution (`shutil.which("gcloud")`):**
   - Removed `shutil.which("gcloud")` and `~` expansion from `tools/gcloud_bridge.py`, replaced with `TRUSTED_GCLOUD_PATHS`, `TRUSTED_GCLOUD_REALPATH_PREFIXES`, `validate_gcloud_executable_path()`, `resolve_trusted_gcloud_binary()`, and pinned `TRUSTED_SUBPROCESS_PATH`, and hardened `_try_workstation_auto_gcloud_token()` in `pqc_agent/workspace_server.py`.

---

## 3. Files Changed

### Source Files
- `tools/gcloud_bridge.py`
- `pqc_agent/workspace_server.py`
- `pqc_agent/auth_store.py`
- `tools/gcp_inventory.py`
- `pqc_agent/portal_ui.py`

### Test Files
- `tests/test_phase3_adc_authorization.py` (new — 41 tests covering all 21 mandatory scenarios)
- `tests/test_phase3_egress_security.py` (explicit operator `PQC_ADMIN_EMAILS` setup for trusted ADC cases + updated project-scoped `storage buckets list` regression case)
- `tests/test_auth_hardening.py` (explicit `PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS` for Bob's impersonation DB test + updated non-admin Alice default connection assertion)
- `tests/test_pqc_inventory.py` (explicit `PQC_ADMIN_EMAILS` / `PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS` for admin/impersonation cases + updated non-admin Anna default assertion)

### Documentation Files
- `security_test_logs/phase_03_1_p3_01_hotfix/EXECUTION_CHECKPOINT.md`
- `security_test_logs/phase_03_1_p3_01_hotfix/TEST_RESULTS.md`
- `security_test_logs/phase_03_1_p3_01_hotfix/ADVERSARIAL_TESTS.md`
- `security_test_logs/phase_03_1_p3_01_hotfix/SECURITY_REVIEW.md`

---

## 4. Verification & Delivery Checklist

- [x] Focused ADC & tenant-isolation test suite: `41 passed, 0 failed, 0 skipped` (`tests/test_phase3_adc_authorization.py`)
- [x] Existing Phase 3.1 egress security suite: `181 passed, 0 failed, 0 skipped` (`tests/test_phase3_egress_security.py`)
- [x] Complete project test suite: `304 passed, 0 failed, 3 skipped`
- [x] Bytecode compilation check: `.venv/bin/python -m compileall -q pqc_agent tools tests` -> exit `0`
- [x] Diff whitespace & integrity check: `git diff --check` -> exit `0`
- [x] Repository-wide static audit of `mode="adc"`, auto-ADC paths, `execute_gcloud_command()`, `subprocess`, `shutil.which()`, and credential config persistence/restoration
- [x] Commit staged reviewed files as `fix(security): enforce trusted ADC authorization boundaries` and push to `origin/security-hardening/phase-03-runtime-resilience` (verified via `git log -1` and `git ls-remote origin security-hardening/phase-03-runtime-resilience` immediately after commit & push)

---

## 5. Remaining Limitations

- Live PostgreSQL 16, live Vertex AI Gemini, and live Docker container integration tests remain skipped in this local workstation environment (pre-existing opt-in / Docker-absent gates).
- Enterprise multi-tenant deployments using delegated 3LO tokens should configure `PQC_TENANT_SCOPE_POLICY` (or `PQC_ALLOWED_PROJECTS` / `PQC_ALLOWED_ORGANIZATIONS` / `PQC_ALLOWED_FOLDERS`) alongside GCP IAM least privilege to enforce server-side tenant resource pinning independently of Google Cloud IAM.
- Prompt-injection structural data framing (`P3-05`) and subsequent Phase 3 items remain strictly deferred outside this P0 hotfix scope.
