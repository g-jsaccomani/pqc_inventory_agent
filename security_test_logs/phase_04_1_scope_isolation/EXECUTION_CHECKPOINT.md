# Phase 4.1 — Execution Checkpoint

**Status:** `PASS — PHASE 4.1 READY FOR REVIEW`
**Branch:** `security-hardening/phase-04-scope-isolation`
**Base Revision (`origin/main`):** `7f91cae13060b8fb8ceed9ac689981527c00df9f`
**Implementation Commit:** `5f325a5be161fc204efdc36d4c59a09559494e62` (pushed to `origin/security-hardening/phase-04-scope-isolation`)

## Completed Scope (`P4.1.1` – `P4.1.3`)
1. **Hardcoded Functional Lab Fallback Removed (`P4.1.1`):** Deleted `DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES` and `_cai_search_all_resources_with_fallback` (along with all embedded Functional Lab folder/project/org assumptions and docstrings) from `tools/gcp_inventory.py` and updated all 5 CAI call sites across `tools/gcp_inventory.py` and `tools/pqc_detectors.py`.
2. **Explicit Scope Semantics Enforced (`P4.1.2`):** Added strict `_cai_search_all_resources()` that queries only the explicitly supplied `scope_uri`, never switches to another org/folder/project on failure, and propagates the exact original CAI exception intact. Removed `DEFAULT_ORGANIZATION_ID` tokens from `ORG_MODE_TOKENS` so explicit org scopes are never silently rewritten to another tenant's org. Preserved original same-project semantics on authorized project scopes.
3. **Phase 3 Authorization Controls Preserved & Extended (`P4.1.3`):** Added `authorize_gcp_scope()` in `tools/gcloud_bridge.py` reusing deny-by-default `authorize_adc_mode()` and `resolve_authorized_tenant_scope()`, wired it into fail-closed `_get_client_kwargs(scope_uri=...)`, and enforced it before `_SCAN_CACHE` lookups and SDK client instantiation across all 5 live inventory collectors.

## Verification Summary
- Targeted Phase 4.1 suite (`tests/test_phase4_scope_isolation.py`): **`9 passed, 0 failed, 0 skipped`**
- Existing CAI/inventory suites: **`34 passed, 1 skipped, 0 failed`**
- Phase 3 ADC / Egress / Auth suites: **`41 passed`**, **`181 passed`**, **`30 passed`** (`0 failed`)
- Full safe local regression suite: **`352 passed, 4 skipped, 0 failed`** (`64.24s`)
- `compileall`: **PASS** | `git diff --check`: **PASS** | Secret & sensitive-ID scan: **PASS (`0 findings`)**
- Cloud resources provisioned, modified, or deployed: **None**. Outbound network traffic during test runs was not instrumented (see `TEST_RESULTS.md`).
- **Provenance:** the counts above, including `352 passed, 4 skipped, 0 failed`, are the recorded results of one local run on the implementation author's workstation against the source and tests committed as `5f325a5be161fc204efdc36d4c59a09559494e62`. They are an execution report, not an independently reproduced result; they were not re-run during documentation finalization and no automated CI status exists for that commit.

## Remaining Limitations & Separate Follow-Up Findings (Out of Scope for P4.1)
1. **Default Organization Fallback Defaults Outside CAI:** `DEFAULT_ORGANIZATION_ID` / `DEFAULT_ORGANIZATION_NAME` module defaults remain in tool parameter defaults, CLI `--scope` defaults (`main.py`), prompt guidance (`pqc_agent/agent.py`), startup warmup (`pqc_agent/workspace_server.py`), admin-only connection templates (`tools/gcloud_bridge.py`), and deploy scripts (`scripts/*.sh`). Active live access is fail-closed via `authorize_adc_mode()` and `authorize_gcp_scope()`, and removing hardcoded default env fallbacks across CLI/portal/agent layers should be tracked as a separate multi-tenant configuration phase.
2. **Test Fixture Context Isolation (assessed as pre-existing; not reproduced on the base commit):** One combined invocation ordered `test_phase3_adc_authorization.py`, `test_phase3_egress_security.py`, `test_auth_hardening.py` failed one `test_auth_hardening.py` test because the current-tenant context set by `gcloud_bridge.set_current_tenant_user()` was left populated by an earlier test. By static reading the source is `tests/test_phase3_egress_security.py`, which sets the tenant inside a test body without a restoring fixture. Phase 4.1 did not modify those files, but the failing order was not run on the base commit. Tracked as a test hygiene follow-up.
3. **Child Project Listing Inside an Authorized Organization:** When a caller is explicitly authorized for `organizations/<id>` and CAI succeeds returning child KMS key rings inside that organization, Cloud KMS reads those child key rings using the caller's delegated/authorized credentials (GCP IAM enforces per-project read access). The application applies no additional per-project check to those child reads.
4. **SDK Collectors Now Require a Bound or Allowlisted Scope (behavior change):** Because the five live collectors now call `authorize_gcp_scope()`, a scope is accepted only if it matches the tenant's connection `organization_id` / `project_id` or a server-side allowlist (`PQC_ALLOWED_PROJECTS`, `PQC_ALLOWED_ORGANIZATIONS`, `PQC_ALLOWED_FOLDERS`, `PQC_TENANT_SCOPE_POLICY`); folder scopes are denied unless the operator allowlists them. By code reading of `pqc_agent/workspace_server.py`, the delegated-token sign-in and chat paths bind a token but not an organization or project (only `POST /api/connection` passes them, and non-admin defaults are empty), so a delegated-token tenant with no bound scope receives `UNAUTHORIZED_RESOURCE_SCOPE` from the collectors, where the request previously went to Google Cloud under the tenant's own token. This mirrors the rule applied to `execute_gcloud_command` since Phase 3.1, but it is new for the SDK collectors, is not covered by a dedicated end-to-end test, and whether the portal always binds a scope before a scan was not verified. To be confirmed as intended by the reviewer.
5. **No Automated CI Status:** GitHub reports no commit status and no check runs for `5f325a5be161fc204efdc36d4c59a09559494e62`, and the repository has no `.github/workflows` directory at this revision. All results are local recorded runs.

## Handoff State
- Implementation committed. Commit SHA: `5f325a5be161fc204efdc36d4c59a09559494e62` (`fix(security): enforce explicit CAI scope isolation`).
- Branch pushed to origin. Branch: `security-hardening/phase-04-scope-isolation` (no force-push).
- Evidence finalized in a follow-up documentation-only commit on the same branch (`docs: finalize phase 4.1 execution evidence`); no source or test file changed after `5f325a5be161fc204efdc36d4c59a09559494e62`.
- **STOP GATE ACTIVE:** Do not merge into `main` and do not start Phase 4.2 without explicit human approval.
