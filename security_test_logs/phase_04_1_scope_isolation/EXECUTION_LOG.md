# Phase 4.1 — Execution Log

**Task:** Strict Scope Isolation & Legacy Functional Lab Fallback Removal (`P4.1`)
**Repository:** `pqc_inventory_agent`
**Branch:** `security-hardening/phase-04-scope-isolation`
**Expected & Verified Base `origin/main`:** `7f91cae13060b8fb8ceed9ac689981527c00df9f`

## Timeline

### 1. Mandatory Git Preconditions (2026-11-19 18:09 -03)
- Verified repository root (`<REPO_ROOT>` via `git rev-parse --show-toplevel`).
- Confirmed starting branch: `main` (`## main...origin/main`, zero uncommitted tracked edits; local untracked prompt reference kept untouched and unstaged).
- Executed `git fetch origin`.
- Verified `git rev-parse main` == `git rev-parse origin/main` == `7f91cae13060b8fb8ceed9ac689981527c00df9f` (`BASELINE_MATCH=OK`).
- Inspected Phase 3 merge commit `7f91cae` (`Merge pull request #2 from .../security-hardening/phase-03-runtime-resilience`) and Phase 3 audit/sign-off references to `DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES`.
- Created branch `security-hardening/phase-04-scope-isolation` from `origin/main` (`7f91cae13060b8fb8ceed9ac689981527c00df9f`).

### 2. Scope Discovery & Pre-Edit Documentation (2026-11-19 18:10–18:15 -03)
- Audited all references to `DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES`, `_cai_search_all_resources_with_fallback`, `DEFAULT_ORGANIZATION_ID`, `search_all_resources`, `_resolve_scope`, `resolve_authorized_tenant_scope`, and `authorize_adc_mode` across `tools/`, `pqc_agent/`, `tests/`, `main.py`, and `scripts/`.
- Recorded discovery findings, security design, and test plan prior to editing any code:
  - `security_test_logs/phase_04_1_scope_isolation/SCOPE_DISCOVERY.md`
  - `security_test_logs/phase_04_1_scope_isolation/SECURITY_DESIGN.md`
  - `security_test_logs/phase_04_1_scope_isolation/TEST_PLAN.md`

### 3. Implementation (2026-11-19 18:15–18:18 -03)
- `tools/gcloud_bridge.py`: Added `authorize_gcp_scope()` reusing `resolve_authorized_tenant_scope()`, `_validate_scope_value()`, and `authorize_adc_mode()`.
- `tools/gcp_inventory.py`:
  - Removed `DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES`.
  - Replaced `_cai_search_all_resources_with_fallback()` with strict `_cai_search_all_resources()` (zero fallback queries, propagates original CAI exception intact, removes all Functional Lab assumptions/docstrings).
  - Removed `DEFAULT_ORGANIZATION_ID` / `organizations/{DEFAULT_ORGANIZATION_ID}` from `ORG_MODE_TOKENS` and stopped empty `"organizations/"` substitution in `_resolve_scope()`.
  - Hardened `_get_client_kwargs(scope_uri=...)` to enforce `authorize_gcp_scope(scope_uri)` + `get_active_gcp_credentials()` with zero broad `except Exception: pass` fallback.
  - Enforced scope authorization before `_cache_get()` and SDK client construction across `collect_kms_inventory`, `_discover_kms_targets_via_cai`, `collect_workload_evidence`, and `discover_all_crypto_assets`; prevented caching empty error payloads in `collect_kms_inventory`; restricted `organization_domain` stamping to matching `DEFAULT_ORGANIZATION_ID`.
- `tools/pqc_detectors.py`:
  - Replaced `_cai_search_all_resources_with_fallback` import and call sites with strict `_cai_search_all_resources`.
  - Enforced `_get_client_kwargs(scope_uri=scope_uri)` before `_cache_get()` and SDK client construction across `collect_tls_policies`, `_discover_key_rings_via_cai`, and `collect_kms_import_jobs`.

### 4. Security Testing & Full Safe Regressions (2026-11-19 18:19–18:25 -03)
- Authored `tests/test_phase4_scope_isolation.py` covering all 8 mandatory Phase 4.1 security requirements (9 collected test cases; Cloud Asset Inventory and Cloud KMS clients mocked).
- Two early runs of the new file failed on test-harness defects and were fixed in the test file only (no implementation file changed after the first test run): wrong constructor keyword arguments in the shared fixture (`8 failed, 1 passed`), and later an over-broad substring assertion added to test 04 (`1 failed, 8 passed`).
- Recorded targeted Phase 4.1 suite result: `9 passed, 0 failed, 0 skipped` (`1.40s`).
- Executed existing CAI/inventory suites (`test_pqc_inventory.py`, `test_phase3_scorecard_correctness.py`): `34 passed, 1 skipped, 0 failed` (`11.12s`).
- A first combined invocation of the Phase 3 ADC, egress, and auth suites in one pytest process reported `1 failed, 251 passed` (test-order sensitivity; see `TEST_RESULTS.md`). Run as three separate invocations they reported `41 passed`, `181 passed`, `30 passed` (`0 failed`).
- Executed full safe local regression suite (`.venv/bin/pytest -v -rs`): `352 passed, 4 skipped, 0 failed` (`64.24s`).
- Executed `compileall` (`PASS`), `git diff --check` (`PASS`), and branch-diff secret & sensitive-identifier scan (caught and sanitized local filesystem path in `EXECUTION_LOG.md`, re-verified `0 findings`).
- All counts in this section are recorded results of that single local run; they are an execution report and have not been independently reproduced.

### 5. Cloud & Infrastructure Integrity Confirmation
- No cloud resource was provisioned, modified, or deployed; no Cloud SQL, Cloud Build, IAM, or deployment command was run, and the live PostgreSQL, Vertex AI, and Docker tests were skipped.
- Outbound network traffic was not instrumented during the regression runs. The recorded full-suite log contains a `google.auth` end-user-credential warning (see the provenance section of `TEST_RESULTS.md`), so an absolute "zero live API calls" statement is not supported for the full suite.
- Zero Phase 3 evidence files modified; `main` remains untouched at `7f91cae13060b8fb8ceed9ac689981527c00df9f`.

### 6. Commit and Push (2026-11-19 18:26 -03)
- Staged only the 3 implementation files, the new test file, and the 7 evidence files; committed as `5f325a5be161fc204efdc36d4c59a09559494e62` (`fix(security): enforce explicit CAI scope isolation`).
- Pushed with `git push -u origin security-hardening/phase-04-scope-isolation` (no force-push); the remote branch was verified at the same SHA.

### 7. Documentation Finalization (2026-11-19 18:32 -03, documentation-only)
- Verified preconditions: branch `security-hardening/phase-04-scope-isolation` at `5f325a5be161fc204efdc36d4c59a09559494e62`, `main` at `7f91cae13060b8fb8ceed9ac689981527c00df9f`, no tracked or staged modifications.
- Corrected the test 08 name and authentication wording in `TEST_PLAN.md`; replaced the stale "ready for commit" handoff in `EXECUTION_CHECKPOINT.md`; labelled all test counts as recorded, not independently reproduced; corrected the test-order observation (invocation order, the cited symbol, and the inferred status of "pre-existing"); narrowed the cloud-safety wording to what was observed; recorded the collector-authorization workflow impact and the absence of a CI status as limitations.
- No tests were run in this step, and no source file, test file, or cloud resource was changed.
