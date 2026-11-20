# Phase 4.1.2 — Verification & Regression Test Results

**Branch:** `security-hardening/phase-04-scope-isolation`
**Prior HEAD:** `f8a05b1d6ab55b45ea543610d7cd3c39ce4073ba`
**Base Revision (`origin/main`):** `7f91cae13060b8fb8ceed9ac689981527c00df9f`
**Environment:** Local Python `3.12.13` (`.venv`, `pytest 9.1.1`). Zero GCP APIs, Cloud SQL databases, Vertex AI endpoints, IAM services, or Docker daemons were invoked.

## Result Provenance & Limitations

- All counts below are recorded local workstation runs executed on 2026-11-19 against the working tree immediately prior to commit. No automated GitHub Actions / CI workflow exists in this repository at this revision.
- Mocked tests verify code-level fail-closed behavior and tripwire invariants but do not substitute for live staging verification against Cloud SQL PostgreSQL, Cloud KMS, and live GCP APIs.

## 1. Ordered Test Execution Summary (Section 4 Steps 1–6)

| Step | Command | Exit Code | Duration | Observed Result |
|---|---|---:|---:|---|
| 1 | `.venv/bin/pytest -v -rs tests/test_phase4_fail_closed_scope_resolution.py` | `0` | `1.58s` | **`29 passed, 0 skipped, 0 failed`** (all 12 mandatory scenarios, incl. 14 malformed/cross-tenant cases & 6×2×5 collector/tripwire cases) |
| 2 | `.venv/bin/pytest -q -rs tests/test_phase4_scope_isolation.py` | `0` | `1.49s` | **`9 passed, 0 skipped, 0 failed`** |
| 3 | `.venv/bin/pytest -q -rs tests/test_phase4_delegated_token_validation.py` | `0` | `3.15s` | **`15 passed, 0 skipped, 0 failed`** |
| 4a | `.venv/bin/pytest -q -rs tests/test_phase3_adc_authorization.py` | `0` | `5.24s` | **`41 passed, 0 skipped, 0 failed`** |
| 4b | `.venv/bin/pytest -q -rs tests/test_phase3_egress_security.py` | `0` | `2.14s` | **`181 passed, 0 skipped, 0 failed`** |
| 5a | `.venv/bin/pytest -q -rs tests/test_auth_hardening.py tests/test_phase1_distributed_auth.py` | `0` | `5.36s` | **`40 passed, 0 skipped, 0 failed`** |
| 5b | `.venv/bin/pytest -q -rs tests/test_pqc_inventory.py tests/test_phase3_scorecard_correctness.py` | `0` | `11.32s` | **`34 passed, 1 skipped, 0 failed`** (1 skip: `PQC_LIVE_LLM_TEST=1` live Vertex AI test) |
| 6 | `.venv/bin/pytest -q -rs` (Full Safe Local Suite) | `0` | `63.62s` | **`396 passed, 4 skipped, 0 failed`** (4 skips: 1 live PostgreSQL, 1 live Vertex AI, 2 Docker CLI/daemon) |

## 2. Targeted Phase 4.1.2 Mandatory Scenarios Breakdown

| Scenario # | Test Case (`tests/test_phase4_fail_closed_scope_resolution.py`) | Outcome |
|---|---|---|
| 1 | `test_01_authenticated_tenant_with_valid_organization_binding` | **PASS** |
| 2 | `test_02_authenticated_tenant_with_valid_project_binding` | **PASS** |
| 3 | `test_03_authenticated_tenant_with_no_binding` | **PASS** |
| 4 | `test_04_authenticated_tenant_connection_lookup_exception_fails_closed_with_sanitized_log` | **PASS** |
| 5 | `test_05_authenticated_tenant_malformed_or_cross_tenant_connection_payload_fails_closed` (14 cases) | **PASS** |
| 6 | `test_06_tenant_identity_lookup_failure_never_classified_as_unauthenticated` | **PASS** |
| 7 | `test_07_positively_unauthenticated_cli_test_context_preserves_legacy_default` | **PASS** |
| 8 | `test_08_resolve_scope_org_never_substitutes_default_org_on_lookup_failure` | **PASS** |
| 9 | `test_09_internal_runtime_project_resolution_never_substitutes_default_org_on_failure` | **PASS** |
| 10 & 11 | `test_10_11_all_live_collectors_fail_closed_with_zero_sdk_adc_cai_or_cache_access` (6 failure modes × 2 scopes × 5 collectors; 0 hits on all 8 tripwires) | **PASS** |
| 12 | `test_12_delegated_token_and_admin_adc_behavior_remains_intact` | **PASS** |

## 3. Intermediate Issues Observed & Fixed During Test Runs

1. Initial fixture draft used wrong constructor call (`DistributedCredentialService(store)` -> fixed to `EncryptedDatabaseCredentialService(store=store)`).
2. `test_08` initially included `"gcp"` (not in `ORG_MODE_TOKENS`) -> updated to iterate `sorted(gcp_inventory.ORG_MODE_TOKENS)` directly.
3. First full-suite run (`64.08s`) reported `2 failed, 394 passed, 4 skipped`: `test_04` and `test_06` `caplog` captured empty records because an earlier Alembic test (`test_phase2_persistence_and_credentials.py`) runs `logging.config.fileConfig` with `disable_existing_loggers=True`, setting `tools.gcp_inventory.logger.disabled = True`. Fixed by saving/restoring `gcp_inventory.logger.disabled = False` and `propagate = True` in `_isolated_phase412_env`. Final re-run of Step 1 (`29 passed`, `1.58s`) and Step 6 (`396 passed, 4 skipped, 0 failed`, `63.62s`) both exited `0`.

## 4. Pre-Commit Hygiene, Compilation & Secret Scan

- `.venv/bin/python -m compileall -q pqc_agent tools tests main.py` — **PASS (exit `0`)**
- `git diff --check` — **PASS (exit `0`)**
- Automated secret & sensitive-identifier scan across diff and new files — **PASS (`0 findings`)**
