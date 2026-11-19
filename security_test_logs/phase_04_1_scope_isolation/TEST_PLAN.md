# Phase 4.1 — Security Test Plan

**Target Test Suite:** `tests/test_phase4_scope_isolation.py`
**Mode:** 100% offline, deterministic, mocked clients and isolated temporary SQLite/auth stores. Zero live GCP API calls, zero live Vertex AI calls, zero cloud resource mutations.

## 1. Mandatory Phase 4.1 Security Test Matrix

| # | Requirement (Phase 4.1 Section 4) | Planned Test Cases | Expected Assertion |
|---|---|---|---|
| 1 | Authorized org scope queried exactly as supplied | `test_01_authorized_org_scope_queried_exact_across_all_collectors` | Across `_cai_search_all_resources`, `collect_kms_inventory`, `collect_workload_evidence`, `discover_all_crypto_assets`, `collect_tls_policies`, and `collect_kms_import_jobs`, every CAI `search_all_resources` call receives exact `request["scope"] == "organizations/111111111111"` (call count == 1 per collector, no extra scopes). |
| 2 | Failed org CAI request triggers zero folder/project fallback queries | `test_02_failed_org_cai_never_falls_back_to_folder_or_project_scopes` | Even when `scope_uri == f"organizations/{DEFAULT_ORGANIZATION_ID}"` fails with a simulated CAI exception, CAI `search_all_resources` is called **exactly once** (only for the requested org); zero folder or project queries occur; zero partial resources returned; actionable error reported and not cached. |
| 3 | Original CAI exception propagated intact | `test_03_original_cai_exception_propagated_intact` | Direct `_cai_search_all_resources()` and `_discover_key_rings_via_cai()` propagate the exact original exception instance (`exc_info.value is original_exc`) for org, folder, and project scopes; collector JSON payloads include the original exception class name and message. |
| 4 | No hardcoded Functional Lab scopes remain in active implementation | `test_04_no_hardcoded_functional_lab_fallback_scopes_in_active_code` | Asserts `not hasattr(gcp_inventory, "DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES")`, `not hasattr(gcp_inventory, "_cai_search_all_resources_with_fallback")`, and scans `tools/gcp_inventory.py` and `tools/pqc_detectors.py` confirming zero occurrences of the legacy fallback symbols or hardcoded Functional Lab folder/project scope tokens. |
| 5 | Explicitly supplied project scope continues to work & preserves failure semantics | `test_05_explicit_project_scope_collection_and_failure_semantics` | Authorized `projects/tenant-a-prod-01` succeeds across KMS, workloads, crypto assets, TLS policies, and import jobs; when project CAI fails, zero cross-scope queries occur, original project-level semantics are preserved (same-project KMS global probe for `collect_kms_inventory`; direct error payload for workloads/crypto/TLS/import jobs). |
| 6 | Unauthorized scopes rejected by existing authorization boundary | `test_06_unauthorized_scopes_rejected_before_sdk_or_cache_access` | Tests unauthorized org (`organizations/999999999999`), default-deny folder (`folders/555555555555`), unauthorized project (`projects/tenant-b-prod-02`), malformed/traversal scopes, unauthenticated caller, unauthorized ADC user, and `PQC_ALLOWED_ORGANIZATIONS`/`PQC_ALLOWED_PROJECTS`/`PQC_TENANT_SCOPE_POLICY` restrictions. Proves `PermissionError` (`UNAUTHORIZED_RESOURCE_SCOPE` / `ADC_UNAUTHORIZED` / `UNAUTHENTICATED_EXECUTION_CONTEXT`), zero SDK client instantiations, zero `google.auth.default()` calls, and zero stale `_SCAN_CACHE` reads after scope revocation. |
| 7 | No cross-tenant or cross-scope inventory returned | `test_07_cross_tenant_and_cross_scope_isolation` | Tenant A (`organizations/111111111111`, `projects/tenant-a-prod-01`) and Tenant B (`organizations/222222222222`, `projects/tenant-b-prod-02`) share a process and `_SCAN_CACHE`. Tenant A cannot read Tenant B's org or project via live call or cache; explicit requests for `organizations/{DEFAULT_ORGANIZATION_ID}` are never rewritten to Tenant A's org; authorized folder allowlist (`PQC_ALLOWED_FOLDERS`) grants only the allowlisted folder to the matched principal. |
| 8 | Existing CAI collectors & supported workflows remain compatible | `test_08_supported_workflows_demo_scorecard_cbom_and_impersonation` | Verifies explicit demo/simulation scope, authorized org/project `compute_pqc_scorecard` and `export_cyclonedx_cbom`, and authorized server-side admin ADC within `PQC_ALLOWED_ORGANIZATIONS` continue working end-to-end without regressions. |

## 2. Regression & Verification Commands

1. Targeted Phase 4.1 suite: `.venv/bin/pytest -v -rs tests/test_phase4_scope_isolation.py`
2. Existing inventory & scorecard suites: `.venv/bin/pytest -v -rs tests/test_pqc_inventory.py tests/test_phase3_scorecard_correctness.py`
3. Phase 3 ADC, egress, and auth hardening suites: `.venv/bin/pytest -v -rs tests/test_phase3_adc_authorization.py tests/test_phase3_egress_security.py tests/test_auth_hardening.py`
4. Full safe local regression suite: `.venv/bin/pytest -v -rs` (live PostgreSQL / live Vertex / live Docker tests remain skipped by design; zero cloud calls).
5. Bytecode compilation: `.venv/bin/python -m compileall -q pqc_agent tools tests main.py`
6. Diff hygiene: `git diff --check`
7. Secret and sensitive-identifier scan across the full branch diff (`git diff 7f91cae13060b8fb8ceed9ac689981527c00df9f...HEAD`).
