# Phase 4.1 — Consolidated Security Review Test Plan

All security tests use deterministic fixtures and mocks for GCP SDKs, IAM/OAuth endpoints, and Cloud KMS envelope encryption. Zero real GCP resources are accessed.

## Mapping of All 20 Required Verification Scenarios

| Req # | Requirement | Test File & Case(s) |
| :---: | :--- | :--- |
| 1 | Valid delegated project scope succeeds | `tests/test_phase4_consolidated_security_review.py::test_01_02_valid_delegated_project_and_org_scopes_succeed_with_scorecard_and_cbom`; `tests/test_phase4_delegated_token_validation.py::test_01_*` |
| 2 | Valid delegated organization scope succeeds | `tests/test_phase4_consolidated_security_review.py::test_01_02_valid_delegated_project_and_org_scopes_succeed_with_scorecard_and_cbom`; `tests/test_phase4_delegated_token_validation.py::test_02_*` |
| 3 | Missing tenant connection is denied | `tests/test_phase4_consolidated_security_review.py::test_03_06_07_missing_connection_malformed_scope_and_lookup_exception_fail_closed`; `tests/test_phase4_fail_closed_scope_resolution.py::test_03_*` |
| 4 | Missing `user_id` ownership binding is denied (`CR-01`) | `tests/test_phase4_consolidated_security_review.py::test_04_05_missing_or_mismatched_user_id_ownership_binding_fails_closed` (6 parametrized cases: missing key, `None`, `""`, whitespace, non-string `12345`, mismatched email) |
| 5 | Mismatched tenant identity is denied | `tests/test_phase4_consolidated_security_review.py::test_04_05_missing_or_mismatched_user_id_ownership_binding_fails_closed`; `tests/test_phase4_scope_isolation.py::test_07_*` |
| 6 | Malformed scope is denied | `tests/test_phase4_consolidated_security_review.py::test_03_06_07_missing_connection_malformed_scope_and_lookup_exception_fail_closed`; `tests/test_phase4_scope_isolation.py::test_06_*` |
| 7 | Identity lookup exception fails closed | `tests/test_phase4_consolidated_security_review.py::test_03_06_07_missing_connection_malformed_scope_and_lookup_exception_fail_closed`; `tests/test_phase4_fail_closed_scope_resolution.py::test_06_*` |
| 8 | Non-email identity cannot accidentally receive authenticated privileges or `DEFAULT_ORGANIZATION_ID` (`CR-02`) | `tests/test_phase4_consolidated_security_review.py::test_08_non_email_identities_cannot_receive_default_org_or_authenticated_privileges` (10 parametrized non-email/malformed strings) & `test_08b_production_and_http_request_contexts_never_classify_as_unauthenticated_cli` |
| 9 | Client-supplied scope cannot override server scope | `tests/test_phase4_consolidated_security_review.py::test_09_20_portal_ui_onboarding_without_connection_post_and_zero_hardcoded_default_org`; `tests/test_phase4_delegated_token_validation.py::test_04_*` |
| 10 | Expired token is denied | `tests/test_phase4_consolidated_security_review.py::test_10_11_13_14_15_16_17_expired_revoked_and_explicit_foreign_scopes_blocked_before_cache_or_sdk`; `tests/test_phase4_delegated_token_validation.py::test_07_*` |
| 11 | Revoked token is denied, including cache scenarios | `tests/test_phase4_consolidated_security_review.py::test_10_11_13_14_15_16_17_expired_revoked_and_explicit_foreign_scopes_blocked_before_cache_or_sdk`; `tests/test_phase4_delegated_token_validation.py::test_08_*`, `test_09_*` |
| 12 | Cross-tenant, token-collision, scope-change & concurrent cache reuse is impossible (`CR-03`) | `tests/test_phase4_consolidated_security_review.py::test_12_cache_isolation_across_tenants_token_preview_collisions_scope_changes_and_concurrency` |
| 13 | Unauthorized requests do not instantiate SDK clients | `test_03_06_07_*`, `test_04_05_*`, `test_08_*`, `test_10_11_13_14_15_16_17_*` (`AssetServiceClient`, `KeyManagementServiceClient`, `SslPoliciesClient`, `RegionSslPoliciesClient` tripwires == 0) |
| 14 | Unauthorized requests do not invoke ADC fallback | `test_03_06_07_*`, `test_04_05_*`, `test_08_*`, `test_10_11_13_14_15_16_17_*` (`google.auth.default` tripwire == 0) |
| 15 | Unauthorized requests do not invoke CAI | `test_03_06_07_*`, `test_04_05_*`, `test_08_*`, `test_10_11_13_14_15_16_17_*` (`_cai_search_all_resources` tripwire == 0) |
| 16 | Unauthorized requests do not access protected scan cache entries | `test_03_06_07_*`, `test_04_05_*`, `test_08_*`, `test_10_11_13_14_15_16_17_*` (`_cache_get` & `_cache_put` tripwires == 0) |
| 17 | Explicit organization/project paths (and standalone Compute SSL helper `CR-06`) authorized before execution | `test_10_11_13_14_15_16_17_*`; `tests/test_phase4_scope_isolation.py::test_01_*`, `test_05_*`, `test_06_*` |
| 18 | Admin ADC regression tests pass | `tests/test_phase4_consolidated_security_review.py::test_18_19_admin_adc_and_demo_simulation_regressions`; `tests/test_phase3_adc_authorization.py` |
| 19 | Demo/simulation regression tests pass | `tests/test_phase4_consolidated_security_review.py::test_18_19_admin_adc_and_demo_simulation_regressions`; `tests/test_pqc_inventory.py` |
| 20 | Portal/API onboarding (`CR-04`), startup warmup removal (`CR-05`), and 3LO plugin gating (`CR-07`) covered | `tests/test_phase4_consolidated_security_review.py::test_09_20_portal_ui_onboarding_without_connection_post_and_zero_hardcoded_default_org` |

## Controlled Validation Order (Section 6)

1. New consolidated security tests (`tests/test_phase4_consolidated_security_review.py`)
2. Phase 4.1 tests (`tests/test_phase4_scope_isolation.py`)
3. Phase 4.1.1 delegated-token tests (`tests/test_phase4_delegated_token_validation.py`)
4. Phase 4.1.2 fail-closed tests (`tests/test_phase4_fail_closed_scope_resolution.py`)
5. Phase 3 ADC and egress tests (`tests/test_phase3_adc_authorization.py`, `tests/test_phase3_egress_security.py`)
6. Authentication and inventory regression suites (`tests/test_auth_hardening.py`, `tests/test_phase1_distributed_auth.py`, `tests/test_phase2_persistence_and_credentials.py`, `tests/test_pqc_inventory.py`)
7. Full safe local test suite (`tests/`)
8. Static checks: `python -m compileall`, `git diff --check`, and secret/operational-identifier scan.
