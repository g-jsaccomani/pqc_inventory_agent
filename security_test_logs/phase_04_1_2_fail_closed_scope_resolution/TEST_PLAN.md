# Phase 4.1.2 — Verification & Regression Test Plan

**Targeted Suite:** `tests/test_phase4_fail_closed_scope_resolution.py`
**Tripwires Installed:** `google.auth.default`, `AssetServiceClient`, `KeyManagementServiceClient`, `SslPoliciesClient`, `RegionSslPoliciesClient`, `_cai_search_all_resources`, `_cache_get`, `_cache_put` (plus pre-seeded `_SCAN_CACHE` sentinel entries).

## 1. Mandatory Phase 4.1.2 Scenario Matrix (Section 3 Items 1–12)

| Req # | Mandatory Scenario | Test Function (`tests/test_phase4_fail_closed_scope_resolution.py`) | Verification Focus |
|---|---|---|---|
| 1 | Authenticated tenant with valid organization binding | `test_01_authenticated_tenant_with_valid_organization_binding` | `_active_tenant_default_scope()`, `_active_tenant_org_id()`, `_resolve_scope("org")`, `_resolve_scope("vertex-runtime-tp")` all return `organizations/111111111111`. |
| 2 | Authenticated tenant with valid project binding | `test_02_authenticated_tenant_with_valid_project_binding` | `_active_tenant_default_scope()`, `_resolve_scope("org")`, `_resolve_scope("vertex-runtime-tp")` return `projects/tenant-a-proj-01`; `_active_tenant_org_id()` returns `""`. |
| 3 | Authenticated tenant with no binding | `test_03_authenticated_tenant_with_no_binding` | Returns `("UNBOUND", "", "")` across `_active_tenant_default_scope()`, `_resolve_scope("org")`, `_resolve_scope("default")`, and `_resolve_scope("vertex-runtime-tp")`; `_active_tenant_org_id() == ""`. |
| 4 | Authenticated tenant whose connection lookup raises an exception | `test_04_authenticated_tenant_connection_lookup_exception_fails_closed_with_sanitized_log` | Returns `("UNBOUND", "", "")` (never `DEFAULT_ORGANIZATION_ID`); `caplog` asserts warning contains exception class (`RuntimeError`) and `"UNBOUND"` with zero leakage of secret token, exception message text, or tenant email. |
| 5 | Authenticated tenant whose connection lookup returns malformed data | `test_05_authenticated_tenant_malformed_or_cross_tenant_connection_payload_fails_closed` (14 parametrized cases) | Covers `None`, `[]`, `"organizations/..."`, `42`, mismatched `user_id`, non-string `user_id`, non-string/invalid `organization_id`, non-string/invalid `project_id`, and non-string/invalid `active_scope_uri`; all return `("UNBOUND", "", "")`. |
| 6 | Tenant identity lookup raises an exception | `test_06_tenant_identity_lookup_failure_never_classified_as_unauthenticated` | Covers `get_current_tenant_user()` raising (with sanitized log check), `_is_authenticated_email_identity()` raising, and `None`/`""`/`"   "`/`12345`/`"@missing-local"`/`"missing-domain@"` returns; all return `("UNBOUND", "", "")`. |
| 7 | Positively unauthenticated CLI/test context preserves documented legacy behavior | `test_07_positively_unauthenticated_cli_test_context_preserves_legacy_default` | Verifies `"sec-architect"` and `"default"` preserve `DEFAULT_ORGANIZATION_ID` for scope helpers while all 5 live collectors still fail closed with `UNAUTHENTICATED_EXECUTION_CONTEXT` and 0 tripwire hits. |
| 8 | `_resolve_scope("org")` never substitutes default organization on lookup failure | `test_08_resolve_scope_org_never_substitutes_default_org_on_lookup_failure` | Verifies all `ORG_MODE_TOKENS` return `("UNBOUND", "", "")` under connection exception, malformed connection, and identity lookup failure. |
| 9 | Internal runtime project resolution never substitutes default org after failure | `test_09_internal_runtime_project_resolution_never_substitutes_default_org_on_failure` | Verifies `vertex-runtime-tp`, `projects/vertex-runtime-tp`, `project-cb232322-97f9-4f78-97f`, `agent-engine-tenant`, and `reasoning-engine-tenant` return `("UNBOUND", "", "")` across connection exception, malformed connection, and identity lookup failure. |
| 10 & 11 | Every live collector fails closed & denied requests make 0 SDK / ADC / CAI / cache calls | `test_10_11_all_live_collectors_fail_closed_with_zero_sdk_adc_cai_or_cache_access` (6 parametrized failure modes × 2 scopes × 5 collectors = 60 collector invocations) | Verifies all 5 collectors (`collect_kms_inventory`, `collect_workload_evidence`, `discover_all_crypto_assets`, `collect_tls_policies`, `collect_kms_import_jobs`) fail closed with `scope=""`, `scope_mode="UNBOUND"`, zero `DEFAULT_ORGANIZATION_ID`, zero sentinel cache leak, and 0 hits across all 8 tripwires. |
| 12 | Existing Phase 4.1.1 delegated-token and admin ADC behavior remains intact | `test_12_delegated_token_and_admin_adc_behavior_remains_intact` | Verifies project-bound delegated-token collection (`oauth2.Credentials`) and `PQC_ADMIN_EMAILS` org-bound ADC collection both resolve and execute cleanly with 0 unexpected `google.auth.default` calls. |

## 2. Ordered Regression Execution Plan (Section 4)

1. `.venv/bin/pytest -v -rs tests/test_phase4_fail_closed_scope_resolution.py`
2. `.venv/bin/pytest -q -rs tests/test_phase4_scope_isolation.py`
3. `.venv/bin/pytest -q -rs tests/test_phase4_delegated_token_validation.py`
4. `.venv/bin/pytest -q -rs tests/test_phase3_adc_authorization.py` and `.venv/bin/pytest -q -rs tests/test_phase3_egress_security.py`
5. `.venv/bin/pytest -q -rs tests/test_auth_hardening.py tests/test_phase1_distributed_auth.py` and `.venv/bin/pytest -q -rs tests/test_pqc_inventory.py tests/test_phase3_scorecard_correctness.py`
6. `.venv/bin/pytest -q -rs` (full safe local suite)
