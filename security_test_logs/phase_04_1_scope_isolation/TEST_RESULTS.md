# Phase 4.1 — Verification & Regression Test Results

**Branch:** `security-hardening/phase-04-scope-isolation`
**Base Revision (`origin/main`):** `7f91cae13060b8fb8ceed9ac689981527c00df9f`
**Execution Mode:** 100% offline / deterministic local Python 3.12.13 (`.venv`, `pytest 9.1.1`). Zero live GCP, Vertex AI, Cloud SQL, Cloud Build, or IAM operations.

## 1. Targeted Phase 4.1 Security Suite

Command:
```bash
.venv/bin/pytest -v -rs tests/test_phase4_scope_isolation.py
```

Observed Result: **`9 passed, 0 failed, 0 skipped`** (`1.40s`, exit `0`).

| Test Case | Requirement Verified | Outcome |
|---|---|---|
| `test_01_authorized_org_scope_queried_exact_across_all_collectors` | Req 1 — Authorized org scope queried verbatim across `_cai_search_all_resources` and all 5 collectors (`6/6` exact calls, `organization_domain=None` for non-default org). | **PASS** |
| `test_02_failed_org_cai_never_falls_back_to_folder_or_project_scopes[tenant_org]` | Req 2 — Failed tenant org CAI request triggers `0` folder/project fallback queries, returns `0` partial resources, preserves actionable error, and is not cached. | **PASS** |
| `test_02_failed_org_cai_never_falls_back_to_folder_or_project_scopes[configured_default_org]` | Req 2 — Failed `organizations/{DEFAULT_ORGANIZATION_ID}` CAI request (the exact legacy fallback trigger) triggers `0` fallback queries and returns `0` foreign resources. | **PASS** |
| `test_03_original_cai_exception_propagated_intact` | Req 3 — Exact original CAI exception object (`exc_info.value is original_exc`) propagated across org, default org, folder, and project scopes (`_cai_search_all_resources` and `_discover_key_rings_via_cai`); empty scope fails closed with `ValueError`. | **PASS** |
| `test_04_no_hardcoded_functional_lab_fallback_scopes_in_active_code` | Req 4 — Confirms `DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES` and `_cai_search_all_resources_with_fallback` removed; AST check proves `0` `try/except` in `_cai_search_all_resources` and `0` hardcoded `organizations/<id>`, `folders/<id>`, or `projects/<id>` string literals in `tools/gcp_inventory.py` and `tools/pqc_detectors.py`. | **PASS** |
| `test_05_explicit_project_scope_collection_and_failure_semantics` | Req 5 — Explicit project scope (`projects/tenant-a-prod-01` and bare project ID) succeeds across all 5 collectors; project CAI failures preserve original same-project semantics without querying any other scope. | **PASS** |
| `test_06_unauthorized_scopes_rejected_before_sdk_or_cache_access` | Req 6 — Unauthenticated caller, tampered non-admin `mode=adc`, out-of-scope org/folder/project, malformed/traversal scopes, `PQC_ALLOWED_ORGANIZATIONS` revocation after cache warm, and `PQC_TENANT_SCOPE_POLICY` all fail closed with `0` `google.auth.default()` and `0` SDK client calls. | **PASS** |
| `test_07_cross_tenant_and_cross_scope_isolation` | Req 7 — Tenant A cannot read Tenant B's live or cached org/project inventory; explicit `organizations/{DEFAULT_ORGANIZATION_ID}` is preserved verbatim and denied for Tenant A (never rewritten); cross-tenant `user_id` override rejected; principal-scoped `PQC_ALLOWED_FOLDERS` isolates folders per user. | **PASS** |
| `test_08_supported_workflows_demo_scorecard_cbom_and_admin_adc` | Req 8 — Explicit demo scope (`SIMULATED_DEMO_DATASET`), `compute_pqc_scorecard`, `export_cyclonedx_cbom`, and authorized server-side admin ADC within `PQC_ALLOWED_ORGANIZATIONS` remain fully compatible. | **PASS** |

## 2. Regression Suites

| Suite / Command | Observed Result | Notes |
|---|---|---|
| `.venv/bin/pytest -v -rs tests/test_pqc_inventory.py tests/test_phase3_scorecard_correctness.py` | **`34 passed, 1 skipped, 0 failed`** (`11.12s`) | 1 skip: `test_live_vertex_gemini_turn_reports_model_telemetry` (requires `PQC_LIVE_LLM_TEST=1`, intentionally excluded per Section 5). |
| `.venv/bin/pytest -q -rs tests/test_phase3_adc_authorization.py` | **`41 passed, 0 skipped, 0 failed`** (`4.85s`) | All Phase 3.1 ADC & tenant scope authorization tests green. |
| `.venv/bin/pytest -q -rs tests/test_phase3_egress_security.py` | **`181 passed, 0 skipped, 0 failed`** (`1.88s`) | All Phase 3.1 SSRF/egress/gcloud hardening tests green. |
| `.venv/bin/pytest -q -rs tests/test_auth_hardening.py` | **`30 passed, 0 skipped, 0 failed`** (`3.31s`) | All Phase 1 auth hardening tests green. |
| `.venv/bin/pytest -v -rs` (Full Safe Local Regression Suite) | **`352 passed, 4 skipped, 0 failed`** (`64.24s`) | 4 skips: 1 live PostgreSQL (`PQC_TEST_POSTGRES_URL`), 1 live Vertex AI (`PQC_LIVE_LLM_TEST=1`), 2 live Docker daemon (`Docker CLI/daemon is not installed in this workstation environment`). All 4 skips are out-of-scope live/daemon tests per Section 5. |

### Pre-Existing Test-Order Observation (Unrelated to Phase 4.1)
When `tests/test_phase3_egress_security.py` and `tests/test_auth_hardening.py` were manually invoked in reverse alphabetical order in one pytest process (`test_phase3_egress_security.py` before `test_auth_hardening.py`), a pre-existing context-var leak in `test_phase3_egress_security.py` left `gcloud_bridge._CURRENT_TENANT_USER` set to a previous user, causing `test_auth_hardening.py::test_s7_access_tokens_are_envelope_encrypted_and_never_stored_in_plaintext` to fail with `PermissionError` in `set_gcp_connection_config` (which Phase 4.1 did not modify). Both suites pass 100% independently and in the full suite (`352 passed, 0 failed`). Per Phase 4.1 Section 5 & 7, those unrelated Phase 1/3 test files were not modified and this pre-existing test isolation issue is logged as a separate follow-up finding.

## 3. Static Hygiene & Secret / Sensitive-Identifier Scan

| Check | Command | Outcome |
|---|---|---|
| Python bytecode compilation | `.venv/bin/python -m compileall -q pqc_agent tools tests main.py` | **PASS** (`exit 0`) |
| Whitespace / conflict marker check | `git diff --check` | **PASS** (`exit 0`) |
| Secret & sensitive-identifier scan across full Phase 4.1 branch diff (`git diff 7f91cae...HEAD`) and all new Phase 4.1 files | Automated regex scanner checking private keys, GCP API keys, OAuth client secrets, real bearer tokens, GitHub tokens, legacy Functional Lab folder/org/project IDs, and local OS username / personal domain identifiers | **PASS — 0 findings** (re-verified after sanitizing local workstation path in `EXECUTION_LOG.md` to `<REPO_ROOT>`). |
