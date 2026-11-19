# Phase 4.1 — Verification & Regression Test Results

**Branch:** `security-hardening/phase-04-scope-isolation`
**Base Revision (`origin/main`):** `7f91cae13060b8fb8ceed9ac689981527c00df9f`
**Implementation Commit:** `5f325a5be161fc204efdc36d4c59a09559494e62`
**Execution Mode:** Local Python 3.12.13 (`.venv`, `pytest 9.1.1`); the targeted suite replaces the Cloud Asset Inventory and Cloud KMS clients with mocks. No cloud resource was provisioned, modified, or deployed, and no Cloud SQL, Cloud Build, IAM, or deployment command was run. Outbound network traffic was not instrumented (see below).

## Result Provenance and Scope of the Cloud-Safety Statement

- Every count in this file is a **recorded execution result**, captured once on 2026-11-19 on the implementation author's local workstation against the working-tree source and tests that were then committed unchanged as `5f325a5be161fc204efdc36d4c59a09559494e62`. The results have **not been independently reproduced**, were not re-run on the commit itself or during documentation finalization, and no automated CI status exists for that commit.
- Cloud-safety statements in this bundle mean that no cloud resource was provisioned, modified, or deployed. They do not mean that outbound traffic was measured. The recorded full-suite log contains a `google.auth` warning that end-user Application Default Credentials from the local Cloud SDK were loaded during 9 pre-existing `tests/test_pqc_inventory.py` tests; the same warning appears in a full-suite log recorded before the Phase 4.1 changes. Whether any network request followed was not measured, so an absolute "zero live API calls" claim is not supported for the full regression suite.

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
| `test_08_supported_workflows_demo_scorecard_cbom_and_admin_adc` | Req 8 — Against mocked SDK clients: the explicit demo scope returns `SIMULATED_DEMO_DATASET` data; a delegated `access_token` tenant obtains `compute_pqc_scorecard` (`COMPLETE`) and `export_cyclonedx_cbom` for its bound organization scope; an authorized administrator in `adc` mode (`PQC_ADMIN_EMAILS` plus `PQC_ALLOWED_ORGANIZATIONS`) succeeds on the allowlisted organization and is denied `UNAUTHORIZED_RESOURCE_SCOPE` on another. Service account impersonation is not exercised. | **PASS** |

## 2. Regression Suites

| Suite / Command | Observed Result | Notes |
|---|---|---|
| `.venv/bin/pytest -v -rs tests/test_pqc_inventory.py tests/test_phase3_scorecard_correctness.py` | **`34 passed, 1 skipped, 0 failed`** (`11.12s`) | 1 skip: `test_live_vertex_gemini_turn_reports_model_telemetry` (requires `PQC_LIVE_LLM_TEST=1`, intentionally excluded per Section 5). |
| `.venv/bin/pytest -q -rs tests/test_phase3_adc_authorization.py` | **`41 passed, 0 skipped, 0 failed`** (`4.85s`) | All Phase 3.1 ADC & tenant scope authorization tests green. |
| `.venv/bin/pytest -q -rs tests/test_phase3_egress_security.py` | **`181 passed, 0 skipped, 0 failed`** (`1.88s`) | All Phase 3.1 SSRF/egress/gcloud hardening tests green. |
| `.venv/bin/pytest -q -rs tests/test_auth_hardening.py` | **`30 passed, 0 skipped, 0 failed`** (`3.31s`) | All Phase 1 auth hardening tests green. |
| `.venv/bin/pytest -v -rs` (Full Safe Local Regression Suite) | **`352 passed, 4 skipped, 0 failed`** (`64.24s`) | 4 skips: 1 live PostgreSQL (`PQC_TEST_POSTGRES_URL`), 1 live Vertex AI (`PQC_LIVE_LLM_TEST=1`), 2 live Docker daemon (`Docker CLI/daemon is not installed in this workstation environment`). All 4 skips are out-of-scope live/daemon tests per Section 5. |

### Test-Order Observation (Assessed as Unrelated to Phase 4.1; Not Reproduced on the Base Commit)
The first regression attempt invoked three files in one pytest process, in the order `tests/test_phase3_adc_authorization.py`, `tests/test_phase3_egress_security.py`, `tests/test_auth_hardening.py`, and reported **`1 failed, 251 passed`**: `test_auth_hardening.py::test_s7_access_tokens_are_envelope_encrypted_and_never_stored_in_plaintext` raised `PermissionError` from `set_gcp_connection_config` because the current-tenant context set by `gcloud_bridge.set_current_tenant_user()` still held `alice@google.com` from an earlier test. Each of the three files passes when run on its own (`41`, `181`, `30` passed) and the default-order full suite passed (`352 passed, 0 failed`).

Attribution is by static reading, not by an isolating run: `tests/test_phase3_egress_security.py` calls `set_current_tenant_user("alice@google.com")` inside a test body and has no fixture that restores it, whereas `tests/test_phase3_adc_authorization.py` restores the previous value in an autouse fixture. The issue is assessed as pre-existing because Phase 4.1 changed neither those test files nor `set_gcp_connection_config`, but the failing order was **not** executed on the base commit `7f91cae13060b8fb8ceed9ac689981527c00df9f`, so "pre-existing" is an inference rather than a reproduced result. Those test files were left unmodified and the isolation issue is logged as a separate follow-up finding.

## 3. Static Hygiene & Secret / Sensitive-Identifier Scan

| Check | Command | Outcome |
|---|---|---|
| Python bytecode compilation | `.venv/bin/python -m compileall -q pqc_agent tools tests main.py` | **PASS** (`exit 0`) |
| Whitespace / conflict marker check | `git diff --check` | **PASS** (`exit 0`) |
| Secret & sensitive-identifier scan across full Phase 4.1 branch diff (`git diff 7f91cae...HEAD`) and all new Phase 4.1 files | Automated regex scanner checking private keys, GCP API keys, OAuth client secrets, real bearer tokens, GitHub tokens, legacy Functional Lab folder/org/project IDs, and local OS username / personal domain identifiers | **PASS — 0 findings** (re-verified after sanitizing local workstation path in `EXECUTION_LOG.md` to `<REPO_ROOT>`). |
