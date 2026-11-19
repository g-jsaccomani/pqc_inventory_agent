# Phase 4.1 — Execution Checkpoint

**Status:** `PASS — PHASE 4.1 READY FOR REVIEW`
**Branch:** `security-hardening/phase-04-scope-isolation`
**Base Revision (`origin/main`):** `7f91cae13060b8fb8ceed9ac689981527c00df9f`

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
- Live cloud resources touched: **None (`0`)**

## Remaining Limitations & Separate Follow-Up Findings (Out of Scope for P4.1)
1. **Default Organization Fallback Defaults Outside CAI:** `DEFAULT_ORGANIZATION_ID` / `DEFAULT_ORGANIZATION_NAME` module defaults remain in tool parameter defaults, CLI `--scope` defaults (`main.py`), prompt guidance (`pqc_agent/agent.py`), startup warmup (`pqc_agent/workspace_server.py`), admin-only connection templates (`tools/gcloud_bridge.py`), and deploy scripts (`scripts/*.sh`). Active live access is fail-closed via `authorize_adc_mode()` and `authorize_gcp_scope()`, and removing hardcoded default env fallbacks across CLI/portal/agent layers should be tracked as a separate multi-tenant configuration phase.
2. **Pre-Existing Test Fixture Context Isolation (`test_phase3_egress_security.py`):** Leaves `_CURRENT_TENANT_USER` populated after execution, which can affect `test_auth_hardening.py` if invoked in reverse alphabetical order in the same pytest process. Unrelated to Phase 4.1; tracked as test hygiene follow-up.
3. **Child Project Listing Inside an Authorized Organization:** When a caller is explicitly authorized for `organizations/<id>` and CAI succeeds returning child KMS key rings inside that organization, Cloud KMS reads those child key rings using the caller's delegated/authorized credentials (GCP IAM enforces per-project read access).

## Handoff State
- Ready for commit (`fix(security): enforce explicit CAI scope isolation`) and push to `origin/security-hardening/phase-04-scope-isolation`.
- **STOP GATE ACTIVE:** Do not merge into `main` and do not start Phase 4.2 without explicit human approval.
