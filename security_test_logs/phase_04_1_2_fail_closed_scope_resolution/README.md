# Phase 4.1.2 — Fail-Closed Tenant Scope Resolution

## Overview

This directory contains the security analysis, verification plan, recorded test results, execution log, and handoff checkpoint for **Phase 4.1.2 (`P4.1.2`)**, a targeted security correction to Phase 4.1.1 eliminating the remaining implicit `DEFAULT_ORGANIZATION_ID` exception fallback in `tools/gcp_inventory.py::_active_tenant_default_scope()`.

## Git Context

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-04-scope-isolation`
- **Base (`origin/main`):** `7f91cae13060b8fb8ceed9ac689981527c00df9f` (unchanged)
- **Prior Phase 4.1.1 HEAD:** `f8a05b1d6ab55b45ea543610d7cd3c39ce4073ba` (`fix(security): validate delegated token scope binding`)
- **Open Pull Request:** `#3` (`https://github.com/g-jsaccomani/pqc_inventory_agent/pull/3`, targeting `main`)
- **Cloud Resources Touched:** **None.** No GCP API calls, IAM operations, Cloud SQL connections, Vertex AI calls, or Docker/Cloud Build actions were executed.

## Summary of Remediation

- **Defect Fixed:** Previously, `tools/gcp_inventory.py::_active_tenant_default_scope()` wrapped tenant identity resolution and connection lookup in a broad `try ... except Exception: pass` block that fell through to `return ("ORG", f"organizations/{DEFAULT_ORGANIZATION_ID}", DEFAULT_ORGANIZATION_ID)`. Any exception during tenant identity lookup or connection config lookup — or a malformed non-string connection attribute — caused an authenticated tenant's symbolic scope (`"org"`, `"default"`, internal `-tp` runtime project) to silently substitute `DEFAULT_ORGANIZATION_ID`.
- **Fix Applied:**
  - Separated identity resolution from connection lookup in `tools/gcp_inventory.py::_active_tenant_default_scope()`.
  - Any identity lookup exception, empty/non-string identity, or malformed email identity returns `("UNBOUND", "", "")` (never classified as unauthenticated).
  - For authenticated tenants, any connection lookup exception, non-`Mapping` payload, mismatched `user_id`, or malformed `organization_id` / `project_id` / `active_scope_uri` logs a sanitized diagnostic (exception class / type only — zero tokens, credentials, exception bodies, or tenant emails) and returns `("UNBOUND", "", "")`.
  - Preserved legacy `DEFAULT_ORGANIZATION_ID` exclusively when the helper positively establishes an unauthenticated CLI/test context (valid non-email placeholder without `@` where `_is_authenticated_email_identity()` returns `False`).
  - Added defensive `Mapping` and tenant `user_id` checks on `effective_conn` in `tools/gcloud_bridge.py::authorize_gcp_scope()`.

## Files in This Evidence Bundle

| File | Purpose |
|---|---|
| `README.md` | Navigation index, Git provenance, and remediation summary. |
| `SECURITY_ANALYSIS.md` | Root cause, exact changed code paths, authenticated vs. unauthenticated behavior, failure-mode matrix, and remaining risks. |
| `TEST_PLAN.md` | 1-to-1 verification matrix for all 12 mandatory Phase 4.1.2 scenarios, tripwires, and ordered regression plan. |
| `TEST_RESULTS.md` | Verbatim commands, exit codes, durations, pass/skip/fail counts, and static/secret scan results. |
| `EXECUTION_LOG.md` | Chronological log of precondition checks, edits, test execution, and pre-commit verification. |
| `EXECUTION_CHECKPOINT.md` | Final readiness status, explicit confirmation that the fallback is eliminated for authenticated tenants, and stop-gate state. |
