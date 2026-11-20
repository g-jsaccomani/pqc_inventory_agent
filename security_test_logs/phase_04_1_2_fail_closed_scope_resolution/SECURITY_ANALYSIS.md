# Phase 4.1.2 — Security Analysis: Fail-Closed Tenant Scope Resolution

**Branch:** `security-hardening/phase-04-scope-isolation`
**Prior HEAD:** `f8a05b1d6ab55b45ea543610d7cd3c39ce4073ba`
**Base (`origin/main`):** `7f91cae13060b8fb8ceed9ac689981527c00df9f`

## 1. Root Cause

In `tools/gcp_inventory.py::_active_tenant_default_scope()` (introduced in Phase 4.1.1), tenant identity resolution and server-side connection lookup were wrapped in a single `try ... except Exception: pass` block whose fallthrough returned:

```python
return ("ORG", f"organizations/{DEFAULT_ORGANIZATION_ID}", DEFAULT_ORGANIZATION_ID)
```

This created a **fail-open fallback** under multiple runtime failure modes:

1. **Authenticated Tenant Connection Lookup Exception:** If `get_gcp_connection_config(mask_token=True, user_id=active_uid)` raised any exception (e.g., transient PostgreSQL outage, pool exhaustion, KMS unwrap failure), `except Exception: pass` silently replaced the authenticated tenant's scope with `DEFAULT_ORGANIZATION_ID`.
2. **Malformed Connection Payload / Attribute Type:** If `get_gcp_connection_config()` returned `None`, a non-dict, or non-string fields (e.g., integer `organization_id`), calling `.get()` or `.strip()` raised `AttributeError`, falling through to `DEFAULT_ORGANIZATION_ID`.
3. **Malformed Scope Values or Cross-Tenant Payload:** No format validation (`_validate_numeric_id_value`, `_validate_project_value`, `_validate_scope_value`) or tenant `user_id` ownership check was applied to the returned connection mapping.
4. **Identity Lookup Failure Misclassified as Unauthenticated:** If `get_current_tenant_user()` or `_is_authenticated_email_identity()` raised an exception (or returned `None`/malformed email), the exception handler silently treated the failure as an unauthenticated CLI helper and substituted `DEFAULT_ORGANIZATION_ID`.

Although live collectors still invoke `authorize_gcp_scope()` downstream, silently resolving an authenticated tenant's scope to another organization (`DEFAULT_ORGANIZATION_ID`) violates strict fail-closed tenant isolation and risks cross-tenant scope confusion whenever callers inspect `_resolve_scope()` or `_active_tenant_org_id()`.

## 2. Exact Code Paths Changed

1. **`tools/gcp_inventory.py`**
   - Imported `Mapping` from `typing`.
   - Rewrote `_active_tenant_default_scope()` with strict two-stage fail-closed logic:
     - **Stage 1 (Identity Resolution):** Imports helpers, calls `get_current_tenant_user()`, verifies `isinstance(active_uid, str)` and non-empty, and evaluates `_is_authenticated_email_identity(active_uid)`. Any exception, empty/non-string identity, or malformed `@`-containing non-email identity logs a sanitized warning (`type(exc).__name__` / `type(active_uid).__name__` only) and returns `("UNBOUND", "", "")`.
     - **Stage 2 (Authenticated Connection Lookup & Validation):** Calls `get_gcp_connection_config(mask_token=True, user_id=norm_active_uid)` inside an isolated `try`/`except`. Rejects exceptions, non-`Mapping` payloads, mismatched `conn["user_id"]`, non-string field types, and invalid organization/project/scope syntax via `_validate_numeric_id_value`, `_validate_project_value`, and `_validate_scope_value`, returning `("UNBOUND", "", "")` in every failure case.
   - Updated `_active_tenant_org_id()` docstring to document fail-closed empty-string return on errors.
   - Preserved propagation of `("UNBOUND", "", "")` through `_resolve_scope()` for all `ORG_MODE_TOKENS` (`""`, `"org"`, `"organization"`, `"all"`, `"default"`) and all internal runtime tenant projects (`_is_internal_runtime_tenant_project`: `*-tp`, `project-<hex>-*`, `vertex-ai-tenant`, `agent-engine-tenant`, `reasoning-engine-tenant`).
2. **`tools/gcloud_bridge.py`**
   - Hardened `authorize_gcp_scope()` to validate `isinstance(effective_conn, Mapping)` and enforce `normalize_user_id(conn_uid) == uid` when `effective_conn.get("user_id")` is present, failing closed with `PermissionError("UNAUTHORIZED_RESOURCE_SCOPE ...")` if connection configuration is malformed or belongs to a different tenant.

## 3. Authenticated vs. Unauthenticated Behavior

| Execution Context | Identity State | `_active_tenant_default_scope()` | `_active_tenant_org_id()` | Live Collector Outcome |
|---|---|---|---|---|
| **Authenticated tenant — valid org binding** | Valid corporate email (`alice@tenant-a.example`) | `("ORG", "organizations/111111111111", "111111111111")` | `"111111111111"` | Authorized via `authorize_gcp_scope()` |
| **Authenticated tenant — valid project binding** | Valid corporate email (`alice@tenant-a.example`) | `("PROJECT", "projects/tenant-a-proj-01", "tenant-a-proj-01")` | `""` | Authorized via `authorize_gcp_scope()` |
| **Authenticated tenant — valid folder binding** | Valid corporate email (`alice@tenant-a.example`) | `("FOLDER", "folders/999999999999", "999999999999")` | `""` | Authorized via `authorize_gcp_scope()` |
| **Authenticated tenant — unbound / error / malformed / mismatched** | Valid corporate email | `("UNBOUND", "", "")` (NEVER `DEFAULT_ORGANIZATION_ID`) | `""` | Fails closed before `_SCAN_CACHE` & SDK clients (0 calls) |
| **Identity resolution failure / malformed identity** | Exception, `None`, `""`, non-`str`, `"@bad"` | `("UNBOUND", "", "")` (NEVER classified as unauthenticated) | `""` | Fails closed before `_SCAN_CACHE` & SDK clients (0 calls) |
| **Positively unauthenticated CLI / unit-test helper** | Valid non-empty `str`, no `@`, `_is_authenticated_email_identity == False` (e.g., `"sec-architect"`, `"default"`) | `("ORG", f"organizations/{DEFAULT_ORGANIZATION_ID}", DEFAULT_ORGANIZATION_ID)` | `DEFAULT_ORGANIZATION_ID` | Still fails closed in live collectors (`UNAUTHENTICATED_EXECUTION_CONTEXT`, 0 SDK/ADC/cache calls) |

## 4. Failure-Mode Analysis

| Failure Mode | Trigger | Diagnostic Logged | Returned Scope | Downstream Live Collector Side Effects |
|---|---|---|---|---|
| DB / KMS / runtime error in connection lookup | `get_gcp_connection_config()` raises `RuntimeError`/`ConnectionError` | `WARNING`: exception class name only (`type(exc).__name__`); **zero** `str(exc)`, tokens, credentials, or emails | `("UNBOUND", "", "")` | Fails closed; 0 SDK clients, 0 `google.auth.default`, 0 CAI calls, 0 `_SCAN_CACHE` access |
| Non-`Mapping` connection payload | Returns `None`, `[]`, `"str"`, `42` | `WARNING`: payload type name only | `("UNBOUND", "", "")` | Fails closed (`PermissionError`); 0 SDK/ADC/CAI/cache calls |
| Cross-tenant connection payload | `conn["user_id"] != active_uid` | `WARNING`: generic mismatch notice (no emails) | `("UNBOUND", "", "")` | Fails closed (`PermissionError`); 0 SDK/ADC/CAI/cache calls |
| Malformed scope field type or value | `organization_id=12345`, `"not-numeric"`, `"organizations/"`, `project_id=["x"]`, `"BAD PROJECT"`, `active_scope_uri="organizations/../../etc"` | `WARNING`: field category & type only (no raw values) | `("UNBOUND", "", "")` | Fails closed (`PermissionError`); 0 SDK/ADC/CAI/cache calls |
| Identity lookup failure | `get_current_tenant_user()` or `_is_authenticated_email_identity()` raises; or returns `None`/`""`/non-`str`/`"@bad"` | `WARNING`: exception class or type name only | `("UNBOUND", "", "")` | Fails closed; 0 SDK/ADC/CAI/cache calls |

## 5. Remaining Risks & Limitations

1. **Module-Level `DEFAULT_ORGANIZATION_ID` Constant Outside Authenticated Scope Resolution:** `DEFAULT_ORGANIZATION_ID` remains as a default argument literal on tool function signatures and in positively unauthenticated CLI/unit-test helpers (Phase 4.1 explicitly documented removing global default-org constants as a separate multi-tenant configuration phase). For authenticated tenants, `_active_tenant_default_scope()` can no longer fall back to `DEFAULT_ORGANIZATION_ID` under any error or unbound condition, and explicit references to `DEFAULT_ORGANIZATION_ID` are still subject to `authorize_gcp_scope()`.
2. **Offline Mocked Verification Only:** Phase 4.1.2 verification runs exclusively with isolated mocks, tripwires, and local SQLite test stores; no live GCP, Cloud SQL, Vertex AI, or Docker workloads were executed. Live staging verification remains mandatory before production rollout.
3. **No Automated CI Status:** The repository has no `.github/workflows` pipeline at this revision; all recorded test results are local workstation runs.
