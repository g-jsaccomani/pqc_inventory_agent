# Phase 4.1 — Security Design: Strict Scope Isolation & Legacy Fallback Removal

**Branch:** `security-hardening/phase-04-scope-isolation`
**Base Revision (`origin/main`):** `7f91cae13060b8fb8ceed9ac689981527c00df9f`

## 1. Threat Model & Security Rationale

### Previous Risk (Legacy Functional Lab Fallback + Unchecked SDK Scopes)
1. **Silent Cross-Scope Data Disclosure / Confused Scope Assembly:** When an organization-level Cloud Asset Inventory (`search_all_resources`) query failed for `organizations/{DEFAULT_ORGANIZATION_ID}`, `_cai_search_all_resources_with_fallback()` swallowed the primary exception and queried three hardcoded non-production scopes (`DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES`), assembling a partial inventory from unrelated folders/projects and presenting it as the requested organization's inventory.
2. **Scope Authorization Parity Gap:** While Phase 3.1 enforced `resolve_authorized_tenant_scope()` on `execute_gcloud_command()`, the Python SDK collectors (`tools/gcp_inventory.py`, `tools/pqc_detectors.py`) did not call the tenant scope authorizer before invoking `asset_v1.AssetServiceClient` or `kms_v1.KeyManagementServiceClient`, nor before reading `_SCAN_CACHE`.
3. **Implicit Scope Rewriting & Broad Exception Swallowing:** `ORG_MODE_TOKENS` rewrote explicit requests for `organizations/{DEFAULT_ORGANIZATION_ID}` into another tenant's `active_org`, and `_get_client_kwargs()` caught generic `Exception` into `{}` (which could unintentionally fall back to ambient ADC).

## 2. Exact Design Changes

### P4.1.1 — Remove Hardcoded Functional Lab Scope Fallbacks
- Delete `DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES` from `tools/gcp_inventory.py`.
- Replace `_cai_search_all_resources_with_fallback()` with strict `_cai_search_all_resources()`, removing all embedded Functional Lab organization/folder/project references from code and docstrings.
- Do not introduce any replacement hardcoded scopes or env-var fallback lists.

### P4.1.2 — Enforce Explicit Scope Semantics
- `_cai_search_all_resources(cai_client, scope_uri, asset_types, read_mask=None, page_size=500)` validates `scope_uri` is non-empty and executes a single `list(cai_client.search_all_resources(request=req))` call for `scope_uri`.
- On any CAI error (organization, folder, or project):
  - Propagate the original exception directly out of `_cai_search_all_resources()`.
  - Perform zero fallback queries against any other organization, folder, or project.
  - Preserve structured, actionable error reporting in all 5 collector tools (`collect_kms_inventory`, `collect_workload_evidence`, `discover_all_crypto_assets`, `collect_tls_policies`, `collect_kms_import_jobs`) and avoid caching failed live error payloads in `_SCAN_CACHE`.
- Remove `DEFAULT_ORGANIZATION_ID.lower()` and `f"organizations/{DEFAULT_ORGANIZATION_ID}".lower()` from `ORG_MODE_TOKENS` in `tools/gcp_inventory.py`, and stop rewriting malformed empty `"organizations/"` to `active_org` in `_resolve_scope()`.
- Only populate `organization_domain` in `collect_kms_inventory` when `clean_id == DEFAULT_ORGANIZATION_ID` (otherwise `None`).

### P4.1.3 — Preserve & Extend Phase 3 Authorization Controls
- Add `authorize_gcp_scope(scope_uri, *, user_id=None, conn_cfg=None) -> str` in `tools/gcloud_bridge.py`:
  - Requires an authenticated tenant identity (`_is_authenticated_email_identity`), rejecting cross-tenant identity overrides.
  - Verifies raw stored DB `mode == "adc"` and effective `mode == "adc"` via existing deny-by-default `authorize_adc_mode(uid)`.
  - Validates `scope_uri` format via `_validate_scope_value()` (`organizations/<digits>`, `folders/<digits>`, or `projects/<valid-id>`).
  - Reuses canonical `resolve_authorized_tenant_scope(uid, effective_conn)` (enforcing `PQC_ALLOWED_PROJECTS`, `PQC_ALLOWED_ORGANIZATIONS`, `PQC_ALLOWED_FOLDERS`, `PQC_TENANT_SCOPE_POLICY`, tenant-bound `project_id`/`organization_id`, and default-deny folders).
  - Fails closed with `PermissionError("UNAUTHORIZED_RESOURCE_SCOPE: ...")` when `scope_uri` is outside the caller's authorized scope.
- Harden `_get_client_kwargs(scope_uri: Optional[str] = None)` in `tools/gcp_inventory.py`:
  - When `scope_uri` is supplied, invokes `authorize_gcp_scope(scope_uri)` **before** calling `get_active_gcp_credentials()` (ensuring zero `google.auth.default()` or token exchanges occur for unauthorized scopes).
  - Removes the legacy `except Exception: pass` fallback so failures never silently degrade to `{}` (ambient ADC).
- In all 5 live collectors (`collect_kms_inventory`, `collect_workload_evidence`, `discover_all_crypto_assets`, `collect_tls_policies`, `collect_kms_import_jobs`), invoke `_get_client_kwargs(scope_uri=scope_uri)` **before** `_cache_get(cache_key)` and before instantiating any Google Cloud SDK client, then pass the authorized `client_kwargs` to the SDK clients and CAI discovery helpers.

## 3. Security Properties Preserved
- `authorize_adc_mode()` remains strictly deny-by-default.
- No static credential fallback is introduced.
- No new IAM roles or permissions are required.
- All GCP API calls remain strictly read-only.
- No Phase 3 evidence files or unrelated subsystems are modified.
