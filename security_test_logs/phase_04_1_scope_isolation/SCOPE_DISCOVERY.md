# Phase 4.1 — Scope Discovery Findings

**Branch:** `security-hardening/phase-04-scope-isolation`
**Base Revision (`origin/main`):** `7f91cae13060b8fb8ceed9ac689981527c00df9f`
**Status:** Recorded prior to code modification (per Phase 4.1 Section 2).

## 1. Legacy Hardcoded Functional Lab Fallback Inventory

Inspection of the full repository located the legacy hardcoded Functional Lab scope fallback exclusively in `tools/gcp_inventory.py`, invoked from 5 Cloud Asset Inventory (CAI) call sites across 2 modules:

| Symbol / Call Site | File & Lines (Baseline `7f91cae`) | Observed Legacy Behavior |
|---|---|---|
| `DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES` | `tools/gcp_inventory.py:656-660` | Hardcoded tuple of 3 non-production Functional Lab scopes (one folder scope and two host/dev project scopes). |
| `_cai_search_all_resources_with_fallback` | `tools/gcp_inventory.py:663-704` | When `cai_client.search_all_resources` failed and `scope_uri == f"organizations/{DEFAULT_ORGANIZATION_ID}"`, silently caught the primary exception, iterated across `DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES`, deduplicated returned resources by `name`, and returned a partial inventory assembled from unrelated lab scopes (swallowing the original failure). Docstring also embedded the hardcoded Functional Lab org, folder, and project identifiers. |
| `_discover_kms_targets_via_cai` | `tools/gcp_inventory.py:707-726` (call at `L712`) | Discovers `(project_id, location)` KMS targets via `_cai_search_all_resources_with_fallback`. |
| `collect_workload_evidence` | `tools/gcp_inventory.py:919-983` (call at `L947`) | Collects workload and CMEK evidence via `_cai_search_all_resources_with_fallback`. |
| `discover_all_crypto_assets` | `tools/gcp_inventory.py:1009-1085` (call at `L1040`) | Collects SSL/Certificate Manager/CAS/SSL policy assets via `_cai_search_all_resources_with_fallback`. |
| `collect_tls_policies` | `tools/pqc_detectors.py:166-278` (import `L26`, call `L215`) | Collects SSL policies and HTTPS/SSL target proxies via `_cai_search_all_resources_with_fallback`. |
| `_discover_key_rings_via_cai` (used by `collect_kms_import_jobs`) | `tools/pqc_detectors.py:307-329` (call `L311`) | Discovers Cloud KMS key rings for BYOK import-job inspection via `_cai_search_all_resources_with_fallback`. |

No tests, scripts, or other modules import or depend on `DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES` or `_cai_search_all_resources_with_fallback`.

## 2. Related Scope-Resolution & Authorization Gaps Identified During Discovery

1. **Silent Rewriting of Explicit Org Scopes (`tools/gcp_inventory.py:61-76`, `275-296`):**
   - `ORG_MODE_TOKENS` previously included `DEFAULT_ORGANIZATION_ID.lower()` and `f"organizations/{DEFAULT_ORGANIZATION_ID}".lower()`.
   - When an authenticated tenant had a different `active_org` configured and explicitly passed `organizations/<DEFAULT_ORGANIZATION_ID>`, `_resolve_scope()` matched `ORG_MODE_TOKENS` and silently rewrote the requested scope to the tenant's own `active_org` rather than preserving the explicitly supplied scope for strict authorization evaluation.
   - Similarly, `_resolve_scope("organizations/")` (empty organization identifier) silently substituted `active_org`.
   - `collect_kms_inventory` stamped `"organization_domain": DEFAULT_ORGANIZATION_NAME` on every `mode == "ORG"` payload even when scanning a different organization.

2. **Missing Tenant Scope Allowlist Enforcement on Python SDK / CAI Collectors (`tools/gcp_inventory.py:192-204`, `tools/pqc_detectors.py`):**
   - In Phase 3.1 (`tools/gcloud_bridge.py:1550-1756`), `resolve_authorized_tenant_scope()` and `authorize_gcloud_command_scope()` enforced strict per-tenant project/organization/folder allowlists (`PQC_ALLOWED_PROJECTS`, `PQC_ALLOWED_ORGANIZATIONS`, `PQC_ALLOWED_FOLDERS`, `PQC_TENANT_SCOPE_POLICY`, and tenant-bound `project_id`/`organization_id`, with folders default-deny) for `execute_gcloud_command()`.
   - However, the 5 live Python SDK / CAI collectors (`collect_kms_inventory`, `collect_workload_evidence`, `discover_all_crypto_assets`, `collect_tls_policies`, `collect_kms_import_jobs`) only checked credential resolution via `_get_client_kwargs()` (`get_active_gcp_credentials()`) and did **not** validate `scope_uri` against `resolve_authorized_tenant_scope()`.
   - Additionally, `_get_client_kwargs()` had a broad `except Exception: pass` fallback returning `{}`, which could silently fall back to ambient ADC on non-`PermissionError` exceptions, and `_cache_get()` ran before live authorization checks, risking stale cache reads if a tenant's scope authorization changed.

3. **Existing Project-Level Semantics Preserved:**
   - `_discover_kms_targets_via_cai` (for an explicitly authorized `projects/<id>` when CAI returns no targets) probes `(<same_project_id>, "global")` within that exact project.
   - `collect_kms_import_jobs` (for an explicitly authorized `projects/<id>` when CAI succeeds with zero key rings) probes `list_key_rings` directly on that exact project.
   - Neither path switches to another project, folder, or organization; both remain strictly bounded to the caller-supplied authorized project.

## 3. References to `DEFAULT_ORGANIZATION_ID` Retained as Out-of-Scope Architectural Follow-Up

Per Phase 4.1 Section 7 (Change Control), broader removal of configurable `DEFAULT_ORGANIZATION_ID` defaults outside the CAI fallback and scope-isolation boundary is documented as a separate follow-up finding rather than expanding Phase 4.1:

- `tools/gcp_inventory.py:33-34` (`DEFAULT_ORGANIZATION_ID`, `DEFAULT_ORGANIZATION_NAME` env-configurable module defaults) and default parameter annotations on tool functions (`tools/gcp_inventory.py:767,919,1009,1215,1388`, `tools/pqc_detectors.py:166,333`, `tools/quantum_engine.py:186`).
- `tools/gcloud_bridge.py:924-925` (admin-only `_default_connection_template`, already gated by deny-by-default `is_adc_authorized_user`).
- `pqc_agent/agent.py:96` (system prompt default scope hint).
- `pqc_agent/workspace_server.py:1015` (consent-card display fallback string) and `1677-1703` (`_warm_inventory_cache`, which already fails closed at startup without live credentials).
- `main.py:279,289` (CLI `--scope` defaults) and deployment helper scripts (`scripts/deploy_cloud_run.sh`, `scripts/setup_and_deploy_vertex.sh`).

None of these retained references bypass `authorize_adc_mode()` or `authorize_gcp_scope()`, and none perform silent cross-scope fallback.

## 4. Existing Test Coverage Baseline

- `tests/test_pqc_inventory.py::test_resolve_scope_org_folder_project_and_tenant_redirect` verifies `_resolve_scope()` for explicit org, symbolic `"org"`, folder, project, bare project ID, and internal runtime tenant project (`-tp` / `project-<hex>`).
- `tests/test_pqc_inventory.py::test_live_mode_never_falls_back_to_demo_data` verifies all 5 collectors return live error payloads (never simulated demo data) when GCP APIs fail.
- `tests/test_phase3_adc_authorization.py` verifies deny-by-default `authorize_adc_mode()`, `_get_client_kwargs()` fail-closed behavior, and `authorize_gcloud_command_scope()` tenant allowlists.
- No existing test exercised `_cai_search_all_resources_with_fallback` or depended on legacy Functional Lab fallback scopes.
