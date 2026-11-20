# Phase 4.1.1 — Delegated Token Flow Security Validation and Scope Binding

## Overview

This directory contains the security investigation, lifecycle trace, remediation rationale, verification plan, recorded test results, execution log, and handoff checkpoint for **Phase 4.1.1 (`P4.1.1`)**: validating and hardening the end-to-end delegated OAuth 2.0 (`access_token`) workflow following Phase 4.1 strict GCP scope authorization.

## Git Context

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-04-scope-isolation`
- **Base (`origin/main`):** `7f91cae13060b8fb8ceed9ac689981527c00df9f`
- **Phase 4.1 Implementation Commit:** `5f325a5be161fc204efdc36d4c59a09559494e62` (`fix(security): enforce explicit CAI scope isolation`)
- **Phase 4.1 Documentation Commit (Pre-4.1.1 HEAD):** `36dec313551c158a1e01abb4e11e8a384d5575a7` (`docs: finalize phase 4.1 execution evidence`)
- **Open Pull Request:** `#3` (`https://github.com/g-jsaccomani/pqc_inventory_agent/pull/3`)
- **Cloud Resources Provisioned or Modified:** **None.** Zero GCP API calls, IAM modifications, PostgreSQL connections, Vertex AI inference calls, or Docker/Cloud Build operations were performed.

## Summary of Findings

The investigation identified **both a compatibility gap and five concrete security defects** in the delegated-token lifecycle:

1. **Compatibility / Onboarding Gap (Missing Server-Bound Auto-Resolution):** Non-admin delegated-token logins initialized `organization_id=""` and `project_id=""` even when server-side scope policies (`PQC_ALLOWED_PROJECTS`, `PQC_ALLOWED_ORGANIZATIONS`, `PQC_TENANT_SCOPE_POLICY`) explicitly granted an unambiguous scope; downstream `/api/sessions`, `/api/chat`, and `_resolve_scope()` then produced malformed `organizations/` or fell back to `DEFAULT_ORGANIZATION_ID` and failed `UNAUTHORIZED_RESOURCE_SCOPE`.
2. **Critical Vulnerability — Partial Server Policy Bypass:** `_ServerScopePolicy` evaluated `PQC_ALLOWED_PROJECTS`, `PQC_ALLOWED_ORGANIZATIONS`, and `PQC_ALLOWED_FOLDERS` independently; setting only `PQC_ALLOWED_PROJECTS` left `has_org_restriction=False`, allowing a tenant to self-bind and scan any arbitrary GCP organization via `POST /api/connection` (and symmetrically for org-only or folder-only policies).
3. **High Vulnerability — Production Self-Binding & Post-Binding Scope Mutation:** When no server scope policy env var was set, a non-admin delegated tenant could self-bind arbitrary orgs/projects in production (`K_SERVICE`) and overwrite or pivot an already-established `organization_id`/`project_id` to another tenant's scope via `POST /api/connection`.
4. **High Vulnerability — Unvalidated Client Scope Overrides & Consent Identity Binding:** `POST /api/chat`, `POST /api/sessions`, `GET /api/auth/oauth/authorize`, `GET /api/auth/oauth/callback`, `POST /api/auth/tool-consent`, and `PqcOAuth3LOPlugin` accepted client-supplied scopes without validating against `authorize_gcp_scope()`, and `/api/auth/tool-consent` (`verify_with_google=True`) did not enforce `verified_email == uid`.
5. **Medium Vulnerability — Expired/Malformed Token Handling & Unscoped Compute Lookup:** `store_delegated_token(..., expires_in<=0)` silently fell back to a 3600s default TTL instead of failing closed; `get_active_gcp_credentials()` did not validate token syntax or set `expiry` on `google.oauth2.credentials.Credentials`; `_fetch_compute_pq_key_exchange()` called bare `_get_client_kwargs()` without a `scope_uri`.

## Files in This Evidence Bundle

| File | Purpose |
|---|---|
| `README.md` | Navigation index, Git provenance, and executive summary. |
| `SECURITY_ANALYSIS.md` | Root cause analysis, threat model, security invariants, production onboarding contract, and production-safety assessment. |
| `FLOW_TRACE.md` | Complete 9-step before/after lifecycle trace from authentication through SDK client creation and API/UI error propagation. |
| `TEST_PLAN.md` | 1-to-1 verification matrix for all 14 mandatory Section 4 scenarios, PKCE 3LO revocation, and regression suites. |
| `TEST_RESULTS.md` | Exact commands, observed pass/skip/fail counts, compilation, diff hygiene, and secret/identifier scan outcomes. |
| `EXECUTION_LOG.md` | Chronological log of precondition checks, investigation, edits, test runs, failure remediation, and verification. |
| `EXECUTION_CHECKPOINT.md` | Final status, verified guarantees, remaining limitations, and explicit review handoff state. |

## Status

`READY FOR REVIEW` (mocked offline validation complete; live GCP end-to-end delegated-token validation remains a required pre-production gate — see `SECURITY_ANALYSIS.md`).
