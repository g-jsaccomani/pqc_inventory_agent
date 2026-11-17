# Phase 0 — Baseline and Remediation Plan Report

- **Phase:** `0` (`Baseline and remediation plan`)
- **Status:** `COMPLETED`
- **Repository:** `https://github.com/g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/2026-11`
- **Baseline Commit SHA (prior to Phase 0 commit):** `2449589`
- **Assessment Timestamp:** `2026-11-17T15:27:00-03:00`

---

## 1. Working Tree & Pre-Check Verification

Executed prior to branch creation and baseline testing:

```text
$ git status --short --branch
## main...origin/main
?? PQC_INVENTORY_AGENT_REMEDIATION.md
```

- Tracked working tree was completely clean (`0` modified or staged tracked files).
- Created working branch `security-hardening/2026-11` from `2449589` without modifying any application code.

---

## 2. Baseline Test Suite & Static Analysis Execution

### Commands Executed

1. **Unit, Integration & Security Regression Suite (`pytest`):**
   ```bash
   .venv/bin/pytest -q
   ```
   - **Result:** `53 passed, 1 skipped, 220 warnings in 20.43s` (Exit code `0`).
   - **Skipped Test:** `tests/test_pqc_inventory.py::test_live_vertex_ai_agent_turn_opt_in` (opt-in live Vertex AI test gated by `RUN_LIVE_VERTEX_TEST=1`; classified as **BLOCKED / opt-in external infrastructure** in offline baseline runs).
   - **Pre-existing Failures:** `0`.

2. **Python Bytecode / Syntax Compilation Check:**
   ```bash
   .venv/bin/python -m compileall -q pqc_agent tools tests
   ```
   - **Result:** `PASS` (Exit code `0`, `0` syntax or compilation errors).

3. **Git Whitespace / Conflict Marker Check:**
   ```bash
   git diff --check
   ```
   - **Result:** `PASS` (Exit code `0`, `0` issues).

4. **Tracked File Secret Scan (Regex check for `GOCSPX-*`, `AIza*`, Private Keys):**
   - **Result:** `PASS` (`0` hits across all `git ls-files` tracked files).

5. **External Linters / Scanners Availability in `.venv`:**
   - Checked `.venv/bin`: `pytest` and `coverage` are installed; `ruff`, `flake8`, `mypy`, `bandit`, `pip-audit`, and `trivy` are **not installed** in `.venv` (recorded as unavailable in the current environment; not claimed as executed).

---

## 3. Baseline Findings Summary (10 Hypotheses + Additional Controls)

Full technical details, file/line citations, prerequisites, and remediation designs are documented in [`docs/security-remediation/MASTER_REMEDIATION_PLAN.md`](../../docs/security-remediation/MASTER_REMEDIATION_PLAN.md).

| ID | Finding | Status | Severity | Key Evidence (Redacted) |
|---|---|---|---|---|
| **H1** | Wildcard `postMessage('*')` in `/api/auth/bridge` & credential delivery in OAuth popup `postMessage` without `event.source` validation | **Confirmed in code** | **Critical (P0)** | `pqc_agent/workspace_server.py:2385` (`window.opener.postMessage(msg, '*')` sends `access_token` / `credential`); `workspace_server.py:1505,1538,2004` sends signed `token` in popup payload; `pqc_agent/portal_ui.py:3170-3216` checks `event.origin` against a static list of 5 origins without checking `event.source`. |
| **H2** | Session bearer token (`pqc_session_token` & `pqc_saved_accounts`) stored in `localStorage`; no server-side token revocation on logout; missing CSRF token on cookie-authenticated POST/DELETE endpoints | **Confirmed in code** | **High (P0)** | `pqc_agent/portal_ui.py:2063,2129,2438,2609,2736`; `pqc_agent/workspace_server.py:2181-2188`. |
| **H3** | SQLite (`sqlite:///data/pqc_sessions.db`) configured on Cloud Storage FUSE mount (`/data`) in deployment scripts and `Dockerfile` | **Confirmed in code** | **High (P1)** | `Dockerfile:30`; `scripts/deploy_cloud_run.sh:146-168`; `scripts/setup_and_deploy_vertex.sh:89-99`. |
| **H4** | Session metadata, tenant profiles, and uploaded artifact text caches rely on local JSON files and process-local caches (`_SESSION_METADATA_CACHE`, `_TENANT_USERS_CACHE`, `_UPLOADED_ARTIFACT_CACHE`) | **Confirmed in code** | **High (P1)** | `pqc_agent/workspace_server.py:287-290,363-403,495-531`; `tools/calibration_engine.py:44,194`. |
| **H5** | Delegated GCP OAuth tokens live only in process-local memory (`_USER_CONNECTIONS` & `InMemoryCredentialService`) | **Confirmed in code** | **High (P1)** | `tools/gcloud_bridge.py:181-194,351-361`; `pqc_agent/workspace_server.py:1761`. |
| **H6** | Transient Vertex AI probe failures overwrite `self._results[model]["available"] = False` and remove configured models from `verified_entries()`, `default_entry()`, and `resolve()` | **Confirmed in code** | **High (P1)** | `pqc_agent/model_registry.py:128-144,199-239`. |
| **H7** | Missing retry/backoff, timeout bounds, circuit breaker, and allowlisted fallback for Vertex AI probes and agent turns | **Confirmed in code** | **High (P1)** | `pqc_agent/model_registry.py:69-95`; `pqc_agent/workspace_server.py:3158-3206`. |
| **H8** | `weighted_kms_pqc_maturity` renormalizes weights when asymmetric keys = 0 (allowing 100% maturity with 0 asymmetric keys) and lacks an explicit GCP service/resource coverage matrix | **Confirmed in code** | **Medium-High (P1)** | `tools/gcp_inventory.py:1085-1135`. |
| **H9** | KMS-to-workload correlation confidence (`STRONG`/`MEDIUM`/`WEAK`) is delegated to LLM prompt instructions without programmatic validation or a typed evidence schema | **Confirmed in code** | **High (P1)** | `tools/gcp_inventory.py:863-968`; `pqc_agent/agent.py:84-87,139-144`. |
| **H10** | Uploaded document content and GCP resource labels are injected into model context without untrusted-data boundaries; `execute_gcloud_command` does not bind `--project`/`--organization` to the tenant's scope | **Confirmed in code** | **High (P1)** | `pqc_agent/workspace_server.py:3121-3156`; `tools/gcloud_bridge.py:532-629`. |
| **A1** | Missing `PQC_AUTH_SECRET` falls back to file/ephemeral secret instead of failing closed in production | **Configuration-dependent** | **High (P0)** | `pqc_agent/auth_guard.py:193-244`. |
| **A2** | Missing `PQC_IAP_AUDIENCE` logs a warning instead of rejecting IAP JWTs in production | **Configuration-dependent** | **High (P0)** | `pqc_agent/auth_guard.py:352-394`. |
| **A3** | Workstation auto-login (`/api/auth/auto` -> `_try_workstation_auto_gcloud_token`) mints a session from host `gcloud` credentials when `K_SERVICE` is unset | **Confirmed in code** | **Medium-High (P0)** | `pqc_agent/workspace_server.py:817-856,2190-2236`. |
| **A4** | `Dockerfile` runs as `root` and installs unpinned `requirements.txt` without a frozen lockfile | **Confirmed in code** | **Medium (P2)** | `Dockerfile:1-47`; `requirements.txt:1-29`. |
| **A5** | File uploads (`POST /api/chat`) lack byte-size limits, magic-byte validation, filename sanitization, and decompression-bomb guards | **Confirmed in code** | **Medium-High (P2)** | `pqc_agent/workspace_server.py:3121-3137`; `tools/calibration_engine.py:268-333`. |

---

## 4. Files Created in Phase 0

- `docs/security-remediation/MASTER_REMEDIATION_PLAN.md`
- `security_test_logs/phase_00_baseline/REPORT.md`

*(No application or test files were modified in Phase 0.)*

---

## 5. Residual Risks & Next Steps

- **Residual Risk:** All baseline vulnerabilities (`H1`–`H10`, `A1`–`A5`) remain present until Phases 1–5 are executed.
- **Exact Next Step:** Update `EXECUTE_PHASE: 1` in `PQC_INVENTORY_AGENT_REMEDIATION.md` (or instruct execution of Phase 1) to remediate OAuth, popup `postMessage`, PKCE, `localStorage` token exposure, CSRF, session fixation/logout revocation, fail-closed `PQC_AUTH_SECRET`, and mandatory `PQC_IAP_AUDIENCE` validation.
