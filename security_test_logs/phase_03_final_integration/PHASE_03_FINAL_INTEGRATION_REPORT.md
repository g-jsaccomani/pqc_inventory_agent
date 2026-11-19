# Phase 3 — Final Live Integration Validation Report

## 1. Execution Context & Preconditions
- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Validated Codebase Commit SHA (`HEAD` prior to this evidence commit):** `57a904f40196d013007052146ac6303278ec583f`
- **Main Branch Baseline SHA (Untouched):** `62f7247b52effc3f3cf2086a86f06071eea1b6fc`
- **Validation Timestamp (UTC):** `2026-11-19T15:11:16Z` – `2026-11-19T15:18:33Z`
- **Preconditions Verified:**
  - Remote branch fetched (`git fetch origin`) and confirmed synchronized with `origin/security-hardening/phase-03-runtime-resilience` (`57a904f40196d013007052146ac6303278ec583f`).
  - Zero application code, `Dockerfile`, or `cloudbuild.docker-validation.yaml` modifications introduced.
  - Zero GCP resources created, modified, or deleted; zero APIs enabled; zero IAM roles granted; zero deployments or image publications performed.

---

## 2. Status Classification Key
- **PASS** — Test executed in an eligible environment and passed.
- **FAIL** — Test executed and failed.
- **BLOCKED** — Mandatory safety, credential, API, or infrastructure prerequisites were unavailable or unsafe without explicit authorization; test was not executed.
- **NOT RUN** — Intentionally not executed in this run.

---

## 3. Live Integration Validation Gate Matrix

| Gate Area | Target Test (Prompt Reference / Exact Pytest Node ID) | Status | Execution Summary |
| :--- | :--- | :---: | :--- |
| **A. PostgreSQL 16 / Cloud SQL Persistence** | Prompt ref: `tests/test_phase2_persistence_and_credentials.py::test_live_postgres_16_alembic_and_multi_instance_persistence`<br>Exact node ID: `tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration` | **`BLOCKED`** | No local PostgreSQL 16 daemon or container runtime is available; `sqladmin.googleapis.com` is disabled in `pqc-inventory-agent-validation`; no authorized credentials or `PQC_TEST_POSTGRES_URL` + `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true` are available for an existing disposable `pqc_test_*` database without modifying Cloud SQL infrastructure. See [postgresql_validation.md](./postgresql_validation.md). |
| **B. Vertex AI / Gemini Live Integration** | Prompt ref: `tests/test_pqc_inventory.py::test_live_vertex_ai_gemini_turn`<br>Exact node ID: `tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry` | **`BLOCKED`** | `aiplatform.googleapis.com` is disabled and ADC lacks IAM permissions in `pqc-inventory-agent-validation`; ADC also has zero Vertex AI permissions on the existing non-production lab project; the default `.env` project hosts deployed runtime services (`tier: platform`) and is not an authorized dedicated validation environment (and ADC lacks a quota project / `serviceusage.services.use`). See [vertex_ai_validation.md](./vertex_ai_validation.md). |
| **C. Docker Non-Root & Read-Only Container Validation** *(Prior Validated Gate — Not Rerun)* | `tests/test_phase3_container_hardening.py::test_p3_04_live_docker_non_root_uid_and_read_only_migration_help`<br>`tests/test_pre_merge_hotfix.py::test_pre_merge_01_live_docker_build_and_container_smoke` | **`PASS`** *(Prior Cloud Build Evidence)* | Already validated in Cloud Build `605c784d-6949-4891-bfd0-0ba519a6c68d` (`pqc-inventory-agent-validation`, `us-central1`, `2 passed, 0 failed, 0 skipped` in `16.31s`). Not rerun in this pass because no code or `Dockerfile` changes occurred. See [GCP_CLOUD_BUILD_DOCKER_VALIDATION.md](../cloud_build_validation/GCP_CLOUD_BUILD_DOCKER_VALIDATION.md). |

---

## 4. Automated Regression & Integrity Verification

All safe automated suites were executed cleanly against commit `57a904f40196d013007052146ac6303278ec583f`:

| Verification Command | Timestamp (UTC) | Passed | Failed | Skipped | Duration | Exit Code |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `.venv/bin/pytest -v -rs tests/test_phase3_egress_security.py tests/test_phase3_adc_authorization.py tests/test_phase3_upload_security.py tests/test_phase3_scorecard_correctness.py tests/test_phase3_vertex_resilience.py tests/test_phase3_container_hardening.py` | `2026-11-19T15:16:56Z` | **`261`** | **`0`** | **`1`** | `10.67s` | `0` |
| `.venv/bin/pytest -v -rs` *(complete safe repository suite)* | `2026-11-19T15:17:28Z` | **`343`** | **`0`** | **`4`** | `62.68s` | `0` |
| `.venv/bin/python -m compileall -q pqc_agent tools tests main.py` | `2026-11-19T15:18:33Z` | N/A | **`0`** | `0` | `<1.0s` | `0` |
| `git diff --check` | `2026-11-19T15:18:33Z` | N/A | **`0`** | `0` | `<0.5s` | `0` |

### Skipped Tests Reported Separately (4 Total in Local Complete Suite)
1. `tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration` *(line 1507)* — **`BLOCKED`**: requires authorized disposable PostgreSQL 16 `PQC_TEST_POSTGRES_URL` (`^pqc_test_[a-zA-Z0-9_]+$`) and explicit `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`.
2. `tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry` *(line 974)* — **`BLOCKED`**: requires `PQC_LIVE_LLM_TEST=1` with working ADC targeting a dedicated authorized project with `aiplatform.googleapis.com` enabled.
3. `tests/test_phase3_container_hardening.py::test_p3_04_live_docker_non_root_uid_and_read_only_migration_help` *(line 269)* — skipped locally (no local Docker daemon), **previously `PASS`** in Cloud Build `605c784d-6949-4891-bfd0-0ba519a6c68d`.
4. `tests/test_pre_merge_hotfix.py::test_pre_merge_01_live_docker_build_and_container_smoke` *(line 210)* — skipped locally (no local Docker daemon), **previously `PASS`** in Cloud Build `605c784d-6949-4891-bfd0-0ba519a6c68d`.

---

## 5. Remaining Blockers Before Final Sign-Off
1. **PostgreSQL 16 Live Persistence Gate (`BLOCKED`):** Provide an authorized, dedicated disposable PostgreSQL 16 database matching `^pqc_test_[a-zA-Z0-9_]+$` (either a local/CI PostgreSQL 16 service or authorized secure credentials + Cloud SQL Auth Proxy access for an isolated test instance) and run with `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`.
2. **Vertex AI Gemini Live Integration Gate (`BLOCKED`):** Authorize and configure Application Default Credentials (or workload identity) with `aiplatform.endpoints.predict` and `serviceusage.services.use` against a dedicated test project with `aiplatform.googleapis.com` enabled (e.g., enabling `aiplatform.googleapis.com` on `pqc-inventory-agent-validation` or provisioning ADC for an authorized non-production lab project), verify availability of the configured Gemini Pro model, and execute with `PQC_LIVE_LLM_TEST=1`.

---

## 6. Final Gate Recommendation

**`PHASE 3 NOT READY`**

**Rationale:**
- All Phase 3 code changes, offline unit/integration suites (`261 passed, 0 failed` across Phase 3 suites; `343 passed, 0 failed` across the full local suite), and live Cloud Build Docker container hardening checks (`2 passed, 0 failed`) are green with zero regressions.
- However, both live external integration gates required by this validation pass (**PostgreSQL 16 persistence** and **Vertex AI Gemini live turn**) remain **`BLOCKED`** due to unavailable authorized credentials/APIs in the dedicated test environment. Per strict acceptance rules, `BLOCKED` gates cannot be treated as `PASS`.
- Do not merge `security-hardening/phase-03-runtime-resilience` into `main` until human reviewers either authorize the missing test environment prerequisites to execute both live gates or formally waive them in writing.
