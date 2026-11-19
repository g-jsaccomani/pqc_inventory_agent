# Phase 3 — Final Live Integration Validation Report

## 1. Execution Context & Commit Lineage
- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Tested Branch `HEAD` SHA:** `ff9287681d5c38560e03142ee4e12e0c0e2b0e5f`
- **Latest Source / Test / Container Commit SHA:** `9027888484b37581c3433be3bc5917454930d4d1` *(unchanged since Cloud Build Docker validation; subsequent commits updated documentation/evidence only)*
- **Main Branch Baseline SHA (Untouched):** `62f7247b52effc3f3cf2086a86f06071eea1b6fc`
- **Validation Window (UTC):** `2026-11-19T16:51:00Z` – `2026-11-19T17:09:11Z`
- **Authorization & Change-Control Verified:**
  - Explicit human authorization was obtained before live execution for:
    1. Reusing an existing non-production disposable Cloud SQL PostgreSQL 16 validation instance and `pqc_test_validation` database over a temporary loopback mTLS 1.3 tunnel (ephemeral client certificate + in-memory password rotation, zero firewall rule changes).
    2. Executing a single live Vertex AI Gemini turn against a non-production validation project where `aiplatform.googleapis.com` was already enabled (zero API enablement or IAM modifications).
    3. Acquiring temporary isolated user Application Default Credentials (ADC) in a separate non-default CLI config directory (zero service account keys created or downloaded), revoked immediately after validation.
  - Zero application source files, test files, `Dockerfile`, or `cloudbuild.docker-validation.yaml` files were modified.
  - Zero production systems were touched; zero deployments or container image publications occurred; `main` was not modified or merged.

---

## 2. Status Classification Key
- **PASS** — Live integration test actually executed against a real external service and passed.
- **FAIL** — Live integration test executed and failed.
- **BLOCKED** — Mandatory safety, credential, API, or infrastructure prerequisites were unavailable or unauthorized.
- **SKIPPED** — Intentionally not executed in a given run, with explicit justification.

---

## 3. Live Integration Validation Gate Matrix

| Gate Area | Target Test (Exact Pytest Node ID) | Status | Execution Summary |
| :--- | :--- | :---: | :--- |
| **A. PostgreSQL 16 / Cloud SQL Persistence** | `tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration` | **`PASS`** | Executed live against real managed **PostgreSQL 16.15** (`pqc_test_validation`) over an ephemeral loopback mTLS 1.3 tunnel with `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`. **`1 passed, 0 failed, 0 skipped`** in **`150.30s`** (exit code `0`). Verified Alembic upgrade to `20261117_0002`, destructive safety guard, 11-step multi-instance (`Instance A` <-> `Instance B` + restart) workflow, 8-thread concurrent OAuth callback race, explicit rollback, and delegated credential lifecycle. Tunnel closed, temporary certificates deleted, and test password invalidated via discard rotation. See [postgresql_validation.md](./postgresql_validation.md). |
| **B. Vertex AI / Gemini Live Integration** | `tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry` | **`PASS`** | Executed a single live Vertex AI Gemini turn (`PQC_LIVE_LLM_TEST=1`) using the repository's canonical default model **`gemini-3.1-pro-preview-customtools`** (`location=global`, `thinking_level=MEDIUM`, explicit timeouts `60s`/`90s`). **`1 passed, 0 failed, 0 skipped`** in **`6.52s`** (exit code `0`). Observed real Vertex AI telemetry: `llm_call_count=1`, `prompt_tokens=3197`, `output_tokens=53`, `thinking_tokens=74`, `error_count=0`. Temporary isolated user ADC revoked and deleted immediately after validation. See [vertex_ai_validation.md](./vertex_ai_validation.md). |
| **C. Docker Non-Root & Read-Only Container Validation** *(Prior Validated Gate — Not Rerun)* | `tests/test_phase3_container_hardening.py::test_p3_04_live_docker_non_root_uid_and_read_only_migration_help`<br>`tests/test_pre_merge_hotfix.py::test_pre_merge_01_live_docker_build_and_container_smoke` | **`PASS`** *(Prior Cloud Build Evidence Valid)* | Validated in GCP Cloud Build `605c784d-6949-4891-bfd0-0ba519a6c68d` (`pqc-inventory-agent-validation`, `us-central1`, **`2 passed, 0 failed, 0 skipped`** in `16.31s`). Remains valid for tested source revision `9027888484b37581c3433be3bc5917454930d4d1` (zero code, test, `Dockerfile`, or Cloud Build changes since). Intentionally not rerun to avoid unnecessary cloud build cost. See [GCP_CLOUD_BUILD_DOCKER_VALIDATION.md](../cloud_build_validation/GCP_CLOUD_BUILD_DOCKER_VALIDATION.md). |

---

## 4. Automated Regression & Repository Integrity Verification

Executed after both live gates completed (without live/destructive environment flags) against `HEAD` `ff9287681d5c38560e03142ee4e12e0c0e2b0e5f`:

| Verification Command | Timestamp (UTC) | Passed | Failed | Skipped | Duration | Exit Code |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `.venv/bin/pytest -v -rs` *(complete safe repository suite)* | `2026-11-19T17:07:44Z` – `2026-11-19T17:08:47Z` | **`343`** | **`0`** | **`4`** | `61.82s` | `0` |
| `.venv/bin/pytest -v -rs tests/test_phase3_egress_security.py tests/test_phase3_adc_authorization.py tests/test_phase3_upload_security.py tests/test_phase3_scorecard_correctness.py tests/test_phase3_vertex_resilience.py tests/test_phase3_container_hardening.py` | `2026-11-19T17:09:00Z` – `2026-11-19T17:09:11Z` | **`261`** | **`0`** | **`1`** | `10.07s` | `0` |
| `.venv/bin/python -m compileall -q pqc_agent tools tests main.py` | `2026-11-19T17:08:46Z` | N/A | **`0`** | `0` | `<1.0s` | `0` |
| `git diff --check` | `2026-11-19T17:08:47Z` | N/A | **`0`** | `0` | `<0.5s` | `0` |

### Accounting for All 4 Opt-In / Environment-Gated Skips in the Default Safe Local Run
Every test skipped by default in the offline local regression suite has been independently executed and **`PASS`**-verified in its dedicated live environment:

1. `tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration` *(line 1507)* — Skipped in default safe offline run; **`PASS`** in Gate A live PostgreSQL 16.15 execution (`150.30s`, exit `0`).
2. `tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry` *(line 974)* — Skipped in default safe offline run; **`PASS`** in Gate B live Vertex AI Gemini execution (`6.52s`, exit `0`).
3. `tests/test_phase3_container_hardening.py::test_p3_04_live_docker_non_root_uid_and_read_only_migration_help` *(line 269)* — Skipped locally (no local Docker daemon); **`PASS`** in Gate C Cloud Build validation `605c784d-6949-4891-bfd0-0ba519a6c68d`.
4. `tests/test_pre_merge_hotfix.py::test_pre_merge_01_live_docker_build_and_container_smoke` *(line 210)* — Skipped locally (no local Docker daemon); **`PASS`** in Gate C Cloud Build validation `605c784d-6949-4891-bfd0-0ba519a6c68d`.

---

## 5. Temporary Resource Provisioning & Cleanup Verification
- **Cloud Infrastructure Provisioned:** None. No Cloud SQL instance, database, firewall rule, VPC peering, IAM binding, service account, service account key, API enablement, or Cloud Run deployment was created or modified.
- **Temporary Ephemeral Artifacts Created & Verified Cleaned Up (`2026-11-19T17:08:06Z`):**
  - Loopback mTLS 1.3 proxy socket and ephemeral client certificate/key temp directory (`pqc-pg-mtls-*`): closed and deleted; verified `0` leftover temp directories.
  - Ephemeral PostgreSQL test password rotated in memory for Gate A: invalidated immediately via final random discard rotation.
  - Cloud SQL disposable validation instance state post-run: verified `POSTGRES_16`, `RUNNABLE`, `authorizedNetworks=0` (pre-existing resource untouched).
  - Temporary isolated user ADC credential file used for Gate B: revoked via `gcloud auth application-default revoke --quiet` and deleted; confirmed absent on disk.
  - Temporary scratch helper scripts outside the repository: deleted and confirmed absent.

---

## 6. Final Gate Determination

**`READY FOR FINAL SIGN-OFF`**

**Rationale:**
- **Gate A (PostgreSQL 16 Live Persistence):** **`PASS`** (`1 passed, 0 failed` against real PostgreSQL 16.15).
- **Gate B (Vertex AI Live Gemini Inference & Telemetry):** **`PASS`** (`1 passed, 0 failed` against live `gemini-3.1-pro-preview-customtools` on Vertex AI `global`).
- **Gate C (Cloud Build Docker Non-Root & Read-Only Runtime):** **`PASS`** (`2 passed, 0 failed`, Build ID `605c784d-6949-4891-bfd0-0ba519a6c68d`, still valid for tested source revision `9027888484b37581c3433be3bc5917454930d4d1`).
- **Complete Safe Regression Suite & Phase 3 Suites:** **`343 passed, 0 failed, 4 skipped`** (full safe suite) and **`261 passed, 0 failed, 1 skipped`** (Phase 3 suites), with all 4 environment-gated skips independently verified as **`PASS`** across Gates A, B, and C.
- **Safety, Sanitization & Cleanup:** All temporary artifacts cleaned up and verified; zero unresolved critical safety issues; `main` (`62f7247b52effc3f3cf2086a86f06071eea1b6fc`) remains untouched pending human sign-off and merge review.
