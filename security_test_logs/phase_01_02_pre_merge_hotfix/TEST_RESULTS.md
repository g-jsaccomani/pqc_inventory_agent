# Phase 1–2 Targeted Pre-Merge Hotfix — Test Results

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-01-02`
- **Original Baseline `HEAD` SHA:** `5eff14fc0e676b335b695ea0813a6620af29c296`
- **Target Branch (`main`) SHA:** `1d112f65c5b917f7fdcd00bb00b8e8a772d18cc0`

---

## 1. Resolution Status of Pre-Merge Gate Findings

| Finding ID | Summary | Resolution Status | Evidence |
| :--- | :--- | :---: | :--- |
| **`PRE-MERGE-01`** | `Dockerfile` omitted `scripts/run_db_migrations.py` required by the Cloud Run Alembic migration job. | **`RESOLVED`** *(Code + Staged `/app` CLI `PASS`; Live Docker Build `BLOCKED` on workstation without Docker)* | `Dockerfile:49,52` (`COPY scripts/run_db_migrations.py ./scripts/run_db_migrations.py` + `RUN chmod 0755 ...`); verified by `tests/test_pre_merge_hotfix.py::test_pre_merge_01_dockerfile_copies_migration_script_without_secrets_and_runs_staged_cli` and `tests/test_pqc_inventory.py::test_deployment_configuration_disables_simulation_and_keeps_persistence`. |
| **`PRE-MERGE-02`** | (A) `main.py` eagerly imported `workspace_server` (`create_workspace_app()`), initializing `DistributedAuthStore` before `main.py deploy` could execute; (B) `scripts/setup_and_deploy_vertex.sh` deployed the Cloud Run service without running the Alembic migration job first. | **`RESOLVED` (`PASS`)** | `main.py:29-56,237` (lazy `get_workspace_app()` + PEP 562 `__getattr__`); `scripts/setup_and_deploy_vertex.sh:111-188` (image build -> serialized `--tasks=1 --max-retries=0` migration job deploy -> `jobs execute --wait` -> service deploy); verified by `test_pre_merge_02_cli_deploy_and_tools_do_not_initialize_auth_store`, `test_pre_merge_02_server_startup_initializes_once_and_fails_closed_in_production`, and `test_pre_merge_02_deployment_scripts_syntax_sequencing_and_mocked_execution`. |
| **`PRE-MERGE-03`** | Documentation drift in `app.yaml` and `docs/security-remediation/MIGRATION_AND_ROLLBACK.md` (`20261117_0001` vs `20261117_0002`, and `DRY_RUN_VALIDATED` vs `DRY_RUN_OK`). | **`RESOLVED` (`PASS`)** | `app.yaml:27` and `docs/security-remediation/MIGRATION_AND_ROLLBACK.md:11,153` updated to `20261117_0002` and `DRY_RUN_OK`; verified by `test_pre_merge_03_documentation_drift_resolved`. |

---

## 2. Detailed Command & Test Execution Log

### Test 1 — Python Bytecode & Syntax Compilation
- **Exact Command:** `.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests`
- **Purpose:** Verify all application, tool, migration, script, and test Python modules compile cleanly with zero syntax errors.
- **Expected Result:** Exit code `0`, empty stderr/stdout.
- **Actual Result:** Compiled cleanly with zero errors.
- **Exit Code:** `0`
- **Status:** **`PASS`**
- **Runtime:** `0.08s`

### Test 2 — Deployment Shell Script Syntax Validation
- **Exact Command:** `bash -n scripts/setup_and_deploy_vertex.sh && bash -n scripts/deploy_cloud_run.sh`
- **Purpose:** Validate POSIX/Bash syntax of both Cloud Run / Vertex AI deployment and migration scripts without invoking cloud commands.
- **Expected Result:** Exit code `0`, zero syntax errors.
- **Actual Result:** Both scripts parsed cleanly with zero errors.
- **Exit Code:** `0`
- **Status:** **`PASS`**
- **Runtime:** `0.016s`

### Test 3 — Migration Script Non-Destructive CLI Invocation
- **Exact Command:** `.venv/bin/python scripts/run_db_migrations.py --help`
- **Purpose:** Verify `scripts/run_db_migrations.py` imports all required runtime dependencies (`sqlalchemy`, `alembic`, `pqc_agent.auth_guard`, `pqc_agent.auth_store`, `pqc_agent.migration_tool`) and exposes `--require-postgres` and `--verify-only` without opening any database connection.
- **Expected Result:** Exit code `0`; usage output contains `--require-postgres` and `--verify-only`.
- **Actual Result:** Usage help printed cleanly containing `--require-postgres` and `--verify-only`; zero database connections opened.
- **Exit Code:** `0`
- **Status:** **`PASS`**
- **Runtime:** `1.86s`

### Test 4 — Offline PostgreSQL Transactional DDL Generation (Alembic)
- **Exact Command:** `DATABASE_URL="postgresql+psycopg://pqc_app:placeholder@127.0.0.1:5432/pqc_workspace" .venv/bin/alembic upgrade head --sql`
- **Purpose:** Confirm Alembic generates valid transactional PostgreSQL DDL through head revision `20261117_0002` (`20261117_0001` -> `20261117_0002`) without opening a live socket.
- **Expected Result:** Exit code `0`; emits complete PostgreSQL DDL for all 10 `pqc_*` tables and all 5 ADK `v1` tables.
- **Actual Result:** Generated `254` lines of transactional PostgreSQL DDL cleanly.
- **Exit Code:** `0`
- **Status:** **`PASS`**
- **Runtime:** `1.48s`

### Test 5 — Live Docker Image Build, Filesystem Inspection & Container Smoke Test (`PRE-MERGE-01`)
- **Exact Command:** `command -v docker` (prerequisite for `docker build -t pqc-inventory-agent:pre-merge-hotfix-smoke . && docker run --rm --entrypoint python pqc-inventory-agent:pre-merge-hotfix-smoke scripts/run_db_migrations.py --help`)
- **Purpose:** Build the container image with Docker, inspect `/app/scripts/run_db_migrations.py`, and run `--help` inside the container.
- **Expected Result:** Execute container build and runtime smoke test if Docker is installed; otherwise record as `BLOCKED` without claiming static checks substitute for live Docker execution.
- **Actual Result:** `docker` and `podman` CLIs/daemons are not installed on this corporate macOS workstation (`NOT_INSTALLED`); pytest test `tests/test_pre_merge_hotfix.py::test_pre_merge_01_live_docker_build_and_container_smoke` recorded as `SKIPPED` (`BLOCKED: Docker CLI/daemon is not installed in this workstation environment`).
- **Exit Code:** N/A (`BLOCKED` — tool absent)
- **Status:** **`BLOCKED`**
- **Runtime:** `< 0.01s`

### Test 6 — Dedicated Pre-Merge Hotfix Regression Suite (`PRE-MERGE-01`, `PRE-MERGE-02`, `PRE-MERGE-03`)
- **Exact Command:** `.venv/bin/pytest -v -rs tests/test_pre_merge_hotfix.py`
- **Purpose:** Execute hermetic tests for:
  1. `test_pre_merge_01_dockerfile_copies_migration_script_without_secrets_and_runs_staged_cli`: replays `Dockerfile` `COPY` + `chmod 0755` into an isolated `/app` directory, verifies `/app/scripts/run_db_migrations.py` exists with mode `0755`, verifies zero `.env`/`.db`/secret files, and runs `python scripts/run_db_migrations.py --help` inside staged `/app`.
  2. `test_pre_merge_01_live_docker_build_and_container_smoke`: gated on `shutil.which("docker")`.
  3. `test_pre_merge_02_cli_deploy_and_tools_do_not_initialize_auth_store`: executes `main.py deploy` (both without `PQC_CLOUD_SQL_CONNECTION_NAME` and with `PQC_CLOUD_SQL_CONNECTION_NAME` + `PQC_PRODUCTION_MODE=true`), `main.py --help`, and `main.run_tools_smoke_test()`, proving neither `pqc_agent.workspace_server` nor `pqc_agent.auth_store` is imported on `deploy`/`--help`.
  4. `test_pre_merge_02_server_startup_initializes_once_and_fails_closed_in_production`: verifies `main.app` initializes `DistributedAuthStore` exactly once, serves `GET /api/health` = `200`, and fails closed on missing, SQLite, or unreachable production PostgreSQL configs on both `main.app` and `main.py serve`.
  5. `test_pre_merge_02_deployment_scripts_syntax_sequencing_and_mocked_execution`: runs mocked `gcloud` + mocked `vertexai` through `bash scripts/setup_and_deploy_vertex.sh`, verifying `builds submit` -> `beta run jobs deploy` (`--tasks=1 --max-retries=0`, `scripts/run_db_migrations.py,--require-postgres`) -> `beta run jobs execute --wait` -> `beta run deploy` with identical `--image`, secret redaction, and non-zero abort (zero `beta run deploy` calls) when either migration execution (`exit 7`) or image build (`exit 9`) fails.
  6. `test_pre_merge_03_documentation_drift_resolved`: verifies `20261117_0002` and `DRY_RUN_OK` in `app.yaml` and `MIGRATION_AND_ROLLBACK.md`.
- **Expected Result:** `5 passed, 1 skipped` (Docker `BLOCKED`), `0 failed`, exit code `0`.
- **Actual Result:** `5 passed, 1 skipped in 24.87s`.
- **Exit Code:** `0`
- **Status:** **`PASS`** *(with 1 `SKIPPED` / `BLOCKED` live Docker test)*
- **Runtime:** `24.87s`

### Test 7 — Full Repository Regression Suite
- **Exact Command:** `.venv/bin/pytest -v -rs`
- **Purpose:** Confirm zero regressions across all Phase 1, Phase 2, authentication hardening, inventory, and pre-merge hotfix test suites (`84` collected tests).
- **Expected Result:** `81 passed, 0 failed, 3 skipped`, exit code `0`.
- **Actual Result:** `81 passed, 0 failed, 3 skipped in 49.51s`:
  - `SKIPPED [1]` `tests/test_phase2_persistence_and_credentials.py:1507`: Live PostgreSQL 16 integration test requires disposable `PQC_TEST_POSTGRES_URL` and explicit `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true` opt-in (`BLOCKED` in current shell without disposable PG env vars; destructive safety guard preserved untouched).
  - `SKIPPED [1]` `tests/test_pqc_inventory.py:952`: `Set PQC_LIVE_LLM_TEST=1 with Vertex AI access to run` (`SKIPPED` opt-in live Vertex AI test).
  - `SKIPPED [1]` `tests/test_pre_merge_hotfix.py:210`: `BLOCKED: Docker CLI/daemon is not installed in this workstation environment` (`BLOCKED`).
- **Exit Code:** `0`
- **Status:** **`PASS`**
- **Runtime:** `49.51s`

### Test 8 — Git Diff Whitespace & Conflict Marker Check
- **Exact Command:** `git diff --check`
- **Purpose:** Ensure zero trailing whitespace, broken indentation, or conflict markers in any modified file.
- **Expected Result:** Exit code `0`, empty output.
- **Actual Result:** Clean (empty output).
- **Exit Code:** `0`
- **Status:** **`PASS`**
- **Runtime:** `< 0.05s`

---

## 3. Follow-Up Pre-Merge Correction — Duplicate Workspace App Initialization (`2026-11-18`)

- **Prior Pre-Merge Hotfix Commit SHA (`HEAD` Baseline for Follow-Up):** `d24004489b0c83a4813361d8832f338d9e673e74`
- **Original Pre-Hotfix Baseline SHA:** `5eff14fc0e676b335b695ea0813a6620af29c296`
- **Follow-Up Commit Message (Direct Child of `d24004489b0c83a4813361d8832f338d9e673e74` on `security-hardening/phase-01-02`):** `fix(security): prevent duplicate workspace app initialization` *(exact self-SHA recorded via `git rev-parse HEAD` upon commit creation, as a single unamended Git commit cannot embed its own SHA-1 digest)*

### Root Cause & Fix Summary
- **Defect:** `main.get_workspace_app()` previously inspected `"pqc_agent.workspace_server" in sys.modules` (`preloaded`) and invoked `_ws.create_workspace_app()` when `workspace_server` had already been imported. Because `pqc_agent/workspace_server.py` constructs its module-level `app = create_workspace_app()` on import, importing `pqc_agent.workspace_server` before `main` and then calling `main.get_workspace_app()` created a duplicate FastAPI instance and a second `DistributedAuthStore` / SQLAlchemy engine pool.
- **Fix (`main.py`):** Removed `preloaded` branching and unused `sys` import so `get_workspace_app()` lazily imports `pqc_agent.workspace_server` under `_WORKSPACE_APP_LOCK` and unconditionally reuses `_ws.app`, preserving thread-safe singleton initialization, PEP 562 lazy module attributes (`app`, `session_service`, `artifact_service`), CLI decoupling (`deploy`, `tools`, `cbom`, `--help`), and fail-closed production PostgreSQL checks.

### Import-Order Regression Test Added
- **Test:** `tests/test_pre_merge_hotfix.py::test_pre_merge_02_workspace_server_first_import_order_reuses_singleton_app`
- **Verified Steps (Fresh Subprocess):**
  1. Imports `pqc_agent.workspace_server` first (verifies `1` `DistributedAuthStore.__init__` call).
  2. Imports `main` (verifies `main._WORKSPACE_APP is None` and `0` extra `create_workspace_app()` / `DistributedAuthStore.__init__` calls).
  3. Calls `main.get_workspace_app()`.
  4. Asserts returned object `is workspace_server.app` (and `main.app is workspace_server.app`, `main.session_service is workspace_server.session_service`, `main.artifact_service is workspace_server.artifact_service`).
  5. Asserts `0` additional `create_workspace_app()` calls and `1` total `DistributedAuthStore.__init__` call across the entire process.
- **Result:** **`PASS`**

### Exact Regression Commands, Counts & Exit Codes

| Command | Result Summary | Exit Code | Status | Runtime |
| :--- | :--- | :---: | :---: | :---: |
| `.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests` | Zero bytecode/syntax errors (also verified with `main.py` included) | `0` | **`PASS`** | `< 0.1s` |
| `bash -n scripts/setup_and_deploy_vertex.sh` | Valid Bash syntax | `0` | **`PASS`** | `< 0.02s` |
| `bash -n scripts/deploy_cloud_run.sh` | Valid Bash syntax | `0` | **`PASS`** | `< 0.02s` |
| `.venv/bin/pytest -v -rs tests/test_pre_merge_hotfix.py` | **`6 passed, 0 failed, 1 skipped`** (`7` collected) | `0` | **`PASS`** | `26.84s` |
| `.venv/bin/pytest -v -rs` | **`82 passed, 0 failed, 3 skipped`** (`85` collected) | `0` | **`PASS`** | `54.95s` |
| `git diff --check` | Zero whitespace/conflict formatting defects | `0` | **`PASS`** | `< 0.05s` |

### Docker Validation Status
- **Status:** **`BLOCKED`**
- **Details:**
  - Local container CLIs/daemons (`docker`, `podman`, `nerdctl`, `colima`, `lima`, `finch`) are not installed on this workstation (`NOT_INSTALLED`).
  - Checked repository and GitHub Actions configuration for an existing CI workflow capable of building `Dockerfile`: `.github/` does not exist (`NO_DOT_GITHUB_DIR`), and `gh workflow list -R g-jsaccomani/pqc_inventory_agent --all` lists only GitHub's built-in `Dependency Graph` (no CI runner workflow exists).
  - Per instructions, no unrelated CI infrastructure was introduced and live Docker image build is NOT claimed. Staged `/app` filesystem replay and `python scripts/run_db_migrations.py --help` execution (`0755` permissions, zero `.env`/`.db`/secret artifacts) passed (`test_pre_merge_01_dockerfile_copies_migration_script_without_secrets_and_runs_staged_cli`).

### PostgreSQL Validation Status
- **Destructive Safety Guard (`validate_destructive_postgres_test_target`):** **`PASS`** (`tests/test_phase2_persistence_and_credentials.py::test_phase2_destructive_postgres_test_guard_rejects_unsafe_targets` passed; enforces `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`, `^pqc_test_[a-zA-Z0-9_]+$` DB name, zero production terms/env flags, PostgreSQL dialect only, and zero SQL statements on rejected targets).
- **Live PostgreSQL 16 Multi-Instance Integration (`test_phase2_live_postgresql_multi_instance_integration`):** **`SKIPPED` / `BLOCKED` in current local run** — no local `postgres` daemon or `cloud-sql-proxy` is running (`NO_LOCAL_PG_OR_PROXY_RUNNING`; the disposable Cloud SQL PostgreSQL 16.15 instance validated in commit `686e4ff` was torn down after testing, and `PQC_TEST_POSTGRES_URL` / `PQC_ALLOW_DESTRUCTIVE_TEST_DB` are unset). Safety checks preserved untouched.

### Remaining Blockers
1. **Live Docker Image Build & Container Runtime Smoke (`PRE-MERGE-01`):** `BLOCKED` locally due to absent Docker daemon and absence of an existing GitHub Actions build workflow; must be executed via Docker in CI or via `gcloud builds submit` during `scripts/setup_and_deploy_vertex.sh`.
2. **Live Cloud Run + Cloud SQL Staging/Production Rollout Verification:** `NOT EXECUTED` (requires operator execution of `scripts/setup_and_deploy_vertex.sh` in target GCP project with Cloud SQL PostgreSQL, Secret Manager, and Cloud KMS provisioned).
