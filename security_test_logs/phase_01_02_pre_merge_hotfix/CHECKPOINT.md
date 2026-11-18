# Phase 1–2 Targeted Pre-Merge Hotfix — Execution Checkpoint

- **Timestamp (Local):** `2026-11-18T11:36:30-03:00`
- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Working Branch:** `security-hardening/phase-01-02`
- **Baseline `HEAD` SHA:** `5eff14fc0e676b335b695ea0813a6620af29c296`
- **Target Branch (`main`) SHA:** `1d112f65c5b917f7fdcd00bb00b8e8a772d18cc0`

## Completed Steps

- [x] **1. Preconditions Verified:** Branch `security-hardening/phase-01-02`, `HEAD` `5eff14fc0e676b335b695ea0813a6620af29c296`, clean working tree, `main` unchanged at `1d112f65c5b917f7fdcd00bb00b8e8a772d18cc0` (`0` behind, `10` ahead), existing pre-merge report & checkpoint inspected.
- [x] **2. `PRE-MERGE-01` Fixed (`Dockerfile`):** Added `COPY scripts/run_db_migrations.py ./scripts/run_db_migrations.py` and `RUN chmod 0755 /app/scripts/run_db_migrations.py /app/scripts/migrate_sqlite_to_postgres.py`; verified staged `/app` permissions (`0755`), zero `.env`/secret/DB files, and `python scripts/run_db_migrations.py --help` (`exit 0`); live `docker build` honestly recorded `BLOCKED` (`docker` CLI not installed on workstation).
- [x] **3. `PRE-MERGE-02` Part A Fixed (`main.py`):** Replaced eager `workspace_server` import with thread-safe lazy `get_workspace_app()` and PEP 562 `__getattr__`; verified `main.py deploy` and `main.py --help` never import `workspace_server` or `auth_store` (with or without `PQC_CLOUD_SQL_CONNECTION_NAME` / `PQC_PRODUCTION_MODE=true`), while `main.app` and `main.py serve` initialize once and fail closed when production PostgreSQL config is missing, SQLite, or unreachable.
- [x] **4. `PRE-MERGE-02` Part B Fixed (`scripts/setup_and_deploy_vertex.sh`):** Implemented strict sequence: build & publish `${IMAGE_URI}` -> deploy `${SERVICE_NAME}-db-migrate` (`--image="${IMAGE_URI}"`, `--tasks=1`, `--max-retries=0`, `python scripts/run_db_migrations.py --require-postgres`) -> execute migration job with `--wait` -> deploy Cloud Run service (`--image="${IMAGE_URI}"`) only after migration succeeds; verified via `bash -n` and mocked end-to-end execution (including simulated migration & build failure abort tests).
- [x] **5. `PRE-MERGE-03` Fixed (`app.yaml`, `docs/security-remediation/MIGRATION_AND_ROLLBACK.md`):** Updated drifted `20261117_0001` references to head revision `20261117_0002` and `DRY_RUN_VALIDATED` to `DRY_RUN_OK`.
- [x] **6. Full Regression Validation Passed:** `compileall` (`exit 0`), `bash -n` (`exit 0`), `alembic upgrade head --sql` (`exit 0`, `254` lines), `pytest -v -rs` (`81 passed, 0 failed, 3 skipped` in `49.51s`, `exit 0`), `git diff --check` (`exit 0`).
- [x] **7. Scope Control Verified:** Zero Phase 1–2 security controls weakened or rewritten; zero historical evidence reports modified; no merge or cloud deployment executed.

---

## Follow-Up Correction Checkpoint — Prevent Duplicate Workspace App Initialization

- **Timestamp (Local):** `2026-11-18T13:44:00-03:00`
- **Working Branch:** `security-hardening/phase-01-02`
- **Original Pre-Hotfix Baseline `HEAD` SHA:** `5eff14fc0e676b335b695ea0813a6620af29c296`
- **Follow-Up Correction Baseline `HEAD` SHA:** `d24004489b0c83a4813361d8832f338d9e673e74`
- **Final Commit Message (Direct Child of `d24004489b0c83a4813361d8832f338d9e673e74`):** `fix(security): prevent duplicate workspace app initialization` *(single unamended commit; exact self-SHA inspectable via `git rev-parse HEAD`)*

### Completed Follow-Up Steps
- [x] **1. Preconditions Verified:** Checked out `security-hardening/phase-01-02` at exact `HEAD` `d24004489b0c83a4813361d8832f338d9e673e74` with clean working tree; `main` untouched; zero commits amended or rewritten.
- [x] **2. Lazy Application Singleton Fixed (`main.py`):** Removed `preloaded` check and second `_ws.create_workspace_app()` call in `main.get_workspace_app()`; always reuses `_ws.app` under `_WORKSPACE_APP_LOCK` while preserving PEP 562 `__getattr__`, non-server CLI decoupling, and fail-closed production PostgreSQL validation.
- [x] **3. Import-Order Regression Test Added (`tests/test_pre_merge_hotfix.py`):** Added `test_pre_merge_02_workspace_server_first_import_order_reuses_singleton_app` verifying `import pqc_agent.workspace_server` -> `import main` -> `main.get_workspace_app()` returns `workspace_server.app` identically with `0` extra `create_workspace_app()` calls and `1` total `DistributedAuthStore` initialization (`PASSED`).
- [x] **4. Docker Build Validation Checked:** Confirmed local `docker`/`podman` CLIs are absent (`NOT_INSTALLED`) and no `.github/workflows` CI workflow exists in repository (`NO_DOT_GITHUB_DIR`; `gh workflow list` shows only `Dependency Graph`). Preserved live Docker build validation as **`BLOCKED`** without introducing unrelated CI infrastructure or claiming an image build.
- [x] **5. PostgreSQL Validation Checked:** Destructive test safety guard (`validate_destructive_postgres_test_target`) verified `PASS` without weakening any check; live PostgreSQL 16 integration test (`test_phase2_live_postgresql_multi_instance_integration`) cleanly `SKIPPED` / **`BLOCKED`** in current local shell (`NO_LOCAL_PG_OR_PROXY_RUNNING`, disposable `PQC_TEST_POSTGRES_URL` + `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true` unset; historical Cloud SQL PG16 validation preserved in `686e4ff`).
- [x] **6. Regression Suite Verified:** `compileall` (`exit 0`), `bash -n scripts/setup_and_deploy_vertex.sh` (`exit 0`), `bash -n scripts/deploy_cloud_run.sh` (`exit 0`), `.venv/bin/pytest -v -rs` (**`82 passed, 0 failed, 3 skipped` in `54.95s`, `exit 0`**), `git diff --check` (`exit 0`).
- [x] **7. Remaining Blockers Recorded:** (1) Live Docker image build & container smoke test (`BLOCKED` until run on a host with Docker or Cloud Build); (2) Live Cloud Run + Cloud SQL staging/production rollout execution (`NOT EXECUTED`).
