# Phase 1–2 Targeted Pre-Merge Hotfix — Test Plan

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-01-02`
- **Baseline `HEAD` SHA:** `5eff14fc0e676b335b695ea0813a6620af29c296`
- **Target Branch (`main`) SHA:** `1d112f65c5b917f7fdcd00bb00b8e8a772d18cc0`

---

## 1. Scope of Targeted Findings

| Finding ID | Original Defect | Corrective Change Planned | Planned Verification |
| :--- | :--- | :--- | :--- |
| **`PRE-MERGE-01`** | `Dockerfile` copied `scripts/migrate_sqlite_to_postgres.py` (`line 49`) while omitting `scripts/run_db_migrations.py`, breaking the `agentic-pqc-db-migrate` Cloud Run Job (`python scripts/run_db_migrations.py --require-postgres`). | Add `COPY scripts/run_db_migrations.py ./scripts/run_db_migrations.py` and `RUN chmod 0755 /app/scripts/run_db_migrations.py /app/scripts/migrate_sqlite_to_postgres.py` in `Dockerfile` without copying `.env`, DB files, or credentials. | 1. Static `Dockerfile` audit + staged `/app` filesystem replay + `0755` permission check + non-destructive `python scripts/run_db_migrations.py --help` execution inside staged `/app`.<br>2. Live `docker build` & `docker run` container smoke test when `docker` is installed (must be recorded `BLOCKED` if `docker` is unavailable). |
| **`PRE-MERGE-02` (Part A — CLI Initialization)** | `main.py` eagerly executed `from pqc_agent.workspace_server import app, artifact_service, session_service` at module import time (`app = create_workspace_app()`), triggering `DistributedAuthStore` PostgreSQL connection checks during `python main.py deploy`. | Replace eager import in `main.py` with thread-safe `get_workspace_app()` and PEP 562 `__getattr__` (`app`, `session_service`, `artifact_service`) so CLI commands (`deploy`, `tools`, `cbom`, `--help`) never initialize `DistributedAuthStore`, while `uvicorn main:app` and `main.py serve` initialize once and preserve fail-closed production PostgreSQL enforcement. | 1. Clean subprocess execution of `python main.py deploy` both without and with `PQC_CLOUD_SQL_CONNECTION_NAME` + `PQC_PRODUCTION_MODE=true` verifying zero `workspace_server` / `auth_store` imports.<br>2. Clean subprocess verification of `main.app` single initialization + `/api/health` = `200`.<br>3. Clean subprocess verification that `main.app` and `main.py serve` fail closed on missing, SQLite, or unreachable production PostgreSQL configs. |
| **`PRE-MERGE-02` (Part B — Migration Before Service Deployment)** | `scripts/setup_and_deploy_vertex.sh` deployed the Cloud Run service directly without building a shared image or running the serialized `agentic-pqc-db-migrate` Alembic Cloud Run Job first. | Update `scripts/setup_and_deploy_vertex.sh` to: (1) build & publish immutable image `${IMAGE_URI}`, (2) deploy `${SERVICE_NAME}-db-migrate` with `--image="${IMAGE_URI}"`, `--tasks=1`, `--max-retries=0`, `python scripts/run_db_migrations.py --require-postgres`, (3) execute the migration job with `--wait`, (4) abort immediately on build/migration failure, and (5) deploy the Cloud Run service with `--image="${IMAGE_URI}"` only after migration succeeds. | 1. `bash -n` syntax validation on `scripts/setup_and_deploy_vertex.sh` and `scripts/deploy_cloud_run.sh`.<br>2. Static topological ordering check.<br>3. End-to-end mocked `gcloud` + mocked `vertexai` execution proving build -> job deploy -> job execute `--wait` -> service deploy ordering, secret non-exposure, and immediate non-zero abort (with zero `run deploy` calls) on simulated migration or build failure. |
| **`PRE-MERGE-03` (Documentation Drift)** | `app.yaml:27` and `docs/security-remediation/MIGRATION_AND_ROLLBACK.md:11` referenced `20261117_0001` instead of head `20261117_0002`, and `MIGRATION_AND_ROLLBACK.md:153` referenced `DRY_RUN_VALIDATED` instead of `DRY_RUN_OK`. | Update `app.yaml:27` and `MIGRATION_AND_ROLLBACK.md:11, 153` to reference `20261117_0002` and `DRY_RUN_OK` while preserving historical lineage notes. | Automated assertion against `auth_store.EXPECTED_ALEMBIC_REVISION` (`20261117_0002`) and `MigrationReport` `DRY_RUN_OK` status. |

---

## 2. Planned Validation Matrix

1. **Bytecode & Syntax Compilation:** `.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests`
2. **Deployment Script Shell Syntax:** `bash -n scripts/setup_and_deploy_vertex.sh` and `bash -n scripts/deploy_cloud_run.sh`
3. **Migration CLI Non-Destructive Smoke Check:** `.venv/bin/python scripts/run_db_migrations.py --help`
4. **Alembic Offline PostgreSQL Transactional DDL:** `DATABASE_URL="postgresql+psycopg://pqc_app:placeholder@127.0.0.1:5432/pqc_workspace" .venv/bin/alembic upgrade head --sql`
5. **Live Container Image Build & Runtime Smoke Check:** `docker build -t pqc-inventory-agent:pre-merge-hotfix-smoke .` + `docker run --rm --entrypoint python ... scripts/run_db_migrations.py --help` (if `docker` CLI/daemon is available; otherwise mark `BLOCKED`)
6. **Dedicated Hotfix Regression Suite:** `.venv/bin/pytest -v -rs tests/test_pre_merge_hotfix.py`
7. **Full Repository Regression Suite:** `.venv/bin/pytest -v -rs` (without weakening destructive PostgreSQL guards or touching unknown databases)
8. **Git Formatting & Whitespace Hygiene:** `git diff --check`
