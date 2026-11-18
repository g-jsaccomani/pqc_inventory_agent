# Phase 1–2 Final Corrective Pass — Validation & Acceptance Report

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-01-02`
- **Original Pre-Remediation Baseline SHA (Phase 0):** `2449589` (`1d112f6` on `main`)
- **Pre-Corrective-Pass Baseline HEAD SHA:** `d43e17e594131a23a021b1afa68541851ff32307` (`d43e17e`)
- **Prior Remediation Commits Preserved:** `60ffaa2` (Phase 1 OAuth/Auth), `02b53e9` (Phase 2 Persistence/Credentials), `d43e17e` (Specs/Logs)
- **Final Corrective-Pass Commit:** `HEAD` on `security-hardening/phase-01-02` — `security: close phase 1-2 acceptance gaps` (parent `d43e17e594131a23a021b1afa68541851ff32307`; resolve exact 40-char commit hash via `git rev-parse HEAD`, as Git blobs cannot self-embed the hash of the commit object wrapping their tree)

---

## 1. Security Findings Addressed

### Finding 1 — `AUTH-02`: OAuth Transaction TTL Upper Bound (`PASS`)
- **Original Issue:** `DistributedAuthStore.create_oauth_transaction()` (`pqc_agent/auth_store.py`) and `_oauth_ttl_seconds()` (`pqc_agent/workspace_server.py`) clamped `ttl_seconds` with `min(..., 1800)`, allowing OAuth state/PKCE transactions to remain valid for up to 1,800 seconds instead of 600 seconds.
- **Corrective Fix:**
  - Defined `MIN_OAUTH_TRANSACTION_TTL_SECONDS = 1` and `MAX_OAUTH_TRANSACTION_TTL_SECONDS = 600` in `pqc_agent/auth_store.py`.
  - Updated `create_oauth_transaction()` to clamp `effective_ttl = max(1, min(int(ttl_seconds), 600))` (never `<= 0` and never `> 600`).
  - Added defense-in-depth `OAuthTransactionRecord.created_at > (now - 600.0)` inside the atomic single-query `UPDATE ... WHERE consumed_at IS NULL` in `consume_oauth_transaction()` so no transaction can ever be consumed more than 600 seconds after creation even if `expires_at` were tampered in storage.
  - Updated `_oauth_ttl_seconds()` and `_set_oauth_nonce_cookie()` `Max-Age` in `pqc_agent/workspace_server.py` to clamp strictly to `[1, 600]`.

### Finding 2 — `DB-01`: Exclusive Alembic Production Schema Authority (`PASS`)
- **Original Issue:** `DistributedAuthStore.__init__()` / `ensure_schema()` invoked `PqcPersistenceBase.metadata.create_all(self.engine)` by default, and Google ADK `DatabaseSessionService.prepare_tables()` invoked `BaseV1.metadata.create_all()`, allowing tables to be created outside Alembic's versioned migration history in production.
- **Corrective Fix:**
  - Added Alembic revision `migrations/versions/20261117_0002_add_adk_v1_session_schema.py` (`down_revision = "20261117_0001"`), bringing all 5 Google ADK `v1` session tables (`adk_internal_metadata`, `sessions`, `events`, `app_states`, `user_states`) under Alembic authority (`EXPECTED_ALEMBIC_REVISION = "20261117_0002"`).
  - Updated `DistributedAuthStore.__init__()` and `ensure_schema()` in `pqc_agent/auth_store.py` to forbid `metadata.create_all()` and `create_schema=True` whenever `is_production_environment()` is true, and to execute read-only `verify_alembic_schema_on_engine()` on startup — failing closed if `alembic_version` is missing, outdated (`20261117_0001`), multi-head, or missing any required `pqc_*` or ADK `v1` table.
  - Added `ManagedSchemaDatabaseSessionService(DatabaseSessionService)` in `pqc_agent/workspace_server.py` so ADK session persistence performs read-only schema validation in production and never invokes `BaseV1.metadata.create_all()`.
  - Created `scripts/run_db_migrations.py` (`--require-postgres`, `--verify-only`, PostgreSQL session advisory lock `pg_try_advisory_lock(7081632026)`, post-migration revision verification), removed `adk_schema_v1.Base.metadata.create_all()` from `pqc_agent/migration_tool.py`, and updated `scripts/deploy_cloud_run.sh` to execute a single-task Cloud Run Job (`--tasks=1 --max-retries=0`) before deploying Cloud Run service instances.

---

## 2. Changed Files

- **Modified:**
  - `PHASE1.md`
  - `pqc_agent/auth_store.py`
  - `pqc_agent/workspace_server.py`
  - `pqc_agent/migration_tool.py`
  - `scripts/deploy_cloud_run.sh`
  - `tests/test_auth_hardening.py`
  - `tests/test_phase1_distributed_auth.py`
  - `tests/test_phase2_persistence_and_credentials.py`
  - `security_test_logs/phase_01_02_remediation/REPORT.md`
  - `docs/security-remediation/PHASE_01_02_ACCEPTANCE.md`
  - `docs/security-remediation/MIGRATION_AND_ROLLBACK.md`
- **Created:**
  - `migrations/versions/20261117_0002_add_adk_v1_session_schema.py`
  - `scripts/run_db_migrations.py`
  - `security_test_logs/phase_01_02_final_validation/BASELINE.md`
  - `security_test_logs/phase_01_02_final_validation/FINAL_REPORT.md`
  - `security_test_logs/phase_01_02_final_validation/CHECKPOINT.md`

---

## 3. Test Execution Evidence

| Command | Exit Code | Passed | Failed | Skipped / Blocked | Runtime |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests` | `0` | N/A | `0` | `0` | `< 1.0s` |
| `.venv/bin/pytest -v -rs` | `0` | **`75`** | **`0`** | **`2`** (`BLOCKED`) | **`22.18s`** |
| `.venv/bin/pytest -v -rs tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration` | `0` | `0` | `0` | **`1`** (`BLOCKED`) | **`1.14s`** |
| `DATABASE_URL="postgresql+psycopg://pqc_app:placeholder@127.0.0.1:5432/pqc_workspace" .venv/bin/alembic upgrade head --sql` | `0` | `254` lines DDL | `0` | `0` | `< 1.0s` |
| `git diff --check` | `0` | N/A | `0` | `0` | `< 0.5s` |

---

## 4. PostgreSQL 16 Integration Status (`BLOCKED`)

- **Target Test:** `tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration`
- **Status:** **`BLOCKED`** (reported as `SKIPPED` by pytest when `PQC_TEST_POSTGRES_URL` is unset; **never** reported as `PASS`).
- **PostgreSQL Server Version:** Unavailable locally (no running PostgreSQL daemon on workstation).
- **Exact Infrastructure / Endpoint Requirement Blocking Local Execution:**
  - Corporate macOS workstation (`aarch64-apple-darwin`) has no local `postgres`, `initdb`, `pg_ctl`, `docker`, or `podman` installation, and Google Santa endpoint protection blocks unsigned embedded `initdb` binaries (`SIGKILL 9`, `No matching rule`).
  - To unblock in CI/staging, provision a disposable PostgreSQL 16 or Cloud SQL for PostgreSQL 16 test database and run:
    ```bash
    PQC_TEST_POSTGRES_URL="postgresql+psycopg://<test_user>:<test_pass>@<host>:5432/<disposable_db>" \
      .venv/bin/pytest -v -rs \
      tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration
    ```

---

## 5. Remaining Risks & Final Recommendation

- **Remaining Risks:**
  1. Live PostgreSQL 16 row-level locking, advisory-lock contention, and Cloud SQL Auth Proxy Unix socket behavior have not yet been executed against a live PostgreSQL 16 server daemon (`PQC_TEST_POSTGRES_URL`).
  2. Cloud Run + Cloud SQL + Secret Manager + Cloud KMS staging deployment verification has not yet been executed.
  3. Phase 3+ items (SSRF/egress controls, Vertex AI circuit-breaker resilience, scorecard denominator adjustments, non-root container user, upload size/magic-byte limits) remain out of scope for Phases 1–2.
- **Final Production Recommendation:** **`NO-GO` (`BLOCKED`)** — All Phase 1 and Phase 2 code-level security findings (`AUTH-01`..`AUTH-05`, `DB-01`..`DB-04`, `ID-01`, including strict 600s OAuth TTL and exclusive Alembic production schema authority) are implemented and verified (`75 passed, 0 failed`), but production cutover MUST remain **`NO-GO`** until `test_phase2_live_postgresql_multi_instance_integration` executes and passes against a live disposable PostgreSQL 16 / Cloud SQL staging database (`PQC_TEST_POSTGRES_URL`).
