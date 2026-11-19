# PostgreSQL 16 / Cloud SQL Persistence Validation Record

## 1. Target Test Identification
- **Prompt Reference:** `tests/test_phase2_persistence_and_credentials.py::test_live_postgres_16_alembic_and_multi_instance_persistence`
- **Actual Repository Pytest Node ID:** `tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration` *(lines 1507–1606)*
- **Tested Source Code Commit SHA:** `57a904f40196d013007052146ac6303278ec583f`
- **Validation Timestamp (UTC):** `2026-11-19T15:11:33Z` – `2026-11-19T15:16:15Z`
- **Environment Classification:** Dedicated disposable test database required (production and shared databases strictly forbidden).
- **Status:** **`BLOCKED`**
- **Execution Command Attempted:** *None — live execution intentionally withheld because mandatory connectivity and authorized credential prerequisites were not met.*
- **Duration:** `N/A` *(not executed)*

---

## 2. Pre-Execution Code & Safety Inspection

### Dependencies & Fixtures
- Autouse fixture `_clean_phase2_env` (`tests/test_phase2_persistence_and_credentials.py`, lines 108–136) clears production indicators (`K_SERVICE`, `PQC_PRODUCTION_MODE`, `PQC_ENV`, `DATABASE_URL`, `PQC_CLOUD_SQL_CONNECTION_NAME`, `PQC_DB_HOST`, `PQC_KMS_KEY_NAME`, OAuth client vars) and resets fallback stores.
- Shared `tests/conftest.py` registers `FakeModelForTests` for offline chat plumbing so the multi-instance workflow does not call live Vertex AI.
- Credential envelope encryption checks inside this test use `_DeterministicCloudKmsStub` (no live Cloud KMS calls).

### Required Environment Variables & External Resources
- `PQC_TEST_POSTGRES_URL` — PostgreSQL connection URL pointing to a dedicated disposable PostgreSQL 16 database.
- `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true` — explicit opt-in required before any DB connection or SQL execution.
- Reachable PostgreSQL 16 server (local daemon, container, or authorized secure proxy connection).

### Destructive Operations & Built-In Safeguards
- **Operations Performed by the Test:**
  1. Executes Alembic schema migrations (`scripts/run_db_migrations.py --db-url <pg_url> --require-postgres`) up to revision `20261117_0002`.
  2. Executes destructive `TRUNCATE TABLE events, sessions, user_states, app_states, pqc_session_metadata, pqc_delegated_credentials, pqc_user_connections, pqc_calibration_events, pqc_oauth_client_configs, pqc_auth_sessions, pqc_consumed_nonces, pqc_oauth_transactions, pqc_tenant_users CASCADE`.
  3. Runs the 11-step multi-instance workflow (`Instance A` <-> `Instance B` + restart), 8-thread concurrent OAuth callback race, explicit rollback check, and credential storage/expiration/revocation tests.
- **Fail-Closed Safety Guard (`validate_destructive_postgres_test_target`, lines 1181–1252):**
  - Rejects missing or non-`true` `PQC_ALLOW_DESTRUCTIVE_TEST_DB`.
  - Rejects active production indicators (`K_SERVICE`, `PQC_PRODUCTION_MODE`, `PQC_ENV in {"prod", "production"}`).
  - Rejects any non-`postgresql` backend.
  - Rejects database names containing `prod`, `production`, `live`, `customer`, or `primary`.
  - Requires database name strictly matching `^pqc_test_[a-zA-Z0-9_]+$`.
  - Offline safety-guard regression test `test_phase2_destructive_postgres_safety_guard_and_zero_sql_on_rejection` **PASSED** during the local suite run, confirming zero SQL execution on rejected targets.
- **Cleanup Behavior:**
  - Closes SQLAlchemy connections (`store_a.close()`, `store_b.close()`), revokes synthetic delegated tokens during assertions, and leaves the migrated schema and final synthetic rows inside the disposable `pqc_test_*` database (tables/database are not dropped after test completion).

---

## 3. Prerequisite Audit & Blocking Reasons

All environment checks were strictly read-only, and zero unauthorized infrastructure changes were performed:

1. **No Local PostgreSQL 16 Runtime or Proxy Client Available:**
   - Neither local PostgreSQL 16 binaries, a local PostgreSQL service on TCP `5432`, a local container runtime, nor a Cloud SQL proxy/connector client is available in the execution environment.
2. **No Authorized Dedicated Test Database Credentials Configured:**
   - Neither `PQC_TEST_POSTGRES_URL` (targeting a dedicated disposable `^pqc_test_[a-zA-Z0-9_]+$` PostgreSQL 16 database) nor `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true` is configured, and no authorized test database credentials are provided through an existing secure authentication mechanism for this run.
3. **No Unauthorized Infrastructure Mutations Performed:**
   - Creating, modifying, or reconfiguring database instances, database accounts, authentication modes, network rules, or APIs is prohibited without explicit authorization. Consequently, the test was not attempted and remains **`BLOCKED`**.

---

## 4. Cleanup Confirmation & Sanitized Evidence
- **Cleanup Required:** None (no database connection was opened, no migration ran, no `TRUNCATE` ran, and zero database or cloud resources were created or modified).
- **Offline Regression Confirmation:** During the full safe repository suite (`.venv/bin/pytest -v -rs`, `343 passed, 0 failed, 4 skipped` in `62.68s`), all offline PostgreSQL URL normalization, Unix socket translation, Alembic offline PostgreSQL DDL generation (`upgrade head --sql`), Alembic online migration cycle, fail-closed production checks, multi-instance 11-step workflow, and destructive-test safety guard tests in `tests/test_phase2_persistence_and_credentials.py` **PASSED**, while line 1507 reported:
  ```text
  SKIPPED [1] tests/test_phase2_persistence_and_credentials.py:1507: Live PostgreSQL 16 integration test requires disposable PQC_TEST_POSTGRES_URL and explicit PQC_ALLOW_DESTRUCTIVE_TEST_DB=true opt-in.
  ```
- **Phase 3 Gate Status:** Live PostgreSQL 16 re-execution on `security-hardening/phase-03-runtime-resilience` remains **`BLOCKED`** until authorized dedicated test database credentials and connectivity are provided.
