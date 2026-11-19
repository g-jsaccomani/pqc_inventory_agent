# PostgreSQL 16 / Cloud SQL Persistence Validation Record

## 1. Target Test Identification
- **Prompt Reference:** `tests/test_phase2_persistence_and_credentials.py::test_live_postgres_16_alembic_and_multi_instance_persistence`
- **Actual Repository Pytest Node ID:** `tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration` *(lines 1507–1606)*
- **Tested Branch `HEAD` SHA:** `ff9287681d5c38560e03142ee4e12e0c0e2b0e5f` *(source revision `9027888484b37581c3433be3bc5917454930d4d1`)*
- **Execution Window (UTC):** `2026-11-19T17:00:23Z` – `2026-11-19T17:03:07Z` *(pytest run: `17:00:33Z` – `17:03:04Z`)*
- **Environment Category:** Live managed Cloud SQL for PostgreSQL 16 (authorized non-production disposable test database `pqc_test_validation`)
- **Verified Server Engine Version:** `PostgreSQL 16.15 on x86_64-pc-linux-gnu, compiled by Debian clang version 12.0.1, 64-bit`
- **Status:** **`PASS`**
- **Exit Code:** `0`
- **Duration:** `150.30s` (`0:02:30` pytest; `151.42s` end-to-end process wall time)

---

## 2. Authorization & Safety Controls Applied
1. **Explicit Human Approval:** Executed only after explicit user authorization to reuse the existing disposable non-production PostgreSQL 16 validation database (`pqc_test_validation`) via an ephemeral loopback mTLS 1.3 tunnel and in-memory password rotation.
2. **Zero Infrastructure or Firewall Mutations:**
   - Cloud SQL instance `<DISPOSABLE_CLOUD_SQL_INSTANCE>` in `<VALIDATION_GCP_PROJECT>` kept `authorizedNetworks=0` before, during, and after the test.
   - Connection used an ephemeral 1-hour Cloud SQL client certificate (`sqladmin.instances.createEphemeral`) over mTLS 1.3 to port `3307`, exposed locally on `127.0.0.1:<ephemeral_port>` only.
   - No new Cloud SQL instances, databases, users, or firewall rules were created, and no pre-existing cloud resources were deleted.
3. **Fail-Closed Destructive Test Guard Verified (`validate_destructive_postgres_test_target`):**
   - Verified `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`.
   - Verified no production indicators (`K_SERVICE`, `PQC_PRODUCTION_MODE`, `PQC_ENV`) were active.
   - Verified PostgreSQL dialect and disposable database name `pqc_test_validation` matching `^pqc_test_[a-zA-Z0-9_]+$`.
4. **Credential Hygiene:**
   - Ephemeral random test password was generated in memory, never written to disk, and redacted from captured logs.
   - Immediately in the runner `finally` block after test completion, `<TEST_DB_USER>`'s password was rotated to a brand-new discarded random value, the loopback tunnel was closed, and temporary certificate/key files were deleted.

---

## 3. Sanitized Execution Command & Observed Output

### Sanitized Command
```bash
PQC_ALLOW_DESTRUCTIVE_TEST_DB=true \
PQC_TEST_POSTGRES_URL="postgresql+psycopg://<TEST_DB_USER>:<EPHEMERAL_TEST_PASSWORD>@127.0.0.1:<LOOPBACK_MTLS_PORT>/pqc_test_validation" \
  .venv/bin/pytest -v -rs \
  tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration
```

### Sanitized Verification Output
```text
UTC_START=2026-11-19T17:00:23Z
INSTANCE_VERIFIED: databaseVersion=POSTGRES_16 state=RUNNABLE authorizedNetworks=0
EPHEMERAL_CERT_ISSUED: OK
PASSWORD_ROTATED_IN_MEMORY=OK
LOOPBACK_MTLS_TUNNEL_READY=127.0.0.1:<LOOPBACK_MTLS_PORT>
PG_SERVER_VERSION= PostgreSQL 16.15 on x86_64-pc-linux-gnu, compiled by Debian clang version 12.0.1, 64-bit
PG_CURRENT_DATABASE= pqc_test_validation
TEST_START_UTC=2026-11-19T17:00:33Z
collected 1 item

tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration PASSED [100%]

================== 1 passed, 39 warnings in 150.30s (0:02:30) ==================
TEST_EXIT_CODE=0
TEST_DURATION_SECONDS=151.42
TEST_END_UTC=2026-11-19T17:03:04Z
CLEANUP_LOOPBACK_MTLS_TUNNEL=CLOSED_AND_TEMP_CERTS_DELETED
CLEANUP_PASSWORD_DISCARD_ROTATION=OK
UTC_END=2026-11-19T17:03:07Z
```

---

## 4. Assertions Verified Against Live PostgreSQL 16.15
1. **Alembic Migration Verification:** `scripts/run_db_migrations.py --db-url <pg_url> --require-postgres` upgraded and verified Alembic revision `20261117_0002` against live PostgreSQL 16.15.
2. **Disposable Database Isolation & Truncation:** Confirmed destructive `TRUNCATE ... CASCADE` executed exclusively against verified disposable database `pqc_test_validation`.
3. **11-Step Multi-Instance Persistence & Restart Workflow:**
   - Independent FastAPI/ADK application instances (`Instance A` and `Instance B`) shared auth sessions, OAuth 3LO PKCE transactions (`A -> B` callback handoff), ADK sessions/events, session metadata, user connection preferences, and session revocation consistently via PostgreSQL 16.
   - Full application restart preserved state cleanly across instances.
4. **Concurrency & Transaction Atomicity:**
   - 8-thread concurrent OAuth callback race confirmed single-use atomic transaction consumption under live PostgreSQL row locking.
   - Explicit rollback test verified atomicity without leaking partial rows.
5. **Delegated Credential Lifecycle:**
   - Verified envelope-encrypted delegated credential persistence, retrieval across instances, expiration handling, and revocation.

---

## 5. Runner Troubleshooting Notes (Non-Application Deviations)
Two initial runs of the temporary scratch mTLS tunnel wrapper failed prior to the clean `PASS` run due to wrapper-only issues (zero application or test code defects):
1. `16:57:19Z` – `16:58:04Z` (`exit 1`): The scratch wrapper appended `?sslmode=disable` to `PQC_TEST_POSTGRES_URL`, which `psycopg` accepted but `asyncpg` rejected with `TypeError: connect() got an unexpected keyword argument 'sslmode'`. Fixed in the scratch wrapper by using the clean documented URL without query parameters (`postgresql+psycopg://...@127.0.0.1:<port>/pqc_test_validation`).
2. `16:58:43Z` – `16:59:45Z` (`exit 1`): The scratch tunnel left a 15-second connect timeout on the wrapped mTLS socket (`socket.create_connection(..., timeout=15)`), causing idle pooled connections to drop after 15 seconds. Fixed in the scratch wrapper by calling `settimeout(None)` immediately after the mTLS handshake, after which the full test passed cleanly in `150.30s`.

---

## 6. Post-Run Cleanup Verification
- `2026-11-19T17:03:07Z`: Ephemeral loopback mTLS tunnel closed, temporary cert/key files removed, and `<TEST_DB_USER>` password invalidated via final discard rotation.
- `2026-11-19T17:08:06Z`: Confirmed `0` leftover `pqc-pg-mtls-*` temp directories, scratch runner script deleted, and `<DISPOSABLE_CLOUD_SQL_INSTANCE>` verified untouched (`POSTGRES_16`, `RUNNABLE`, `authorizedNetworks=0`).
