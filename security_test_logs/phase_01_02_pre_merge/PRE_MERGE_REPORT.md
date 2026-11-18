# Phase 1–2 — Final Pre-Merge Security Gate Report

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Source Branch:** `security-hardening/phase-01-02`
- **Validated Source `HEAD` SHA:** `a8d2b0113bfe768503a18249f7568530884e33e4` (`a8d2b01` — `docs: restore phase 1-2 corrective specification`)
- **Target Branch (`main`) SHA:** `1d112f65c5b917f7fdcd00bb00b8e8a772d18cc0` (`1d112f6`)
- **Divergence (`main...HEAD`):** `0` commits behind `main`, `9` commits ahead of `main` (`44 files changed, 10910 insertions(+), 1560 deletions(-)`)
- **Validation Mode:** Read-only independent pre-merge gate (zero code, test, migration, dependency, `Dockerfile`, or existing documentation files modified)
- **Final Pre-Merge Gate Status:** **`FAIL`** — concrete defects in Cloud Run migration packaging (`Dockerfile` vs `scripts/deploy_cloud_run.sh`) and deployment entrypoint (`scripts/setup_and_deploy_vertex.sh` + `main.py`) prevent merge until remediated in a targeted follow-up fix.

---

## 1. Baseline & Git History Verification (`PASS`)

| Precondition | Expected | Observed | Result |
| :--- | :--- | :--- | :---: |
| Active branch (`git branch --show-current`) | `security-hardening/phase-01-02` | `security-hardening/phase-01-02` | **PASS** |
| Source `HEAD` (`git rev-parse HEAD`) | `a8d2b0113bfe768503a18249f7568530884e33e4` | `a8d2b0113bfe768503a18249f7568530884e33e4` | **PASS** |
| Working tree (`git status --short`) | Clean (`""`) | Clean (`""`) | **PASS** |
| Target `main` (`git rev-parse main`) | `1d112f65c5b917f7fdcd00bb00b8e8a772d18cc0` | `1d112f65c5b917f7fdcd00bb00b8e8a772d18cc0` | **PASS** |
| Commit divergence (`git rev-list --left-right --count main...HEAD`) | `0` behind, `9` ahead | `0	9` | **PASS** |
| Restored `PHASE1.md` & preserved `docs/security-remediation/HOTFIX_PHASE_01_02.md` | Present on `HEAD` | Present (`252b80b6...` & `a385212c...`) | **PASS** |

### Commit Lineage (`git log --oneline main..HEAD`)
1. `a8d2b01` — `docs: restore phase 1-2 corrective specification`
2. `209def8` — `security: guard destructive postgres integration tests`
3. `16181d5` — `docs(security): record hotfix spec and final commit SHA`
4. `35ef845` — `security: guard destructive postgres integration tests`
5. `686e4ff` — `test(security): validate live Cloud SQL PostgreSQL 16 multi-instance integration`
6. `bdcf692` — `security: close phase 1-2 acceptance gaps`
7. `d43e17e` — `docs(security): add remediation specifications and execution checkpoint logs`
8. `02b53e9` — `security: complete PostgreSQL persistence and credential architecture`
9. `60ffaa2` — `security: complete OAuth and distributed authentication remediation`

---

## 2. Independent Code & Migration Security Review

### 2.1 Control Matrix Across Scope Areas

| Review Area | Inspected Files | Verdict | Key Verification Notes |
| :--- | :--- | :---: | :--- |
| OAuth Authorization Code + PKCE `S256` | `pqc_agent/workspace_server.py`, `pqc_agent/auth_guard.py`, `pqc_agent/portal_ui.py` | **PASS** | Enforces `response_type=code` and RFC 7636 `S256` (`secrets.token_urlsafe(64)`); rejects implicit/token-bearing parameters (`access_token`, `id_token`, `token_type`, `response_type`) on `/api/auth/oauth/signin`, `/api/auth/oauth/authorize`, `/api/auth/oauth/callback`; GIS `initTokenClient` removed; `/api/auth/bridge` client ID gated behind `PQC_ENABLE_GIS_JAVASCRIPT_CLIENT=true` (default `false`). |
| OAuth transaction TTL `<= 600s` | `pqc_agent/auth_store.py`, `pqc_agent/workspace_server.py` | **PASS** | `MIN_OAUTH_TRANSACTION_TTL_SECONDS = 1`, `MAX_OAUTH_TRANSACTION_TTL_SECONDS = 600`; clamped in `create_oauth_transaction()`, `_oauth_ttl_seconds()`, and enforced on consumption via `created_at > (now - 600.0)` and `expires_at > now`. |
| `state`, `nonce`, browser binding & single-use consumption | `pqc_agent/auth_store.py`, `pqc_agent/workspace_server.py` | **PASS** | 256-bit CSPRNG `state_id`, `oidc_nonce`, and `browser_binding_token` (`HttpOnly` cookie `pqc_oauth_nonce` compared via SHA-256 + `hmac.compare_digest`); race-free single-query `UPDATE ... WHERE consumed_at IS NULL` (`rowcount == 1`); PK-backed `pqc_consumed_nonces` replay ledger for both `auth_code` and `oidc_nonce`; 3LO account match enforced against initiating session identity and verified ID token. |
| Session cookies, CSRF & server-side revocation | `pqc_agent/auth_guard.py`, `pqc_agent/auth_store.py`, `pqc_agent/workspace_server.py` | **PASS** | `pqc_session_token` and `pqc_account_jar` set `HttpOnly=True`, `SameSite=Lax`, `Secure=True` (on HTTPS/prod); zero session tokens in JSON responses or popup `postMessage`; `Origin`/`Referer`/`Sec-Fetch-Site` + HMAC-derived `X-PQC-CSRF-Token` enforced on state-changing routes; fail-closed DB allowlist (`if not rows: return True`) and fail-closed DB exception handling; cross-instance revocation on `/api/auth/logout`. |
| Distributed PostgreSQL persistence | `pqc_agent/auth_store.py`, `tools/gcloud_bridge.py`, `tools/calibration_engine.py`, `tools/report_exporter.py` | **PASS** | `postgresql+psycopg` (sync) + `postgresql+asyncpg` (ADK async), Cloud SQL Unix socket & TCP builders, pool/statement/connect timeouts, startup `SELECT 1` gate, strict production rejection of `sqlite://` and universal rejection of `/data` GCS FUSE paths; zero authoritative JSON/JSONL dual-writes. |
| Alembic-only production schema management | `migrations/env.py`, `migrations/versions/20261117_0001_*.py`, `migrations/versions/20261117_0002_*.py`, `scripts/run_db_migrations.py` | **PASS** | Revisions `20261117_0001` -> `20261117_0002` own all 10 `pqc_*` tables and all 5 Google ADK `v1` tables; `metadata.create_all()` prohibited in production across `DistributedAuthStore`, `ManagedSchemaDatabaseSessionService`, and `migration_tool.py`; serialized via `pg_try_advisory_lock(7081632026)`. |
| Production startup schema verification | `pqc_agent/auth_store.py`, `pqc_agent/workspace_server.py` | **PASS** | `verify_alembic_schema_on_engine()` and `ManagedSchemaDatabaseSessionService.prepare_tables()` verify `alembic_version == '20261117_0002'`, all 15 required tables, `pqc_schema_metadata == '20261117_0002'`, and `adk_internal_metadata == '1'` read-only, failing closed otherwise. |
| ADK database session schema | `migrations/versions/20261117_0002_add_adk_v1_session_schema.py` | **PASS** | Matches Google ADK `2.11.0` `v1` schema (`adk_internal_metadata`, `sessions`, `events` with composite FK `ON DELETE CASCADE` + `idx_events_app_user_session_ts_id`, `app_states`, `user_states`). |
| AES-256-GCM credential encryption & Cloud KMS | `pqc_agent/credential_service.py` | **PASS** | Per-write 256-bit CSPRNG DEK + 96-bit GCM nonce, DEK zeroized in `finally:` blocks, `CloudKmsDekWrapper` (`encrypt`/`decrypt` with `additional_authenticated_data`), production fail-closed when `PQC_KMS_KEY_NAME` is unset, refresh tokens never returned to callers/`ToolContext`, ciphertext/DEK wiped on revocation/expiry, zero `mkstemp` disk token files. |
| Tenant/user AAD isolation | `pqc_agent/credential_service.py`, `pqc_agent/auth_store.py` | **PASS** | Canonical AAD `pqc-cred-v1|app=<app>|tenant=<domain>|user=<uid>|key=<key>` bound to both KMS DEK wrap and AES-256-GCM payload ciphertext, verified alongside `aad_sha256` and explicit `caller_user_id` / `caller_tenant_domain` checks. |
| SQLite-to-PostgreSQL migration safeguards | `pqc_agent/migration_tool.py`, `scripts/migrate_sqlite_to_postgres.py` | **PASS** | Read-only SQLite URI (`?mode=ro`), pre/post SHA-256 source immutability check, `--allow-production-target` guard, legacy plaintext token stripping, cross-user session conflict & orphan event detection, FK/count validation, atomic rollback on `--dry-run` or validation failure, idempotent re-runs. |
| Destructive PostgreSQL integration-test safety guard | `tests/test_phase2_persistence_and_credentials.py` | **PASS** | `validate_destructive_postgres_test_target()` runs before any DB connection/migration/`TRUNCATE`; requires `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`, `postgresql` backend via `make_url()`, `^pqc_test_[a-zA-Z0-9_]+$` name, rejects `prod`/`production`/`live`/`customer`/`primary` & prod env vars, and fails closed (`1 failed`, never silently skipped) with zero SQL executed. |
| Cloud Run deployment & migration scripts | `Dockerfile`, `scripts/deploy_cloud_run.sh`, `scripts/setup_and_deploy_vertex.sh`, `main.py` | **`FAIL`** | Concrete packaging and CLI initialization defects identified — see Section 2.2 (`PRE-MERGE-01` and `PRE-MERGE-02`). |

### 2.2 Concrete Findings Preventing Merge

#### `PRE-MERGE-01` (HIGH — Blocker): `Dockerfile` Omits `scripts/run_db_migrations.py` Invoked by `scripts/deploy_cloud_run.sh`
- **Files & Lines:** `Dockerfile:45-50` vs `scripts/deploy_cloud_run.sh:183-202`.
- **Evidence:**
  - `scripts/deploy_cloud_run.sh` deploys the serialized pre-deployment Alembic Cloud Run Job from the repository root (`--source .`, which builds `./Dockerfile`) and executes:
    ```bash
    --command="python" \
    --args="scripts/run_db_migrations.py,--require-postgres"
    ```
  - However, `Dockerfile` (line 49) copies only `scripts/migrate_sqlite_to_postgres.py`:
    ```dockerfile
    COPY alembic.ini .
    COPY migrations ./migrations
    COPY pqc_agent ./pqc_agent
    COPY tools ./tools
    COPY scripts/migrate_sqlite_to_postgres.py ./scripts/migrate_sqlite_to_postgres.py
    COPY main.py .
    ```
    `scripts/run_db_migrations.py` (introduced in commit `bdcf692`) is never copied into the container image.
- **Impact:** Executing `scripts/deploy_cloud_run.sh` builds a Cloud Run Job image in which `/app/scripts/run_db_migrations.py` is absent (`python: can't open file '/app/scripts/run_db_migrations.py': [Errno 2] No such file or directory`), causing the mandatory pre-deployment Alembic schema migration job (`gcloud beta run jobs execute ... --wait`) to fail unconditionally.

#### `PRE-MERGE-02` (MEDIUM — Blocker): `scripts/setup_and_deploy_vertex.sh` Breaks on Eager `main.py` Import & Omits Pre-Deploy Alembic Migration Job
- **Files & Lines:** `scripts/setup_and_deploy_vertex.sh:20-31, 94-120` and `main.py:22-25` (`pqc_agent/workspace_server.py:3521`).
- **Evidence:**
  1. `scripts/setup_and_deploy_vertex.sh` (lines 27–31) requires `PQC_CLOUD_SQL_CONNECTION_NAME` to be exported in the shell and then runs `.venv/bin/python main.py deploy ...` (line 95). Because `main.py` (line 23) eagerly executes `from pqc_agent.workspace_server import app, artifact_service, session_service` at module import time (`app = create_workspace_app()` at `workspace_server.py:3521`, also prior to `load_dotenv()` on line 25), `DistributedAuthStore.__init__()` immediately attempts to connect to `/cloudsql/<proj>:<region>:<inst>/.s.PGSQL.5432` on the operator workstation and aborts with `RuntimeError: Database connectivity verification failed ... No such file or directory` before `deploy_to_agent_engine()` executes (reproduced during review).
  2. Step `[5/5]` (`scripts/setup_and_deploy_vertex.sh:104-120`) deploys `agentic-pqc` to Cloud Run with `PQC_PRODUCTION_MODE=true` without first executing the `agentic-pqc-db-migrate` Alembic Cloud Run Job (`scripts/run_db_migrations.py --require-postgres`), causing deployments against unmigrated/upgraded Cloud SQL instances via this script to fail closed at startup on `verify_production_schema()`.

#### `PRE-MERGE-03` (LOW — Non-Blocking Documentation Drift)
- **Files & Lines:** `app.yaml:27` and `docs/security-remediation/MIGRATION_AND_ROLLBACK.md:11, 153`.
- **Evidence:** `app.yaml:27` and the Section 1.1 summary table in `MIGRATION_AND_ROLLBACK.md:11` still list revision `20261117_0001`, whereas `EXPECTED_ALEMBIC_REVISION` and Sections 4.2 & 6 of `MIGRATION_AND_ROLLBACK.md` enforce `20261117_0002`. In addition, `MIGRATION_AND_ROLLBACK.md:153` references `Status: DRY_RUN_VALIDATED` whereas `MigrationReport.status` (`pqc_agent/migration_tool.py:1179`) emits `DRY_RUN_OK`.

---

## 3. Test Execution Evidence

### 3.1 Commands Executed on `HEAD` (`a8d2b0113bfe768503a18249f7568530884e33e4`)

| Command | Exit Code | Passed | Failed | Skipped | Blocked | Runtime |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests` | `0` | All modules | `0` | `0` | `0` | `< 1.0s` |
| `.venv/bin/pytest -v -rs` (offline suite; `PQC_TEST_POSTGRES_URL` & `PQC_ALLOW_DESTRUCTIVE_TEST_DB` unset) | `0` | **`76`** | **`0`** | **`2`** | **`1`** *(live PG not configured in current shell; see 3.2)* | **`26.18s`** |
| `DATABASE_URL="postgresql+psycopg://pqc_app:placeholder@127.0.0.1:5432/pqc_workspace" .venv/bin/alembic upgrade head --sql` | `0` | `254` lines PG DDL (`20261117_0001` -> `20261117_0002`) | `0` | `0` | `0` | `< 1.0s` |
| `git diff --check` | `0` | Clean | `0` | `0` | `0` | `< 0.5s` |

### 3.2 Skipped / Blocked Test Accounting (No SQLite-for-PostgreSQL Substitution)
1. `tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration` — **SKIPPED / BLOCKED in current shell** because neither disposable `PQC_TEST_POSTGRES_URL` nor `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true` is set in this validation session (per Section 3 rules, live PostgreSQL was not invoked without explicit disposable-DB prerequisites; offline SQLite tests are **not** substituted for live PostgreSQL validation; historical Cloud SQL PostgreSQL 16.15 execution remains recorded at commit `686e4ffce765ed6d615daee10daa4fb5ee423267`).
2. `tests/test_pqc_inventory.py::test_live_vertex_gemini_turn_reports_model_telemetry` — **SKIPPED** (`Set PQC_LIVE_LLM_TEST=1 with Vertex AI access to run`).

---

## 4. Remaining Production Prerequisites & Recommendation

### 4.1 Required Code/Config Fixes Before Merge to `main`
1. **`Dockerfile`:** Copy `scripts/run_db_migrations.py` into `/app/scripts/run_db_migrations.py` alongside `scripts/migrate_sqlite_to_postgres.py` (and add an assertion in `tests/test_pqc_inventory.py::test_deployment_configuration_disables_simulation_and_keeps_persistence`).
2. **`main.py` & `scripts/setup_and_deploy_vertex.sh`:** Defer `create_workspace_app()` / `pqc_agent.workspace_server` instantiation in `main.py` so non-server CLI commands (`deploy`, `tools`, `cbom`) and `load_dotenv()` do not trigger eager Cloud SQL socket connections at import time, and run the serialized `agentic-pqc-db-migrate` Cloud Run Job before `gcloud beta run deploy` in `scripts/setup_and_deploy_vertex.sh`.
3. **Documentation Sync (Optional/Low):** Update `20261117_0001` -> `20261117_0002` in `app.yaml:27` and `MIGRATION_AND_ROLLBACK.md:11`, and `DRY_RUN_VALIDATED` -> `DRY_RUN_OK` in `MIGRATION_AND_ROLLBACK.md:153`.

### 4.2 Remaining Operational Prerequisites Prior to Production Deployment
- Provision dedicated production Cloud SQL for PostgreSQL 16 HA instance, Secret Manager secrets (`pqc-session-secret`, `pqc-db-password`, `pqc-oauth-client-secret`), and a live Google Cloud KMS symmetric key (`PQC_KMS_KEY_NAME` with key-scoped `roles/cloudkms.cryptoKeyEncrypterDecrypter`).
- Execute `scripts/run_db_migrations.py --require-postgres` against staging PostgreSQL, validate `scripts/migrate_sqlite_to_postgres.py --dry-run` on immutable legacy backups if migrating existing data, and validate a multi-instance (`>= 2`) Cloud Run staging deployment with live Cloud KMS envelope encryption prior to production traffic cutover.
- Complete Phase 3+ security roadmap items before public/production exposure.

### 4.3 Final Pre-Merge Gate Decision
- **Gate Status:** **`FAIL`** — *concrete defect prevents merge* (`PRE-MERGE-01` & `PRE-MERGE-02`).
- **Pull Request & Merge Eligibility:** **NOT YET ELIGIBLE FOR MERGE** until `PRE-MERGE-01` (`Dockerfile` missing `scripts/run_db_migrations.py`) and `PRE-MERGE-02` (`main.py` eager import + `scripts/setup_and_deploy_vertex.sh` migration step) are fixed in a targeted commit on `security-hardening/phase-01-02`. All core Phase 1–2 OAuth, session, CSRF, PostgreSQL persistence, Alembic schema-authority, KMS/AAD credential encryption, data-migration, and destructive-test safety controls **PASSED** without regression.
