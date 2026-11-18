# Phase 1–2 Technical Handoff Checkpoint

## 1. Repository & Commit Lineage
- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Active Branch:** `security-hardening/phase-01-02`
- **Commit Lineage on Branch:**
  1. `1d112f65c5b917f7fdcd00bb00b8e8a772d18cc0` (`1d112f6`, `main`) — `security: remediate oauth and session authentication vulnerabilities`
  2. `60ffaa21adfadda135ba5dd65d628f699e48425f` (`60ffaa2`) — `security: complete OAuth and distributed authentication remediation`
  3. `02b53e9da7590b67d9b3c1960a400cea04add49d` (`02b53e9`) — `security: complete PostgreSQL persistence and credential architecture`
  4. `d43e17e594131a23a021b1afa68541851ff32307` (`d43e17e`) — `docs(security): add remediation specifications and execution checkpoint logs`
  5. `bdcf69268843a141d2ebc3a68b0272791a0ec813` (`bdcf692`) — `security: close phase 1-2 acceptance gaps`
  6. `686e4ffce765ed6d615daee10daa4fb5ee423267` (`686e4ff`) — `test(security): validate live Cloud SQL PostgreSQL 16 multi-instance integration`
  7. `35ef8455a4db9f32daf519aa4e6653e9f10d72a9` (`35ef845`) — `security: guard destructive postgres integration tests`
  8. `16181d5f4efa6b0aeb64ee80251b7ae84eb10c07` (`16181d5`) — `docs(security): record hotfix spec and final commit SHA` (Pre-hotfix baseline `HEAD` SHA)
  9. **Final `HEAD`** (parent `16181d5f4efa6b0aeb64ee80251b7ae84eb10c07`, resolve exact 40-char SHA via `git rev-parse HEAD`) — `security: guard destructive postgres integration tests`
- **Python Environment:** Python `3.12.13` managed by `uv` (`uv.lock` + `.venv/bin/pytest`). Never run bare `pip`; use `uv` or `.venv/bin/python`.

---

## 2. Architecture State After Phase 1–2 Final Corrective & Safety Hotfix Pass

### 2.1 Authentication & OAuth 2.0 + PKCE (`pqc_agent/auth_guard.py`, `pqc_agent/auth_store.py`, `pqc_agent/workspace_server.py`, `pqc_agent/portal_ui.py`)
- **OAuth 2.0 Authorization Code + PKCE (`S256`) Only (`AUTH-01`):** Implicit flow (`response_type=token`, URL `#access_token` fragments, and GIS `initTokenClient`) is disabled and rejected across public and confidential clients.
- **Strict 600-Second OAuth Transaction TTL (`AUTH-02`):**
  - `MIN_OAUTH_TRANSACTION_TTL_SECONDS = 1`, `MAX_OAUTH_TRANSACTION_TTL_SECONDS = 600` in `pqc_agent/auth_store.py`.
  - Both `DistributedAuthStore.create_oauth_transaction()` and `_oauth_ttl_seconds()` (`PQC_OAUTH_STATE_TTL_SECONDS`) clamp strictly to `[1, 600]`.
  - `consume_oauth_transaction()` atomically executes `UPDATE pqc_oauth_transactions SET consumed_at = :now WHERE state_id = :id AND consumed_at IS NULL AND expires_at > :now AND created_at > (:now - 600.0) ...`, guaranteeing single-use consumption across instances and zero validity beyond 600s.
- **Zero Frontend Token Exposure & Fail-Closed Sessions (`AUTH-03`, `AUTH-04`):**
  - Session tokens are stored exclusively in `HttpOnly; SameSite=Lax; Secure` cookies (`pqc_session_token`, `pqc_session_jar`) with session-bound `X-PQC-CSRF-Token` enforcement on mutating endpoints.
  - `pqc_auth_sessions` acts as a server-side allowlist: unknown/unregistered `jti` rows or database errors fail closed (`HTTP 401`).

### 2.2 PostgreSQL Persistence, Exclusive Alembic Schema Authority & KMS Credentials (`DB-01`..`DB-04`, `ID-01`)
- **Alembic Is the Sole Production Schema Authority (`DB-01`):**
  - Revision `20261117_0001_initial_phase1_phase2_schema.py` creates all 10 `pqc_*` tables (`pqc_schema_metadata`, `pqc_oauth_transactions`, `pqc_consumed_nonces`, `pqc_auth_sessions`, `pqc_tenant_users`, `pqc_session_metadata`, `pqc_user_connections`, `pqc_oauth_client_configs`, `pqc_calibration_events`, `pqc_delegated_credentials`).
  - Revision `20261117_0002_add_adk_v1_session_schema.py` creates all 5 Google ADK `v1` session tables (`adk_internal_metadata`, `sessions`, `events`, `app_states`, `user_states`) and sets `EXPECTED_ALEMBIC_REVISION = "20261117_0002"`.
  - In production (`K_SERVICE`, `PQC_PRODUCTION_MODE=true`, or `PQC_ENV=production`):
    - SQLite and `/data` (GCS FUSE) paths are unconditionally rejected (`validate_production_postgres_only()`).
    - `DistributedAuthStore` and `ManagedSchemaDatabaseSessionService` **never** call `metadata.create_all()`; startup calls read-only `verify_alembic_schema_on_engine()` and fails closed if `alembic_version != '20261117_0002'` or any table is missing.
  - Explicit migration entry point: `scripts/run_db_migrations.py` (`--require-postgres`, `--verify-only`, PostgreSQL advisory lock `7081632026`), invoked as a single-task Cloud Run Job (`--tasks=1 --max-retries=0`) in `scripts/deploy_cloud_run.sh` before Cloud Run service deployment.
- **Delegated Credentials (`pqc_agent/credential_service.py`, `tools/gcloud_bridge.py`, `ID-01`):**
  - `EncryptedDatabaseCredentialService` wraps per-record 256-bit DEKs via Google Cloud KMS (`PQC_KMS_KEY_NAME`, mandatory in production) with canonical AAD `app_name|tenant_domain|user_id|credential_key` (tested with deterministic local KMS stub `_DeterministicCloudKmsStub`; live Cloud KMS API validation remains a staging prerequisite). No `InMemoryCredentialService` or disk `mkstemp` token files remain in runtime paths.
- **Legacy Data Migration (`pqc_agent/migration_tool.py`, `scripts/migrate_sqlite_to_postgres.py`, `DB-04`):**
  - Idempotent, read-only source migration with `--dry-run`, SHA-256 source immutability verification, orphan/conflict detection, and legacy plaintext token stripping.

### 2.3 Final Safety Hotfix Safeguards Implemented
1. **Mandatory Destructive-Test Database Isolation Guard (`tests/test_phase2_persistence_and_credentials.py`):**
   - `validate_destructive_postgres_test_target()` and `_truncate_disposable_postgres_test_tables()` execute **before** any database connection, Alembic migration, or `TRUNCATE` in `test_phase2_live_postgresql_multi_instance_integration`.
   - Enforces explicit `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`, SQLAlchemy `make_url()` parsing, `postgresql`-only backend, `^pqc_test_[a-zA-Z0-9_]+$` database naming, rejection of `prod`/`production`/`live`/`customer`/`primary`, rejection of `K_SERVICE` / `PQC_PRODUCTION_MODE=true` / `PQC_ENV=production`, fail-closed `RuntimeError` with **zero SQL executed** on rejection, and a clear pre-`TRUNCATE` warning identifying the disposable database.
2. **Documentation & Commit Lineage Synchronization:**
   - Synchronized `FINAL_REPORT.md`, `CHECKPOINT.md`, and `PHASE_01_02_ACCEPTANCE.md` with the exact Git lineage (`bdcf692`, `686e4ff`, and final `HEAD`), added offline zero-SQL guard regression results (`8 passed, 1 skipped` in Phase 2 suite; `40 passed` in Auth/Phase 1 suites), preserved `PostgreSQL 16.15` integration evidence, and explicitly noted that live Cloud KMS API validation was not performed.

---

## 3. Remaining Production Prerequisites & Next Recommended Phase

1. **Remaining Production Prerequisites (Before Production Cutover):**
   - Provision dedicated production Cloud SQL for PostgreSQL 16 HA instance (`--availability-type=REGIONAL`) and least-privilege database user.
   - Provision Secret Manager secrets (`pqc-session-secret`, `pqc-db-password`, `pqc-oauth-client-secret`) and bind runtime Service Account IAM (`roles/cloudsql.client`, `roles/secretmanager.secretAccessor`).
   - Provision a live Google Cloud KMS symmetric key (`PQC_KMS_KEY_NAME`) with `roles/cloudkms.cryptoKeyEncrypterDecrypter` and validate live KMS `encrypt`/`decrypt` envelope wrapping in staging.
   - Execute serialized schema migration job (`scripts/run_db_migrations.py --require-postgres`, `--tasks=1 --max-retries=0`) and validate multi-instance (`>= 2` instances) Cloud Run + IAP staging deployment before production traffic cutover.
2. **Next Recommended Engineering Phase — Phase 3 (Runtime Security, Resilience & Input Hardening):**
   - Proceed to **Phase 3** remediation items: outbound SSRF/egress controls, Vertex AI model call timeouts/circuit-breaker resilience, PQC scorecard denominator & edge-case hardening, non-root container execution in `Dockerfile`, and strict multimodal upload size/magic-byte validation.
