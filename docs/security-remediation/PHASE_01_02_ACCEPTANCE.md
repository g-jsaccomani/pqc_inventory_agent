# Phase 1 & Phase 2 Corrective Security Remediation — Acceptance Checklist

- **Branch:** `security-hardening/phase-01-02`
- **Primary Evidence Report:** [`security_test_logs/phase_01_02_remediation/REPORT.md`](../../security_test_logs/phase_01_02_remediation/REPORT.md)
- **Migration & Rollback Runbook:** [`docs/security-remediation/MIGRATION_AND_ROLLBACK.md`](./MIGRATION_AND_ROLLBACK.md)

Status Legend (per `PHASE1.md` Section 6):
- **`PASS`** — Implementation and automated tests verified with real execution output.
- **`FAIL`** — Implementation or tests failed.
- **`BLOCKED`** — External infrastructure or OS-allowlisted daemon unavailable in workstation environment (never reported as `PASS`).
- **`NOT_IMPLEMENTED`** — Not completed.

---

## 1. Phase 1 — OAuth and Authentication (`P0`)

| Requirement ID | Control Requirement | Status | Supporting Implementation & Test Evidence |
| :--- | :--- | :---: | :--- |
| **`AUTH-01`** | Eliminate OAuth 2.0 Implicit Flow (`response_type=token`, URL fragment `#access_token`, GIS `initTokenClient` disabled by default) for both public and confidential clients via Authorization Code + PKCE (`S256`). | **`PASS`** | `pqc_agent/workspace_server.py` (`/api/auth/oauth/signin`, `/api/auth/oauth/authorize`, `/api/auth/bridge`), `pqc_agent/portal_ui.py`; verified by `tests/test_phase1_distributed_auth.py::test_auth05_01_*`, `test_auth05_02_*`, `test_auth05_03_implicit_flow_is_rejected_everywhere`. |
| **`AUTH-02`** | Server-side PKCE `code_verifier` storage behind opaque CSPRNG `state` (`>= 128` bits), `S256` challenge, strict TTL (`1..600s` max; values `>600s` clamped to `600s`, `<=0` clamped to `1s`), atomic single-use consumption, `code_verifier` never serialized in URLs/cookies/JSON/`state`. | **`PASS`** | `pqc_agent/auth_store.py` (`MAX_OAUTH_TRANSACTION_TTL_SECONDS = 600`), `pqc_agent/workspace_server.py` (`_oauth_ttl_seconds`); verified by `tests/test_phase1_distributed_auth.py::test_auth02_strict_600s_oauth_ttl_bounds_and_concurrent_single_use`, `test_auth05_04_05_06_*`, `test_auth05_16_*`. |
| **`AUTH-03`** | Eliminate session bearer token exposure in JSON responses (`/api/auth/google`, `/api/auth/auto`, `/api/auth/switch`, `/api/auth/me`, OAuth callbacks), `localStorage`, `sessionStorage`, and URL params; enforce `HttpOnly`, `SameSite=Lax`, `Secure` cookies + session-bound CSRF (`X-PQC-CSRF-Token`). | **`PASS`** | `pqc_agent/workspace_server.py`, `pqc_agent/portal_ui.py`, `pqc_agent/auth_guard.py`; verified by `tests/test_phase1_distributed_auth.py::test_auth05_10_11_12_13_*`, `tests/test_auth_hardening.py::test_phase1_no_localstorage_*`, `test_phase1_csrf_protection_*`. |
| **`AUTH-04`** | Distributed server-side replay & session state (`pqc_oauth_transactions`, `pqc_consumed_nonces`, `pqc_auth_sessions`), fail-closed session allowlist + DB error handling, OIDC ID-token `nonce` & 3LO account-match enforcement across multiple instances and restarts. | **`PASS`** | `pqc_agent/auth_store.py` (`is_session_revoked_or_expired`, `consume_replay_token`), `pqc_agent/workspace_server.py`; verified by `tests/test_phase1_distributed_auth.py::test_auth05_07_08_09_*`, `test_auth05_14_15_cross_instance_revocation_and_restart_persistence`, `test_auth05_unregistered_session_fail_closed_and_3lo_account_binding`. |
| **`AUTH-05`** | Complete OAuth & session security regression suite with synthetic credentials and real RSA-2048 JWKS verification. | **`PASS`** | `tests/test_phase1_distributed_auth.py` (`10 passed`), `tests/test_auth_hardening.py` (`30 passed`). |

---

## 2. Phase 2 — PostgreSQL and Distributed Persistence (`P1`)

| Requirement ID | Control Requirement | Status | Supporting Implementation & Test Evidence |
| :--- | :--- | :---: | :--- |
| **`DB-01` (Code, Pooling, Alembic-Only Authority & Fail-Closed)** | Replace SQLite production persistence with PostgreSQL (`psycopg` + `asyncpg`), Cloud SQL Auth Proxy socket & TCP support, connection pooling, statement/connect timeouts, startup `SELECT 1` gate, Alembic as sole production schema authority (`20261117_0001` + `20261117_0002`, zero `metadata.create_all()` in production, explicit `scripts/run_db_migrations.py` with PostgreSQL advisory lock), and fail-closed rejection of missing/outdated/inconsistent schema or SQLite in production. | **`PASS`** | `pqc_agent/auth_store.py`, `pqc_agent/workspace_server.py` (`ManagedSchemaDatabaseSessionService`), `scripts/run_db_migrations.py`, `migrations/versions/20261117_0002_add_adk_v1_session_schema.py`; verified by `test_phase2_alembic_sole_production_schema_authority_and_migration_cli` and `test_phase2_production_postgres_fail_closed_url_normalization_and_alembic_ddl`. |
| **`DB-02`** | Eliminate every production configuration placing SQLite or authoritative JSONL on Cloud Storage FUSE (`/data/pqc_sessions.db`, `--add-volume=name=pqc-data,type=cloud-storage`, WAL monkeypatches); reserve GCS strictly for object storage (`GcsArtifactService`). | **`PASS`** | `Dockerfile`, `app.yaml`, `scripts/deploy_cloud_run.sh`, `scripts/setup_and_deploy_vertex.sh`, `pqc_agent/workspace_server.py`, `pqc_agent/auth_store.py`; verified by `tests/test_pqc_inventory.py::test_deployment_configuration_disables_simulation_and_keeps_persistence` and `test_phase2_production_postgres_fail_closed_*`. |
| **`DB-03`** | Move authoritative user profiles (`pqc_tenant_users`), session metadata (`pqc_session_metadata` with FK ownership), user connections (`pqc_user_connections`), OAuth client config (`pqc_oauth_client_configs`), and calibration events (`pqc_calibration_events`) to relational tables; eliminate dual-writes and filesystem fallback; retain JSON strictly as explicit backup export (`export_workspace_json_backup`). | **`PASS`** | `pqc_agent/auth_store.py`, `pqc_agent/workspace_server.py`, `tools/gcloud_bridge.py`, `tools/calibration_engine.py`; verified by `tests/test_auth_hardening.py::test_auto_signin_account_switcher_and_partitioned_tenant_storage` and `tests/test_phase2_persistence_and_credentials.py`. |
| **`ID-01`** | Replace `InMemoryCredentialService` and disk temp token files (`mkstemp`); enforce Service Account impersonation allowlist (`PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS`, short-lived read-only scope) as preferred pattern, and `EncryptedDatabaseCredentialService` with Google Cloud KMS DEK envelope encryption (`CloudKmsDekWrapper` + canonical tenant/user AAD), refresh rotation, expiry, and cross-instance revocation for delegated 3LO tokens. | **`PASS`** | `pqc_agent/credential_service.py`, `tools/gcloud_bridge.py`, `docs/security-remediation/MIGRATION_AND_ROLLBACK.md`; verified by `tests/test_phase2_persistence_and_credentials.py::test_phase2_kms_envelope_encryption_refresh_expiry_revocation_and_cross_tenant_isolation` and `tests/test_auth_hardening.py::test_s7_*`. |
| **`DB-04`** | Implement safe, idempotent, read-only SQLite + JSON/JSONL migration (`--dry-run`, count & FK referential integrity validation, duplicate/conflict/orphan detection, plaintext token stripping, SHA-256 source immutability, JSON + Markdown reports, backup & rollback docs). | **`PASS`** | `pqc_agent/migration_tool.py`, `scripts/migrate_sqlite_to_postgres.py`, `docs/security-remediation/MIGRATION_AND_ROLLBACK.md`; verified by `tests/test_phase2_persistence_and_credentials.py::test_phase2_safe_idempotent_data_migration_and_conflict_detection`. |

---

## 3. Section 4 — Multi-Instance & Live Infrastructure Integration Verification

| Test / Verification Requirement | Status | Supporting Evidence / Blocker Detail |
| :--- | :---: | :--- |
| **11-Step Multi-Instance Workflow + Full Instance Restart** (`Instance A` <-> `Instance B` -> `Instance A2`/`B2`) | **`PASS`** | `tests/test_phase2_persistence_and_credentials.py::test_phase2_multi_instance_11_step_workflow_and_restart_consistency`. |
| **Concurrent OAuth Callbacks & Concurrent Multi-Instance DB Writes** | **`PASS`** | `tests/test_phase2_persistence_and_credentials.py::test_phase2_concurrent_oauth_callbacks_and_concurrent_multi_instance_db_writes` (`1 x 200`, `7 x 400`; 12 concurrent writers verified). |
| **Database Interruption (Fail-Closed), Atomic Transaction Rollback & Database Recovery** | **`PASS`** | `tests/test_phase2_persistence_and_credentials.py::test_phase2_database_interruption_fail_closed_rollback_and_recovery`. |
| **Credential Expiration, Revocation, Cross-User Session Isolation & Cross-Tenant Credential AAD Isolation** | **`PASS`** | `tests/test_phase2_persistence_and_credentials.py::test_phase2_kms_envelope_encryption_refresh_expiry_revocation_and_cross_tenant_isolation` & `tests/test_pqc_inventory.py::test_multi_tenant_google_auth_*`. |
| **Destructive PostgreSQL Test Isolation Guard (`PQC_ALLOW_DESTRUCTIVE_TEST_DB=true` & `^pqc_test_[a-zA-Z0-9_]+$`)** | **`PASS`** | `tests/test_phase2_persistence_and_credentials.py::test_phase2_destructive_postgres_safety_guard_and_zero_sql_on_rejection` — Enforces explicit opt-in, SQLAlchemy `make_url()`, `postgresql`-only backend, disposable `^pqc_test_...$` naming, forbidden term & prod-env rejection, pre-`TRUNCATE` warning, and **zero SQL executed** on rejected configs. |
| **Live PostgreSQL Server Execution (`PQC_TEST_POSTGRES_URL`)** | **`PASS`** | `tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration` — Executed over Cloud SQL mTLS 1.3 (`port 3307`) against `fnlab-ai-data-8fa913:us-central1:pqc-pg16-validation` (`PostgreSQL 16.15 on x86_64-pc-linux-gnu`, disposable DB `pqc_test_validation`): **`1 passed in 134.69s`** standalone and **`76 passed, 0 failed, 1 skipped in 260.60s`** across the full suite. |
| **Cloud Run / Cloud SQL / Cloud KMS Live Deployment Verification** | **`BLOCKED`** | Production/Cloud Run service deployment and live Cloud KMS API invocation intentionally not executed per `PHASE1.md` rules (`no deployment` in this phase). |

---

## 4. Configuration, Documentation & Git Hygiene (`Sections 5–8`)

| Deliverable | Status | Reference |
| :--- | :---: | :--- |
| Deployment Config, `Dockerfile`, `app.yaml`, `.env.example`, Lockfiles (`uv.lock`, `requirements.txt`) free of SQLite/FUSE & real secrets | **`PASS`** | Verified by `test_deployment_configuration_disables_simulation_and_keeps_persistence` and secret scan. |
| Cloud SQL, Secret Manager, IAM, KMS Credential Justification, Migration & Rollback Documentation | **`PASS`** | [`docs/security-remediation/MIGRATION_AND_ROLLBACK.md`](./MIGRATION_AND_ROLLBACK.md), [`README.md`](../../README.md), [`docs/06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md`](../06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md). |
| Mandatory Test Evidence Report & Acceptance Checklist | **`PASS`** | [`security_test_logs/phase_01_02_remediation/REPORT.md`](../../security_test_logs/phase_01_02_remediation/REPORT.md), [`security_test_logs/phase_01_02_final_validation/FINAL_REPORT.md`](../../security_test_logs/phase_01_02_final_validation/FINAL_REPORT.md) & this file. |
| Remediation Commits Preserved (`no force-push`, `no deploy`, `no merge to main`, `no commit rewrite`) | **`PASS`** | `60ffaa2`, `02b53e9`, `d43e17e`, `bdcf692`, `686e4ff`, `35ef845`, `16181d5` + final `HEAD` (`security: guard destructive postgres integration tests`) on `security-hardening/phase-01-02`. |

---

## 5. Final Corrective Pass Summary (`AUTH-02`, `DB-01` & Live PostgreSQL 16.15 Validation)

- **Original Findings Fixed:**
  1. `AUTH-02`: `DistributedAuthStore.create_oauth_transaction()` and `_oauth_ttl_seconds()` previously allowed `ttl_seconds` up to `1800`s; root cause was `min(..., 1800)`. Corrected to strict `[1, 600]` clamping + `created_at > (now - 600.0)` enforcement (`PASS`).
  2. `DB-01`: Production startup previously called `PqcPersistenceBase.metadata.create_all()` and ADK `BaseV1.metadata.create_all()`; root cause was default `create_schema=True` without read-only Alembic verification. Corrected by making Alembic (`20261117_0001` -> `20261117_0002`) the exclusive production schema authority via `scripts/run_db_migrations.py`, prohibiting `metadata.create_all()` in production, and failing closed on missing, outdated, or inconsistent schema (`PASS`).
- **Actual Test Results (with Live Cloud SQL PostgreSQL 16.15 Active):** **`76 passed, 0 failed, 1 skipped`** (`260.60s`, exit `0`; standalone PostgreSQL 16 multi-instance suite: **`1 passed in 134.69s`**).
- **Phase 1–2 Acceptance Status:** **`PASS` (`GO` for Phase 1–2 code & PostgreSQL 16 persistence gate; Cloud Run staging rollout remains a separate deployment step)**.
