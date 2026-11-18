# Phase 1 & Phase 2 Corrective Security Remediation — Verification & Evidence Report

- **Branch:** `security-hardening/phase-01-02`
- **Parent Baseline Commit on `main`:** `1d112f6` (`security: remediate oauth and session authentication vulnerabilities`)
- **Commit 1 (Phase 1 — OAuth & Distributed Auth):** `60ffaa2` (`security: complete OAuth and distributed authentication remediation`)
- **Commit 2 (Phase 2 — PostgreSQL Persistence & Credential Architecture):** Committed immediately following this report (`security: complete PostgreSQL persistence and credential architecture`)
- **Execution Environment:** Corporate macOS (`aarch64-apple-darwin`), Python `3.12.13` (`uv`-managed `.venv`), `google-adk==2.11.0`, `sqlalchemy==2.0.55`, `psycopg==3.3.8`, `asyncpg==0.32.0`, `alembic==1.20.1`, `cryptography==46.0.7`, `pytest==9.1.1`.

---

## 1. Root Cause of Each Previously Identified Finding

| Requirement / Baseline ID | Vulnerability / Incomplete Control | Root Cause in Pre-Remediation Implementation |
| :--- | :--- | :--- |
| **`AUTH-01`** (`H1`) | Residual OAuth 2.0 Implicit Flow (`response_type=token`) & GIS token client | `/api/auth/oauth/authorize` fell back to `response_type=token` whenever `client_secret` was unset; `_OAUTH_IMPLICIT_CALLBACK_HTML` parsed `window.location.hash` (`access_token`); `/api/auth/bridge` unconditionally initialized `google.accounts.oauth2.initTokenClient` in browser JS. |
| **`AUTH-02`** (`A1`) | PKCE `code_verifier` embedded inside client-held `state` parameter | `sign_oauth_state_token` serialized the raw PKCE `code_verifier` inside an HMAC-signed `state` payload transmitted through browser redirects instead of keeping `code_verifier` exclusively server-side behind an opaque `state` key. |
| **`AUTH-03`** (`H2`) | Session bearer token exposed in JSON responses & client storage | `/api/auth/google`, `/api/auth/auto`, `/api/auth/switch`, and `/api/auth/me` returned `"token": <raw_session_token>` in JSON bodies (and `/api/auth/switch` accepted raw bearer tokens in JSON POST payloads), defeating `HttpOnly` cookie isolation against XSS. |
| **`AUTH-04`** (`H2`) | Process-local replay/revocation state & missing server-side session allowlist | Consumed OAuth nonces (`_CONSUMED_OAUTH_STATES`) and revoked session `jti`s (`_REVOKED_SESSION_JTIS` + `pqc_revoked_tokens.json` capped to 2,000 entries) lived in process memory / local files, failing across multiple Cloud Run instances or container restarts. Unregistered tokens signed with the HMAC key were accepted unless explicitly listed in a revocation file. |
| **`AUTH-05`** | Missing multi-instance & cryptographic RSA OIDC regression coverage | Existing tests mocked `_verify_google_oauth_or_id_token` at high level without testing real RSA-2048 JWT signature/JWKS validation, concurrent callback races, or cross-instance revocation/restart behavior. |
| **`DB-01`** (`H3`/`H4`) | SQLite used as production database without PostgreSQL pooling, timeouts, or migrations | `workspace_server.py` defaulted `SESSION_DB_URL` to SQLite without `psycopg`/`asyncpg` drivers, connection pooling, statement timeouts, startup connectivity verification, or Alembic schema migrations. |
| **`DB-02`** (`H3`) | SQLite placed on Cloud Storage FUSE (`/data/pqc_sessions.db`) | `Dockerfile`, `app.yaml`, `scripts/deploy_cloud_run.sh`, and `scripts/setup_and_deploy_vertex.sh` mounted GCS (`type=cloud-storage`) at `/data` and set `SESSION_DB_URL=sqlite:///data/pqc_sessions.db` with WAL/locking monkeypatches. GCS FUSE lacks POSIX byte-range/WAL semantics, risking silent corruption. |
| **`DB-03`** (`H4`) | Authoritative shared state stored in local JSON/JSONL files + process dicts | `_SESSION_METADATA_CACHE`, `_TENANT_USERS_CACHE`, `_USER_CONNECTIONS`, `pqc_tenant_users.json`, `pqc_session_metadata.json`, `pqc_user_connections.json`, `pqc_oauth_config.json`, and `/data/calibration-history.jsonl` used per-process `threading.RLock()` and non-atomic filesystem writes. |
| **`ID-01`** (`H5`) | Process-local `InMemoryCredentialService` & `_USER_ACCESS_TOKENS` + temp token files | ADK `Runner` used `InMemoryCredentialService()`, `gcloud_bridge.py` stored tokens in `_USER_ACCESS_TOKENS` in-process dict, and `_build_gcloud_argv_and_env` wrote temporary `pqc_gcloud_tok_*` files to disk via `tempfile.mkstemp`. |
| **`DB-04`** | No safe migration path from legacy SQLite + JSON/JSONL to PostgreSQL | No idempotent, count-validated, FK-checked, non-destructive migration utility or rollback runbook existed. |

---

## 2. Before / After Architecture

### Before (Vulnerable / Single-Instance Local State)
```text
Browser (GIS Implicit Token / JSON bearer token)
   │
   ▼
Cloud Run Instance 1 (max-instances=1 forced)
   ├── In-Memory Dicts: _CONSUMED_OAUTH_STATES, _REVOKED_SESSION_JTIS,
   │                    _SESSION_METADATA_CACHE, _TENANT_USERS_CACHE,
   │                    _USER_CONNECTIONS, _USER_ACCESS_TOKENS, InMemoryCredentialService
   └── GCS FUSE Mount (/data -> gs://<bucket>)
        ├── sqlite:///data/pqc_sessions.db (WAL monkeypatched over FUSE)
        ├── /data/tenants/<uid>/{profile,connection,sessions/*}.json
        ├── /data/pqc_oauth_config.json (plaintext client_secret)
        └── /data/calibration-history.jsonl
```

### After (Horizontally Scalable Zero-Trust Distributed Architecture)
```text
Browser (HttpOnly SameSite=Lax Secure Cookie + Session-Bound X-PQC-CSRF-Token)
   │  OAuth 2.0 Authorization Code + PKCE (S256), Opaque State, Single-Use OIDC Nonce
   ▼
Cloud Run Instances 1..N (Stateless Containers, No GCS FUSE Mount)
   ├── DistributedAuthStore (SQLAlchemy 2.0 + postgresql+psycopg, Pooled + Timeouts)
   │    ├── pqc_schema_metadata & alembic_version (Alembic Revision 20261117_0001)
   │    ├── pqc_oauth_transactions (Server-Side PKCE Verifier, Nonce, Atomic Single-Use UPDATE)
   │    ├── pqc_consumed_nonces (Replay Ledger PK)
   │    ├── pqc_auth_sessions (Fail-Closed Session Allowlist & Cross-Instance Revocation)
   │    ├── pqc_tenant_users (Tenant-Isolated User Profiles)
   │    ├── pqc_session_metadata (FK -> pqc_tenant_users.user_id ON DELETE CASCADE)
   │    ├── pqc_user_connections (Non-Secret ADC / Impersonation / 3LO Config)
   │    ├── pqc_oauth_client_configs (Envelope-Encrypted OAuth Client Secret)
   │    ├── pqc_calibration_events (Scope & Tenant-Keyed Mosca Ledger)
   │    └── pqc_delegated_credentials (AES-256-GCM Ciphertext + Wrapped DEK + AAD SHA-256)
   ├── ADK DatabaseSessionService (postgresql+asyncpg -> sessions, events, app_states, user_states)
   ├── EncryptedDatabaseCredentialService (Google Cloud KMS KeyManagementServiceClient DEK Wrapping + AAD)
   ├── Secret Manager (--set-secrets -> PQC_AUTH_SECRET, PQC_DB_PASSWORD, PQC_GOOGLE_OAUTH_CLIENT_SECRET)
   └── Cloud Storage Object Storage ONLY (GcsArtifactService -> PQC_ARTIFACT_BUCKET)
```

---

## 3. Files Created or Modified

### Core Application & Security Modules
- `pqc_agent/auth_guard.py` — OAuth 2.0 PKCE (`S256`), cryptographic RSA/JWKS OIDC ID-token verification (`iss`, `aud`, `exp`, `nonce`, `email_verified`), Cloud IAP audience enforcement, session-bound CSRF HMAC derivation/verification, production fail-closed `PQC_AUTH_SECRET` + key rotation.
- `pqc_agent/auth_store.py` — Unified SQLAlchemy 2.0 ORM (`PqcPersistenceBase`, 10 tables), `validate_production_postgres_only()`, Cloud SQL Unix socket & TCP DSN builders (`postgresql+psycopg` & `postgresql+asyncpg`), connection pooling + statement/connect timeouts, startup `SELECT 1` health gate, atomic single-use PKCE transaction consumption, fail-closed session allowlist/revocation, transactional user/session/connection/calibration/credential CRUD, and non-authoritative JSON backup export.
- `pqc_agent/credential_service.py` — `EncryptedDatabaseCredentialService(BaseCredentialService)`, `CloudKmsDekWrapper` (Google Cloud KMS `encrypt`/`decrypt` with canonical tenant/user AAD; fails closed in production without `PQC_KMS_KEY_NAME`), `LocalHkdfKekWrapper` (RFC 5869 HKDF-SHA256 AES-256-GCM for local dev/tests), CSPRNG per-record 256-bit DEKs with memory zeroization, server-side refresh-token rotation, expiry & immediate cross-instance revocation.
- `pqc_agent/migration_tool.py` & `scripts/migrate_sqlite_to_postgres.py` — Safe, idempotent, read-only SQLite + JSON/JSONL to PostgreSQL migration engine with dry-run rollback, count & SQL FK validation, duplicate/conflict/orphan detection, legacy plaintext token stripping, SHA-256 source immutability verification, and JSON + Markdown report generation.
- `pqc_agent/portal_ui.py` & `pqc_agent/workspace_server.py` — Removed implicit OAuth flow, removed JSON bearer token serialization, gated GIS JS client behind `PQC_ENABLE_GIS_JAVASCRIPT_CLIENT` (default `false`), removed SQLite WAL/GCS FUSE monkeypatches and JSON caches/files, wired per-instance `DistributedAuthStore` and `EncryptedDatabaseCredentialService`, added `database_healthy` check in `/api/health`.
- `tools/gcloud_bridge.py`, `tools/calibration_engine.py`, `tools/report_exporter.py` — Replaced in-memory/JSON/JSONL/FUSE paths with `DistributedAuthStore` & `EncryptedDatabaseCredentialService`; added `validate_impersonated_service_account()` (`PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS`); passed `CLOUDSDK_AUTH_ACCESS_TOKEN` exclusively via in-memory subprocess env (zero `mkstemp` token files).

### Migrations, Configuration, Dependencies & Documentation
- `alembic.ini`, `migrations/env.py`, `migrations/script.py.mako`, `migrations/versions/20261117_0001_initial_phase1_phase2_schema.py`
- `pyproject.toml`, `uv.lock`, `requirements.txt`, `main.py`
- `Dockerfile`, `app.yaml`, `.env.example`, `scripts/deploy_cloud_run.sh`, `scripts/setup_and_deploy_vertex.sh`
- `README.md`, `docs/03-Agentic-PQC-SOW-Readiness-Assessment-Template.md`, `docs/06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md`, `docs/07-Agentic-PQC-Discovery-Questionnaire.md`, `docs/security-remediation/MIGRATION_AND_ROLLBACK.md`, `docs/security-remediation/PHASE_01_02_ACCEPTANCE.md`

### Regression & Multi-Instance Test Suites
- `tests/conftest.py`
- `tests/test_auth_hardening.py` (30 tests)
- `tests/test_phase1_distributed_auth.py` (9 comprehensive suites covering all 16 `AUTH-05` scenarios + unregistered-session fail-closed + 3LO account mismatch)
- `tests/test_phase2_persistence_and_credentials.py` (7 comprehensive suites covering 11-step multi-instance workflow, concurrency races, DB interruption/rollback/recovery, Cloud KMS envelope encryption & AAD transplant defense, production PostgreSQL fail-closed + Alembic DDL, idempotent data migration, and live PostgreSQL integration gate)
- `tests/test_pqc_inventory.py` (29 tests)

---

## 4. Exact Commands Executed & Real Test Results

### 4.1 Bytecode Compilation & Full Automated Test Suite
```bash
.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests && .venv/bin/pytest -v -rs
```
- **Exit Code:** `0`
- **Summary:** **`73 passed, 0 failed, 2 skipped in 24.76s`**
  - **Authentication & Hardening (`tests/test_auth_hardening.py`):** `30 passed, 0 failed`
  - **Phase 1 Distributed OAuth & PKCE (`tests/test_phase1_distributed_auth.py`):** `9 passed, 0 failed`
    - Public & confidential PKCE (`S256`) clients, complete implicit-flow rejection, PKCE `code_verifier` server-side-only isolation, RSA-2048 JWKS OIDC ID-token verification, tampered/expired/replayed `state` & `nonce` rejection, zero JSON/`localStorage`/`sessionStorage` bearer tokens, `HttpOnly; SameSite=Lax; Secure` cookies, CSRF + multi-tab preservation, cross-instance revocation & restart persistence, 10-thread concurrent OAuth callback race (`1 x 200`, `9 x 400`), fail-closed unregistered session rejection, and 3LO OIDC account-mismatch (`HTTP 403 USER_MISMATCH`) rejection.
  - **Phase 2 Persistence, KMS Envelope & Multi-Instance (`tests/test_phase2_persistence_and_credentials.py`):** `6 passed, 0 failed, 1 skipped (BLOCKED)`
    - `test_phase2_multi_instance_11_step_workflow_and_restart_consistency`: **PASSED** (Full 11-step workflow across independent `Instance A` and `Instance B`, followed by full shutdown and fresh `Instance A2`/`B2` restart verification).
    - `test_phase2_concurrent_oauth_callbacks_and_concurrent_multi_instance_db_writes`: **PASSED** (8 concurrent OAuth callbacks -> `1 x 200`, `7 x 400`; 12 concurrent multi-instance DB writers across users, sessions, connections, and calibrations -> 0 lost writes).
    - `test_phase2_database_interruption_fail_closed_rollback_and_recovery`: **PASSED** (Mid-transaction exception rolls back atomically; simulated DB outage on `Instance B` fails closed with `HTTP 401` and `database_healthy: False`; DB restoration recovers immediately with zero data loss).
    - `test_phase2_kms_envelope_encryption_refresh_expiry_revocation_and_cross_tenant_isolation`: **PASSED** (Production fail-closed without `PQC_KMS_KEY_NAME`; `CloudKmsDekWrapper` AEAD wrapping + canonical AAD; zero plaintext in DB; server-side refresh rotation without frontend/ToolContext leakage; expiry & immediate cross-instance wipe on revocation; `PermissionError` on cross-user, cross-tenant, and raw SQL ciphertext-transplant attacks; SA impersonation allowlist validation).
    - `test_phase2_production_postgres_fail_closed_url_normalization_and_alembic_ddl`: **PASSED** (Rejects missing DB, `sqlite://` in production, `sqlite:///data/pqc_sessions.db` & `/data/*` everywhere, and unreachable PostgreSQL DSNs; validates Cloud SQL Auth Proxy `/cloudsql/...` socket args for both `psycopg` and `asyncpg`; validates Alembic online `upgrade head -> downgrade base -> upgrade head` and offline PostgreSQL DDL).
    - `test_phase2_safe_idempotent_data_migration_and_conflict_detection`: **PASSED** (Validates `--dry-run` rollback, exact row counts, SQL FK referential integrity with `0` orphans, cross-user duplicate session conflict rejection, orphan ADK event skipping, legacy plaintext token stripping, OAuth `client_secret` envelope encryption, SHA-256 source file immutability, and `0` new inserts on idempotent re-run).
    - `test_phase2_live_postgresql_multi_instance_integration`: **`BLOCKED` (reported as `SKIPPED` by pytest when `PQC_TEST_POSTGRES_URL` is unset)** — see Section 5 below.
  - **Core PQC Inventory & Deployment Config (`tests/test_pqc_inventory.py`):** `28 passed, 0 failed, 1 skipped (BLOCKED)`
    - `test_live_vertex_gemini_turn_reports_model_telemetry`: **`BLOCKED` / opt-in** (`PQC_LIVE_LLM_TEST!=1`, live Vertex AI billing/network gated).

### 4.2 Offline PostgreSQL Transactional DDL Verification (Alembic)
```bash
DATABASE_URL="postgresql+psycopg://pqc_app:placeholder@127.0.0.1:5432/pqc_workspace" .venv/bin/alembic upgrade head --sql
```
- **Exit Code:** `0` (`Context impl PostgresqlImpl`, `Will assume transactional DDL`, 201 lines of valid PostgreSQL SQL creating `alembic_version` and all 10 `pqc_*` tables, 19 indexes/unique constraints, and `FOREIGN KEY(user_id) REFERENCES pqc_tenant_users (user_id) ON DELETE CASCADE`).

---

## 5. Blocked Tests & Honest Environment Evidence

Per Section 1, Section 4, and Section 8 of `PHASE1.md`, blocked infrastructure tests are **never** reported as passed:

1. **Live Local PostgreSQL Server Execution (`test_phase2_live_postgresql_multi_instance_integration`, `PQC_TEST_POSTGRES_URL`) — `BLOCKED`:**
   - **Evidence:** Inspected workstation PATH, `/opt/homebrew`, `/usr/local`, `/Library/PostgreSQL`, and `/Applications`: `postgres`, `initdb`, `pg_ctl`, `psql`, `docker`, and `podman` are not installed on this corporate macOS host. Attempted installing embedded PostgreSQL (`pgserver==0.1.4`) into `.venv`, and Google corporate macOS **Santa** binary allowlisting terminated `pgserver/pginstall/bin/initdb` with `SIGKILL (9)` (`Reason: No matching rule`, `SHA-256: 9ca85ea1860c59199c3544879c777814b347bf925c0ec5fbf3d60cbbb5a7a5b4`).
   - **What Was Verified vs What Remains Blocked:** PostgreSQL SQLAlchemy dialect compilation (`postgresql+psycopg` & `postgresql+asyncpg`), Cloud SQL Unix socket connect-args translation, connection pool/timeout configuration, fail-closed unreachable-PostgreSQL startup ping, and Alembic `PostgresqlImpl` transactional DDL generation are **verified (`PASS`)**; multi-instance transactional semantics, concurrency, rollback, recovery, KMS envelope encryption, and data migration are **verified (`PASS`)** against shared file-backed SQLAlchemy engines; execution against a live running PostgreSQL 16 server process (`PQC_TEST_POSTGRES_URL`) is **`BLOCKED`** until run in a CI/staging environment with PostgreSQL or Cloud SQL access.
2. **Cloud Run + Cloud SQL + Cloud KMS Live Deployment Verification — `BLOCKED`:**
   - **Evidence:** Per `PHASE1.md` rules ("Do not deploy, migrate or modify production infrastructure") and absence of provisioned Cloud SQL / Cloud KMS staging resources in this offline session, live Cloud Run + Cloud SQL deployment verification is **`BLOCKED`**.
3. **Live Vertex AI LLM Turn (`test_live_vertex_gemini_turn_reports_model_telemetry`) — `BLOCKED` (Opt-In External Service):**
   - Gated behind `PQC_LIVE_LLM_TEST=1` requiring live Vertex AI credentials/quota.

---

## 6. Remaining Risks & Production Infrastructure Prerequisites

### Remaining Risks / Limitations
1. **Live PostgreSQL Staging Gate Required Before Production Cutover:** Before deploying Commit 2 to Cloud Run, CI/staging must execute `PQC_TEST_POSTGRES_URL="postgresql+psycopg://..." .venv/bin/pytest -v` against a disposable PostgreSQL 16 / Cloud SQL staging instance so `test_phase2_live_postgresql_multi_instance_integration` passes against live PostgreSQL row locks.
2. **Phase 3+ Out of Scope:** Per `PHASE1.md`, SSRF/egress hardening, Vertex AI model registry circuit-breaker resilience (`H6`/`H7`), scorecard denominator adjustments (`H8`), programmatic correlation schema validation (`H9`), untrusted prompt-boundary wrapping (`H10`), non-root container user (`A4`), and upload size/magic-byte guards (`A5`) belong to subsequent remediation phases and were intentionally not mixed into Phases 1–2.

### Production Infrastructure Prerequisites (Before Deployment)
1. **Cloud SQL for PostgreSQL 16 Instance:** Provision regional HA instance, database `pqc_workspace`, and least-privilege user `pqc_app`; attach to Cloud Run via `--add-cloudsql-instances=<PROJECT>:<REGION>:<INSTANCE>` and set `PQC_CLOUD_SQL_CONNECTION_NAME`.
2. **Google Secret Manager Secrets:** Create `pqc-session-secret` (`>= 32` random bytes -> `PQC_AUTH_SECRET`), `pqc-db-password` (`-> PQC_DB_PASSWORD`), and `pqc-oauth-client-secret` (`-> PQC_GOOGLE_OAUTH_CLIENT_SECRET`), granting secret-scoped `roles/secretmanager.secretAccessor` to the runtime SA.
3. **Google Cloud KMS Symmetric CryptoKey (`PQC_KMS_KEY_NAME`):** Create dedicated HSM-backed key `projects/<PROJECT>/locations/<REGION>/keyRings/pqc-portal-kr/cryptoKeys/pqc-cred-kek` with 90-day rotation and grant key-scoped `roles/cloudkms.cryptoKeyEncrypterDecrypter` ONLY on this key to the runtime SA.
4. **Cloud IAP Audience (`PQC_IAP_AUDIENCE`):** Set exact `/projects/<NUMBER>/locations/<REGION>/services/<SERVICE>` string on Cloud Run.
5. **Schema & Data Migration:** Follow [`docs/security-remediation/MIGRATION_AND_ROLLBACK.md`](../../docs/security-remediation/MIGRATION_AND_ROLLBACK.md) (`alembic upgrade head` + `--dry-run` + idempotent `scripts/migrate_sqlite_to_postgres.py`).
