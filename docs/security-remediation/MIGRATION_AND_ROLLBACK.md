# Cloud SQL PostgreSQL Architecture, Credential Envelope Design, Migration & Rollback Runbook

## 1. Architecture Overview (Phase 2 Remediation)

All process-local caches (`InMemoryCredentialService`, `_SESSION_METADATA_CACHE`, `_TENANT_USERS_CACHE`, `_USER_CONNECTIONS`), SQLite-on-GCS-FUSE configurations (`sqlite:///data/pqc_sessions.db`, `--add-volume=name=pqc-data,type=cloud-storage`), and authoritative local JSON/JSONL files have been eliminated from production.

### 1.1 Authoritative Relational Schema (`PqcPersistenceBase` + Google ADK `v1`)

| Table | Engine / Driver | Purpose & Ownership Enforcement |
| :--- | :--- | :--- |
| `alembic_version` & `pqc_schema_metadata` | `postgresql+psycopg` | Tracks applied Alembic schema revisions (head revision `20261117_0002`). |
| `pqc_oauth_transactions` | `postgresql+psycopg` | Ephemeral server-side OAuth 2.0 + PKCE (`code_verifier`), OIDC `nonce`, browser binding SHA-256 hash, redirect URI, and atomic single-use `consumed_at` guard. |
| `pqc_consumed_nonces` | `postgresql+psycopg` | Primary-key-enforced single-use replay prevention for OIDC `nonce` claims and authorization codes. |
| `pqc_auth_sessions` | `postgresql+psycopg` | Server-side session allowlist & immediate cross-instance revocation registry keyed by `jti` and `token_sha256`. |
| `pqc_tenant_users` | `postgresql+psycopg` | Authoritative corporate user profiles isolated by `user_id` and `tenant_domain`. |
| `pqc_session_metadata` | `postgresql+psycopg` | Conversation titles, scopes, attachment index, and model telemetry with `FOREIGN KEY (user_id) REFERENCES pqc_tenant_users(user_id) ON DELETE CASCADE`. |
| `pqc_user_connections` | `postgresql+psycopg` | Non-secret per-user GCP connection config (`adc`, `impersonation`, `access_token`). |
| `pqc_oauth_client_configs` | `postgresql+psycopg` | Administrator-managed OAuth 2.0 client ID and envelope-encrypted client secret. |
| `pqc_calibration_events` | `postgresql+psycopg` | Longitudinal Mosca (`X + Y > Z`) calibration ledger keyed by `scope`, `user_id`, and `tenant_domain` (`event_uuid` unique). |
| `pqc_delegated_credentials` | `postgresql+psycopg` | Cloud KMS AES-256-GCM envelope-encrypted delegated OAuth credentials bound via AAD (`app_name\|tenant\|user_id\|key`). |
| `sessions`, `events`, `app_states`, `user_states` | `postgresql+asyncpg` | Native Google ADK `DatabaseSessionService` tables storing conversation events and agent state. |

**Cloud Storage (`GcsArtifactService`)** is reserved strictly for object storage of uploaded assessment attachments and generated reports (`PQC_ARTIFACT_BUCKET=gs://<bucket>`). Cloud Storage FUSE (`/data`) is never used for database or session storage; `validate_production_postgres_only()` fails closed at startup if `DATABASE_URL` / `SESSION_DB_URL` is missing, points to `sqlite://`, targets `/data`, or fails a live `SELECT 1` connectivity check.

---

## 2. Selected Credential Architecture & Security Justification (`ID-01`)

### 2.1 Dual-Tier Identity Design
1. **Primary / Preferred Tier — Keyless Service Account Impersonation (`mode="impersonation"` or `"adc"`):**
   - When assessing customer organizations or folders with a dedicated read-only scanner Service Account (`pqc-scanner-sa@<project>.iam.gserviceaccount.com`), the portal requests short-lived (`<= 3600s`), read-only (`https://www.googleapis.com/auth/cloud-platform.read-only`) access tokens on demand via IAM Credentials API / `gcloud --impersonate-service-account`.
   - Enforces `validate_impersonated_service_account()` against `PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS` (exact email or `@<project>.iam.gserviceaccount.com` suffix allowlist).
   - Zero long-lived user credentials or static JSON keys are persisted.
2. **Alternative Tier — Cloud KMS Envelope-Encrypted Delegated Credentials (`EncryptedDatabaseCredentialService`):**
   - Required **only** when user-specific 3-Legged OAuth (3LO) authorization is explicitly chosen so GCP Cloud Audit Logs attribute read-only inventory queries directly to the individual consultant/architect's Google identity rather than a shared scanner Service Account.
   - Replaces `google.adk.auth.credential_service.InMemoryCredentialService` across all Cloud Run instances.
   - **Envelope Encryption (`pqc_agent/credential_service.py`):**
     1. Generates a fresh 256-bit random Data Encryption Key (DEK) and 96-bit GCM IV (`secrets.token_bytes`) per write.
     2. Encrypts `{access_token, refresh_token, client_id, client_secret, scopes}` with `AES-256-GCM` bound to canonical Additional Authenticated Data (`AAD = pqc-cred-v1|app=<app>|tenant=<domain>|user=<uid>|key=<cred_key>`).
     3. Wraps the DEK via **Google Cloud KMS** (`KeyManagementServiceClient.encrypt` / `decrypt` on `PQC_KMS_KEY_NAME`) passing the exact same `AAD` (`additional_authenticated_data`), preventing cross-user or cross-tenant row transplant even under full database read/write compromise.
     4. Zeroizes plaintext DEK buffers in `finally:` blocks after encryption/decryption.
     5. Enforces strict `expires_at` checks, performs server-side refresh-token rotation when available, never returns `refresh_token` or `client_secret` to the frontend or `ToolContext`, passes `CLOUDSDK_AUTH_ACCESS_TOKEN` exclusively via in-memory subprocess environment (zero `mkstemp` token files on disk), and wipes `ciphertext_b64` + `wrapped_dek_b64` immediately upon `/api/auth/logout` or revocation.
     6. Production fails closed (`RuntimeError`) if `PQC_KMS_KEY_NAME` is unset; deterministic HKDF-SHA256 local KEK wrapping is restricted strictly to non-production local development and unit tests.

---

## 3. Cloud SQL Connectivity, Secret Manager & Least-Privilege IAM

### 3.1 Cloud SQL Instance Provisioning (Prerequisite)
```bash
gcloud sql instances create pqc-postgres-prod \
  --database-version=POSTGRES_16 \
  --tier=db-custom-2-8192 \
  --availability-type=REGIONAL \
  --storage-auto-increase \
  --backup-start-time=03:00 \
  --enable-point-in-time-recovery \
  --region="${REGION}" \
  --project="${PROJECT_ID}"

gcloud sql databases create pqc_workspace \
  --instance=pqc-postgres-prod \
  --project="${PROJECT_ID}"

gcloud sql users create pqc_app \
  --instance=pqc-postgres-prod \
  --password="${DB_PASSWORD_FROM_CSPRNG}" \
  --project="${PROJECT_ID}"
```

### 3.2 Cloud Run Connectivity Modes
- **Cloud SQL Auth Proxy Unix Socket (Default on Cloud Run Gen2):**
  - Deploy flag: `--add-cloudsql-instances="${PROJECT_ID}:${REGION}:pqc-postgres-prod"`
  - Env vars:
    - `PQC_CLOUD_SQL_CONNECTION_NAME="${PROJECT_ID}:${REGION}:pqc-postgres-prod"`
    - `PQC_DB_NAME="pqc_workspace"`
    - `PQC_DB_USER="pqc_app"`
    - `PQC_DB_PASSWORD` mounted from Secret Manager (`--set-secrets=PQC_DB_PASSWORD=pqc-db-password:latest`).
  - `pqc_agent.auth_store` automatically builds both `postgresql+psycopg://pqc_app:***@/pqc_workspace?host=/cloudsql/<CONN_NAME>` and `postgresql+asyncpg://pqc_app:***@/pqc_workspace?host=/cloudsql/<CONN_NAME>`.
- **Direct Private IP + TLS (VPC Connector / Direct VPC Egress):**
  - Set `DATABASE_URL="postgresql+psycopg://pqc_app:<PASSWORD>@<PRIVATE_IP>:5432/pqc_workspace?sslmode=require"` via Secret Manager.

### 3.3 Secret Manager & Cloud KMS Setup
1. **Secrets in Secret Manager (never placed in `Dockerfile`, `app.yaml`, or `.env.example`):**
   - `pqc-session-secret` -> `PQC_AUTH_SECRET` (>= 32 bytes CSPRNG base64url)
   - `pqc-db-password` -> `PQC_DB_PASSWORD`
   - `pqc-oauth-client-secret` -> `PQC_GOOGLE_OAUTH_CLIENT_SECRET` (when confidential 3LO client is enabled)
2. **Cloud KMS Key Encryption Key (`PQC_KMS_KEY_NAME`):**
   ```bash
   gcloud kms keyrings create pqc-portal-kr --location="${REGION}" --project="${PROJECT_ID}"
   gcloud kms keys create pqc-cred-kek \
     --keyring=pqc-portal-kr \
     --location="${REGION}" \
     --purpose=encryption \
     --protection-level=hsm \
     --rotation-period=90d \
     --next-rotation-time="$(date -u -v+90d +%Y-%m-%dT%H:%M:%SZ)" \
     --project="${PROJECT_ID}"
   ```
3. **Least-Privilege Runtime Service Account IAM Roles:**
   - Host Project: `roles/cloudsql.client`, `roles/aiplatform.user`, `roles/serviceusage.serviceUsageConsumer`.
   - Secret-scoped (per secret, NOT project-wide): `roles/secretmanager.secretAccessor` on `pqc-session-secret`, `pqc-db-password`, `pqc-oauth-client-secret`.
   - Key-scoped (ONLY on `pqc-cred-kek`, NEVER org-wide): `roles/cloudkms.cryptoKeyEncrypterDecrypter`.
   - Target Assessment Scope (Org/Folder): read-only `roles/cloudasset.viewer`, `roles/cloudkms.viewer`, `roles/resourcemanager.organizationViewer`, `roles/compute.viewer`, `roles/privateca.auditor`.

---

## 4. Schema Migration & Safe Data Migration Procedure (`DB-01` / `DB-04`)

> **CRITICAL:** Never run untested migrations directly against production without completing Steps 4.1 and 4.2 on a staging copy first. The migration tool opens legacy files strictly read-only (`?mode=ro`) and verifies SHA-256 checksums before and after execution.

### 4.1 Step 1 — Immutable Backup Snapshot of Legacy State & Target PostgreSQL
```bash
mkdir -p ./backups/pre_phase2_$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="./backups/pre_phase2_$(date -u +%Y%m%dT%H%M%SZ)"

# 1. Copy legacy GCS / local SQLite & JSON files to an immutable backup prefix
gcloud storage cp -r "gs://${BUCKET_NAME}/*" "${BACKUP_DIR}/gcs_snapshot/"
shasum -a 256 $(find "${BACKUP_DIR}" -type f) > "${BACKUP_DIR}/SHA256SUMS.txt"

# 2. Take an on-demand Cloud SQL backup before applying schema/data changes
gcloud sql backups create \
  --instance=pqc-postgres-prod \
  --description="Pre-Phase-2 schema and data migration snapshot" \
  --project="${PROJECT_ID}"
```

### 4.2 Step 2 — Apply Versioned Schema Migrations (Alembic)
```bash
# Preview generated PostgreSQL transactional DDL offline (zero DB mutations):
DATABASE_URL="postgresql+psycopg://pqc_app:placeholder@127.0.0.1:5432/pqc_workspace" \
  .venv/bin/alembic upgrade head --sql > "${BACKUP_DIR}/planned_schema_upgrade.sql"

# Apply online against target PostgreSQL database via the explicit single-runner migration entry point
# (enforces PostgreSQL backend, acquires pg_try_advisory_lock, upgrades to head 20261117_0002, and verifies schema):
DATABASE_URL="${TARGET_POSTGRES_URL}" .venv/bin/python scripts/run_db_migrations.py --require-postgres

# Optional read-only verification gate prior to starting Cloud Run revisions:
DATABASE_URL="${TARGET_POSTGRES_URL}" .venv/bin/python scripts/run_db_migrations.py --require-postgres --verify-only
```

### 4.3 Step 3 — Dry-Run Data Migration & Anomaly Inspection
```bash
.venv/bin/python scripts/migrate_sqlite_to_postgres.py \
  --source-sqlite "${BACKUP_DIR}/gcs_snapshot/pqc_sessions.db" \
  --source-data-dir "${BACKUP_DIR}/gcs_snapshot" \
  --target-db-url "${TARGET_POSTGRES_URL}" \
  --dry-run \
  --report-json "${BACKUP_DIR}/dry_run_report.json" \
  --report-md "${BACKUP_DIR}/dry_run_report.md"
```
Verify in `dry_run_report.md`:
- `Status: DRY_RUN_OK`
- `Source Files Untouched (SHA-256 Verified): True`
- `Orphan Session Metadata Rows: 0` and `Orphan ADK Event Rows: 0`
- Review any `CROSS_USER_SESSION_ID_CONFLICT` or `PLAINTEXT_TOKEN_STRIPPED` warnings.

### 4.4 Step 4 — Execute Idempotent Migration & Verify Counts
```bash
.venv/bin/python scripts/migrate_sqlite_to_postgres.py \
  --source-sqlite "${BACKUP_DIR}/gcs_snapshot/pqc_sessions.db" \
  --source-data-dir "${BACKUP_DIR}/gcs_snapshot" \
  --target-db-url "${TARGET_POSTGRES_URL}" \
  --allow-production-target \
  --report-json "${BACKUP_DIR}/final_migration_report.json" \
  --report-md "${BACKUP_DIR}/final_migration_report.md"
```
Because `migrate_sqlite_to_postgres.py` is strictly idempotent, re-running it produces `inserted: 0` and `already_present_or_updated: N` with zero duplicate rows.

---

## 5. Rollback Procedure

If a post-deployment health check (`/api/health`), authentication check, or data verification fails:

1. **Immediate Traffic Rollback on Cloud Run (< 30 seconds):**
   ```bash
   gcloud run services update-traffic agentic-pqc \
     --to-revisions="${PREVIOUS_REVISION_NAME}=100" \
     --region="${LOCATION}" \
     --project="${PROJECT_ID}"
   ```
   Because legacy SQLite and JSON files were **never deleted or modified** during migration (verified by `SHA256SUMS.txt`), the previous revision's data files remain intact in `${BACKUP_DIR}` / GCS snapshot if emergency rollback is required.
2. **Database Schema / Point-in-Time Rollback on Cloud SQL:**
   - **Schema-only rollback** (on an empty/staging database):
     ```bash
     DATABASE_URL="${TARGET_POSTGRES_URL}" .venv/bin/alembic downgrade base
     ```
   - **Full transactional data restore** (from the Step 4.1 pre-migration Cloud SQL backup ID or PITR timestamp):
     ```bash
     gcloud sql backups restore "${PRE_MIGRATION_BACKUP_ID}" \
       --restore-instance=pqc-postgres-prod \
       --project="${PROJECT_ID}"
     ```
3. **Emergency Credential & Session Revocation (if compromise is suspected):**
   - Rotate `pqc-session-secret` in Secret Manager to invalidate all signed cookies across every Cloud Run instance simultaneously.
   - Disable or rotate the Cloud KMS key version on `PQC_KMS_KEY_NAME` to immediately render all wrapped DEKs in `pqc_delegated_credentials` undecryptable (fail-closed).

---

## 6. Corrective Pass Update — Exclusive Alembic Production Schema Authority (`DB-01`)

- **Original Finding & Root Cause:** Application startup previously called SQLAlchemy `metadata.create_all()` via `DistributedAuthStore.ensure_schema()` and Google ADK `DatabaseSessionService.prepare_tables()`, risking unversioned table creation ahead of Alembic.
- **Corrective Implementation:**
  1. Added Alembic revision `20261117_0002_add_adk_v1_session_schema.py` (revising `20261117_0001`) so all 10 `pqc_*` tables and all 5 ADK `v1` session tables (`adk_internal_metadata`, `sessions`, `events`, `app_states`, `user_states`) are owned exclusively by Alembic (`EXPECTED_ALEMBIC_REVISION = "20261117_0002"`).
  2. Prohibited `metadata.create_all()` in production across `DistributedAuthStore`, `ManagedSchemaDatabaseSessionService`, and `migration_tool.py`; production startup performs read-only `verify_alembic_schema_on_engine()` and fails closed if `alembic_version` is missing, outdated, or inconsistent.
  3. Added `scripts/run_db_migrations.py` and wired a serialized single-task Cloud Run Job (`--tasks=1 --max-retries=0` + PostgreSQL advisory lock `7081632026`) in `scripts/deploy_cloud_run.sh` so schema upgrades run explicitly before application containers start and never execute concurrently across Cloud Run instances.
- **Verification Status:** Automated schema-authority regression suite (`test_phase2_alembic_sole_production_schema_authority_and_migration_cli`): **`PASS`** | Live PostgreSQL 16 staging execution (`PQC_TEST_POSTGRES_URL`): **`BLOCKED`** (`NO-GO` for production cutover until executed in CI/staging).
