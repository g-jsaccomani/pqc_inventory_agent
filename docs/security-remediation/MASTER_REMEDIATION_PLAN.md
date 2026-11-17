# PQC Inventory Agent — Master Security Remediation Plan (Phase 0 Baseline)

- **Repository:** `https://github.com/g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/2026-11`
- **Baseline Commit:** `2449589` (`feat(auth): add auto corporate gcloud session detection, GIS One-Tap & Gemini multi-account switcher`)
- **Assessment Date:** `2026-11-17`
- **Scope:** Authoritative code-level audit of `pqc_agent/`, `tools/`, `Dockerfile`, `requirements.txt`, `scripts/`, and `tests/` prior to remediation phases 1–6.

---

## 1. Executive Summary & Actual Architecture

The PQC Inventory Agent is a FastAPI + Google Agent Development Kit (`google-adk==1.31.0`) multi-agent workspace served by `pqc_agent/workspace_server.py` and `pqc_agent/portal_ui.py`.

1. **Authentication & Identity (`pqc_agent/auth_guard.py`, `pqc_agent/workspace_server.py`):**
   - Supports Cloud IAP JWT verification (`X-Goog-IAP-JWT-Assertion` via `auth_guard.verify_iap_jwt`), Google OIDC/OAuth 2.0 (`_verify_google_oauth_or_id_token`), OAuth 2.0 3-Legged OAuth (3LO) delegation (`/api/auth/oauth/authorize`, `/api/auth/oauth/callback`), and a cross-origin Google Identity Bridge popup (`/api/auth/bridge`).
   - Issues HMAC-SHA256 signed session tokens (`sign_tenant_session_token`, 30-day TTL) stored both in an `HttpOnly; SameSite=lax` cookie (`pqc_session_token`) and returned in the JSON body (`token`), which `pqc_agent/portal_ui.py` persists in `localStorage`.
2. **Persistence (`pqc_agent/workspace_server.py`, `tools/gcloud_bridge.py`, `tools/calibration_engine.py`):**
   - Uses ADK `DatabaseSessionService` backed by SQLite (`SESSION_DB_URL=sqlite:///data/pqc_sessions.db`, mapped to `sqlite+aiosqlite` with WAL mode and `busy_timeout=30000`).
   - Deployment scripts (`scripts/deploy_cloud_run.sh`, `scripts/setup_and_deploy_vertex.sh`) mount a Cloud Storage bucket (`gs://<bucket>`) at `/data` via Cloud Run Gen2 GCS FUSE (`--add-volume=name=pqc-data,type=cloud-storage`).
   - Session metadata (`pqc_session_metadata.json` + `/data/tenants/<uid>/sessions/<sid>.json`), tenant user profiles (`pqc_tenant_users.json` + `/data/tenants/<uid>/profile.json`), non-secret connection configs (`pqc_user_connections.json` + `/data/tenants/<uid>/connection.json`), and Mosca calibration history (`/data/calibration-history.jsonl`) are stored as files on `/data` with process-local in-memory caches (`_SESSION_METADATA_CACHE`, `_TENANT_USERS_CACHE`, `_USER_CONNECTIONS`).
3. **Model Registry & Execution (`pqc_agent/model_registry.py`, `pqc_agent/agent.py`):**
   - `ModelRegistry` probes candidate Gemini Pro models on Vertex AI via `vertex_generate_probe` and overwrites `self._results[model]` in place (`_verify_one`), filtering the active catalog (`verified_entries`) strictly to `result["available"] == True`.
4. **PQC Collectors, Scoring & AI Inputs (`tools/gcp_inventory.py`, `tools/pqc_detectors.py`, `tools/calibration_engine.py`, `tools/gcloud_bridge.py`):**
   - Collects Cloud KMS keys, KMS ImportJobs, Compute SSL policies/target proxies, CAI crypto assets, and CAI workload CMEK references.
   - `compute_scorecard_from_keys` computes deterministic KMS ratios and `weighted_kms_pqc_maturity`, renormalizing weights across non-zero denominators.
   - Uploaded documents (`PDF`, `DOCX`, `CSV`, `PEM/CRT`, `TXT`) are extracted via `extract_text_from_uploaded_bytes` and appended directly into the user `types.Content` prompt (`chat_with_multimodal_uploads`).

---

## 2. Investigation of the 10 Security & Reliability Hypotheses

Each hypothesis is classified strictly as **CONFIRMED IN CODE**, **CONFIGURATION-DEPENDENT**, or **NOT VERIFIED**, with exact file/line evidence.

| # | Hypothesis | Classification | Severity | Primary Evidence (`file:lines`) |
|---|---|---|---|---|
| **H1** | OAuth popup may send authentication data using wildcard `postMessage` origin | **CONFIRMED IN CODE** | **Critical (P0)** | `pqc_agent/workspace_server.py:2381-2387` (`GET /api/auth/bridge` calls `window.opener.postMessage(msg, '*')` carrying Google OAuth `access_token` or OIDC `credential` JWT); `pqc_agent/workspace_server.py:1505,1538,2004` (`_oauth_popup_result_html` and `_OAUTH_IMPLICIT_CALLBACK_HTML` send `content` containing signed `token` via `postMessage`); `pqc_agent/portal_ui.py:3170-3216` does not verify `event.source === expectedPopupWindow`. |
| **H2** | Session bearer token may be exposed through `localStorage` | **CONFIRMED IN CODE** | **High (P0)** | `pqc_agent/portal_ui.py:2063,2082,2129,2438,2609,2736` and `pqc_agent/workspace_server.py:1547,2004,2104,2210,2278,2614` store `pqc_session_token` (and multi-account tokens in `pqc_saved_accounts`) in `localStorage` and transmit it via `X-PQC-User-Token`. In addition, `/api/auth/logout` (`workspace_server.py:2181-2188`) only deletes the browser cookie without server-side token revocation, and state-changing POST/DELETE endpoints lack CSRF token/origin validation when cookie auth is used. |
| **H3** | SQLite may be stored on a Cloud Storage FUSE mount | **CONFIRMED IN CODE** (in deployment scripts & `Dockerfile`) | **High (P1)** | `Dockerfile:30` sets `SESSION_DB_URL=sqlite:///data/pqc_sessions.db`; `scripts/deploy_cloud_run.sh:146-168` and `scripts/setup_and_deploy_vertex.sh:89-99` mount GCS bucket `${BUCKET_NAME}` at `/data` via Cloud Run Gen2 GCS FUSE while setting `SESSION_DB_URL=sqlite:///data/pqc_sessions.db`. SQLite WAL/POSIX file locking over GCS FUSE is unsupported and risks database corruption under concurrent writes or multi-instance scaling. |
| **H4** | Session/user metadata may rely on local files or process-local state | **CONFIRMED IN CODE** | **High (P1)** | `pqc_agent/workspace_server.py:287-290,363-403,495-531` caches `_SESSION_METADATA_CACHE` and `_TENANT_USERS_CACHE` in process memory (never invalidated after initial load) and writes JSON files under `/data` using `threading.RLock()` (`_STORAGE_LOCK`), which only synchronizes threads within a single process. `tools/calibration_engine.py:44,194` caches `_UPLOADED_ARTIFACT_CACHE` in process memory and appends to `/data/calibration-history.jsonl` without cross-instance locking. |
| **H5** | Delegated Google credentials may exist only in process memory | **CONFIRMED IN CODE** | **High (P1)** | `tools/gcloud_bridge.py:181-194,351-361,406-430` stores `access_token` only in the process-local `_USER_CONNECTIONS` dictionary (`_SECRET_CONNECTION_KEYS` are stripped before disk persistence), and `pqc_agent/workspace_server.py:1761` uses `InMemoryCredentialService()`. Container restarts or load-balancing across >1 instance drop delegated credentials; furthermore, `/api/connection` (`workspace_server.py:3293-3307`) and `/api/chat` (`workspace_server.py:3078-3093`) allow setting `impersonated_service_account` or `access_token` without verifying target service account allowlists. |
| **H6** | Transient Vertex AI probe failures may remove models from the catalog | **CONFIRMED IN CODE** | **High (P1)** | `pqc_agent/model_registry.py:128-144,199-207` (`ModelRegistry._verify_one` and `verified_entries`): any single failed probe (`429`, `503`, deadline exceeded) overwrites `self._results[cand["model"]]["available"] = False`, immediately removing the model from `verified_entries()`, `default_entry()`, and `resolve()`. Configured models are conflated with runtime probe availability. |
| **H7** | Retry/fallback policies may be missing or unsafe | **CONFIRMED IN CODE** | **High (P1)** | `pqc_agent/model_registry.py:69-95` (`vertex_generate_probe`) and `pqc_agent/workspace_server.py:3158-3206` (`chat_with_multimodal_uploads`) have no per-probe timeout enforcement, no transient error classification (`429`/`503` vs `401`/`403`/`400`), no exponential backoff with jitter/`Retry-After`, no circuit breaker, and no controlled model fallback policy. |
| **H8** | PQC maturity/coverage claims may exceed collector coverage | **CONFIRMED IN CODE** | **Medium-High (P1)** | `tools/gcp_inventory.py:1085-1135` (`compute_scorecard_from_keys`): (1) `SCORECARD_WEIGHTS` renormalizes over non-zero denominators (`available = {name: w ... if metrics[name]["denominator"]}`), so a scope with 0 asymmetric keys and 1 quantum-resistant symmetric key scores `100.0%` on `weighted_kms_pqc_maturity`; (2) `unknown` keys (`UNKNOWN_REQUIRES_REVIEW`) are counted in denominators without blocking high maturity claims or exposing unassessed service coverage gaps (e.g., application-layer crypto libraries, external/on-prem HSMs, GKE internal mTLS, Cloud SQL internal TLS) in a structured coverage matrix. |
| **H9** | Evidence confidence may rely too heavily on LLM instructions | **CONFIRMED IN CODE** | **High (P1)** | `tools/gcp_inventory.py:863-968` (`collect_workload_evidence`) returns raw `workloads` and `cmek_references` without programmatic correlation classification, delegating `STRONG` / `MEDIUM` / `WEAK` confidence grading entirely to LLM prompt instructions in `pqc_agent/agent.py:84-87,139-144`. There is no deterministic evidence schema separating `CONFIRMED_OBSERVATION`, `INFERENCE`, `UNKNOWN`, `NOT_ASSESSED`, and `COLLECTION_FAILURE`. |
| **H10** | Indirect prompt injection defenses may be incomplete | **CONFIRMED IN CODE** | **High (P1)** | `pqc_agent/workspace_server.py:3121-3156` injects raw uploaded file bytes/extracted text (`extract_text_from_uploaded_bytes` in `tools/calibration_engine.py:268-333`) and GCP resource names/labels directly into the user turn without structural untrusted-data delimiters or sanitization; `pqc_agent/agent.py` lacks explicit untrusted-data isolation boundaries; `tools/gcloud_bridge.py:532-629` (`validate_gcloud_command`) enforces read-only verbs and blocks `--impersonate-service-account`, but does not enforce that the `--project` / `--organization` arguments in `execute_gcloud_command` match the tenant's authorized scope, and allows reading secret metadata (`gcloud secrets list/describe`). |

### Additional Baseline Security Findings (Auth, Secrets, Supply Chain & Uploads)

- **A1 — Ephemeral HMAC Fallback in Production (`CONFIGURATION-DEPENDENT`, High / P0):**
  - `pqc_agent/auth_guard.py:193-244` (`load_or_create_hmac_secret`): if `PQC_AUTH_SECRET` is unset in production (`K_SERVICE` set), the server falls back to `<data_dir>/.pqc_auth_secret` or generates an ephemeral random key (`secrets.token_hex(32)`) instead of failing closed.
- **A2 — Optional IAP Audience Verification (`CONFIGURATION-DEPENDENT`, High / P0):**
  - `pqc_agent/auth_guard.py:352-394` (`verify_iap_jwt`): when `PQC_IAP_AUDIENCE` is unset, `expected_audience` is `None` and `verify_iap_jwt` logs a warning (`PQC_IAP_AUDIENCE is not set: the IAP JWT audience is not checked`) instead of rejecting the assertion in production.
- **A3 — Auto Workstation `gcloud` Token Inheritance (`CONFIRMED IN CODE`, Medium-High / P0):**
  - `pqc_agent/workspace_server.py:817-856,2190-2236` (`_try_workstation_auto_gcloud_token` & `POST /api/auth/auto`): when `K_SERVICE` is unset and `PQC_AUTO_WORKSTATION_GCLOUD_AUTH` is not `false`, any unauthenticated caller reaching `/api/auth/auto` causes the server to run `gcloud auth print-access-token` on the host workstation and sign the caller in as the workstation owner.
- **A4 — Container Runs as Root & Unpinned Lockfile (`CONFIRMED IN CODE`, Medium / P2):**
  - `Dockerfile:1-47` has no non-root `USER` directive (runs as `root` UID 0) and installs from loose lower-bound ranges in `requirements.txt` (`pip install --no-cache-dir -r requirements.txt`) with no committed `uv.lock` or hash-pinned lockfile.
- **A5 — Unbounded Upload Size & Missing Content Validation (`CONFIRMED IN CODE`, Medium-High / P2):**
  - `pqc_agent/workspace_server.py:3121-3137` calls `raw_bytes = await up_file.read()` with no byte-size limit, no extension/magic-byte allowlist validation, no filename path-traversal normalization before passing `fname` to `save_artifact`, and no protection against decompression bombs in `.docx` (ZIP) or malformed PDFs.

---

## 3. Phased Remediation Plan

### Phase 1 — OAuth and Authentication (`P0`)
- **Target Files:** `pqc_agent/auth_guard.py`, `pqc_agent/workspace_server.py`, `pqc_agent/portal_ui.py`, `tests/test_auth_hardening.py`.
- **Remediations:**
  1. **Eliminate Wildcard `postMessage` & Credential Delivery via Popup Messages (`H1`):**
     - Remove `window.opener.postMessage(msg, '*')` from `/api/auth/bridge` (`workspace_server.py:2385`). Require an explicit allowlisted origin validated server-side.
     - Never transmit `token`, `access_token`, `id_token`, or `credential` in `postMessage` payloads (`_oauth_popup_result_html`, `_OAUTH_IMPLICIT_CALLBACK_HTML`, `/api/auth/bridge`). Popup completion messages must send only non-sensitive completion status (`{type, ok, mode}`), after the server has already set the `HttpOnly` session cookie.
     - In `portal_ui.py:3170-3216`, track the popup `WindowProxy` reference (`activeAuthPopupWindow`), verify `event.source === activeAuthPopupWindow` and exact `event.origin === window.location.origin` (or configured bridge origin), and refresh auth state via `GET /api/auth/me` with `credentials: "same-origin"`.
  2. **OAuth 2.0 Authorization Code + PKCE & Strict Validation (`H1`):**
     - Add PKCE (`code_verifier` stored in signed/encrypted HttpOnly nonce cookie, `code_challenge` + `code_challenge_method=S256` on `/api/auth/oauth/signin` and `/api/auth/oauth/authorize`) and pass `code_verifier` during `_exchange_oauth_code`.
     - Bind OIDC `nonce` claim inside the OAuth state and verify it on ID tokens.
  3. **Remove `localStorage` Session Bearer Tokens & Harden Session Lifecycle (`H2`):**
     - Stop storing `pqc_session_token` or `pqc_saved_accounts` bearer tokens in `localStorage` (`portal_ui.py`). Rely on `HttpOnly; SameSite=Lax; Secure` cookies (`pqc_session_token`).
     - Add CSRF protection (`X-PQC-CSRF-Token` double-submit/session-bound token + strict `Origin`/`Sec-Fetch-Site` validation on all state-changing `POST`/`PUT`/`DELETE` `/api/*` requests).
     - Add a unique `jti` (token ID) + session generation counter/revocation store so `/api/auth/logout` revokes the token server-side and login rotates the session ID (preventing session fixation).
     - Disable `_try_workstation_auto_gcloud_token` unless an explicit opt-in flag (`PQC_ENABLE_WORKSTATION_GCLOUD_AUTOLOGIN=true`) is set in local development.
  4. **Fail-Closed Secret & IAP Audience Enforcement in Production (`A1`, `A2`):**
     - In `auth_guard.load_or_create_hmac_secret`, raise `RuntimeError` (fail closed) when `running_on_cloud_run()` (or `PQC_ENV=production`) and `PQC_AUTH_SECRET` is missing or `< 32` bytes.
     - In `auth_guard.verify_iap_jwt`, require `PQC_IAP_AUDIENCE` when `running_on_cloud_run()` (or when IAP is active), rejecting assertions with missing or mismatched `aud`.
- **Regression Risks & Validation:** Existing tests in `tests/test_auth_hardening.py` and `tests/test_pqc_inventory.py` that pass `X-PQC-User-Token` or inspect `portal_ui.py` strings must be checked; add comprehensive unit/integration tests for all Phase 1 controls.

### Phase 2 — Persistence and Distributed GCP Identity (`P1`)
- **Target Files:** `pqc_agent/workspace_server.py`, `tools/gcloud_bridge.py`, `tools/calibration_engine.py`, `scripts/migrate_sqlite_to_postgres.py` (new), `requirements.txt`, deployment docs/scripts.
- **Remediations:**
  1. **Transactional Database Persistence (`H3`, `H4`):**
     - Support Cloud SQL PostgreSQL (`postgresql+asyncpg://` / `postgresql+psycopg://`) in `create_workspace_app` with bounded SQLAlchemy pool settings (`pool_size`, `max_overflow`, `pool_timeout`, `pool_pre_ping`), statement timeouts, and health checks.
     - Fail closed in production if `SESSION_DB_URL` points to SQLite or a GCS FUSE path (`/data/*.db`); restrict SQLite strictly to local development/testing on local disk.
     - Move session metadata, tenant profiles, and calibration records out of unsynchronized JSON files into transactional database tables (with SQLite compatibility for local dev/tests).
  2. **Idempotent Migration Utility:**
     - Create an idempotent migration script/module from legacy SQLite (`pqc_sessions.db`) + JSON metadata (`pqc_session_metadata.json`, `pqc_tenant_users.json`, `pqc_user_connections.json`, `calibration-history.jsonl`) to the relational schema with referential-integrity and row-count verification.
  3. **Distributed Delegated GCP Credential Store (`H5`):**
     - Replace process-local `_USER_CONNECTIONS` token storage with encrypted-at-rest persistence in the database (envelope encryption / Fernet with KMS/Secret Manager key), strict owner/tenant binding, TTL expiry, and immediate revocation on logout.
- **Validation:** Multi-instance isolation tests (Instance A / Instance B), concurrent update tests, rollback/reconnect tests, and migration idempotency tests.

### Phase 3 — Vertex AI Model Registry and Resilience (`P1`)
- **Target Files:** `pqc_agent/model_registry.py`, `pqc_agent/workspace_server.py`, `tests/test_model_resilience.py` (new).
- **Remediations:**
  1. **Decouple Configured Catalog from Runtime Health (`H6`):**
     - Introduce explicit states (`CONFIGURED`, `UNKNOWN`, `AVAILABLE`, `DEGRADED`, `TEMPORARILY_UNAVAILABLE`, `AUTHENTICATION_FAILED`, `PERMISSION_DENIED`, `INVALID_CONFIGURATION`, `DISABLED`).
     - Preserve last-known-good verification state (`stale-while-revalidate`) so transient probe failures (`429`, `503`, timeout) never delete a configured model from the catalog.
  2. **Bounded Retries, Circuit Breaker & Allowlisted Fallback (`H7`):**
     - Classify Vertex AI errors (`400`, `401`, `403`, `404`, `408`, `429`, `5xx`, network/timeout, safety refusal, context overflow).
     - Retry only transient failures (`408`, `429`, `500`, `502`, `503`, `504`, network timeout) with bounded exponential backoff, jitter, and `Retry-After` support.
     - Add per-model circuit breaker and explicit allowlisted fallback (recording `requested_model`, `actual_model`, `fallback_reason`, `attempts`, and latency in privacy-safe telemetry).

### Phase 4 — AI Security, PQC Evidence and Scoring Integrity (`P1`)
- **Target Files:** `pqc_agent/agent.py`, `pqc_agent/workspace_server.py`, `tools/gcp_inventory.py`, `tools/pqc_detectors.py`, `tools/gcloud_bridge.py`, `tools/calibration_engine.py`.
- **Remediations:**
  1. **Untrusted Input Isolation & Tool Scope Enforcement (`H10`):**
     - Wrap all uploaded document text, X.509 subject/issuer strings, and GCP resource metadata/labels in structured untrusted-data envelopes; strip control characters/prompt-override markers; enforce outside the LLM that `execute_gcloud_command` and inventory collectors only query scopes authorized for the tenant and cannot inspect sensitive secret payloads.
  2. **Validated Evidence Schema & Programmatic KMS-to-Workload Correlation (`H9`):**
     - Introduce a typed evidence schema (`CONFIRMED_OBSERVATION`, `INFERENCE`, `UNKNOWN`, `NOT_ASSESSED`, `COLLECTION_FAILURE`) with provenance, collection timestamp, collector version, and limitations.
     - Compute KMS-to-workload correlation programmatically (`STRONG` only for explicit CMEK resource references; `MEDIUM`/`WEAK` labeled as `INFERENCE` with explicit limitations; name similarity alone never classified as a confirmed dependency).
  3. **Service Coverage Matrix & Honest Scoring (`H8`):**
     - Add an explicit GCP service/resource coverage matrix (`ASSESSED`, `PARTIALLY_ASSESSED`, `NOT_ASSESSED`, `UNSUPPORTED`, `PERMISSION_DENIED`, `COLLECTION_FAILED`) covering Cloud KMS, Compute TLS, Certificate Manager, Private CA, and explicitly marking unassessed domains (application runtime crypto libraries, GKE pod mTLS, external/multicloud).
     - Prevent missing/zero-denominator categories or `UNKNOWN_REQUIRES_REVIEW` keys from inflating `weighted_kms_pqc_maturity`.

### Phase 5 — Application and Supply-Chain Hardening (`P2`)
- **Target Files:** `Dockerfile`, `requirements.txt`, `uv.lock` / lockfile, `pqc_agent/workspace_server.py`, `tools/calibration_engine.py`, SBOM artifact.
- **Remediations:**
  1. Non-root container user (`uid >= 10001`), minimal runtime packages, documented writable paths.
  2. Reproducible locked dependencies and CycloneDX/SPDX SBOM generation for the application supply chain.
  3. Strict upload hardening: configurable byte size limit (e.g., 10 MB default), allowlisted extensions + magic-byte/MIME verification, filename sanitization, ZIP/DOCX decompression bomb limits, and bounded PDF parsing.
  4. API rate limiting, request body limits, structured privacy-safe audit logging with correlation IDs, and error redaction.

### Phase 6 — Independent Security Acceptance and Release Gate
- End-to-end adversarial re-testing across Phases 1–5 and formal `GO` / `CONDITIONAL GO` / `NO-GO` release readiness gate in `docs/security-remediation/RELEASE_READINESS.md`.
