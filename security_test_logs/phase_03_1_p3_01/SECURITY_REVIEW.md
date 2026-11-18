# Phase 3.1 (`P3-01`) — Security Review & Outbound Egress Audit

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Baseline `main` SHA:** `62f7247b52effc3f3cf2086a86f06071eea1b6fc`
- **Starting `HEAD` SHA:** `90ddf8fd08dc3b0e50d54176f44c267330493854`

---

## 1. Stage 5 Security Verification Checklist

| # | Audit Check | Verification Result | Status |
| :---: | :--- | :--- | :---: |
| 1 | **Review all changed code** | Reviewed [egress_guard.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/egress_guard.py), [workspace_server.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py), [credential_service.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/credential_service.py), [auth_guard.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/auth_guard.py), [gcloud_bridge.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcloud_bridge.py), and [test_phase3_egress_security.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_phase3_egress_security.py). | **PASS** |
| 2 | **Search repository for remaining direct `urlopen()` usages** | Zero direct `urllib.request.urlopen()` calls remain in `pqc_agent/` or `tools/`. Only `scripts/rebuild_all_with_official_cloudstyle_templates.py` (an offline local Google Docs/Slides deck generator not copied into `Dockerfile`) retains `urllib.request.urlopen()`, documented in Section 2 below. | **PASS** |
| 3 | **Search for remaining unsafe `gcloud` flag handling** | Token-stripping (`not t.startswith("-")`) completely removed from `validate_gcloud_command()`. Replaced with exact `gcloud` binary check, canonical flag parsing (`--flag=value` and `--flag value`), duplicate-flag rejection, blocked-flag + prefix-abbreviation denylist, URL-in-value rejection, per-command flag allowlists, and allowlisted subprocess environment construction (`build_sanitized_gcloud_env()`). | **PASS** |
| 4 | **Search for any `access_token`-to-ADC fallback** | Grepped `CLOUDSDK_AUTH_ACCESS_TOKEN` across repository: both retry blocks that popped `CLOUDSDK_AUTH_ACCESS_TOKEN` were removed. Missing/expired delegated tokens now fail closed (`ACCESS_TOKEN_REQUIRED`, `0` subprocess invocations) in both `execute_gcloud_command()` and `get_active_gcp_credentials()`, and unrecognized mode strings in `normalize_connection_mode()` raise `ValueError` instead of defaulting to `"adc"`. | **PASS** |
| 5 | **Verify no credential values exposed in errors or logs** | `redact_sensitive_text()` and `redact_url_for_log()` strip query parameters (`?access_token=...`, `?id_token=...`), `Bearer` headers, `ya29.*` access tokens, `1//*` refresh tokens, `GOCSPX-*` client secrets, and JWTs from raised errors, `HTTPError.filename`, and `gcloud` `stdout`/`stderr`/traces. | **PASS** |
| 6 | **Verify all new policies fail closed** | Empty allowlists, DNS errors, mixed public+private DNS answers, HTTP `3xx` redirects, missing/non-finite timeouts, disabled TLS verification, oversized `Content-Length`/streams, unknown `gcloud` groups/verbs/flags, and missing/expired delegated tokens all fail closed. | **PASS** |
| 7 | **Verify OAuth and OIDC regression tests remain green** | All existing OAuth 2.0 Authorization Code + PKCE, OIDC nonce, Cloud IAP JWT, and multi-instance persistence tests in `test_auth_hardening.py`, `test_phase1_distributed_auth.py`, `test_phase2_persistence_and_credentials.py`, and `test_pqc_inventory.py` pass without modification. | **PASS** |
| 8 | **Verify zero new third-party dependencies** | `pyproject.toml`, `requirements.txt`, and `uv.lock` are untouched (`egress_guard.py` uses Python 3.12 standard library only). | **PASS** |
| 9 | **Verify no unrelated files or Phase 1–2 evidence changed** | Verified via `git status --short` and `git diff --stat`: zero Phase 1–2 logs, migrations, Dockerfiles, scorecard files, or upload parsers modified. | **PASS** |

---

## 2. Documented Remaining Outbound HTTP Paths Outside `egress_guard.py`

Per Stage 5 instructions, complete repository egress is NOT claimed because the following non-`urlopen` transports intentionally remain outside `pqc_agent/egress_guard.py`:

1. **Official Google Cloud & Vertex AI Python SDK Clients (Runtime — Intended First-Party Transports):**
   - `pqc_agent/model_registry.py` (`genai.Client(vertexai=True, ...)`) and `pqc_agent/agent.py` (Google ADK `Runner` / `google-genai`): communicate with Vertex AI (`aiplatform.googleapis.com`). *Note: explicit model-call timeouts, retries, and circuit breakers are scheduled for `P3-02`.*
   - `pqc_agent/credential_service.py` (`google.cloud.kms_v1.KeyManagementServiceClient`): wraps/unwraps 256-bit DEKs via Cloud KMS (`cloudkms.googleapis.com`).
   - `pqc_agent/workspace_server.py` (`GcsArtifactService`), `main.py` (`storage.Client`), and `tools/report_exporter.py` (`storage.Client`): persist session artifacts and Markdown/HTML exports to operator-configured GCS buckets (`storage.googleapis.com`).
   - `tools/gcp_inventory.py`, `tools/pqc_detectors.py`, and `tools/gcloud_bridge.py` (`get_active_gcp_credentials` -> `google.auth.impersonated_credentials.Credentials`): official Google Cloud Python SDK clients (`kms_v1`, `asset_v1`, `compute_v1`, `private_ca_v1`, IAM Credentials API) using gRPC/HTTPS to hardcoded Google API endpoints.
   - **Risk Assessment:** Low for arbitrary SSRF because endpoints are SDK-managed Google APIs rather than user-supplied URLs; in Cloud Run production, defense-in-depth VPC Egress firewalling (`private.googleapis.com` / `restricted.googleapis.com`) is recommended alongside application controls.
2. **Workstation Local Auto-Auth Helper (`pqc_agent/workspace_server.py:L626-L666`, `_try_workstation_auto_gcloud_token`):**
   - Hard-disabled in production (`if auth_guard.is_production_environment(): return None`) and disabled unless `PQC_AUTO_WORKSTATION_GCLOUD_AUTH=true` is explicitly set by a local developer; invokes static argv `["gcloud", "auth", "print-access-token", "--quiet"]` with `timeout=4`.
   - **Risk Assessment:** Negligible in production (unreachable when `K_SERVICE`, `PQC_PRODUCTION_MODE=true`, or `PQC_ENV=production` is set).
3. **Offline Consultant Deliverable Generator Script (`scripts/rebuild_all_with_official_cloudstyle_templates.py:L64, L78`):**
   - Standalone CLI script that calls `urllib.request.urlopen()` with `SSL_CTX = ssl._create_unverified_context()` against `https://oauth2.googleapis.com/token` and `https://www.googleapis.com/drive|docs|slides/...` to rebuild Google Docs/Slides templates.
   - **Reason Not Modified:** Stage 1 & Stage 5 forbid blind global replacement of unrelated files; this script is never imported by `main.py`, `pqc_agent/`, or `tools/`, and is excluded from the production container image (`Dockerfile` copies only `scripts/run_db_migrations.py` and `scripts/migrate_legacy_stores_to_db.py`).
   - **Risk Assessment:** Zero runtime/container risk; low local-operator risk if executed manually over an untrusted network due to unverified TLS in that standalone script.

---

## 3. Remaining Deferred Phase 3 Security Risks (Out of Scope for `P3-01`)

1. **`P3-05` (Next Immediate Step — High Priority / P0):** Multimodal file uploads in `POST /api/chat` (`workspace_server.py` and `tools/calibration_engine.py`) still require streaming byte/count caps, filename sanitization, magic-byte/MIME verification, `.docx` ZIP-bomb/XXE guards, bounded PDF extraction, private-key upload rejection, and `user_id`-isolated bounded LRU caching.
2. **`P3-02` (High Priority / P1):** Vertex AI `genai.Client` / ADK `runner.run_async()` calls require explicit HTTP timeouts, bounded exponential-backoff retries on transient `429`/`503`, and per-model circuit-breaker protection.
3. **`P3-03` (High Priority / P1):** PQC scorecard denominators in `tools/gcp_inventory.py` require hardening for `UNKNOWN_REQUIRES_REVIEW` / `EXTERNAL_KEY_MANAGER` keys, asymmetric `versions_listing_error` active-state handling, `postQuantumKeyExchange=DEFERRED` TLS proxies, and partial collection error indicators.
4. **`P3-04` (Medium-High Priority / P1):** `Dockerfile` still runs as `root` (`UID 0`) until dedicated non-root `USER 10001:10001` and read-only `/app` permissions are implemented.
5. **Tenant Scope Authorization on `--project` / `--organization` / `--scope` (`H10` Architecture Note):** While `execute_gcloud_command()` now enforces read-only grammar, sanitized environments, and strict caller credentials (eliminating server ADC escalation), in `adc` mode the Cloud Run SA can still query any GCP scope readable by that SA; production multi-tenant deployments for external orgs should pair `P3-01` with least-privilege IAM / per-tenant 3LO or allowlisted SA impersonation and Serverless VPC Egress controls.
