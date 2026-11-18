# Phase 3.0 Comprehensive Verification & Adversarial Test Plan

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Baseline (`main`) Commit SHA:** `62f7247b52effc3f3cf2086a86f06071eea1b6fc`
- **Companion Audit Document:** [PHASE_03_0_AUDIT.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/security_test_logs/phase_03_audit/PHASE_03_0_AUDIT.md)

---

## Test Suite Architecture

All Phase 3 tests will be implemented in `tests/test_phase3_runtime_resilience.py` while keeping all existing suites (`85` collected tests across `test_auth_hardening.py`, `test_phase1_distributed_auth.py`, `test_phase2_persistence_and_credentials.py`, `test_pqc_inventory.py`, `test_pre_merge_hotfix.py`) 100% green.

---

## Area 1 (`P3-01`) — Outbound SSRF and Egress Controls

### 1.1 Unit Tests
- **`test_p3_01_unit_safe_urlopen_enforces_https_and_host_allowlist`:**
  - Accepts `https://oauth2.googleapis.com/token`, `https://www.googleapis.com/oauth2/v3/userinfo`, `https://openidconnect.googleapis.com/v1/userinfo`, `https://accounts.google.com/.well-known/openid-configuration`.
  - Rejects `http://oauth2.googleapis.com/token` (plaintext HTTP), `file:///etc/passwd`, `ftp://...`, and non-allowlisted hosts (`https://evil.example.com/token`, `https://oauth2.googleapis.com.attacker.com/token`).
- **`test_p3_01_unit_safe_urlopen_blocks_private_loopback_and_metadata_ips`:**
  - Rejects literal IP hosts and DNS resolutions mapping to `169.254.169.254`, `127.0.0.1`, `10.0.0.1`, `172.16.0.1`, `192.168.1.1`, `::1`, `fe80::1`, and `0.0.0.0`.
- **`test_p3_01_unit_gcloud_validator_enforces_group_and_flag_allowlist`:**
  - Verifies `validate_gcloud_command()` accepts approved diagnostic groups and standard query flags (`--project`, `--location`, `--scope`, `--filter`, `--format=json`, `--limit`, `--quiet`) and rejects unapproved groups (`gcloud compute ssh`, `gcloud functions call`, `gcloud builds submit`) and dangerous global flags.

### 1.2 Integration Tests
- **`test_p3_01_integration_oauth_exchange_and_refresh_route_through_safe_urlopen`:**
  - Exercises `/api/auth/oauth/callback`, `/api/auth/google`, and `EncryptedDatabaseCredentialService` refresh-token rotation end-to-end through `safe_urlopen()`, confirming normal token exchange and bounded response handling succeed.
- **`test_p3_01_integration_gcloud_endpoint_preserves_strict_user_token_isolation`:**
  - When a tenant configured in `access_token` mode receives `PERMISSION_DENIED` from `gcloud`, `POST /api/gcloud` returns `COMMAND_ERROR` without stripping `CLOUDSDK_AUTH_ACCESS_TOKEN` or falling back to server ADC.

### 1.3 Adversarial Tests
- **`test_p3_01_adversarial_gcloud_ssrf_and_flag_smuggling_blocked`:**
  - Attempts via `validate_gcloud_command()` and `POST /api/gcloud`:
    1. `gcloud kms keys list --location=global --api-endpoint-overrides=cloudkms=https://attacker.example/`
    2. `gcloud asset search-all-resources --property=api_endpoint_overrides/cloudasset=http://169.254.169.254/`
    3. `gcloud kms keys list --impersonate-service-account=unapproved-admin@proj.iam.gserviceaccount.com`
    4. `gcloud kms keys list --flags-file=/etc/passwd`
    5. `gcloud kms keys list --credential-file-override=/tmp/fake.json`
    6. `gcloud kms keys list --access-token-file=/etc/hostname`
    7. `gcloud kms keys list --log-http`
  - Asserts HTTP `200` payload `status == "BLOCKED_DESTRUCTIVE_OR_INVALID_COMMAND"`, `exit_code == 126`, and **zero** subprocess invocations.
- **`test_p3_01_adversarial_http_redirect_to_metadata_and_oversized_body_blocked`:**
  - Simulates an upstream `302 Found` redirect from `https://oauth2.googleapis.com/tokeninfo` to `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` -> rejected before following redirect.
  - Simulates a `10 MiB` response body from token endpoint -> aborted at `max_bytes` cap (`64 KiB`) without memory spike.

### 1.4 Regression Tests
- **`test_p3_01_regression_legitimate_pqc_gcloud_queries_succeed`:**
  - Verifies representative read-only commands used by `discovery_agent` and `correlation_analyst_agent` (`gcloud kms keys list`, `gcloud kms keys describe`, `gcloud asset search-all-resources`, `gcloud compute ssl-policies describe`, `gcloud privateca pools list`, `gcloud --version`) pass validation and scrub `CLOUDSDK_API_ENDPOINT_OVERRIDES_*` from subprocess `env`.

---

## Area 2 (`P3-02`) — Vertex AI Model-Call Timeouts, Retries, and Circuit-Breaker Resilience

### 2.1 Unit Tests
- **`test_p3_02_unit_generate_content_config_and_probe_set_explicit_http_timeouts`:**
  - Verifies `build_generate_content_config()` and `vertex_generate_probe()` populate `http_options` timeout in the exact unit expected by `google-genai` (`milliseconds` vs `seconds` verified against installed SDK schema).
- **`test_p3_02_unit_circuit_breaker_state_machine`:**
  - Verifies `CLOSED` -> `OPEN` after `failure_threshold` transient errors (`429`, `503`, `TimeoutError`), fast-fail while `OPEN`, transition to `HALF_OPEN` after cooldown, recovery to `CLOSED` on probe success, and immediate re-open on `HALF_OPEN` probe failure.
  - Verifies `400 INVALID_ARGUMENT` and `403 PERMISSION_DENIED` do **not** increment circuit failure count.
- **`test_p3_02_unit_exponential_backoff_retry_policy`:**
  - Verifies bounded retries (`max_attempts`) with jitter on `429`/`503`/`TimeoutError`, zero retry on `400`, and strict adherence to remaining turn deadline.

### 2.2 Integration Tests
- **`test_p3_02_integration_chat_recovers_from_transient_vertex_503`:**
  - Injects a mock runner/model that raises `503 UNAVAILABLE` on attempt 1 and succeeds on attempt 2; verifies `POST /api/chat` returns `200 OK` with telemetry intact.
- **`test_p3_02_integration_cli_ask_enforces_turn_timeout_and_circuit_breaker`:**
  - Verifies `main.run_adk_agent_turn()` enforces `PQC_AGENT_TURN_TIMEOUT_SECONDS` and returns structured `MODEL_ERROR` (`MODEL_TIMEOUT` / `MODEL_CIRCUIT_OPEN`) without hanging.

### 2.3 Adversarial Tests
- **`test_p3_02_adversarial_stalled_llm_stream_aborts_at_turn_deadline`:**
  - Injects an async generator in `runner.run_async` that sleeps `60s` while `PQC_AGENT_TURN_TIMEOUT_SECONDS=0.3`; asserts `POST /api/chat` terminates in `< 1.0s` with HTTP `504` (or `502` per API contract) and `error.code == "MODEL_TIMEOUT"`, releasing session/DB resources cleanly.
- **`test_p3_02_adversarial_sustained_vertex_outage_trips_breaker_without_thread_starvation`:**
  - Fires `N` failing `/api/chat` requests to trip the per-model breaker, then fires `20` concurrent `/api/chat` requests and asserts all `20` fail fast (`< 50ms` total) with `error.code == "MODEL_CIRCUIT_OPEN"` and zero upstream runner invocations while an unaffected model remains callable.

### 2.4 Regression Tests
- **`test_p3_02_regression_3lo_oauth_consent_pause_and_normal_chat_unaffected`:**
  - Confirms `OAUTH_CONSENT_REQUIRED` turns (`adk_request_credential`) and normal multi-specialist turns neither trip timeouts nor increment circuit-breaker failure counters.

---

## Area 3 (`P3-03`) — PQC Scorecard Denominator Correctness and Edge Cases

### 3.1 Unit Tests
- **`test_p3_03_unit_empty_and_single_family_denominators_never_divide_by_zero`:**
  - Tests `compute_scorecard_from_keys([])`, asymmetric-only, symmetric-only, MAC-only (`ENCRYPT_DECRYPT` count = `0`), and inactive-only key sets; verifies `value_pct is None` where `denominator == 0` and exact weight renormalization.
- **`test_p3_03_unit_unknown_and_ekm_keys_included_in_denominators_with_zero_numerator`:**
  - Tests `1` active `ML_KEM_768` + `4` active `UNKNOWN_ALGORITHM` `ASYMMETRIC_SIGN` keys -> `asymmetric_pqc_migration == 20.0%` (`1/5`), never `100.0%`.
  - Tests `1` active `GOOGLE_SYMMETRIC_ENCRYPTION` + `1` active `EXTERNAL_SYMMETRIC_ENCRYPTION` (`Cloud EKM`) -> `symmetric_quantum_resistance == 50.0%` (`1/2`), never `100.0%`.
- **`test_p3_03_unit_asymmetric_key_with_version_listing_error_stays_active`:**
  - Calls `build_key_record(purpose="ASYMMETRIC_SIGN", algorithm="RSA_SIGN_PSS_2048_SHA256", primary_state="NO_PRIMARY", enabled_version_ids=[], versions_listing_error="PermissionDenied: 403")` -> asserts `is_active is True` and counted in `active_shor_vulnerable_keys`!
  - Contrasts with `versions_listing_error=None, enabled_version_ids=[]` -> asserts `is_active is False` (genuinely disabled/destroyed asymmetric key).

### 3.2 Integration Tests
- **`test_p3_03_integration_compute_pqc_scorecard_tls_deferred_and_partial_errors`:**
  - Scope with `TargetHttpsProxy` requiring `TLS_1_3` + `post_quantum_key_exchange="DEFERRED"` -> verifies PQC TLS readiness metric does not credit `DEFERRED` proxy as PQC-enabled.
  - Scope with non-empty `collection_errors` -> verifies scorecard includes explicit partial/incomplete inventory status (`completeness_status`).

### 3.3 Adversarial / Edge-Case Tests
- **`test_p3_03_adversarial_mixed_versions_and_unrecognized_purpose_cannot_inflate_maturity`:**
  - Key with `template_algorithm="ML_DSA_65"` but an enabled `RSA_SIGN_PKCS1_2048_SHA256` version -> classified `QUANTUM_VULNERABLE_SHOR` (`0` numerator).
  - Active key with `purpose="CRYPTO_KEY_PURPOSE_UNSPECIFIED"` and `algorithm="FUTURE_UNKNOWN_ALGO"` -> penalizes `algorithmic_quantum_safe` and `weighted_kms_pqc_maturity` (cannot yield `100.0%` maturity alongside 1 PQC key).

### 3.4 Regression Tests
- **`test_p3_03_regression_demo_scope_scorecard_reproducibility`:**
  - Re-runs `tests/test_pqc_inventory.py::test_scorecard_is_reproducible_with_numerators_and_denominators` to verify deterministic numerators, denominators, and JSON schema compatibility.

---

## Area 4 (`P3-04`) — Docker Non-Root Execution and Filesystem Permissions

### 4.1 Unit & Static Analysis Tests
- **`test_p3_04_unit_dockerfile_enforces_non_root_user_and_immutable_app_permissions`:**
  - Parses `Dockerfile` to verify:
    1. Dedicated non-root group/user creation (`UID >= 10000`, e.g. `10001:10001`).
    2. Final `USER` instruction before `CMD` is non-root (`10001:10001`, never `root` or `0`).
    3. `/app` code is NOT chowned writable to the runtime user (`root:root`, mode `0755`/`0644`, scripts `0755`).
    4. `PQC_EXPORT_DIR` and `CLOUDSDK_CONFIG` point to writable non-code paths (e.g. `/tmp/pqc-exports`, `/tmp/gcloud-config`).

### 4.2 Integration Tests (Staged Read-Only `/app` Simulation)
- **`test_p3_04_integration_read_only_app_tree_execution`:**
  - Replays `Dockerfile` `COPY` layout into `tmp_path / "app"`, locks `tmp_path / "app"` and all subdirectories read-only (`0555` dirs / `0444` `.py` files / `0555` `scripts/run_db_migrations.py`), sets `HOME` and `TMPDIR` to an isolated writable `tmp_path / "runtime_tmp"`, and verifies:
    1. `python scripts/run_db_migrations.py --help` exits `0`.
    2. `main:app` boots and `GET /api/health` returns `200`.
    3. `save_assessment_report()` writes `.md`/`.html` exports cleanly into `PQC_EXPORT_DIR` without touching `/app`.
    4. `execute_gcloud_command("gcloud --version")` (or mocked `gcloud` writing to `$CLOUDSDK_CONFIG`) succeeds with writable `$CLOUDSDK_CONFIG`.

### 4.3 Adversarial Tests
- **`test_p3_04_adversarial_runtime_code_tampering_denied_on_locked_app_dir`:**
  - Inside the staged `0555`/`0444` `/app` tree, verifies an attempted runtime write to `/app/main.py` or `/app/pqc_agent/workspace_server.py` raises `PermissionError`.

### 4.4 Live Container Smoke Test (Gated on Docker CLI Availability)
- **`test_p3_04_live_docker_non_root_uid_and_migration_help`:**
  - Gated with `@pytest.mark.skipif(shutil.which("docker") is None, reason="BLOCKED: Docker CLI/daemon is not installed...")`:
    1. `docker build` succeeds.
    2. `docker run --rm --entrypoint id <image> -u` outputs `10001` (`!= 0`).
    3. `docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid --entrypoint python <image> scripts/run_db_migrations.py --help` exits `0`.

---

## Area 5 (`P3-05`) — Multimodal Upload Size Limits, MIME Validation, and Magic-Byte Validation

### 5.1 Unit Tests
- **`test_p3_05_unit_filename_sanitizer`:**
  - Strips `../../`, `\`, NUL bytes, control chars, leading dots, and overlong names (`> 128` chars) while preserving valid extensions.
- **`test_p3_05_unit_magic_byte_and_mime_sniffer`:**
  - Validates genuine `.pdf` (`%PDF-1.7`), `.png` (`\x89PNG\r\n\x1a\n`), `.jpg` (`\xff\xd8\xff\xe0`), `.docx` (valid OOXML ZIP with `[Content_Types].xml` + `word/document.xml`), `.pem`/`.crt` (valid X.509 cert), `.md`/`.csv`/`.json`/`.txt` (UTF-8 and UTF-8 with BOM `\xef\xbb\xbf` + CRLF).
  - Rejects mismatched header vs extension, unsupported extensions (`.exe`, `.sh`, `.py`, `.dll`, `.zip`, `.tar.gz`, `.key`, `.p12`, `.pfx`), and `0`-byte payloads.
- **`test_p3_05_unit_bounded_lru_upload_cache_is_tenant_isolated`:**
  - Verifies `_UPLOADED_ARTIFACT_CACHE` keys include `(user_id, session_id, sanitized_filename)`, enforces max entry / byte caps via LRU eviction, and prevents collision when User A and User B both use `session_id="custom-session-1"`.

### 5.2 Integration Tests
- **`test_p3_05_integration_valid_multimodal_uploads_through_chat_api`:**
  - Uploads valid `.md`, `.csv`, `.pdf`, `.docx`, `.png`, and public `.pem` X.509 certificate through `POST /api/chat`; verifies HTTP `200`, `artifact_service` storage under sanitized filename, and `read_uploaded_artifact()` extraction.

### 5.3 Adversarial Tests
- **`test_p3_05_adversarial_size_and_count_limits_enforced_via_streaming_read`:**
  - Single file `> PQC_MAX_UPLOAD_FILE_BYTES` -> HTTP `413` before GCS save or LLM invocation.
  - Multi-file batch exceeding `PQC_MAX_UPLOAD_TOTAL_BYTES` -> HTTP `413`.
  - File count `> PQC_MAX_UPLOAD_FILES_PER_TURN` -> HTTP `400` / `413`.
- **`test_p3_05_adversarial_magic_byte_spoofing_and_binary_smuggling_rejected`:**
  - `MZ\x90\x00...` PE executable named `inventory.pdf` (`application/pdf`) -> HTTP `415`.
  - `\x7fELF...` binary named `notes.txt` (`text/plain`) -> HTTP `415` (proving `latin-1` fallback is eliminated).
  - PNG image renamed to `scan.pdf` -> HTTP `415`.
  - Plain `.zip` archive without `word/document.xml` renamed to `report.docx` -> HTTP `415`.
- **`test_p3_05_adversarial_docx_zip_bomb_and_xxe_entity_rejected`:**
  - Crafted `.docx` with declared uncompressed member size `> 32 MiB` (or compression ratio `> 100:1`) -> HTTP `400`/`413` before `docx.Document()` parses XML.
  - Crafted `.docx` containing `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` in `word/document.xml` -> HTTP `400`/`415`.
  - Crafted `.docx` containing `../../evil.xml` zip-slip entry -> HTTP `400`/`415`.
- **`test_p3_05_adversarial_private_key_upload_rejected`:**
  - PEM containing `-----BEGIN PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----` uploaded as `cert.pem` -> HTTP `400` with explicit private-key rejection message and zero persistence in DB/GCS/cache.
- **`test_p3_05_adversarial_cross_tenant_same_session_id_upload_isolation`:**
  - Tenant `alice@google.com` and Tenant `bob@google.com` each create `session_id="shared-audit-id"` and upload distinct `.md` files; verifies `read_uploaded_artifact()` for Alice never returns Bob's document.

### 5.4 Regression Tests
- **`test_p3_05_regression_existing_multimodal_upload_suite`:**
  - Re-runs `tests/test_pqc_inventory.py::test_multimodal_upload_is_attached_for_the_model_without_pre_analysis` and `test_read_uploaded_artifact_returns_raw_content_scoped_to_session` unmodified.
