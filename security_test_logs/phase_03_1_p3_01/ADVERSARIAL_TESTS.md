# Phase 3.1 (`P3-01`) — Adversarial Security Test Report

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Test Module:** [tests/test_phase3_egress_security.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_phase3_egress_security.py)
- **Network Safety:** 100% deterministic local mocks/fakes (`_SingleHopOpener`, `_FakeRawSocket`, `_PinnedRawSocket`, `_mock_subprocess_run`); zero external or attacker-controlled endpoints contacted.

---

## 1. Outbound HTTP SSRF, Redirect & Response-Bound Adversarial Matrix (`safe_urlopen`)

| Adversarial Vector | Representative Payload / Scenario | Expected Policy | Observed Outcome |
| :--- | :--- | :--- | :---: |
| **Plaintext HTTP & Non-HTTPS Schemes** | `http://oauth2.googleapis.com/token`, `file:///etc/passwd`, `ftp://...`, `data:...` | Reject (`EgressPolicyError`), `0` DNS/socket calls | **PASS (Blocked)** |
| **Unknown Hostname** | `https://attacker.example/token` | Reject (`EgressPolicyError`), `0` DNS/socket calls | **PASS (Blocked)** |
| **Suffix & Subdomain Spoofing** | `https://oauth2.googleapis.com.attacker.example/token`, `https://sub.oauth2.googleapis.com/token`, `https://evil-oauth2.googleapis.com/token` | Reject (`EgressPolicyError`), exact allowlist match only | **PASS (Blocked)** |
| **URL Userinfo & Authority Confusion** | `https://user:pass@oauth2.googleapis.com/token`, `https://oauth2.googleapis.com@attacker.example/token`, `https://oauth2.googleapis.com\@attacker.example/token` | Reject (`EgressPolicyError`) | **PASS (Blocked)** |
| **Unexpected Ports** | `https://oauth2.googleapis.com:8443/token`, `:80`, `:/token` | Reject (`EgressPolicyError`), port `443` only | **PASS (Blocked)** |
| **IP-Literal & Encoded-IP URLs** | `https://142.250.80.10/token`, `https://127.0.0.1/token`, `https://169.254.169.254/computeMetadata/v1/`, `https://2130706433/token`, `https://0x7f000001/token`, `https://[::1]/token`, `https://[fd00:ec2::254]/...` | Reject (`EgressDestinationError`), `0` DNS/socket calls | **PASS (Blocked)** |
| **Host Header Smuggling** | `Request("https://oauth2.googleapis.com/token", headers={"Host": "attacker.example"})` | Reject (`EgressPolicyError`) | **PASS (Blocked)** |
| **HTTP `301/302/303/307/308` Redirect to Metadata** | Upstream `3xx` with `Location: http://169.254.169.254/computeMetadata/v1/` | Fail closed (`EgressRedirectError`); second destination (`169.254.169.254`) **never** contacted | **PASS (Blocked)** |
| **Oversized `Content-Length`** | `Content-Length: 65537` (`> 64 KiB`) | Reject (`EgressResponseTooLargeError`) before reading body | **PASS (Blocked)** |
| **Lying `Content-Length` / Missing `Content-Length` Stream Flood** | `Content-Length: 32` or chunked stream sending `> 65536` bytes | Abort stream at `64 KiB + 1`, close socket, raise `EgressResponseTooLargeError` with **zero** partial data returned | **PASS (Blocked)** |
| **Missing / Infinite / NaN Timeout** | `safe_urlopen(url)`, `timeout=None`, `0`, `-1.5`, `inf`, `nan`, `120.0` | Reject (`EgressPolicyError`) | **PASS (Blocked)** |
| **Disabled TLS Verification** | `ssl._create_unverified_context()` or `check_hostname=False` | Reject (`EgressPolicyError`) | **PASS (Blocked)** |
| **Credential Leakage in Errors/Logs** | Failing request carrying `Authorization: Bearer ya29...`, `?access_token=ya29...`, `refresh_token=1//...`, `client_secret=GOCSPX-...` | Scrubbed from raised `URLError` and `caplog` (`DEBUG`) | **PASS (Redacted)** |
| **JWKS & Refresh Transport Bypass** | Tampered `token_uri` in `_default_oauth_refresh_exchange` & untrusted URL/redirect in `auth_guard._CertCachingRequest` | Fail closed (`EgressError` / `TransportError`) | **PASS (Blocked)** |

---

## 2. DNS Resolution, IPv4/IPv6 Edge Cases & Rebinding Pinning Matrix

| Adversarial Vector | Tested Addresses / Scenario | Observed Outcome |
| :--- | :--- | :---: |
| **Loopback & Unspecified** | `127.0.0.1`, `127.0.0.53`, `::1`, `0.0.0.0`, `::` | **PASS (Blocked)** |
| **Private RFC 1918 & IPv6 ULA** | `10.0.0.1`, `10.128.0.15`, `172.16.0.1`, `172.31.255.254`, `192.168.1.1`, `fc00::1`, `fd12:3456:789a::1` | **PASS (Blocked)** |
| **Link-Local & Cloud Metadata** | `169.254.169.254`, `169.254.0.10`, `fe80::1`, `fe80::1%eth0`, `fd00:ec2::254`, `100.100.100.200`, `100.64.0.1` | **PASS (Blocked)** |
| **Multicast, Reserved & Documentation** | `224.0.0.1`, `ff02::1`, `240.0.0.1`, `255.255.255.255`, `192.0.2.1`, `2001:db8::1` | **PASS (Blocked)** |
| **IPv6 Transition/Encapsulation Smuggling** | `::ffff:169.254.169.254`, `::ffff:127.0.0.1`, `::ffff:142.250.80.10`, `2002:7f00:0001::1` (`6to4`), `2001:0000:...` (`Teredo`), `64:ff9b::a9fe:a9fe` (`NAT64`), `::142.250.80.10` | **PASS (Blocked)** |
| **Mixed Public + Prohibited Multi-A Record** | `[("142.250.80.10", 443), ("169.254.169.254", 443)]` | **PASS (Entire resolution failed closed)** |
| **DNS Rebinding (Validation vs Use)** | Resolver returns `142.250.80.42` on lookup 1 and `169.254.169.254` on lookup 2 | **PASS (`1` DNS lookup; socket connected to `("142.250.80.42", 443)` with SNI `oauth2.googleapis.com`)** |

---

## 3. `gcloud` CLI Flag Smuggling, Config Injection & Environment Override Matrix

All `53` parameterized adversarial command strings in `test_p3_01_gcloud_adversarial_commands_rejected_with_zero_subprocess_calls` returned `is_valid is False`, `status == "BLOCKED_DESTRUCTIVE_OR_INVALID_COMMAND"`, `exit_code == 126`, and **`0` `subprocess.run()` invocations**:

1. `gcloud kms keys list --location=global --api-endpoint-overrides=cloudkms=https://attacker.example/` -> **BLOCKED (`0` subprocess calls)**
2. `gcloud kms keys list --location=global --property=api_endpoint_overrides/cloudkms=https://attacker.example/` -> **BLOCKED (`0` subprocess calls)**
3. `gcloud kms keys list --flags-file=/etc/passwd` -> **BLOCKED (`0` subprocess calls)**
4. `gcloud kms keys list --credential-file-override=/tmp/credentials.json` -> **BLOCKED (`0` subprocess calls)**
5. `gcloud kms keys list --access-token-file=/tmp/token` -> **BLOCKED (`0` subprocess calls)**
6. `gcloud kms keys list --impersonate-service-account=attacker@example.iam.gserviceaccount.com` -> **BLOCKED (`0` subprocess calls)**
7. `gcloud kms keys list --log-http` -> **BLOCKED (`0` subprocess calls)**
8. Space-separated variants (`--api-endpoint-overrides ...`, `--property ...`, `--flags-file ...`, `--credential-file-override ...`, `--access-token-file ...`, `--impersonate-service-account ...`, `--account ...`, `--configuration ...`) -> **BLOCKED (`0` subprocess calls)**
9. Alternate spellings & `argparse`/`calliope` abbreviations (`--api_endpoint_overrides=...`, `--API-ENDPOINT-OVERRIDES=...`, `--api-endpoint=...`, `--propert=...`, `--impersonate=...`, `--cred=...`, `--no-log-http`, `--authorization-token-file=...`, `--output-file=...`) -> **BLOCKED (`0` subprocess calls)**
10. Repeated flags (`--location=global --location=us-central1`, `--project=... --project=...`, `-q --quiet`), unknown flags (`--unknown-flag`, `--verbosity`), cross-command flags (`kms keys list --scope=...`), `--` option terminators, URLs/metadata IPs in flag values or positionals, `alpha`/`beta` tracks, and `gcloud config` / `gcloud auth` / `gcloud secrets` / `gcloud compute ssh` -> **BLOCKED (`0` subprocess calls)**
11. Inherited environment poisoning (`CLOUDSDK_API_ENDPOINT_OVERRIDES_*`, `CLOUDSDK_PROXY_*`, `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `ALL_PROXY`, `NO_PROXY`, `GCE_METADATA_HOST`, `PYTHONHTTPSVERIFY`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `LD_PRELOAD`) -> **STRIPPED (`build_sanitized_gcloud_env`)**

---

## 4. Confused-Deputy & Tenant Boundary Adversarial Matrix

| Scenario | Expected Subprocess Count | Expected Credential Behavior | Observed Outcome |
| :--- | :---: | :--- | :---: |
| Tenant in `access_token` mode succeeds (`returncode=0`) | **`1`** | Uses `CLOUDSDK_AUTH_ACCESS_TOKEN` only; `GOOGLE_APPLICATION_CREDENTIALS` absent | **PASS** |
| Tenant in `access_token` mode gets `PERMISSION_DENIED` (including on `organizations/31564119954`) | **`1`** (`0` ADC retries) | Returns `COMMAND_ERROR` in `access_token` mode; **never** pops `CLOUDSDK_AUTH_ACCESS_TOKEN` or switches to `adc` | **PASS** |
| Tenant delegated token expired in `EncryptedDatabaseCredentialService` | **`0`** (`0` ADC retries) | Returns `COMMAND_ERROR` (`ACCESS_TOKEN_REQUIRED`); `get_active_gcp_credentials()` raises `PermissionError` | **PASS** |
| Untrusted mode override via `POST /api/gcloud` (`{"mode": "adc"}`) or `--account=...` | **`0`** | HTTP `422` (`extra="forbid"`) / `BLOCKED_DESTRUCTIVE_OR_INVALID_COMMAND` | **PASS** |
| Unrecognized mode string in `POST /api/connection` (`{"mode": "unexpected_untrusted_mode"}`) | **`0`** | HTTP `400` (`ValueError`); active mode remains `access_token` (no silent reset to `adc`) | **PASS** |
| Explicit trusted `adc` mode selected via `POST /api/connection` | **`1`** | Executes cleanly under server ADC (`CLOUDSDK_AUTH_ACCESS_TOKEN` absent) | **PASS** |
