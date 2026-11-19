# Phase 3.1 (`P3-01`) — Critical SSRF & Egress Security Execution Checkpoint

- **Timestamp (Local):** `2026-11-18T14:58:00-03:00`
- **Repository:** `g-jsaccomani/pqc_inventory_agent` (`https://github.com/g-jsaccomani/pqc_inventory_agent.git`)
- **Working Branch:** `security-hardening/phase-03-runtime-resilience`
- **Baseline `main` Commit SHA:** `62f7247b52effc3f3cf2086a86f06071eea1b6fc` (verified ancestor of `HEAD` and `main`)
- **Exact Starting Commit SHA (`HEAD`):** `90ddf8fd08dc3b0e50d54176f44c267330493854`
- **Scope:** `P3-01` **ONLY** (Outbound SSRF & Egress Controls, Strict `gcloud` Command/Flag Grammar & Env Sanitization, Removal of Confused-Deputy `access_token` -> Server ADC Fallback). `P3-02`, `P3-03`, `P3-04`, and `P3-05` are explicitly excluded from this execution.

---

## Stage 0 Preconditions Verification

| Check | Requirement | Verification Result | Status |
| :--- | :--- | :--- | :---: |
| **1. Repository Identity** | `g-jsaccomani/pqc_inventory_agent` | `origin https://github.com/g-jsaccomani/pqc_inventory_agent.git` | **PASS** |
| **2. Remote References** | Fetch `origin` | `git fetch origin` succeeded; `HEAD` matches `origin/security-hardening/phase-03-runtime-resilience` (`90ddf8fd08dc3b0e50d54176f44c267330493854`) | **PASS** |
| **3. Working Branch** | `security-hardening/phase-03-runtime-resilience` | Active branch verified (`* security-hardening/phase-03-runtime-resilience`) | **PASS** |
| **4. Baseline Ancestry** | `main` (`62f7247b52effc3f3cf2086a86f06071eea1b6fc`) is ancestor | `git merge-base --is-ancestor 62f7247b52effc3f3cf2086a86f06071eea1b6fc main` and `HEAD` exited `0` | **PASS** |
| **5. Phase 3.0 Artifacts** | `PHASE_03_0_AUDIT.md` & `PHASE_03_0_TEST_PLAN.md` present | Verified present under `security_test_logs/phase_03_audit/` | **PASS** |
| **6. Clean Working Tree** | Zero modified/staged tracked files | Verified (`git diff` empty; only untracked user instruction file `PHASE03` exists in workspace root and will remain unstaged) | **PASS** |
| **7. Pre-Change Baseline Suite** | Existing pytest suite green before changes | `.venv/bin/pytest -v` -> **`82 passed, 3 skipped` in `50.07s`** (exit `0`) | **PASS** |

---

## Pre-Implementation Code Inspection Summary

1. **`pqc_agent/workspace_server.py`:**
   - 4 direct `urllib.request.urlopen(...)` calls (`L510`, `L559`, `L594`, `L1305`) targeting `https://oauth2.googleapis.com/tokeninfo`, `https://www.googleapis.com/oauth2/v3/userinfo`, and `https://oauth2.googleapis.com/token`.
   - Note on existing regression tests: `tests/test_auth_hardening.py` (`L187`, `L934`), `tests/test_phase1_distributed_auth.py` (`L123`, `L193`, `L272`), and `tests/test_phase2_persistence_and_credentials.py` (`L206`, `L369`) monkeypatch `ws.urllib.request.urlopen` with synthetic response objects after constructing requests to allowlisted Google URLs. `safe_urlopen()` must enforce full URL/scheme/host/port/userinfo/timeout/response-size policy BEFORE transport dispatch, and respect monkeypatched `urllib.request.urlopen` when substituted by existing tests while using a pinned-DNS, redirect-disabled `HTTPSConnection` opener for real network execution.
2. **`pqc_agent/credential_service.py`:**
   - 1 direct `urllib.request.urlopen(...)` call (`L236`) in `_default_oauth_refresh_exchange()` targeting `token_uri` (default `https://oauth2.googleapis.com/token`). Must route through `safe_urlopen()` so any tampered or unexpected `token_uri` fails closed and response size/redirects are bounded.
3. **`pqc_agent/auth_guard.py`:**
   - `_CertCachingRequest` (`L413-L440`) subclasses `google.auth.transport.requests.Request` to fetch Google OIDC and Cloud IAP public key documents (`https://www.gstatic.com/iap/verify/public_key`, `https://www.googleapis.com/oauth2/v3/certs`, `https://accounts.google.com/.well-known/openid-configuration`). Currently uses default `requests.Session` (which follows redirects and allows unbounded responses without host/IP pinning). Must enforce HTTPS-only, explicit JWKS/OIDC cert host allowlist (`www.gstatic.com`, `www.googleapis.com`, `oauth2.googleapis.com`, `openidconnect.googleapis.com`, `accounts.google.com`), DNS/IP destination validation, `allow_redirects=False` (3xx fail-closed), TLS verification (`verify=True`), explicit finite timeout, and bounded streaming read (`<= 64 KiB`).
4. **`tools/gcloud_bridge.py`:**
   - `validate_gcloud_command()` (`L416-L497`) strips `-*` flags and checks non-flag verbs only, leaving `--api-endpoint-overrides`, `--property`, `--impersonate-service-account`, `--flags-file`, `--credential-file-override`, `--access-token-file`, `--account`, `--configuration`, and `--log-http` open.
   - `execute_gcloud_command()` (`L556-L648`) copies full `os.environ` without scrubbing `CLOUDSDK_API_ENDPOINT_OVERRIDES_*` or proxy vars, and silently retries failed `access_token` calls (`L582-L610` and `L630-L647`) by stripping `CLOUDSDK_AUTH_ACCESS_TOKEN` (confused-deputy escalation to server ADC).

---

## Execution Progress Tracker

- [x] **Stage 0:** Strict preconditions & baseline inspection completed (`90ddf8fd08dc3b0e50d54176f44c267330493854`).
- [x] **Stage 1:** Implemented `pqc_agent/egress_guard.py` (`safe_urlopen`) and integrated into `workspace_server.py`, `credential_service.py`, and `auth_guard.py`.
- [x] **Stage 2:** Refactored `tools/gcloud_bridge.py` with structured command/flag grammar and allowlisted subprocess environment sanitization (`build_sanitized_gcloud_env`).
- [x] **Stage 3:** Eliminated confused-deputy `access_token` -> server ADC fallback in `execute_gcloud_command()` and `get_active_gcp_credentials()`.
- [x] **Stage 4:** Implemented `tests/test_phase3_egress_security.py` (`181 passed, 0 skipped`) and verified full repository suite (`263 passed, 0 failed, 3 skipped`).
- [x] **Stage 5:** Completed security review and outbound HTTP/flag/credential audit.
- [x] **Stage 6:** Recorded complete evidence in `EXECUTION_CHECKPOINT.md`, `TEST_RESULTS.md`, `ADVERSARIAL_TESTS.md`, and `SECURITY_REVIEW.md`.
- [x] **Stage 7:** Final verification and single atomic commit (`fix(security): harden outbound egress and gcloud execution`; exact self-SHA inspectable via `git rev-parse HEAD`).
