# PQC Inventory Agent — Security Remediation Runbook

> **Purpose:** one compact, phased instruction set for the coding agent. Follow only the selected phase. Do not execute future phases automatically.

## Execution control — edit this value before each run

```yaml
EXECUTE_PHASE: 1
# 0 = baseline | 1 = OAuth/auth | 2 = persistence/identity | 3 = model reliability
# 4 = AI security/PQC evidence | 5 = hardening | 6 = independent audit
```

**Repository:** `https://github.com/g-jsaccomani/pqc_inventory_agent`  
**Working branch:** `security-hardening/2026-11`

---

## Global rules — mandatory for every phase

You are acting as a senior application security engineer, Google Cloud architect, AI platform engineer and Python engineer, as appropriate to the selected phase.

1. Inspect the existing implementation before changing it. Treat source code, tests and deployment configuration as authoritative; do not rely on README claims alone.
2. Preserve existing behavior unless a documented security or reliability defect requires a change. Do not perform unrelated refactoring.
3. Never overwrite uncommitted user work. Start with `git status`. If the working tree contains changes, do not reset, stash, clean or overwrite them; report the blocker and stop before changing branches or files.
4. Do not deploy, provision, migrate, or modify production infrastructure. Use isolated local/test resources and synthetic data only.
5. Never print, commit, or log secrets, tokens, private keys, personal data or production data. Redact test output.
6. Do not assume production environment variables or Cloud Run settings. Label findings as **confirmed in code**, **configuration-dependent**, or **not verified**.
7. Make the smallest safe change. Check API compatibility against the versions actually installed in the repository; do not invent APIs or model IDs.
8. Add regression tests for every confirmed defect. Run tests; never claim a test passed unless it was actually executed. Mark unavailable infrastructure tests **BLOCKED**, not PASS.
9. For the selected phase, create a detailed but concise Markdown report under `security_test_logs/phase_<NN>_<name>/REPORT.md`. Include commit SHA, changed files, commands, actual results, failures, blocked tests, residual risks and redacted evidence.
10. Run relevant unit, integration and security tests, static analysis/lint/format checks where configured, and `git diff --check`. Do not remove or weaken tests to obtain a passing result.
11. Commit only intended changes after mandatory tests pass. Never force-push. Do not deploy.
12. Keep the final response token-efficient: summarize outcome, tests, blockers, residual risks and commit SHA. Do not repeat this runbook or dump source code. Point to the report path.
13. Stop after the selected phase. Do not begin another phase without a new instruction.

### Branch and commit policy

- Phase 0: create `security-hardening/2026-11` only when the working tree is clean and branch creation is safe.
- Later phases: use the same branch; verify the expected prior commit/state before changing files.
- If the branch or repository state differs from expectations, do not force a checkout or reset. Explain the discrepancy and stop safely.
- Use the exact commit message specified in the selected phase.

---

# Phase 0 — Baseline and remediation plan

**Goal:** establish the actual architecture, reproduce the current baseline and map remediation work. Do not implement product fixes in this phase.

Inspect the repository structure and relevant files for:

- OAuth login, popup/callback, `postMessage`, state/nonce, redirect URI, cookies, browser storage and logout.
- Session signing/HMAC, `PQC_AUTH_SECRET`, IAP JWT validation and audience.
- ADK `DatabaseSessionService`, SQLite, GCS FUSE, JSON metadata and filesystem writes.
- Delegated GCP credentials, `gcloud_bridge.py`, process-local caches and service-account permissions.
- `model_registry.py`, model discovery/verification/cache, Vertex AI execution, retries and fallback.
- Agent orchestration, tool permissions, read-only enforcement and tenant/project scoping.
- PQC collectors, KMS/TLS inventory, evidence/correlation, scoring, reporting and file uploads.
- Dockerfile, dependency manifests/lockfiles, CI/CD, deployment manifests and existing tests.

Run the existing test suite and applicable lint/static-analysis/security checks without changing application code. Record pre-existing failures separately.

Create:

- `docs/security-remediation/MASTER_REMEDIATION_PLAN.md`
- `security_test_logs/phase_00_baseline/REPORT.md`

The plan must classify each finding as confirmed, configuration-dependent or unverified; include severity, impact, affected files/functions, prerequisites, remediation, regression risks and validation tests. Explicitly investigate these hypotheses without assuming they are true in production:

1. OAuth popup may send authentication data using wildcard `postMessage` origin.
2. Session bearer token may be exposed through `localStorage`.
3. SQLite may be stored on a Cloud Storage FUSE mount.
4. Session/user metadata may rely on local files or process-local state.
5. Delegated Google credentials may exist only in process memory.
6. Transient Vertex AI probe failures may remove models from the catalog.
7. Retry/fallback policies may be missing or unsafe.
8. PQC maturity/coverage claims may exceed collector coverage.
9. Evidence confidence may rely too heavily on LLM instructions.
10. Indirect prompt injection defenses may be incomplete.

**Commit:** `security: establish remediation baseline and test evidence`  
**Stop condition:** report baseline and exact next steps; do not start Phase 1.

---

# Phase 1 — OAuth and authentication (P0)

**Goal:** close credential exposure paths and make browser/server authentication robust.

Inspect the complete authentication flow. In particular, search for `postMessage` calls using `"*"`. If confirmed, remove wildcard delivery of all authentication-related data. Never send ID/access/refresh tokens, authorization codes or reusable session bearer tokens through unrestricted popup messaging. Use an exact server-configured trusted origin, validate both `event.origin` and expected `event.source` at the receiver, and reject malformed, unexpected or replayed messages. Popup messaging should communicate completion only, not credentials.

Review the Google OIDC/OAuth flow and, where compatible, use Authorization Code Flow with PKCE and server-side code exchange. Validate state, nonce where applicable, issuer, signature, audience, expiry, exact redirect URI and authorized Workspace domain. Prevent login CSRF, account substitution, replay and open redirects. Do not blindly replace a working identity integration; document migration/compatibility requirements.

Review session handling:

- Remove reusable bearer/session tokens from `localStorage` and other JS-readable storage.
- Prefer `Secure`, `HttpOnly`, appropriately configured `SameSite` cookies.
- Add CSRF protection for state-changing requests and review CORS/credentialed requests.
- Prevent session fixation; rotate session identifiers after login and privilege changes.
- Ensure logout revokes server-side session state; validate expiry and renewal.
- Preserve legitimate multi-tab behavior without exposing credentials.

Review secrets and IAP:

- Production must fail closed if the stable HMAC signing secret is missing; do not silently generate an ephemeral production secret.
- Load secrets from Secret Manager or an equivalent secure provider; document safe rotation.
- If IAP is enabled, validate JWT signature, issuer, expiry and exact configured audience. Reject missing/wrong audience and do not trust user-supplied identity headers.
- Keep local development behavior explicitly separated from production.

Add tests for untrusted/wildcard origins, opener/source mismatch, malformed/replayed responses, invalid OAuth state/nonce/issuer/audience/signature, expired tokens, redirect mismatch, unauthorized domain, localStorage exposure, cookie flags, CSRF, fixation, logout, missing HMAC secret and IAP audience enforcement. Use synthetic credentials only.

Create `security_test_logs/phase_01_oauth/REPORT.md`.

**Commit:** `security: remediate oauth and session authentication vulnerabilities`  
**Stop condition:** relevant security/authentication tests pass; report manual staging validation still required. Do not deploy.

---

# Phase 2 — Persistence and distributed GCP identity (P1)

**Goal:** remove unsafe shared-filesystem database assumptions and process-local credential dependencies.

Trace every database and file write. Verify whether SQLite is actually configured on Cloud Storage FUSE and identify all session/user metadata stored in JSON or local files. Do not assume a process-level lock provides cross-instance locking.

For production persistence, use Cloud SQL PostgreSQL (or an equally suitable transactional managed database) with the supported adapter for the installed ADK version. Verify actual `DatabaseSessionService`/SQLAlchemy compatibility before implementation. Add shared configuration, Cloud Run connectivity, bounded pooling/concurrency, timeouts, transactions, migrations/schema versioning and health checks. Production must not silently fall back to SQLite. SQLite may remain for explicitly configured local development only; never place its database on GCS FUSE.

Provide a safe, repeatable, idempotent migration path from current SQLite/JSON data. Preserve IDs, ownership, relationships and timestamps; detect duplicates/inconsistency; validate counts and referential integrity; produce a report; document backup, cutover and rollback. Do not auto-delete old data and do not introduce unsafe dual writes.

Review delegated GCP access in `gcloud_bridge.py` and related code. Do not use process-local dictionaries as the authoritative credential store. Prefer short-lived service-account impersonation with least privilege when it meets the user-access model. If delegated user refresh tokens are required, persist them in a protected store, encrypt at rest with an appropriate KMS-backed design, enforce owner/tenant isolation, expiry and revocation, and never return/log refresh tokens. Require identity and authorization checks before privileged operations.

Add isolated tests for two independent instances: create in A/read in B/update in B/read in A; concurrent updates; restart; DB disconnect/reconnect; rollback; expiry/revocation; migration idempotency and referential integrity. Use disposable local PostgreSQL/test infrastructure only.

Update deployment templates/docs for Cloud SQL, Secret Manager, service account IAM and environment variables. Do not provision or change real GCP resources.

Create `security_test_logs/phase_02_persistence/REPORT.md`.

**Commit:** `security: migrate distributed session persistence to PostgreSQL`  
**Stop condition:** migration is documented and tested in isolation; any unavailable real-GCP validation is BLOCKED. Do not deploy.

---

# Phase 3 — Vertex AI model registry and resilience (P1)

**Goal:** prevent transient health-check failures from making configured models disappear and provide safe, observable execution recovery.

Inspect `pqc_agent/model_registry.py`, discovery, verification, caching, model selection, default model, client initialization, execution and error propagation. Verify model IDs, locations, API/tool-calling/structured-output compatibility against current project dependencies and authoritative supported configuration. Do not change model IDs based on guesses.

Separate **configured model** from **runtime availability**. Represent states such as `CONFIGURED`, `UNKNOWN`, `AVAILABLE`, `DEGRADED`, `TEMPORARILY_UNAVAILABLE`, `AUTHENTICATION_FAILED`, `PERMISSION_DENIED`, `INVALID_CONFIGURATION` and `DISABLED`. A transient probe failure must not delete a configured model or overwrite its last known successful state. Show last successful verification, latest failure reason/time and make clear that cached availability does not guarantee a successful execution.

Implement bounded probes/timeouts, configurable TTL, stale-while-revalidate/last-known-good behavior, concurrency protection and shared cache/state if multiple instances require it. Avoid excessive probes and retry storms.

Classify errors including 400, 401, 403, 404, 408, 429, 5xx, network/deadline errors, safety refusals and context-length failures. Retry only transient failures, with bounded exponential backoff, jitter, deadlines and `Retry-After` support. Do not retry permanent configuration/auth/permission errors, safety refusals or invalid tool arguments. Add a circuit breaker with bounded recovery behavior.

Fallback must use an explicit allowlist and only models proven compatible with the task's tool calling, structured output and context needs. Never silently degrade a security-sensitive assessment, bypass safety/permissions, or fallback after authorization errors, malformed requests or safety rejection. Record requested and actual model IDs, reason and attempts; expose a fallback notice where relevant.

Add privacy-safe execution metadata: request ID, logical task, requested/actual model, location where appropriate, timestamps, latency, attempts/retries, fallback, classified error and final status. Never log secrets, confidential inventory or sensitive prompts.

Test success; timeout; 429/503; 401/403/400; invalid model; cache expiry; known-good model during outage; recovery; concurrent probes; circuit breaker; retry limits; approved/unapproved fallback; actual-model attribution; safety refusal; and catalog persistence through transient errors. Use mocks plus an isolated integration test where available.

Create `security_test_logs/phase_03_model_resilience/REPORT.md`.

**Commit:** `reliability: implement resilient Vertex AI model management`  
**Stop condition:** model registry and agent regression tests pass. Do not deploy.

---

# Phase 4 — AI security, PQC evidence and scoring integrity (P1)

**Goal:** ensure untrusted data cannot control the agent and findings/scores distinguish facts, inferences and unknowns.

Trace every input to model context: uploads, PDFs/documents, resource names/labels/descriptions, KMS/IAM/certificate metadata, API/tool outputs, retrieved content and prior agent outputs. Treat all external content as untrusted data, never as instructions. Separate trusted system/developer policy from untrusted data; use structured typed outputs; validate tool arguments and authorization outside the LLM. Untrusted content must not authorize tools, change system policy, access another tenant/project or alter a conclusion. Minimize sensitive data sent to models.

Add benign synthetic adversarial fixtures for direct/indirect prompt injection in documents, PDFs, resource metadata, labels and tool outputs; system prompt extraction; cross-user data access; unauthorized commands; read-only bypass; and manipulated conclusions. Verify actual behavior and tool permissions, not just prompt text.

Create a validated evidence schema with, where applicable: evidence/finding IDs, source service/API, resource/project identifiers, collection time, collector version, observed value, classification, confidence, limitations, provenance and supporting references. Distinguish `CONFIRMED_OBSERVATION`, `INFERENCE`, `UNKNOWN`, `NOT_ASSESSED` and `COLLECTION_FAILURE`. Missing information must never become a negative finding or compliance assertion. Do not fabricate values, timestamps or sources.

Validate KMS-to-workload/application correlations programmatically. Preserve STRONG/MEDIUM/WEAK only where justified. Explicit CMEK references may support a strong association; IAM permissions alone do not prove runtime key usage; name similarity alone never proves a dependency. Every inference must expose its supporting evidence and limitations.

Build a service/resource coverage matrix with states such as `ASSESSED`, `PARTIALLY_ASSESSED`, `NOT_ASSESSED`, `UNSUPPORTED`, `PERMISSION_DENIED` and `COLLECTION_FAILED`. Document exact GCP resource coverage and gaps such as application libraries/runtime behavior and external/multicloud infrastructure when not collected. Never claim complete enterprise-wide cryptographic inventory if only selected GCP services are covered.

Review `weighted_kms_pqc_maturity` and related scoring. Keep deterministic calculations and expose formula, inputs, exclusions, missing data and limitations. Separate KMS PQC maturity, network TLS PQC readiness, application cryptographic discovery coverage and overall assessment coverage. Missing/unassessed data must not inflate maturity or appear compliant. Do not arbitrarily change weights; any criteria change needs rationale and traceable authoritative NIST/Google sources with version/date. Deterministic math must be tested with deterministic assertions, not judged by an LLM.

Review all infrastructure tools and `gcloud_bridge.py`: strict command/argument allowlists, no shell execution/arbitrary command construction, explicit project/resource scope, bounded pagination, least-privilege IAM and read-only enforcement both in code and GCP IAM. Test unauthorized/destructive operations.

Test partial inventory, insufficient permissions, collection failures, weak/incorrect correlation, malicious metadata, prompt injection, cross-tenant attempts, evidence provenance, invalid/missing scoring inputs, score reproducibility and read-only bypass.

Create `security_test_logs/phase_04_evidence_integrity/REPORT.md` with threat model, attack matrix, schema, coverage, correlation/scoring methodology, results, authoritative references and remaining gaps.

**Commit:** `security: strengthen AI input defenses and PQC evidence integrity`  
**Stop condition:** relevant evidence, scoring, workflow and tool-security tests pass. Do not deploy.

---

# Phase 5 — Application and supply-chain hardening (P2)

**Goal:** reduce container, dependency, upload and API attack surface.

Container: use a non-root runtime user; minimize packages and filesystem permissions; avoid secrets in build args/image layers; use deterministic builds; document writable paths and preserve Cloud Run compatibility. Add applicable image/container checks.

Dependencies: inspect `requirements.txt`, `uv.lock`, `pyproject.toml`, transitive/build dependencies and CI. Use the committed lockfile for reproducible installation (for example, the project's compatible frozen-lock workflow). Detect and document vulnerable dependencies; do not perform unrelated upgrades. Generate an SBOM in a suitable standard format and document update/provenance procedures.

Uploads: enforce configurable conservative size limits, allowlisted extensions/types and content-based validation; normalize filenames; prevent path traversal; use safe temporary storage; limit parsing time/resources; handle malformed files and decompression bombs; enforce user authorization and cleanup. Never execute uploaded content.

API: review authentication/authorization, CORS, CSRF, rate limits, request body limits, headers, error handling, session/tenant isolation and sensitive responses. Do not expose stack traces, secrets or sensitive evidence in errors.

Observability: structured privacy-safe logs with correlation IDs for authentication/authorization, session lifecycle, DB errors, model selection/fallback, tool execution, read-only violations, collection failures and assessment lifecycle. Never log credentials, private keys, session tokens or complete sensitive payloads.

Run configured Python static analysis, dependency scanning, secret scanning, container scanning, SBOM generation, unit/integration/security/auth/upload/agent tests and complete regression. State clearly which scanners were unavailable and review false positives; do not claim unavailable scans ran.

Create `security_test_logs/phase_05_hardening/REPORT.md` with container, dependencies, SBOM path, scans, upload/API tests, full regression and residual risks.

**Commit:** `security: harden container dependencies and application surface`  
**Stop condition:** no unresolved critical test failures or committed secrets; do not deploy.

---

# Phase 6 — Independent security acceptance and release gate

**Goal:** audit the actual code independently; do not trust prior summaries or the existence of tests. Reproduce high-impact findings using synthetic accounts/data and isolated infrastructure.

Re-test OAuth: wildcard `postMessage`, origin/source validation, replay/state/nonce, login CSRF, fixation, cookie flags, localStorage token exposure, logout invalidation, IAP audience and missing HMAC behavior.

Re-test distributed behavior: cross-instance session reads/writes, concurrent updates, DB interruption/recovery, transaction rollback, restarts, delegated credential recovery, expiry and revocation.

Re-test model resilience: timeouts, quota/outages, invalid IDs, permission errors, context overflow, tool incompatibility, fallback misconfiguration, actual model attribution, catalog persistence and retry loops.

Re-test AI security: direct/indirect prompt injection, malicious metadata/tool output, data exfiltration, cross-user access, unauthorized tools, read-only bypass and evidence manipulation.

Re-test PQC accuracy using fully assessed, partial, permission-denied, missing-metadata, conflicting-evidence, weak-correlation, confirmed-CMEK and unassessed-external examples. Verify evidence traceability, confidence, explicit coverage, score determinism and no unsupported compliance claims.

For each test record attack scenario, preconditions, steps, expected/actual results, PASS/FAIL/BLOCKED, evidence, severity and residual risk. Do not fabricate execution. If a critical issue is discovered, document it, make a separate minimal fix with regression test, re-run affected tests and re-audit that control.

Create:

- `security_test_logs/phase_06_independent_audit/REPORT.md`
- `docs/security-remediation/RELEASE_READINESS.md`

Release gate must be `GO`, `CONDITIONAL GO` or `NO-GO`. A `GO` requires no unresolved critical vulnerabilities, no unresolved high-risk authentication/session isolation/cross-user leakage, controlled and observable model degradation, validated evidence integrity, enforced read-only controls and passing critical regression tests. Infrastructure-dependent tests not executed remain BLOCKED and cannot count as PASS. Do not deploy.

**Commit:** `security: complete independent security acceptance audit`  
**Stop condition:** deliver audit and release recommendation; stop.

---

## Required final response format (all phases)

Keep the response concise and use this structure:

1. **Phase/status:** completed, blocked or failed.
2. **Findings fixed / confirmed:** only evidence-backed claims.
3. **Files changed:** key paths only.
4. **Tests:** executed commands and PASS/FAIL/BLOCKED counts.
5. **Remaining risks / operator actions:** include GCP setup or staging validation still required.
6. **Commit:** SHA and message, or explain why no commit was made.
7. **Report:** exact Markdown report path.

Do not start the next phase automatically.
