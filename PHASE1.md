# CRITICAL REMEDIATION — PHASE 1 AND PHASE 2 COMPLETION

You are operating as a Principal Application Security Engineer, Senior OAuth Architect and Google Cloud Infrastructure Engineer.

Repository: https://github.com/g-jsaccomani/pqc_inventory_agent

Your mission is to COMPLETE the previously implemented Phase 1 (OAuth and Authentication) and Phase 2 (Persistence and Distributed Identity).

**This is an implementation task, NOT another assessment exercise.**

The previous implementation was reviewed and found incomplete. You must correct the findings below in the actual source code, configuration, tests and deployment documentation.

Do not proceed to Phase 3.

---

## 1. EXECUTION RULES

1. Inspect the current branch, Git status, recent commits and existing implementation.
2. Preserve all valid existing work.
3. Do not reset, overwrite or discard user changes.
4. Do not create duplicate implementations when an existing component can be properly corrected.
5. Do not weaken security controls to make tests pass.
6. Do not introduce mock-only solutions as substitutes for production architecture.
7. Do not deploy or modify production infrastructure.
8. Never expose or commit credentials, tokens, secrets or sensitive user data.
9. Do not declare a requirement complete without implementation and corresponding test evidence.
10. Keep changes strictly within Phase 1 and Phase 2.

If a requirement cannot be implemented safely, explain the technical blocker and do not simulate success.

## 2. PHASE 1 — OAUTH AND AUTHENTICATION

### AUTH-01 — Eliminate OAuth Implicit Flow

Remove every remaining OAuth implicit flow.

Mandatory requirements:

- Use Authorization Code Flow with PKCE.
- Support both confidential and public OAuth clients.
- Never fall back to `response_type=token`.
- Never return access tokens through browser redirects.
- Perform token exchange server-side whenever the existing architecture supports it.
- Validate state, nonce, issuer, audience, signature and expiration.
- Enforce exact redirect URI allowlists.
- Prevent authorization response replay.

Search the entire repository for:
- `response_type=token`
- Implicit OAuth implementations.
- Token-bearing redirects.
- Alternative or legacy OAuth callbacks.

No production authentication path may retain implicit flow.

### AUTH-02 — Correct PKCE Verifier Storage

The previous implementation exposed the PKCE `code_verifier` inside the signed OAuth `state` payload.

Fix this.

Requirements:

- Generate a cryptographically secure random verifier.
- Store the verifier server-side in a temporary OAuth transaction record.
- Keep `state` opaque and random.
- Never place the verifier or reusable credentials inside state.
- Associate each transaction with the initiating session.
- Apply strict expiration.
- Enforce single-use consumption.
- Prevent concurrent callback races.
- Reject replayed or expired transactions.
- Ensure transaction state is shared between application instances.

Do not confuse signing with encryption.

### AUTH-03 — Remove Session Tokens From JSON

Remove all reusable session bearer tokens from authentication API responses.

Requirements:

- Session authentication must use appropriately configured Secure, HttpOnly cookies.
- No reusable session token may be exposed through JSON, browser storage or URLs.
- Verify all login, refresh, callback and logout response paths.
- Maintain CSRF protection.
- Preserve legitimate multi-tab behavior.
- Ensure cookies have appropriate SameSite and Path attributes.
- Ensure production HTTPS behavior.

Search for all occurrences of session tokens in API response serialization.

Do not claim completion based only on removal from localStorage.

### AUTH-04 — Distributed Nonce and Session Revocation

Eliminate process-local authoritative storage for:

- OAuth nonce records.
- OAuth transaction consumption.
- Session revocation.
- Any authentication state requiring consistency between instances.

Use the shared transactional PostgreSQL persistence layer implemented in Phase 2.

Requirements:

- Atomic state transitions.
- Single-use nonce and OAuth transactions.
- Cross-instance revocation.
- Session expiration.
- Replay protection.
- Consistent behavior after application restarts.

Do not rely on Python dictionaries, local caches or in-process locks as authoritative state.

### AUTH-05 — Authentication Regression Tests

Create tests for:

1. Public OAuth client using Authorization Code + PKCE.
2. Confidential OAuth client using Authorization Code + PKCE.
3. Rejection of implicit flow.
4. PKCE verifier never appearing in state.
5. Opaque state validation.
6. Invalid state rejection.
7. Nonce replay rejection.
8. OAuth transaction expiration.
9. OAuth transaction single-use enforcement.
10. Session token absent from JSON responses.
11. Session token absent from localStorage.
12. Secure and HttpOnly cookie behavior.
13. CSRF enforcement.
14. Session revocation across independent instances.
15. Application restart.
16. Concurrent callback handling.

Use synthetic credentials and isolated test identities.

---

## 3. PHASE 2 — POSTGRESQL AND DISTRIBUTED PERSISTENCE

### DB-01 — Implement PostgreSQL as Production Persistence

The current implementation still contains SQLite-based session persistence.

Replace it with PostgreSQL for production.

Requirements:

- Use Cloud SQL PostgreSQL as the supported production architecture.
- Use a PostgreSQL-compatible ADK DatabaseSessionService configuration.
- Verify compatibility against the exact installed Google ADK version.
- Inspect and implement the actual supported SQLAlchemy integration.
- Add the required PostgreSQL driver.
- Configure Cloud Run to Cloud SQL connectivity.
- Implement appropriate connection pooling and timeouts.
- Implement transaction management.
- Add database migrations and schema versioning.

Production must fail closed if PostgreSQL is unavailable or incorrectly configured.

SQLite may remain exclusively for explicitly configured local development and isolated unit tests.

Do not silently fall back from PostgreSQL to SQLite in production.

### DB-02 — Eliminate SQLite on GCS FUSE

Remove every production configuration that places SQLite database files on Cloud Storage FUSE.

Inspect:

- `app.yaml`
- Dockerfile
- Database initialization
- Session service configuration
- Environment variables
- Volume mounts
- Deployment documentation

Requirements:

- PostgreSQL handles transactional data.
- GCS is reserved for appropriate object storage.
- Never use GCS FUSE as a substitute for a transactional database.
- Eliminate WAL and SQLite locking workarounds from production configuration.

Search the complete repository for SQLite production references.

### DB-03 — Eliminate JSON as Authoritative Production Storage

Move authoritative user metadata, session metadata and other shared transactional records to PostgreSQL.

Requirements:

- Define a consistent schema.
- Enforce user ownership.
- Enforce tenant isolation.
- Use atomic updates.
- Apply appropriate unique constraints.
- Preserve timestamps and relationships.
- Avoid inconsistent JSON/database dual writes.
- Eliminate production filesystem fallback.

JSON may remain as an export or backup format, not as authoritative shared storage.

### ID-01 — Replace InMemoryCredentialService

The previous implementation still uses process-local credential storage.

Replace `InMemoryCredentialService` as the authoritative production credential provider.

Evaluate the following identity approaches:

**Preferred:** service account impersonation with short-lived credentials and least-privilege IAM, when compatible with the intended user access model.

**Alternative:** securely persisted delegated user refresh tokens when user-specific authorization is genuinely required.

For delegated credentials:

- Store encrypted credentials in a protected persistent service.
- Use envelope encryption backed by Google Cloud KMS.
- Enforce user and tenant ownership.
- Implement expiration and revocation.
- Never expose refresh tokens to the frontend.
- Never log credentials.
- Ensure credentials remain available across Cloud Run instances.

Do not use process memory, temporary files or plain JSON files as authoritative credential storage.

Document the selected design and justify it.

### DB-04 — Implement Safe Data Migration

Implement a migration procedure from existing SQLite and JSON persistence to PostgreSQL.

Requirements:

- Idempotent migration.
- Preserve user identities.
- Preserve session identifiers.
- Preserve ownership relationships.
- Preserve relevant timestamps.
- Validate record counts.
- Validate referential integrity.
- Detect duplicates and inconsistent records.
- Generate a migration report.
- Document backup and rollback.
- Never delete original data automatically.

The migration must be tested against disposable test data.

Do not execute migrations against production.

---

## 4. MULTI-INSTANCE INTEGRATION TESTING

This is mandatory.

Simulate at least two independent application instances.

Execute the following workflow:

1. Authenticate a synthetic user through instance A.
2. Create an OAuth transaction.
3. Complete the transaction through instance B.
4. Create a session.
5. Retrieve the session from instance B.
6. Update the session from instance B.
7. Retrieve the update from instance A.
8. Revoke the session from instance A.
9. Attempt to access it through instance B.
10. Restart the application instances.
11. Verify that revocation and session state remain consistent.

Also test:

- Concurrent OAuth callbacks.
- Concurrent database writes.
- Database interruption.
- Transaction rollback.
- Database recovery.
- Credential expiration.
- Credential revocation.
- Unauthorized cross-user session access.
- Unauthorized cross-tenant credential access.

Use a real isolated PostgreSQL instance for integration tests whenever available.

Mocks alone do not satisfy this requirement.

If Cloud SQL infrastructure is unavailable, test against disposable PostgreSQL and explicitly mark Cloud Run/Cloud SQL deployment verification as BLOCKED.

Never report blocked tests as passed.

---

## 5. CONFIGURATION AND DOCUMENTATION

Update all relevant files.

Include:

- `app.yaml` or equivalent deployment configuration.
- `requirements.txt` and dependency lockfiles.
- Dockerfile.
- Database configuration.
- Environment variable templates.
- Secret Manager integration.
- Cloud SQL connectivity instructions.
- Service account IAM requirements.
- Credential architecture.
- Migration instructions.
- Rollback instructions.

Production configuration must not contain SQLite/GCS FUSE persistence or process-local authentication dependencies.

Never place real secrets in configuration templates.

---

## 6. MANDATORY TEST EVIDENCE

Create or update:

`security_test_logs/phase_01_02_remediation/REPORT.md`

Include:

- Root cause of each previously identified finding.
- Files modified.
- Before/after architecture.
- Implementation details.
- Authentication test results.
- PostgreSQL integration test results.
- Multi-instance test results.
- Credential isolation tests.
- Migration validation.
- Commands actually executed.
- Passed, failed, skipped and blocked tests.
- Remaining risks.
- Infrastructure prerequisites.
- Redacted logs and supporting evidence.

Every test must have a real execution result.

Do not fabricate successful test outcomes.

Create a separate remediation checklist:

`docs/security-remediation/PHASE_01_02_ACCEPTANCE.md`

Each requirement must be marked:

- PASS — implementation and tests verified.
- FAIL — implementation or tests failed.
- BLOCKED — environment or dependency unavailable.
- NOT_IMPLEMENTED — not completed.

Include links or references to supporting test evidence.

---

## 7. GIT AND CHANGE MANAGEMENT

Work on the current remediation branch.

Preserve all existing commits.

Create two logically separated commits:

First commit:

`security: complete OAuth and distributed authentication remediation`

Second commit:

`security: complete PostgreSQL persistence and credential architecture`

Before each commit:

- Run relevant tests.
- Inspect `git diff`.
- Run `git diff --check`.
- Verify no secrets were added.
- Verify no unrelated changes were introduced.

Do not force-push.

Do not deploy.

Do not merge into main.

---

## 8. FINAL ACCEPTANCE GATE

The task is complete only when the following conditions are satisfied:

### Phase 1

- No implicit OAuth flow remains.
- PKCE verifier is stored server-side, not inside state.
- State and nonce are validated and single-use.
- No reusable session bearer token is returned in JSON.
- Secure cookie authentication is implemented.
- Session revocation works across independent instances.
- Authentication regression tests pass.

### Phase 2

- Production persistence uses PostgreSQL.
- SQLite/GCS FUSE production dependency is removed.
- JSON is no longer authoritative shared persistence.
- Credential storage is distributed and protected.
- Migration is documented and tested.
- Multi-instance consistency tests pass.
- Database recovery behavior is verified.

### Final Rules

If any critical acceptance criterion fails:

- Do not mark the phase completed.
- Do not proceed to Phase 3.
- Document the remaining issue.
- Report the actual blocker.

Provide a concise final execution report with:

1. Corrected vulnerabilities.
2. Architecture changes.
3. Files modified.
4. Test results.
5. Blocked tests.
6. Remaining limitations.
7. Two commit SHAs.
8. Production infrastructure prerequisites.
9. Final Phase 1 status.
10. Final Phase 2 status.

**Do not claim success based on code changes alone. The implementation, tests and evidence must agree.**

STOP after completing these corrective remediations.