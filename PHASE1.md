# PHASE 1–2 FINAL CORRECTIVE PASS — PQC INVENTORY AGENT

Repository: `g-jsaccomani/pqc_inventory_agent`
Branch: `security-hardening/phase-01-02`

## OBJECTIVE

Perform a narrowly scoped corrective pass against the existing Phase 1 and Phase 2 implementation.

Do NOT redesign, rewrite, or reimplement completed functionality.

Preserve all existing implementation work, commits, Markdown documentation, test suites, and migration artifacts.

Fix the two identified findings:

1. OAuth transaction TTL must never exceed 600 seconds.
2. Production database schema initialization must be exclusively controlled by Alembic, not SQLAlchemy `metadata.create_all()`.

Additionally, improve PostgreSQL integration verification and update the existing security evidence.

Do not deploy, merge into `main`, modify production infrastructure, or start Phase 3.

---

## STEP 1 — BASELINE AND REPOSITORY SAFETY

Before editing:

1. Confirm the current branch is `security-hardening/phase-01-02`.
2. Record the current HEAD SHA.
3. Run `git status --short`.
4. Confirm the working tree is clean. If it is not clean, inspect and preserve existing user changes. Never discard them.
5. Inspect the existing implementation and documentation:
   - `pqc_agent/auth_store.py`
   - `pqc_agent/workspace_server.py`
   - `tests/test_phase1_distributed_auth.py`
   - `tests/test_phase2_persistence_and_credentials.py`
   - `security_test_logs/phase_01_02_remediation/REPORT.md`
   - `docs/security-remediation/PHASE_01_02_ACCEPTANCE.md`
   - `docs/security-remediation/MIGRATION_AND_ROLLBACK.md`
   - `migrations/versions/20261117_0001_initial_phase1_phase2_schema.py`

Do not recreate existing Markdown files.

Create a dedicated evidence directory:

`security_test_logs/phase_01_02_final_validation/`

Record baseline information in:

`security_test_logs/phase_01_02_final_validation/BASELINE.md`

---

## STEP 2 — AUTH-02: ENFORCE STRICT 600-SECOND OAUTH TTL

Inspect `DistributedAuthStore.create_oauth_transaction()`.

Current implementation allows:

`effective_ttl = max(1, min(int(ttl_seconds), 1800))`

Correct the implementation so the maximum transaction TTL is exactly 600 seconds.

Requirements:

- Reject or safely clamp TTL values above 600 seconds.
- Never allow zero or negative effective TTL.
- Preserve cryptographically secure state, PKCE verifier, OIDC nonce, and browser binding behavior.
- Preserve atomic single-use transaction consumption.
- Do not expose the PKCE verifier in state, URL parameters, cookies, or browser-visible JSON.

Add explicit regression tests for:

1. Default TTL.
2. TTL = 1.
3. TTL = 600.
4. TTL = 601.
5. TTL = 1800.
6. TTL = 0.
7. Negative TTL.
8. Expired transaction rejection.
9. Concurrent callback single-use behavior.

Verify that no transaction can remain valid beyond 600 seconds.

---

## STEP 3 — DB-01: MAKE ALEMBIC THE ONLY PRODUCTION SCHEMA AUTHORITY

Inspect:

- `DistributedAuthStore.__init__()`
- `DistributedAuthStore.ensure_schema()`
- `create_workspace_app()`
- ADK `DatabaseSessionService` initialization.
- Application startup and deployment scripts.
- Alembic configuration and migration revision.

The current implementation calls:

`PqcPersistenceBase.metadata.create_all(self.engine)`

This may create tables before Alembic applies its versioned migration.

### Required behavior

Production:

- Alembic is the only authority for schema creation and version upgrades.
- Production startup must NOT call `metadata.create_all()`.
- Production startup must validate the expected Alembic revision.
- Production startup must fail closed if the schema is missing, outdated, or inconsistent.
- Never automatically downgrade or modify an existing production schema.
- Never silently create missing production tables.

Development and isolated unit tests:

- Existing convenience initialization may remain available only through an explicit non-production configuration.
- SQLite remains permitted for isolated local tests.
- SQLite must remain prohibited in production.

### Migration execution

Create or update an explicit migration entry point.

Requirements:

1. Run `alembic upgrade head` as a separate, explicit migration operation.
2. Verify the expected revision after migration.
3. Start the application only after successful migration.
4. Do not run migrations concurrently from multiple Cloud Run instances.
5. Never run a production migration automatically during application startup.
6. Preserve the current rollback runbook.

If a deployment script is updated, ensure the migration step is explicit and requires a configured PostgreSQL target.

Do not execute the migration against production.

### Required regression tests

- Production startup with missing schema must fail closed.
- Production startup with outdated Alembic revision must fail closed.
- Production startup must not invoke `metadata.create_all()`.
- Explicit Alembic migration must create the expected schema.
- Re-running migration must be safe.
- SQLite production configuration must remain rejected.
- Local development initialization must continue working.

---

## STEP 4 — POSTGRESQL 16 INTEGRATION VALIDATION

Inspect the existing live PostgreSQL integration test.

Target:

`tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration`

Requirements:

- Use PostgreSQL 16 or compatible Cloud SQL PostgreSQL.
- Use `PQC_TEST_POSTGRES_URL`.
- Test two independent application instances against the same real PostgreSQL database.
- Test OAuth transaction creation on instance A and consumption on instance B.
- Test session creation, retrieval, and updates across instances.
- Test session revocation across instances.
- Test application restart and persistence.
- Test concurrent OAuth callback consumption.
- Test transactional rollback.
- Test credential encryption, retrieval, expiration, and revocation.
- Test tenant isolation.

If PostgreSQL is unavailable:

- Mark the integration test as BLOCKED/SKIPPED.
- Record the exact missing dependency or infrastructure requirement.
- Never report SQLite tests as PostgreSQL integration tests.
- Never fabricate PostgreSQL execution output.

Do not install unauthorized binaries or bypass corporate endpoint protection.

---

## STEP 5 — FULL REGRESSION TESTING

Run:

```bash
.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests
.venv/bin/pytest -v -rs
git diff --check
```

Run the PostgreSQL integration test separately when a valid test database is available:

```bash
PQC_TEST_POSTGRES_URL="<DISPOSABLE_POSTGRESQL_16_TEST_DATABASE>" \
.venv/bin/pytest -v -rs \
tests/test_phase2_persistence_and_credentials.py::test_phase2_live_postgresql_multi_instance_integration
```

Never use production database credentials.

Record:

- Exact commands.
- Exit codes.
- Passed tests.
- Failed tests.
- Skipped tests.
- Blocked tests.
- Runtime.
- PostgreSQL server version when available.

---

## STEP 6 — UPDATE EXISTING DOCUMENTATION

Update, do not recreate:

1. `security_test_logs/phase_01_02_remediation/REPORT.md`
2. `docs/security-remediation/PHASE_01_02_ACCEPTANCE.md`
3. `docs/security-remediation/MIGRATION_AND_ROLLBACK.md`

Add a corrective-pass section containing:

- Original finding.
- Root cause.
- Corrective implementation.
- Files modified.
- Regression tests added.
- Actual test results.
- Remaining blockers.
- Final acceptance status.

Use only these statuses:

- PASS
- FAIL
- BLOCKED
- NOT_IMPLEMENTED

Do not change a previously BLOCKED item to PASS without actual new execution evidence.

Create:

`security_test_logs/phase_01_02_final_validation/FINAL_REPORT.md`

The report must include:

- Original baseline SHA.
- Final commit SHA.
- Changed files.
- Security findings addressed.
- Test execution evidence.
- PostgreSQL integration status.
- Remaining risks.
- Final recommendation: GO or NO-GO.

Also create:

`security_test_logs/phase_01_02_final_validation/CHECKPOINT.md`

Include enough technical context for another coding agent to continue without re-reading the entire repository.

---

## STEP 7 — GIT HYGIENE

Do not amend or rewrite previous commits.

Create one new commit only after all locally executable tests pass:

`security: close phase 1-2 acceptance gaps`

Before committing:

```bash
git status --short
git diff --check
git diff --stat
```

After committing:

```bash
git status --short
git log -3 --oneline
git rev-parse HEAD
```

Record the final SHA in `CHECKPOINT.md` and `FINAL_REPORT.md`.

If the PostgreSQL integration test is blocked, the commit may still be created if all locally executable tests pass, but the final acceptance status MUST remain BLOCKED / NO-GO for production.

---

## STRICT PROHIBITIONS

- No deployment.
- No production database access.
- No merge into main.
- No force-push.
- No rewriting previous commits.
- No Phase 3 implementation.
- No unrelated refactoring.
- No removal of existing tests or documentation.
- No fake test results.
- No weakening of security controls to make tests pass.
- No silent fallback to SQLite in production.

## FINAL RESPONSE

Return a concise technical summary containing:

1. Baseline and final commit SHA.
2. Findings fixed.
3. Files modified.
4. Test results.
5. PostgreSQL integration status.
6. Remaining blockers.
7. GO / NO-GO decision.

Stop after this corrective pass.