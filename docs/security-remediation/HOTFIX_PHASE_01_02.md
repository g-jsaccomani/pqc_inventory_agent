# HOTFIX — PHASE 1–2 FINAL SAFETY FIX

Repository: `g-jsaccomani/pqc_inventory_agent`
Branch: `security-hardening/phase-01-02`

## OBJECTIVE

Implement ONLY two narrowly scoped fixes:

1. Protect the live PostgreSQL integration test from accidentally truncating a non-disposable database.
2. Synchronize final validation documentation with the actual current Git HEAD.

Do not refactor existing architecture or reopen completed remediation work.

## STEP 1 — BASELINE

- Confirm branch: `security-hardening/phase-01-02`.
- Record current HEAD SHA.
- Run `git status --short`.
- Preserve all existing user changes.
- Inspect:
  - `tests/test_phase2_persistence_and_credentials.py`
  - `security_test_logs/phase_01_02_final_validation/FINAL_REPORT.md`
  - `security_test_logs/phase_01_02_final_validation/CHECKPOINT.md`
  - `docs/security-remediation/PHASE_01_02_ACCEPTANCE.md`

## STEP 2 — PROTECT DESTRUCTIVE POSTGRESQL TEST

Target:

`test_phase2_live_postgresql_multi_instance_integration`

The test currently executes TRUNCATE against multiple application tables.

Implement a mandatory safety guard BEFORE any database connection or destructive SQL operation.

Required safeguards:

1. Require explicit environment variable:
   `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`

2. Parse the database URL using SQLAlchemy `make_url()`.

3. Require the database name to match:
   `^pqc_test_[a-zA-Z0-9_]+$`

4. Reject database names containing production-like terms:
   `prod`, `production`, `live`, `customer`, `primary`.

5. Reject execution if any production environment indicator is active:
   - `K_SERVICE`
   - `PQC_PRODUCTION_MODE=true`
   - `PQC_ENV=production`

6. Require PostgreSQL backend. Reject SQLite and all other backends.

7. Fail closed with a clear error message if any condition is not met.

8. Print a clear warning identifying the disposable database before executing TRUNCATE.

9. Keep all existing integration test scenarios intact.

10. Never silently skip the safety guard.

### Add regression tests

- Missing opt-in -> reject.
- Opt-in false -> reject.
- Valid opt-in + `pqc_test_validation` -> allow.
- Database `production` -> reject.
- Database `pqc_production_test` -> reject.
- Database `pqc_test_customer_data` -> reject.
- Database `pqc_workspace` -> reject.
- SQLite URL -> reject.
- `K_SERVICE` configured -> reject.
- `PQC_PRODUCTION_MODE=true` -> reject.
- `PQC_ENV=production` -> reject.
- Verify rejected cases execute ZERO SQL statements, especially ZERO TRUNCATE statements.

The safety guard must be independently testable without requiring a live PostgreSQL server.

Do not change the PostgreSQL production configuration or application behavior.

## STEP 3 — UPDATE FINAL DOCUMENTATION

Update existing files; do not recreate them.

In `security_test_logs/phase_01_02_final_validation/FINAL_REPORT.md`:

- Record the actual current HEAD SHA.
- Record this hotfix commit SHA after committing.
- Add the destructive-test safety guard as a completed finding.
- Include exact regression test results.
- Preserve the existing PostgreSQL 16.15 integration results.
- Do not claim Cloud KMS live validation.
- Preserve Cloud Run / Cloud SQL / Cloud KMS deployment as an outstanding operational prerequisite.

In `security_test_logs/phase_01_02_final_validation/CHECKPOINT.md`:

- Record current branch and final HEAD SHA.
- Record the two safeguards implemented.
- Document the exact remaining production prerequisites.
- Include the next recommended phase.

In `docs/security-remediation/PHASE_01_02_ACCEPTANCE.md`:

- Add the destructive-test isolation guard to the testing acceptance criteria.
- Do not change unrelated acceptance statuses.

## STEP 4 — TESTS

Run:

```bash
.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests

.venv/bin/pytest -q \
  tests/test_phase2_persistence_and_credentials.py

.venv/bin/pytest -q \
  tests/test_auth_hardening.py \
  tests/test_phase1_distributed_auth.py

git diff --check
```

If a test fails, fix only regressions introduced by this hotfix.

Do not rerun the live PostgreSQL destructive integration test unless:
- `PQC_TEST_POSTGRES_URL` points to a disposable PostgreSQL database;
- `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`;
- all safety guards pass.

Do not use production credentials.

## STEP 5 — GIT

Create exactly one new commit:

`security: guard destructive postgres integration tests`

Before committing:

```bash
git status --short
git diff --check
git diff --stat
```

After committing:

```bash
git status --short
git log -4 --oneline
git rev-parse HEAD
```

Update the final SHA in the documentation.

Do not amend previous commits.
Do not force-push.
Do not merge into main.
Do not deploy.
Do not implement Phase 3.

## FINAL RESPONSE

Return only:

1. Commit SHA.
2. Files changed.
3. Regression test results.
4. Confirmation that rejected database configurations execute zero SQL.
5. Remaining production prerequisites.
6. Final Phase 1–2 status.

Stop immediately after the hotfix.
