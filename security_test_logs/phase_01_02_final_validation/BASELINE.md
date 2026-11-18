# Phase 1–2 Final Corrective Pass — Baseline Record

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-01-02`
- **Pre-Corrective-Pass HEAD SHA:** `d43e17e594131a23a021b1afa68541851ff32307` (`d43e17e` — `docs(security): add remediation specifications and execution checkpoint logs`)
- **Prior Remediation Commits on Branch:**
  - `02b53e9` — `security: complete PostgreSQL persistence and credential architecture`
  - `60ffaa2` — `security: complete OAuth and distributed authentication remediation`
  - `1d112f6` — `security: remediate oauth and session authentication vulnerabilities` (`main`)
  - `91efa40` — `security: establish remediation baseline and test evidence`
  - `2449589` — Original pre-remediation Phase 0 baseline SHA
- **Timestamp:** `2026-11-17T23:01:31-03:00`

## Pre-Edit Working Tree Inspection (`git status --short`)

```text
 M PHASE1.md
```

- Only `PHASE1.md` was modified in the working tree (updated by the user with the narrow Phase 1–2 Final Corrective Pass specification). This user change is preserved intact.
- All existing implementation modules, migration scripts, test suites, and Markdown documentation (`security_test_logs/phase_01_02_remediation/REPORT.md`, `docs/security-remediation/PHASE_01_02_ACCEPTANCE.md`, `docs/security-remediation/MIGRATION_AND_ROLLBACK.md`) were inspected and preserved without recreation.

## Findings Targeted in This Corrective Pass

1. **`AUTH-02` (OAuth Transaction TTL Upper Bound):**
   - `DistributedAuthStore.create_oauth_transaction()` (`pqc_agent/auth_store.py:673`) and `_oauth_ttl_seconds()` (`pqc_agent/workspace_server.py:1852`) clamped `ttl_seconds` with `min(..., 1800)`, allowing OAuth transactions to remain valid for up to 1,800 seconds instead of the strict 600-second maximum.
2. **`DB-01` (Production Schema Authority):**
   - `DistributedAuthStore.__init__()` / `ensure_schema()` (`pqc_agent/auth_store.py:626-639`) unconditionally called `PqcPersistenceBase.metadata.create_all(self.engine)` by default, and Google ADK `DatabaseSessionService.prepare_tables()` called `BaseV1.metadata.create_all()`, allowing tables to be created outside Alembic in production instead of enforcing Alembic as the sole production schema authority with fail-closed revision verification.
