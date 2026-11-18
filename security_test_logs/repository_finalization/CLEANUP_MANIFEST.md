# Repository Finalization — Stage 2 Cleanup Manifest

- **Timestamp (Local):** `2026-11-18T14:15:00-03:00`
- **Verified Phase 1–2 Merge Commit on `main`:** `62f7247b52effc3f3cf2086a86f06071eea1b6fc` (PR `#1`, merging `0933e81dc9432b75529fe0d62c561d057b2b0f83`)

---

## 1. Tracked Files Removed from Git

- **None (`0` tracked files removed).**
  - Verification across all `76` tracked files (`git ls-files`) confirmed zero committed `__pycache__/`, `.pytest_cache/`, `.coverage`, `.env`, `.db`/`.sqlite`, or accidental temporary debris.

---

## 2. Verified Disposable Local Artifacts Removed (Untracked / Gitignored)

Every item below was verified before removal to confirm (a) it is reproducible build/test output, and (b) zero tests, migrations, scripts, or docs depend on it:

| Path | Artifact Type | Verification & Reason for Removal |
| :--- | :--- | :--- |
| `./__pycache__/` | Bytecode cache | Reproducible `.pyc` cache (contained stale `main.cpython-314.pyc` alongside `312`). |
| `./pqc_agent/__pycache__/` | Bytecode cache | Reproducible `.pyc` cache (contained stale `.cpython-314.pyc` artifacts). |
| `./tools/__pycache__/` | Bytecode cache | Reproducible `.pyc` cache (contained orphaned `hybrid_multicloud.cpython-312.pyc` from a removed prototype plus stale `.cpython-314.pyc` files). |
| `./tests/__pycache__/` | Pytest bytecode cache | Reproducible pytest `.pyc` cache. |
| `./scripts/__pycache__/` | Bytecode cache | Reproducible `.pyc` cache. |
| `./migrations/__pycache__/` | Bytecode cache | Reproducible `.pyc` cache. |
| `./migrations/versions/__pycache__/` | Bytecode cache | Reproducible `.pyc` cache. |
| `./.pytest_cache/` | Pytest state cache | Reproducible local test runner cache. |
| `./pqc_inventory_agent.egg-info/` | Stale setuptools build metadata | Stale root metadata directory; active `uv` editable `.venv` uses `.venv/lib/python3.12/site-packages/pqc_inventory_agent-2.10.0.dist-info`. |
| `./data/artifacts/pqc_agent/tester@google.com/` | Temporary pytest output (`26` folders) | Reproducible `discovery.md` test artifacts created under `TEST_AUTH_EMAIL = "tester@google.com"` during earlier non-isolated test runs. |

---

## 3. Obsolete Branches Removed (Post-Merge Verification)

| Branch | Last Commit SHA | Verification Before Deletion | Action |
| :--- | :--- | :--- | :--- |
| `origin/security-hardening/phase-01-02` | `0933e81dc9432b75529fe0d62c561d057b2b0f83` | `git merge-base --is-ancestor 0933e81dc9432b75529fe0d62c561d057b2b0f83 main` = `true` (merged into `main` via PR `#1` commit `62f7247b52effc3f3cf2086a86f06071eea1b6fc`) | Deleted remote branch (`git push origin --delete security-hardening/phase-01-02`) |
| `security-hardening/phase-01-02` (local) | `0933e81dc9432b75529fe0d62c561d057b2b0f83` | Safe non-force `git branch -d` confirmed full ancestry in `main` (`62f7247b52effc3f3cf2086a86f06071eea1b6fc`) | Deleted local branch (`git branch -d security-hardening/phase-01-02`) |

---

## 4. Files, Branches, Tags, and Artifacts Intentionally Preserved

| Item / Category | Reason for Preservation |
| :--- | :--- |
| `main` (`62f7247b52effc3f3cf2086a86f06071eea1b6fc`) & tag `v1.0-prod` | Canonical trunk and historical production release tag. |
| `PHASE1.md`, `PQC_INVENTORY_AGENT_REMEDIATION.md`, `CHECKPOINT.md` | Authoritative remediation specifications and execution checkpoints. |
| `docs/security-remediation/*` (`MASTER_REMEDIATION_PLAN.md`, `PHASE_01_02_ACCEPTANCE.md`, `MIGRATION_AND_ROLLBACK.md`, `HOTFIX_PHASE_01_02.md`) | Permanent architecture, acceptance, rollback, and safety documentation. |
| `security_test_logs/phase_00_baseline/`, `phase_01_oauth/`, `phase_01_02_remediation/`, `phase_01_02_final_validation/`, `phase_01_02_pre_merge/`, `phase_01_02_pre_merge_hotfix/` | Immutable historical audit logs and test evidence (untouched and unedited). |
| `alembic.ini`, `migrations/*`, `scripts/run_db_migrations.py`, `scripts/migrate_sqlite_to_postgres.py` | Authoritative Alembic schema revisions (`20261117_0001`, `20261117_0002`) and migration CLIs. |
| `tests/*` (`conftest.py`, `test_auth_hardening.py`, `test_phase1_distributed_auth.py`, `test_phase2_persistence_and_credentials.py`, `test_pqc_inventory.py`, `test_pre_merge_hotfix.py`) | Complete security, multi-instance, encryption, inventory, and hotfix regression suites. |
| `exports/*` | Tracked reference CycloneDX v1.6 CBOM and assessment export samples documented in `README.md`. |
| `pyproject.toml`, `uv.lock`, `requirements.txt`, `Dockerfile`, `app.yaml`, `.env.example`, `scripts/*.sh` | Dependency lockfiles, container build definition, and deployment runbooks. |
| Local `.venv/` and `.env` (gitignored) | Active local Python 3.12 `uv` environment and developer environment config. |
| Local `data/pqc_sessions.db`, `data/pqc_user_connections.json`, `data/tenants/sec-architect/connection.json` (gitignored) | Legacy pre-Phase-2 local state preserved per `DB-04` non-destructive source-file policy. |

---

## 5. Preventive Ignore Hardening Applied

- **`.gitignore`:** Added `.coverage.*`, `htmlcov/`, `*.db`, `*.sqlite`, `*.sqlite3` rules so temporary coverage shards or ad-hoc SQLite files outside `data/` cannot be accidentally staged.
- **`.dockerignore`:** Added `.env`, `.env.*`, `data/`, `*.db`, `*.sqlite*`, `.coverage*`, `*.egg-info/`, `security_test_logs/`, and `docs/` so local environment files, databases, and audit logs are excluded from container build contexts in addition to explicit `COPY` allowlisting in `Dockerfile`.
