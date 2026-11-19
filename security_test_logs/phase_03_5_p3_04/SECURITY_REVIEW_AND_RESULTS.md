# Phase 3.5 (`P3-04`) — Docker Non-Root Execution & Read-Only `/app` Tree Hardening

- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Parent Commit SHA:** `72e6563e365f15296e44794d642048efc5e4ef01`
- **Commit Message:** `fix(container): run Docker image as non-root UID 10001 with read-only app tree`

## Summary of Implementation
1. **`Dockerfile`:**
   - Creates dedicated unprivileged runtime user/group `pqcapp` (`UID 10001`, `GID 10001`, `--home-dir /home/pqcapp`, `--shell /usr/sbin/nologin`).
   - Pre-creates `0700` ephemeral writable runtime directories owned by `10001:10001`: `/home/pqcapp`, `/tmp/pqc-exports`, and `/tmp/gcloud-config`.
   - Sets production runtime environment variables: `PYTHONDONTWRITEBYTECODE=1`, `HOME=/home/pqcapp`, `PQC_EXPORT_DIR=/tmp/pqc-exports`, `CLOUDSDK_CONFIG=/tmp/gcloud-config`.
   - Locks `/app` code tree strictly to `root:root` (`0755` directories, `0644` regular files, `0755` for `/app/scripts/run_db_migrations.py` and `/app/scripts/migrate_sqlite_to_postgres.py`), preventing UID `10001` from modifying application code or dropping files into `/app`.
   - Drops privileges via `USER 10001:10001` before `EXPOSE 8080` and `CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]`.
2. **`tools/report_exporter.py`:**
   - `_default_output_dir()` defaults to `<tmpdir>/pqc-exports` in Cloud Run / `PQC_PRODUCTION_MODE=true` when `PQC_EXPORT_DIR` is not explicitly set.
   - `_ensure_writable_output_dir()` checks write access (`os.access(out_dir, os.W_OK)`) and handles both `PermissionError` (`EACCES`/`EPERM`) and `OSError(EROFS)` (Linux `--read-only` root filesystem), falling back cleanly to a `0700` `<tmpdir>/pqc-exports-<uid>` directory.
3. **`tests/test_phase3_container_hardening.py`:**
   - Static `Dockerfile` audit verifying UID/GID `10001:10001`, `/usr/sbin/nologin`, `USER` before `CMD`, `root:root` `/app` immutability, and ephemeral `ENV` configuration.
   - Staged read-only `/app` (`0555` dirs / `0444` files / `0555` scripts) integration test running `scripts/run_db_migrations.py --help`, `report_exporter.save_assessment_report`, `gcloud_bridge.build_sanitized_gcloud_env`, and FastAPI `/api/health`.
   - Adversarial test confirming `PermissionError` on code tampering (`/app/main.py`, `/app/pqc_agent/workspace_server.py`, or rogue file creation).
   - Unit test simulating Linux `--read-only` rootfs `OSError(errno.EROFS)` fallback in `report_exporter._ensure_writable_output_dir()`.
   - Docker-gated live container smoke test verifying `id -u == 10001` and `docker run --read-only --tmpfs /tmp:rw,noexec,nosuid ... python scripts/run_db_migrations.py --help`.

## Test Results
- Focused suite (`.venv/bin/pytest -v -rs tests/test_phase3_container_hardening.py tests/test_pre_merge_hotfix.py`):
  - **10 passed, 2 skipped, 0 failed** (`31.25s`)
  - Skipped (2): `test_p3_04_live_docker_non_root_uid_and_read_only_migration_help` & `test_pre_merge_01_live_docker_build_and_container_smoke` (`BLOCKED: Docker CLI/daemon is not installed in this workstation environment.`)
- Syntax & whitespace checks (`.venv/bin/python -m compileall -q pqc_agent tools tests main.py && git diff --check`): exit code `0`.
- **Full Repository Regression Suite** (`.venv/bin/pytest -v -rs`):
  - **343 passed, 4 skipped, 0 failed** (`63.56s`)
  - Skipped (4):
    1. `tests/test_phase2_persistence_and_credentials.py:1507` — Live PostgreSQL 16 test requires opt-in `PQC_TEST_POSTGRES_URL` + `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`.
    2. `tests/test_phase3_container_hardening.py:269` — `BLOCKED: Docker CLI/daemon is not installed in this workstation environment.`
    3. `tests/test_pqc_inventory.py:974` — Live Vertex AI Gemini test requires `PQC_LIVE_LLM_TEST=1`.
    4. `tests/test_pre_merge_hotfix.py:210` — `BLOCKED: Docker CLI/daemon is not installed in this workstation environment.`

## Residual Operational Verification (CI / Cloud Build)
- Because local Docker CLI/daemon is unavailable in this workstation, execute `tests/test_phase3_container_hardening.py::test_p3_04_live_docker_non_root_uid_and_read_only_migration_help` and `tests/test_pre_merge_hotfix.py::test_pre_merge_01_live_docker_build_and_container_smoke` in CI or Cloud Build before staging/production promotion.
