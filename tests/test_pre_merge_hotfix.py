"""Targeted regression suite for Phase 1–2 Pre-Merge Hotfix (PRE-MERGE-01, PRE-MERGE-02, PRE-MERGE-03).

Covers:
1. PRE-MERGE-01: Dockerfile copies `scripts/run_db_migrations.py` with read/execute permissions, introduces no secrets
   or `.env`/DB artifacts, and executes cleanly from a staged `/app` filesystem; live Docker build/run test is gated on
   Docker CLI availability (honestly skipped/blocked when `docker` is unavailable).
2. PRE-MERGE-02 (CLI Lazy Initialization): `main.py` separates `deploy` / `tools` / `cbom` / `--help` from
   `create_workspace_app()` / `DistributedAuthStore`, while `main:app` and `main.py serve` preserve single-init
   startup and fail-closed production PostgreSQL enforcement.
3. PRE-MERGE-02 (Migration Before Service Deployment): `scripts/setup_and_deploy_vertex.sh` builds/publishes the
   image, deploys and executes the serialized (`--tasks=1 --max-retries=0`) Alembic Cloud Run migration job with
   `--wait`, aborts immediately without deploying the Cloud Run service on migration or build failure, and deploys the
   service with the exact same image only after migration succeeds.
4. PRE-MERGE-03 (Documentation Drift): `app.yaml` and `docs/security-remediation/MIGRATION_AND_ROLLBACK.md` match
   `EXPECTED_ALEMBIC_REVISION = '20261117_0002'` and `DRY_RUN_OK`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import textwrap

import pytest

from pqc_agent import auth_store

REPO_ROOT = Path(__file__).resolve().parent.parent


def _clean_subprocess_env(**extra: str) -> dict[str, str]:
    """Builds a minimal hermetic environment free of pytest's `SESSION_DB_URL` or local shell GCP overrides."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    env.update(extra)
    return env


def _write_vertex_deploy_stubs(stub_dir: Path, trace_file: Path) -> None:
    """Creates offline `vertexai` and `google.cloud.storage` stubs in `stub_dir` for hermetic `main.py deploy` tests."""
    stub_dir.mkdir(parents=True, exist_ok=True)
    vertex_pkg = stub_dir / "vertexai"
    vertex_pkg.mkdir(parents=True, exist_ok=True)
    (vertex_pkg / "__init__.py").write_text(
        textwrap.dedent(
            """
            import json, os, sys

            _CALLS = []

            def init(*, project=None, location=None, staging_bucket=None, **kwargs):
                _CALLS.append({"fn": "init", "project": project, "location": location, "staging_bucket": staging_bucket})

            class _FakeRemoteAgent:
                def __init__(self, project, location):
                    self.resource_name = f"projects/{project}/locations/{location}/reasoningEngines/mock-re-001"

            class agent_engines:
                class AdkApp:
                    def __init__(self, *, agent=None, enable_tracing=False):
                        self.agent = agent
                        self.enable_tracing = enable_tracing

                @staticmethod
                def create(app_obj, *, requirements=None, extra_packages=None, env_vars=None, display_name=None, description=None):
                    init_info = _CALLS[-1] if _CALLS else {"project": "unknown", "location": "us-central1"}
                    trace_path = os.environ.get("PQC_DEPLOY_TRACE_FILE", "")
                    if trace_path:
                        payload = {
                            "workspace_server_imported": "pqc_agent.workspace_server" in sys.modules,
                            "auth_store_imported": "pqc_agent.auth_store" in sys.modules,
                            "project": init_info["project"],
                            "location": init_info["location"],
                            "staging_bucket": init_info["staging_bucket"],
                            "extra_packages": list(extra_packages or []),
                            "requirements": list(requirements or []),
                        }
                        with open(trace_path, "w", encoding="utf-8") as fh:
                            json.dump(payload, fh)
                    return _FakeRemoteAgent(init_info["project"], init_info["location"])
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    # Provide a lightweight `sitecustomize.py` in `stub_dir` that stubs `_ensure_staging_bucket` GCS network calls
    # and intercepts `pqc_agent.auth_store` ONLY if the target program ever imports it.
    (stub_dir / "sitecustomize.py").write_text(
        textwrap.dedent(
            """
            import importlib.abc, os, sys

            if not (sys.argv and str(sys.argv[0]).endswith("/gcloud")):
                try:
                    from google.cloud import storage as _gcs

                    class _FakeBucket:
                        class iam_configuration:
                            uniform_bucket_level_access_enabled = True
                        def exists(self):
                            return True

                    class _FakeStorageClient:
                        def __init__(self, project=None, *a, **kw):
                            self.project = project
                        def bucket(self, name):
                            return _FakeBucket()
                        def create_bucket(self, bucket, location=None):
                            return bucket

                    _gcs.Client = _FakeStorageClient
                except ImportError:
                    pass

                class _AuthStoreImportWatcher(importlib.abc.MetaPathFinder):
                    def find_spec(self, fullname, path, target=None):
                        if fullname == "pqc_agent.auth_store":
                            marker = os.environ.get("PQC_AUTH_STORE_INIT_LOG", "")
                            if marker:
                                with open(marker, "a", encoding="utf-8") as fh:
                                    fh.write("AUTH_STORE_IMPORTED\\n")
                        return None

                sys.meta_path.insert(0, _AuthStoreImportWatcher())
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


# ==============================================================================
# PRE-MERGE-01: Dockerfile Migration Script Packaging & Smoke Tests
# ==============================================================================


def test_pre_merge_01_dockerfile_copies_migration_script_without_secrets_and_runs_staged_cli(tmp_path: Path) -> None:
    dockerfile_text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    lines = [ln.strip() for ln in dockerfile_text.splitlines() if ln.strip() and not ln.strip().startswith("#")]

    # 1. Verify explicit COPY instructions (never wildcard COPY . . / ADD . .) and chmod 0755
    copy_lines = [ln for ln in lines if ln.upper().startswith(("COPY ", "ADD "))]
    assert "COPY scripts/run_db_migrations.py ./scripts/run_db_migrations.py" in copy_lines
    assert "COPY scripts/migrate_sqlite_to_postgres.py ./scripts/migrate_sqlite_to_postgres.py" in copy_lines
    assert "COPY alembic.ini ." in copy_lines
    assert "COPY migrations ./migrations" in copy_lines
    for ln in copy_lines:
        assert ln not in ("COPY . .", "COPY . /app", "ADD . .", "ADD . /app"), f"Unsafe wildcard copy: {ln}"
        for forbidden in (".env", ".db", ".sqlite", "credentials", "security_test_logs", "tests"):
            assert forbidden not in ln.lower(), f"Unexpected artifact copied into runtime image: {ln}"

    assert any(
        "chmod" in ln and "/app/scripts/run_db_migrations.py" in ln for ln in lines
    ), "Dockerfile must ensure /app/scripts/run_db_migrations.py has read/execute permissions."

    # 2. Replay Dockerfile COPY + chmod instructions into an isolated `/app` staging directory
    staged_app = tmp_path / "app"
    staged_app.mkdir(parents=True, exist_ok=True)
    for ln in copy_lines:
        _, src_rel, dst_rel = ln.split(None, 2)
        src_path = REPO_ROOT / src_rel
        dst_path = staged_app / (src_rel if dst_rel == "." else dst_rel.lstrip("./"))
        assert src_path.exists(), f"Dockerfile COPY source missing: {src_path}"
        if src_path.is_dir():
            shutil.copytree(src_path, dst_path, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dst_path)

    staged_mig = staged_app / "scripts" / "run_db_migrations.py"
    staged_data_mig = staged_app / "scripts" / "migrate_sqlite_to_postgres.py"
    os.chmod(staged_mig, 0o755)
    os.chmod(staged_data_mig, 0o755)

    assert staged_mig.is_file()
    mode = stat.S_IMODE(staged_mig.stat().st_mode)
    # Readable and executable by owner, group, and non-root container UID/GID; not group/world-writable
    assert mode == 0o755

    # Verify zero `.env`, `.db`, `.sqlite`, or secret files exist anywhere in staged `/app`
    staged_files = [p.relative_to(staged_app).as_posix() for p in staged_app.rglob("*") if p.is_file()]
    assert not any(f.endswith((".env", ".db", ".sqlite", ".sqlite3", ".pem", ".key")) for f in staged_files)
    assert "scripts/rebuild_all_with_official_cloudstyle_templates.py" not in staged_files

    # 3. Execute non-destructive CLI smoke test (`python scripts/run_db_migrations.py --help`) inside staged `/app`
    proc = subprocess.run(
        [sys.executable, "scripts/run_db_migrations.py", "--help"],
        cwd=str(staged_app),
        env=_clean_subprocess_env(),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    assert "--require-postgres" in proc.stdout
    assert "--verify-only" in proc.stdout


@pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="BLOCKED: Docker CLI/daemon is not installed in this workstation environment.",
)
def test_pre_merge_01_live_docker_build_and_container_smoke() -> None:
    """Builds the actual Docker image and verifies `/app/scripts/run_db_migrations.py --help` when Docker is installed."""
    image_tag = "pqc-inventory-agent:pre-merge-hotfix-smoke"
    build = subprocess.run(
        ["docker", "build", "-t", image_tag, "."],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    try:
        smoke = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "python", image_tag, "scripts/run_db_migrations.py", "--help"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert smoke.returncode == 0, smoke.stderr
        assert "--require-postgres" in smoke.stdout
    finally:
        subprocess.run(["docker", "rmi", "-f", image_tag], capture_output=True, check=False)


# ==============================================================================
# PRE-MERGE-02: Lazy CLI Initialization vs Fail-Closed Server Startup
# ==============================================================================


def test_pre_merge_02_cli_deploy_and_tools_do_not_initialize_auth_store(tmp_path: Path) -> None:
    stub_dir = tmp_path / "stubs"
    deploy_trace = tmp_path / "deploy_trace.json"
    auth_store_log = tmp_path / "auth_store_init.log"
    _write_vertex_deploy_stubs(stub_dir, deploy_trace)

    # 1. `python main.py deploy` WITHOUT PQC_CLOUD_SQL_CONNECTION_NAME (and without DATABASE_URL / SESSION_DB_URL)
    env_without_sql = _clean_subprocess_env(
        PYTHONPATH=f"{stub_dir}{os.pathsep}{REPO_ROOT}",
        PQC_DEPLOY_TRACE_FILE=str(deploy_trace),
        PQC_AUTH_STORE_INIT_LOG=str(auth_store_log),
        PQC_DATA_DIR=str(tmp_path / "unused_local_data"),
    )
    proc_no_sql = subprocess.run(
        [
            sys.executable,
            "main.py",
            "deploy",
            "--project",
            "pqc-cli-test-proj",
            "--location",
            "us-central1",
            "--staging-bucket",
            "gs://pqc-cli-test-staging",
        ],
        cwd=str(REPO_ROOT),
        env=env_without_sql,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc_no_sql.returncode == 0, f"stderr={proc_no_sql.stderr}\nstdout={proc_no_sql.stdout}"
    assert "projects/pqc-cli-test-proj/locations/us-central1/reasoningEngines/mock-re-001" in proc_no_sql.stdout
    trace_data = json.loads(deploy_trace.read_text(encoding="utf-8"))
    assert trace_data["workspace_server_imported"] is False
    assert not auth_store_log.exists(), "DistributedAuthStore must NEVER be initialized during `main.py deploy`."

    # 2. `python main.py deploy` WITH PQC_CLOUD_SQL_CONNECTION_NAME + PQC_PRODUCTION_MODE=true (exact operator scenario)
    deploy_trace.unlink()
    env_with_sql = _clean_subprocess_env(
        PYTHONPATH=f"{stub_dir}{os.pathsep}{REPO_ROOT}",
        PQC_DEPLOY_TRACE_FILE=str(deploy_trace),
        PQC_AUTH_STORE_INIT_LOG=str(auth_store_log),
        PQC_PRODUCTION_MODE="true",
        PQC_CLOUD_SQL_CONNECTION_NAME="pqc-cli-test-proj:us-central1:unreachable-cloudsql-socket",
    )
    proc_with_sql = subprocess.run(
        [
            sys.executable,
            "main.py",
            "deploy",
            "--project",
            "pqc-cli-test-proj",
            "--location",
            "us-central1",
            "--staging-bucket",
            "gs://pqc-cli-test-staging",
        ],
        cwd=str(REPO_ROOT),
        env=env_with_sql,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc_with_sql.returncode == 0, f"stderr={proc_with_sql.stderr}\nstdout={proc_with_sql.stdout}"
    trace_data_sql = json.loads(deploy_trace.read_text(encoding="utf-8"))
    assert trace_data_sql["workspace_server_imported"] is False
    assert not auth_store_log.exists(), "DistributedAuthStore must NEVER be initialized during `main.py deploy`."

    # 3. `python main.py --help` never initializes DistributedAuthStore; `tools` smoke runner never imports workspace_server
    proc_help = subprocess.run(
        [sys.executable, "main.py", "--help"],
        cwd=str(REPO_ROOT),
        env=_clean_subprocess_env(
            PYTHONPATH=f"{stub_dir}{os.pathsep}{REPO_ROOT}",
            PQC_AUTH_STORE_INIT_LOG=str(auth_store_log),
            PQC_PRODUCTION_MODE="true",
            PQC_CLOUD_SQL_CONNECTION_NAME="pqc-cli-test-proj:us-central1:unreachable-cloudsql-socket",
        ),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc_help.returncode == 0, proc_help.stderr
    assert not auth_store_log.exists()

    proc_tools = subprocess.run(
        [
            sys.executable,
            "-c",
            "import json, sys, main; out = main.run_tools_smoke_test('demo-pqc-project'); "
            "assert out['llm_invoked'] is False; assert 'pqc_agent.workspace_server' not in sys.modules; print('TOOLS_OK')",
        ],
        cwd=str(REPO_ROOT),
        env=_clean_subprocess_env(
            PYTHONPATH=str(REPO_ROOT),
            PQC_DATA_DIR=str(tmp_path / "tools_dev_data"),
        ),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc_tools.returncode == 0, f"stderr={proc_tools.stderr}\nstdout={proc_tools.stdout}"
    assert "TOOLS_OK" in proc_tools.stdout


def test_pre_merge_02_server_startup_initializes_once_and_fails_closed_in_production(tmp_path: Path) -> None:
    # 1. Valid non-production server startup (`main:app`) initializes `create_workspace_app()` ONCE and serves /api/health
    local_db = tmp_path / "server_startup.db"
    startup_script = textwrap.dedent(
        """
        import sys
        import main

        assert main._WORKSPACE_APP is None
        assert "pqc_agent.workspace_server" not in sys.modules

        import pqc_agent.auth_store as auth_store
        init_calls = []
        orig_init = auth_store.DistributedAuthStore.__init__
        def spy_init(self, *a, **kw):
            init_calls.append(1)
            return orig_init(self, *a, **kw)
        auth_store.DistributedAuthStore.__init__ = spy_init

        app_1 = main.app
        app_2 = main.get_workspace_app()
        sess_svc = main.session_service
        art_svc = main.artifact_service

        assert app_1 is app_2
        assert sess_svc is app_1.state.session_service
        assert art_svc is app_1.state.artifact_service
        assert len(init_calls) == 1, f"Expected single DistributedAuthStore init, got {len(init_calls)}"

        from fastapi.testclient import TestClient
        with TestClient(app_1) as client:
            resp = client.get("/api/health")
            assert resp.status_code == 200
            assert resp.json()["database_healthy"] is True
        print("SERVER_SINGLE_INIT_OK")
        """
    )
    proc_ok = subprocess.run(
        [sys.executable, "-c", startup_script],
        cwd=str(REPO_ROOT),
        env=_clean_subprocess_env(
            PYTHONPATH=str(REPO_ROOT),
            SESSION_DB_URL=f"sqlite:///{local_db}",
            PQC_MODEL_VERIFICATION_ON_STARTUP="false",
            PQC_ARTIFACT_BUCKET="",
            PQC_DATA_DIR=str(tmp_path / "dev_data"),
        ),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc_ok.returncode == 0, f"stderr={proc_ok.stderr}\nstdout={proc_ok.stdout}"
    assert "SERVER_SINGLE_INIT_OK" in proc_ok.stdout

    # 2. Missing production database configuration on server path (`main.app` and `main.py serve`) fails closed!
    for label, extra_env, expected_err in [
        (
            "missing_prod_db",
            {"PQC_PRODUCTION_MODE": "true", "PQC_AUTH_SECRET": "a" * 48},
            "Production persistence failure",
        ),
        (
            "sqlite_forbidden_in_prod",
            {
                "K_SERVICE": "agentic-pqc",
                "SESSION_DB_URL": f"sqlite:///{tmp_path / 'forbidden.db'}",
                "PQC_AUTH_SECRET": "b" * 48,
            },
            "prohibited in production",
        ),
        (
            "unreachable_prod_postgres",
            {
                "PQC_PRODUCTION_MODE": "true",
                "PQC_CLOUD_SQL_CONNECTION_NAME": "proj:us-central1:missing-socket",
                "PQC_DB_PASSWORD": "ephemeral-test-password",
                "PQC_AUTH_SECRET": "c" * 48,
            },
            "Database connectivity verification failed",
        ),
    ]:
        proc_fail = subprocess.run(
            [sys.executable, "-c", "import main; _ = main.app"],
            cwd=str(REPO_ROOT),
            env=_clean_subprocess_env(PYTHONPATH=str(REPO_ROOT), **extra_env),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        assert proc_fail.returncode != 0, f"{label}: expected non-zero exit"
        assert expected_err in proc_fail.stderr, f"{label}: unexpected stderr={proc_fail.stderr}"

    proc_serve_fail = subprocess.run(
        [sys.executable, "main.py", "serve", "--port", "0"],
        cwd=str(REPO_ROOT),
        env=_clean_subprocess_env(
            PYTHONPATH=str(REPO_ROOT),
            PQC_PRODUCTION_MODE="true",
            PQC_AUTH_SECRET="d" * 48,
        ),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc_serve_fail.returncode != 0
    assert "Production persistence failure" in proc_serve_fail.stderr


# ==============================================================================
# PRE-MERGE-02: Deployment Script Sequencing & Fail-Fast Mock Execution
# ==============================================================================


def _write_mock_gcloud_binary(bin_dir: Path, log_file: Path) -> Path:
    bin_dir.mkdir(parents=True, exist_ok=True)
    gcloud_script = bin_dir / "gcloud"
    body = textwrap.dedent(
        """
        import json, os, sys

        args = sys.argv[1:]
        log_path = os.environ["MOCK_GCLOUD_LOG"]
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(args) + "\\n")

        joined = " ".join(args)
        fail_on = os.environ.get("MOCK_GCLOUD_FAIL_ON", "")
        if fail_on and fail_on in joined:
            sys.stderr.write(f"Simulated gcloud failure on: {fail_on}\\n")
            sys.exit(int(os.environ.get("MOCK_GCLOUD_FAIL_CODE", "1")))

        if args[:2] == ["projects", "describe"]:
            sys.stdout.write("110254026096\\n")
            sys.exit(0)
        if args[:3] == ["artifacts", "repositories", "describe"]:
            if os.environ.get("MOCK_AR_REPO_MISSING") == "1":
                sys.exit(1)
            sys.exit(0)
        sys.exit(0)
        """
    ).strip()
    gcloud_script.write_text(f"#!/usr/bin/env python3\n{body}\n", encoding="utf-8")
    os.chmod(gcloud_script, 0o755)
    return gcloud_script


def test_pre_merge_02_deployment_scripts_syntax_sequencing_and_mocked_execution(tmp_path: Path) -> None:
    vertex_script = REPO_ROOT / "scripts" / "setup_and_deploy_vertex.sh"
    cloudrun_script = REPO_ROOT / "scripts" / "deploy_cloud_run.sh"

    # 1. Shell syntax validation (`bash -n`)
    for sh_path in (vertex_script, cloudrun_script):
        syn = subprocess.run(["bash", "-n", str(sh_path)], capture_output=True, text=True, timeout=10, check=False)
        assert syn.returncode == 0, f"bash -n failed for {sh_path}: {syn.stderr}"

    # 2. Static topological sequence check in setup_and_deploy_vertex.sh
    v_src = vertex_script.read_text(encoding="utf-8")
    idx_build = v_src.index("gcloud builds submit .")
    idx_job_deploy = v_src.index('gcloud beta run jobs deploy "${MIGRATION_JOB_NAME}"')
    idx_job_exec = v_src.index('gcloud beta run jobs execute "${MIGRATION_JOB_NAME}"')
    idx_svc_deploy = v_src.index('gcloud beta run deploy "${SERVICE_NAME}"')
    assert idx_build < idx_job_deploy < idx_job_exec < idx_svc_deploy

    # 3. Mocked end-to-end execution: SUCCESSFUL migration -> service deploy IS reached with identical image & DB config
    stub_dir = tmp_path / "stubs"
    deploy_trace = tmp_path / "vertex_trace.json"
    _write_vertex_deploy_stubs(stub_dir, deploy_trace)
    mock_bin = tmp_path / "mock_bin"
    gcloud_log = tmp_path / "gcloud_calls.jsonl"
    _write_mock_gcloud_binary(mock_bin, gcloud_log)

    base_env = _clean_subprocess_env(
        PATH=f"{mock_bin}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
        PYTHONPATH=f"{stub_dir}{os.pathsep}{REPO_ROOT}",
        PQC_PYTHON_BIN=sys.executable,
        PQC_DEPLOY_TRACE_FILE=str(deploy_trace),
        MOCK_GCLOUD_LOG=str(gcloud_log),
        MOCK_AR_REPO_MISSING="1",
        PQC_IMAGE_TAG="sha-test-001",
        PQC_CLOUD_SQL_CONNECTION_NAME="pqc-test-proj:us-central1:pqc-pg16-inst",
        PQC_KMS_KEY_NAME="projects/pqc-test-proj/locations/us-central1/keyRings/kr/cryptoKeys/kek",
        PQC_DB_PASSWORD="SUPER_SECRET_NEVER_ECHO_12345",
        PQC_AUTH_SECRET="SUPER_SECRET_HMAC_NEVER_ECHO_67890",
    )

    ok_run = subprocess.run(
        ["bash", str(vertex_script), "pqc-test-proj", "us-central1", "agentic-pqc"],
        cwd=str(REPO_ROOT),
        env=base_env,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert ok_run.returncode == 0, f"stderr={ok_run.stderr}\nstdout={ok_run.stdout}"
    # Verify secrets are never printed to stdout or stderr
    combined_out = ok_run.stdout + ok_run.stderr
    assert "SUPER_SECRET_NEVER_ECHO_12345" not in combined_out
    assert "SUPER_SECRET_HMAC_NEVER_ECHO_67890" not in combined_out

    calls = [json.loads(line) for line in gcloud_log.read_text(encoding="utf-8").splitlines() if line.strip()]
    expected_image = "us-central1-docker.pkg.dev/pqc-test-proj/pqc-containers/agentic-pqc:sha-test-001"

    build_idx = next(i for i, c in enumerate(calls) if c[:2] == ["builds", "submit"])
    job_deploy_idx = next(i for i, c in enumerate(calls) if c[:4] == ["beta", "run", "jobs", "deploy"])
    job_exec_idx = next(i for i, c in enumerate(calls) if c[:4] == ["beta", "run", "jobs", "execute"])
    svc_deploy_idx = next(i for i, c in enumerate(calls) if c[:3] == ["beta", "run", "deploy"])

    assert build_idx < job_deploy_idx < job_exec_idx < svc_deploy_idx

    job_deploy_cmd = calls[job_deploy_idx]
    assert "agentic-pqc-db-migrate" in job_deploy_cmd
    assert f"--image={expected_image}" in job_deploy_cmd
    assert "--tasks=1" in job_deploy_cmd
    assert "--max-retries=0" in job_deploy_cmd
    assert "--set-cloudsql-instances=pqc-test-proj:us-central1:pqc-pg16-inst" in job_deploy_cmd
    assert "--command=python" in job_deploy_cmd
    assert "--args=scripts/run_db_migrations.py,--require-postgres" in job_deploy_cmd

    job_exec_cmd = calls[job_exec_idx]
    assert "agentic-pqc-db-migrate" in job_exec_cmd
    assert "--wait" in job_exec_cmd

    svc_deploy_cmd = calls[svc_deploy_idx]
    assert "agentic-pqc" in svc_deploy_cmd
    assert f"--image={expected_image}" in svc_deploy_cmd
    assert "--add-cloudsql-instances=pqc-test-proj:us-central1:pqc-pg16-inst" in svc_deploy_cmd

    # 4. Simulated MIGRATION FAILURE -> non-zero exit code & Cloud Run service deploy is NEVER invoked!
    gcloud_log.unlink()
    fail_mig_env = dict(base_env, MOCK_GCLOUD_FAIL_ON="beta run jobs execute", MOCK_GCLOUD_FAIL_CODE="7")
    fail_mig = subprocess.run(
        ["bash", str(vertex_script), "pqc-test-proj", "us-central1", "agentic-pqc"],
        cwd=str(REPO_ROOT),
        env=fail_mig_env,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert fail_mig.returncode == 7
    fail_calls = [json.loads(line) for line in gcloud_log.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(c[:4] == ["beta", "run", "jobs", "execute"] for c in fail_calls)
    assert not any(
        c[:3] == ["beta", "run", "deploy"] for c in fail_calls
    ), "Cloud Run service deploy MUST NOT run when the Alembic migration job fails!"

    # 5. Simulated IMAGE BUILD FAILURE -> non-zero exit code & neither migration job nor service deploy runs!
    gcloud_log.unlink()
    fail_build_env = dict(base_env, MOCK_GCLOUD_FAIL_ON="builds submit", MOCK_GCLOUD_FAIL_CODE="9")
    fail_build = subprocess.run(
        ["bash", str(vertex_script), "pqc-test-proj", "us-central1", "agentic-pqc"],
        cwd=str(REPO_ROOT),
        env=fail_build_env,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert fail_build.returncode == 9
    build_fail_calls = [json.loads(line) for line in gcloud_log.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert not any(c[:4] == ["beta", "run", "jobs", "deploy"] for c in build_fail_calls)
    assert not any(c[:3] == ["beta", "run", "deploy"] for c in build_fail_calls)


# ==============================================================================
# PRE-MERGE-03: Documentation Drift Alignment
# ==============================================================================


def test_pre_merge_03_documentation_drift_resolved() -> None:
    expected_rev = auth_store.EXPECTED_ALEMBIC_REVISION
    assert expected_rev == "20261117_0002"

    app_yaml = (REPO_ROOT / "app.yaml").read_text(encoding="utf-8")
    assert f"head revision {expected_rev}" in app_yaml

    runbook = (REPO_ROOT / "docs" / "security-remediation" / "MIGRATION_AND_ROLLBACK.md").read_text(encoding="utf-8")
    assert f"(head revision `{expected_rev}`)" in runbook
    assert "Status: DRY_RUN_OK" in runbook
    assert "DRY_RUN_VALIDATED" not in runbook
