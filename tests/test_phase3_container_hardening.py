"""Phase 3.5 (`P3-04`) Test Suite — Docker Non-Root Execution & Read-Only App Tree Hardening.

Covers all unit, staged read-only `/app` integration, adversarial code-tampering, and Docker-gated smoke tests from
`PHASE_03_0_AUDIT.md` & `PHASE_03_0_TEST_PLAN.md`.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import List

from fastapi.testclient import TestClient
import pytest

from pqc_agent import auth_store, workspace_server as ws
from tools import gcloud_bridge, report_exporter

REPO_ROOT = Path(__file__).resolve().parent.parent


def _parse_dockerfile_instructions(text: str) -> List[str]:
    """Joins backslash-continued lines and strips comments for accurate Dockerfile static inspection."""
    instructions: List[str] = []
    buf = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            buf += stripped[:-1].rstrip() + " "
        else:
            instructions.append((buf + stripped).strip())
            buf = ""
    if buf.strip():
        instructions.append(buf.strip())
    return instructions


def _stage_and_lock_app_tree(tmp_path: Path) -> Path:
    """Replays Dockerfile COPY instructions into `tmp_path/app` and locks the tree read-only (0555 dirs / 0444 files)."""
    dockerfile_text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    instructions = _parse_dockerfile_instructions(dockerfile_text)
    copy_lines = [ln for ln in instructions if ln.upper().startswith("COPY ")]

    staged_app = tmp_path / "app"
    staged_app.mkdir(parents=True, exist_ok=True)
    for ln in copy_lines:
        _, src_rel, dst_rel = ln.split(None, 2)
        src_path = REPO_ROOT / src_rel
        dst_path = staged_app / (src_rel if dst_rel == "." else dst_rel.lstrip("./"))
        if src_path.is_dir():
            shutil.copytree(src_path, dst_path, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dst_path)

    # Lock files first (0444 regular, 0555 scripts), then directories bottom-up (0555)
    for p in staged_app.rglob("*"):
        if p.is_file():
            if p.name in ("run_db_migrations.py", "migrate_sqlite_to_postgres.py"):
                os.chmod(p, 0o555)
            else:
                os.chmod(p, 0o444)
    dirs = sorted([p for p in staged_app.rglob("*") if p.is_dir()] + [staged_app], key=lambda x: len(x.parts), reverse=True)
    for d in dirs:
        os.chmod(d, 0o555)
    return staged_app


def _unlock_app_tree(staged_app: Path) -> None:
    """Restores owner write bits top-down so pytest tmp_path teardown succeeds."""
    dirs = sorted([staged_app] + [p for p in staged_app.rglob("*") if p.is_dir()], key=lambda x: len(x.parts))
    for d in dirs:
        try:
            os.chmod(d, 0o755)
        except OSError:
            pass
    for p in staged_app.rglob("*"):
        if p.is_file():
            try:
                os.chmod(p, 0o644)
            except OSError:
                pass


# =============================================================================
# 4.1 UNIT & STATIC ANALYSIS TESTS
# =============================================================================


def test_p3_04_unit_dockerfile_enforces_non_root_user_and_immutable_app_permissions() -> None:
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    instructions = _parse_dockerfile_instructions(text)

    # 1. Dedicated unprivileged group/user creation (UID/GID 10001, nologin shell)
    assert any(
        "groupadd" in ln and "10001" in ln and "useradd" in ln and "/usr/sbin/nologin" in ln for ln in instructions
    ), "Dockerfile must create dedicated non-root user/group (10001) with /usr/sbin/nologin"

    # 2. Final USER instruction before CMD must be non-root (10001:10001)
    user_indices = [(idx, ln) for idx, ln in enumerate(instructions) if ln.upper().startswith("USER ")]
    cmd_indices = [idx for idx, ln in enumerate(instructions) if ln.upper().startswith("CMD ")]
    assert user_indices, "Dockerfile must specify a non-root USER instruction"
    assert cmd_indices, "Dockerfile must specify a CMD instruction"
    last_user_idx, last_user_ln = user_indices[-1]
    assert last_user_idx < cmd_indices[-1], "USER instruction must appear before CMD"
    user_spec = last_user_ln.split(None, 1)[1].strip()
    assert user_spec == "10001:10001"
    assert user_spec.lower() not in ("root", "0", "0:0")

    # 3. /app is owned by root:root (read-only for UID 10001), NEVER chowned writable to pqcapp/10001
    assert any("chown -R root:root /app" in ln for ln in instructions)
    assert not any(
        "chown" in ln and ("pqcapp" in ln or "10001" in ln) and "/app" in ln for ln in instructions
    ), "Runtime user must NEVER own /app code tree!"

    # 4. Writable ephemeral runtime paths configured in ENV & pre-created for 10001:10001
    env_blob = "\n".join(ln for ln in instructions if ln.upper().startswith("ENV "))
    assert "PYTHONDONTWRITEBYTECODE=1" in env_blob
    assert "HOME=/home/pqcapp" in env_blob
    assert "PQC_EXPORT_DIR=/tmp/pqc-exports" in env_blob
    assert "CLOUDSDK_CONFIG=/tmp/gcloud-config" in env_blob


# =============================================================================
# 4.2 INTEGRATION & 4.3 ADVERSARIAL READ-ONLY /app TESTS
# =============================================================================


def test_p3_04_integration_read_only_app_tree_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged_app = _stage_and_lock_app_tree(tmp_path)
    runtime_tmp = tmp_path / "runtime_tmp"
    runtime_tmp.mkdir(mode=0o700)
    export_dir = runtime_tmp / "pqc-exports"
    gcloud_cfg = runtime_tmp / "gcloud-config"
    db_path = runtime_tmp / "readonly_test.db"

    try:
        # 1. `python scripts/run_db_migrations.py --help` executes cleanly from read-only staged /app
        sub_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": str(runtime_tmp),
            "TMPDIR": str(runtime_tmp),
            "PQC_EXPORT_DIR": str(export_dir),
            "CLOUDSDK_CONFIG": str(gcloud_cfg),
        }
        proc = subprocess.run(
            [sys.executable, "scripts/run_db_migrations.py", "--help"],
            cwd=str(staged_app),
            env=sub_env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
        assert "--require-postgres" in proc.stdout

        # 2. `save_assessment_report` succeeds when cwd is read-only /app and PQC_EXPORT_DIR is unset (falls back to TMPDIR)
        import tempfile

        monkeypatch.chdir(staged_app)
        monkeypatch.delenv("PQC_EXPORT_DIR", raising=False)
        monkeypatch.setenv("TMPDIR", str(runtime_tmp))
        monkeypatch.setattr(tempfile, "tempdir", str(runtime_tmp))
        monkeypatch.setenv("PQC_ARTIFACT_BUCKET", "")
        saved = json.loads(
            asyncio.run(
                report_exporter.save_assessment_report(
                    report_title="Read-Only Container Report",
                    report_markdown="# PQC Assessment\n\nVerified read-only container report export functionality with sufficient length.",
                    report_type="executive",
                    scope="organizations/111",
                )
            )
        )
        assert saved["status"] == "SAVED"
        assert Path(saved["local_files"]["markdown"]).is_file()
        assert Path(saved["local_files"]["html"]).is_file()
        assert str(staged_app) not in saved["local_files"]["markdown"]

        # 3. `build_sanitized_gcloud_env` creates isolated 0700 CLOUDSDK_CONFIG inside TMPDIR without touching /app
        gcloud_env = gcloud_bridge.build_sanitized_gcloud_env(
            mode="access_token",
            user_id="alice@google.com",
            access_token="ya29.readonly-container-token-123456",
            source_env={"TMPDIR": str(runtime_tmp), "HOME": str(runtime_tmp)},
        )
        assert Path(gcloud_env["CLOUDSDK_CONFIG"]).is_dir()
        assert (stat.S_IMODE(Path(gcloud_env["CLOUDSDK_CONFIG"]).stat().st_mode) & 0o077) == 0

        # 4. FastAPI Workspace Portal starts cleanly and serves /api/health under read-only cwd
        monkeypatch.setenv("SESSION_DB_URL", f"sqlite:///{db_path}")
        monkeypatch.setenv("PQC_EXPORT_DIR", str(export_dir))
        monkeypatch.setenv("PQC_DATA_DIR", str(runtime_tmp / "data"))
        monkeypatch.setenv("PQC_AUTH_SECRET", "p3-04-readonly-hmac-secret-material-at-least-32-bytes!!")
        auth_store.clear_fallback_auth_stores()
        app = ws.create_workspace_app(session_db_url=f"sqlite:///{db_path}", verify_models_on_startup=False)
        try:
            with TestClient(app) as client:
                health = client.get("/api/health")
                assert health.status_code == 200
        finally:
            app.state.auth_store.close()
    finally:
        monkeypatch.chdir(REPO_ROOT)
        _unlock_app_tree(staged_app)


def test_p3_04_adversarial_runtime_code_tampering_denied_on_locked_app_dir(tmp_path: Path) -> None:
    """Verifies non-root runtime process cannot modify `/app/main.py`, `workspace_server.py`, or drop rogue files."""
    if os.geteuid() == 0:
        pytest.skip("Running as UID 0; POSIX 0444/0555 permission denial applies to non-root UIDs only.")
    staged_app = _stage_and_lock_app_tree(tmp_path)
    try:
        with pytest.raises(PermissionError):
            (staged_app / "main.py").write_text("# tampered\n", encoding="utf-8")
        with pytest.raises(PermissionError):
            (staged_app / "pqc_agent" / "workspace_server.py").write_text("# tampered\n", encoding="utf-8")
        with pytest.raises(PermissionError):
            (staged_app / "pqc_agent" / "injected_backdoor.py").write_text("import os\n", encoding="utf-8")
    finally:
        _unlock_app_tree(staged_app)


def test_p3_04_unit_report_exporter_handles_erofs_read_only_filesystem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies Linux `--read-only` rootfs `OSError(EROFS)` falls back to a 0700 directory under TMPDIR."""
    import errno
    import tempfile

    runtime_tmp = tmp_path / "erofs_tmp"
    runtime_tmp.mkdir(mode=0o700)
    monkeypatch.setenv("TMPDIR", str(runtime_tmp))
    monkeypatch.setattr(tempfile, "tempdir", str(runtime_tmp))
    monkeypatch.setenv("PQC_EXPORT_DIR", str(tmp_path / "ro_mount" / "exports"))

    orig_mkdir = Path.mkdir

    def fake_mkdir(self: Path, *args, **kwargs) -> None:
        if "ro_mount" in str(self):
            raise OSError(errno.EROFS, "Read-only file system")
        return orig_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fake_mkdir)
    resolved = report_exporter._ensure_writable_output_dir()
    assert resolved.parent == runtime_tmp
    assert resolved.name == f"pqc-exports-{os.getuid()}"
    assert resolved.is_dir()
    assert (stat.S_IMODE(resolved.stat().st_mode) & 0o077) == 0


# =============================================================================
# 4.4 LIVE CONTAINER SMOKE TEST (GATED ON DOCKER CLI)
# =============================================================================


@pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="BLOCKED: Docker CLI/daemon is not installed in this workstation environment.",
)
def test_p3_04_live_docker_non_root_uid_and_read_only_migration_help() -> None:
    image_tag = "pqc-inventory-agent:p3-04-nonroot-smoke"
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
        uid_proc = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "id", image_tag, "-u"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert uid_proc.returncode == 0, uid_proc.stderr
        assert uid_proc.stdout.strip() == "10001"

        ro_proc = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid",
                "--entrypoint",
                "python",
                image_tag,
                "scripts/run_db_migrations.py",
                "--help",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert ro_proc.returncode == 0, ro_proc.stderr
        assert "--require-postgres" in ro_proc.stdout
    finally:
        subprocess.run(["docker", "rmi", "-f", image_tag], capture_output=True, check=False)
