"""Phase 3.1 P0 Hotfix Security Test Suite — ADC Authorization, Tenant Scope Isolation & Executable Hardening.

Covers all 21 mandatory adversarial and regression scenarios:
- ADC authorization tests (Scenarios 1–8)
- Execution & tenant resource scope isolation tests (Scenarios 9–18)
- Hardened gcloud executable resolution tests (Scenarios 19–21)
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
import pytest

from pqc_agent import auth_store, credential_service, workspace_server as ws
from pqc_agent.model_registry import ModelRegistry
from tools import gcp_inventory, gcloud_bridge


@pytest.fixture(autouse=True)
def _hermetic_adc_and_scope_env(monkeypatch: pytest.MonkeyPatch):
    """Ensures no ambient admin, impersonation, or tenant scope env vars leak across tests."""
    for var in (
        "PQC_ADMIN_EMAILS",
        "PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS",
        "PQC_ALLOWED_PROJECTS",
        "PQC_ALLOWED_ORGANIZATIONS",
        "PQC_ALLOWED_FOLDERS",
        "PQC_TENANT_SCOPE_POLICY",
        "PQC_GCP_CONNECTION_MODE",
        "PQC_DEMO_ADC_ENABLED",
    ):
        monkeypatch.delenv(var, raising=False)
    prev_uid = gcloud_bridge.get_current_tenant_user()
    gcloud_bridge.set_current_tenant_user("sec-architect")
    yield
    gcloud_bridge.set_current_tenant_user(prev_uid)


def _make_fake_registry() -> ModelRegistry:
    def _probe(model: str, _level: Any) -> Tuple[bool, Dict[str, Any]]:
        if model == "fake-ok-model":
            return True, {"model_version": "fake-ok-model-001"}
        return False, {"error_code": 404, "error": "Model not found"}

    return ModelRegistry(
        candidates=[{"model": "fake-ok-model", "label": "Fake OK", "thinking_levels": [None]}],
        probe=_probe,
        default_model="fake-ok-model",
        default_thinking_level="",
    )


def _create_hotfix_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "p3_01_hotfix.db"
    monkeypatch.setenv("SESSION_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("PQC_EXPORT_DIR", str(tmp_path / "exports"))
    monkeypatch.setenv("PQC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PQC_AUTH_SECRET", "p3-01-hotfix-hmac-secret-material-at-least-32-bytes!!")
    auth_store.clear_fallback_auth_stores()
    return ws.create_workspace_app(
        session_db_url=f"sqlite:///{db_path}",
        model_registry=_make_fake_registry(),
        verify_models_on_startup=False,
    )


def _login_user(client: TestClient, email: str) -> Tuple[str, Dict[str, str]]:
    resp = client.post("/api/auth/google", json={"google_access_token": f"valid:{email}"})
    assert resp.status_code == 200, resp.text
    csrf = resp.json()["csrf_token"]
    cookie_tok = resp.cookies.get("pqc_session_token") or client.cookies.get("pqc_session_token")
    assert cookie_tok
    headers = {
        "X-PQC-CSRF-Token": csrf,
        "Origin": "http://testserver",
    }
    return cookie_tok, headers


# =============================================================================
# PART 1: ADC AUTHORIZATION TESTS (SCENARIOS 1–8)
# =============================================================================


@pytest.mark.parametrize("adc_alias", ["adc", "ADC", "service_account", "default"])
def test_01_external_user_post_api_connection_mode_adc_returns_403(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any, adc_alias: str
) -> None:
    """Scenario 1: External authenticated user submits `mode=adc` (or alias) to `/api/connection` -> HTTP 403."""
    monkeypatch.setenv("PQC_ADMIN_EMAILS", "trusted-admin@google.com")
    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, headers = _login_user(client, "external.user@google.com")
        resp = client.post(
            "/api/connection",
            headers=headers,
            json={"mode": adc_alias, "project_id": "pqc-inventory-agent-cd06"},
        )
        assert resp.status_code == 403
        assert "ADC_UNAUTHORIZED" in resp.json()["detail"]
    app.state.auth_store.close()


def test_02_unauthorized_adc_request_does_not_persist_configuration_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 2: Unauthorized ADC request never persists or mutates existing or empty connection state."""
    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        # Case A: Brand-new authenticated user with no DB row yet -> row remains None after 403
        _, fresh_headers = _login_user(client, "fresh.tenant@google.com")
        denied_fresh = client.post(
            "/api/connection",
            headers=fresh_headers,
            json={
                "mode": "adc",
                "organization_id": "31564119954",
                "project_id": "pqc-inventory-agent-cd06",
            },
        )
        assert denied_fresh.status_code == 403
        assert app.state.auth_store.get_user_connection("fresh.tenant@google.com") is None
        conn_view = client.get("/api/connection", headers=fresh_headers).json()
        assert conn_view["mode"] == "access_token"
        assert conn_view["organization_id"] == ""
        assert conn_view["project_id"] == ""

        # Case B: User with existing valid 3LO configuration -> existing configuration & token remain untouched
        _, ext_headers = _login_user(client, "ext.customer@google.com")
        ok_setup = client.post(
            "/api/connection",
            headers=ext_headers,
            json={
                "mode": "access_token",
                "organization_id": "888888888888",
                "project_id": "ext-customer-proj-01",
                "access_token": "ya29.ext-customer-valid-3lo-token-998877",
            },
        )
        assert ok_setup.status_code == 200

        denied_overwrite = client.post(
            "/api/connection",
            headers=ext_headers,
            json={
                "mode": "adc",
                "organization_id": "31564119954",
                "project_id": "pqc-inventory-agent-cd06",
                "access_token": "",
            },
        )
        assert denied_overwrite.status_code == 403

        persisted = app.state.auth_store.get_user_connection("ext.customer@google.com")
        assert persisted is not None
        assert persisted["mode"] == "access_token"
        assert persisted["organization_id"] == "888888888888"
        assert persisted["project_id"] == "ext-customer-proj-01"

        after_view = client.get("/api/connection", headers=ext_headers).json()
        assert after_view["mode"] == "access_token"
        assert after_view["has_access_token"] is True
        assert after_view["organization_id"] == "888888888888"
        assert after_view["project_id"] == "ext-customer-proj-01"
    app.state.auth_store.close()


def test_03_unauthorized_adc_request_does_not_activate_server_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 3: Unauthorized ADC request (and even tampered DB `mode='adc'`) never activates server ADC."""
    adc_calls: List[Any] = []

    def _fail_if_google_auth_default_called(*args: Any, **kwargs: Any):
        adc_calls.append((args, kwargs))
        raise AssertionError("google.auth.default() must NEVER be invoked for an unauthorized user!")

    import google.auth

    monkeypatch.setattr(google.auth, "default", _fail_if_google_auth_default_called)
    sentinel_adc = tmp_path / "server_sa_adc.json"
    sentinel_adc.write_text('{"type":"service_account","project_id":"pqc-inventory-agent-cd06"}', encoding="utf-8")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sentinel_adc))

    app = _create_hotfix_app(tmp_path, monkeypatch)
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        with TestClient(app) as client:
            _, headers = _login_user(client, "external@google.com")
            res = client.post("/api/connection", headers=headers, json={"mode": "adc"})
            assert res.status_code == 403

            gcloud_bridge.set_current_tenant_user("external@google.com")
            with pytest.raises(PermissionError, match="ACCESS_TOKEN_REQUIRED"):
                gcloud_bridge.get_active_gcp_credentials(user_id="external@google.com")
            with pytest.raises(PermissionError):
                gcp_inventory._get_client_kwargs()

            # Even if the underlying database row were directly tampered to mode='adc',
            # credential loading, client kwargs, and env builder still fail closed!
            app.state.auth_store.upsert_user_connection(
                user_id="external@google.com",
                mode="adc",
                organization_id="31564119954",
                project_id="pqc-inventory-agent-cd06",
            )
            sanitized_cfg = gcloud_bridge.get_gcp_connection_config(user_id="external@google.com")
            assert sanitized_cfg["mode"] == "access_token"
            with pytest.raises(PermissionError, match="ADC_UNAUTHORIZED"):
                gcloud_bridge.get_active_gcp_credentials(user_id="external@google.com")
            with pytest.raises(PermissionError, match="ADC_UNAUTHORIZED"):
                gcp_inventory._get_client_kwargs()
            with pytest.raises(PermissionError, match="ADC_UNAUTHORIZED"):
                gcloud_bridge.build_sanitized_gcloud_env(mode="adc", user_id="external@google.com")

        assert len(adc_calls) == 0
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


def test_04_direct_set_gcp_connection_config_cannot_bypass_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scenario 4: Direct service-layer calls to `set_gcp_connection_config()` enforce ADC & caller identity checks."""
    app = _create_hotfix_app(tmp_path, monkeypatch)
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        # 1. Non-admin authenticated user cannot set mode='adc' or alias directly
        gcloud_bridge.set_current_tenant_user("external@google.com")
        for alias in ("adc", "service_account", "default"):
            with pytest.raises(PermissionError, match="ADC_UNAUTHORIZED"):
                gcloud_bridge.set_gcp_connection_config(mode=alias, user_id="external@google.com")
        assert app.state.auth_store.get_user_connection("external@google.com") is None

        # 2. Unauthenticated fallback identity ('sec-architect') cannot set mode='adc'
        gcloud_bridge.set_current_tenant_user("sec-architect")
        with pytest.raises(PermissionError, match="ADC_UNAUTHORIZED"):
            gcloud_bridge.set_gcp_connection_config(mode="adc")
        assert app.state.auth_store.get_user_connection("sec-architect") is None

        # 3. Even if an admin email exists, an external caller bound in contextvar cannot mutate admin's config
        monkeypatch.setenv("PQC_ADMIN_EMAILS", "admin@google.com")
        gcloud_bridge.set_current_tenant_user("external@google.com")
        with pytest.raises(PermissionError, match="Forbidden"):
            gcloud_bridge.set_gcp_connection_config(mode="adc", user_id="admin@google.com")
        assert app.state.auth_store.get_user_connection("admin@google.com") is None
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


def test_05_direct_execute_gcloud_command_cannot_bypass_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scenario 5: Direct calls to `execute_gcloud_command()` fail closed without an authorized user & scope."""
    subproc_calls: List[Any] = []
    monkeypatch.setattr(
        gcloud_bridge.subprocess,
        "run",
        lambda *a, **kw: subproc_calls.append((a, kw)),
    )

    app = _create_hotfix_app(tmp_path, monkeypatch)
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        # Case A: Unauthenticated default contextvar ('sec-architect') -> UNAUTHENTICATED_EXECUTION_CONTEXT
        gcloud_bridge.set_current_tenant_user("sec-architect")
        unauth_res = json.loads(
            gcloud_bridge.execute_gcloud_command(
                "gcloud kms keys list --location=global --project=pqc-inventory-agent-cd06"
            )
        )
        assert unauth_res["status"] == "COMMAND_ERROR"
        assert unauth_res["error_code"] == "UNAUTHENTICATED_EXECUTION_CONTEXT"
        assert len(subproc_calls) == 0

        # Case B: Authenticated non-admin user with tampered DB row `mode='adc'` -> ADC_UNAUTHORIZED
        app.state.auth_store.upsert_user_connection(
            user_id="external@google.com",
            mode="adc",
            project_id="pqc-inventory-agent-cd06",
            organization_id="31564119954",
        )
        gcloud_bridge.set_current_tenant_user("external@google.com")
        tampered_res = json.loads(
            gcloud_bridge.execute_gcloud_command(
                "gcloud kms keys list --location=global --project=pqc-inventory-agent-cd06"
            )
        )
        assert tampered_res["status"] == "COMMAND_ERROR"
        assert tampered_res["error_code"] == "ADC_UNAUTHORIZED"
        assert len(subproc_calls) == 0
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


def test_06_automatic_adc_activation_through_api_chat_and_auth_paths_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 6: `/api/chat`, `/api/auth/me`, `/api/auth/auto`, and `PqcOAuth3LOPlugin` never auto-activate ADC."""
    app = _create_hotfix_app(tmp_path, monkeypatch)
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        with TestClient(app) as client:
            _, headers = _login_user(client, "external@google.com")

            # 1. Explicit connection_mode='adc' on /api/chat -> HTTP 403, zero persistence
            chat_adc = client.post(
                "/api/chat",
                headers=headers,
                data={
                    "message": "Scan KMS keys",
                    "model_id": "fake-ok-model",
                    "scope": "organizations/31564119954",
                    "connection_mode": "adc",
                },
            )
            assert chat_adc.status_code == 403
            assert app.state.auth_store.get_user_connection("external@google.com") is None

            # 2. connection_mode='access_token' with empty token on demo org 31564119954 NEVER switches to 'adc'
            chat_3lo_empty = client.post(
                "/api/chat",
                headers=headers,
                data={
                    "message": "Summarize PQC readiness",
                    "model_id": "fake-ok-model",
                    "scope": "organizations/31564119954",
                    "connection_mode": "access_token",
                    "access_token": "",
                },
            )
            assert chat_3lo_empty.status_code == 200
            body = chat_3lo_empty.json()
            assert body["connection"]["mode"] == "access_token"
            assert body["connection"]["has_access_token"] is False

            # 3. GET /api/auth/me and POST /api/auth/auto NEVER auto-heal empty 3LO to 'adc'
            me_res = client.get("/api/auth/me", headers=headers).json()
            assert me_res["connection"]["mode"] == "access_token"
            auto_res = client.post("/api/auth/auto", headers=headers).json()
            assert auto_res["connection"]["mode"] == "access_token"

            # 4. PqcOAuth3LOPlugin.before_tool_callback on demo scope emits OAUTH_3LO_CONSENT_REQUIRED (never switches to ADC)
            plugin = ws.PqcOAuth3LOPlugin()
            fake_tool = MagicMock()
            fake_tool.name = "collect_kms_inventory"
            fake_inv_ctx = MagicMock()
            fake_inv_ctx.user_id = "external@google.com"
            fake_inv_ctx.session.id = "sess-demo-check"
            fake_inv_ctx.agent.name = "pqc_inventory_agent"
            fake_tool_ctx = MagicMock()
            fake_tool_ctx._invocation_context = fake_inv_ctx
            fake_tool_ctx.function_call_id = "fc-demo-001"
            fake_tool_ctx.state = {}

            async def _no_cred(_cfg: Any):
                return None

            fake_tool_ctx.load_credential = _no_cred
            fake_tool_ctx.save_credential = _no_cred

            # 4a. Unbound foreign/default org scope fails closed with SCOPE_AUTHORIZATION_DENIED (never switches to ADC)
            gate_unbound = asyncio.run(
                plugin.before_tool_callback(
                    tool=fake_tool,
                    tool_args={"scope": "organizations/31564119954"},
                    tool_context=fake_tool_ctx,
                )
            )
            assert gate_unbound is not None
            assert gate_unbound["status"] == "SCOPE_AUTHORIZATION_DENIED"
            assert gcloud_bridge.get_gcp_connection_config(user_id="external@google.com")["mode"] == "access_token"

            # 4b. Explicit demo scope with empty 3LO token emits OAUTH_3LO_CONSENT_REQUIRED (never switches to ADC)
            gate_demo = asyncio.run(
                plugin.before_tool_callback(
                    tool=fake_tool,
                    tool_args={"scope": "demo-pqc-project"},
                    tool_context=fake_tool_ctx,
                )
            )
            assert gate_demo is not None
            assert gate_demo["status"] == "OAUTH_3LO_CONSENT_REQUIRED"
            assert gcloud_bridge.get_gcp_connection_config(user_id="external@google.com")["mode"] == "access_token"
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


def test_07_demo_adc_rejected_unless_explicit_server_side_admin_policy_authorizes_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 7: Demo org/project values and env hints cannot enable ADC for non-admin users."""
    monkeypatch.setenv("PQC_GCP_CONNECTION_MODE", "adc")
    monkeypatch.setenv("PQC_DEMO_ADC_ENABLED", "true")
    monkeypatch.setenv("PQC_ADMIN_EMAILS", "designated-admin@google.com")

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        # External user targeting demo org/project is STILL denied ADC (403)
        _, ext_headers = _login_user(client, "visitor@google.com")
        assert client.get("/api/connection", headers=ext_headers).json()["mode"] == "access_token"
        ext_attempt = client.post(
            "/api/connection",
            headers=ext_headers,
            json={
                "mode": "adc",
                "organization_id": "31564119954",
                "project_id": "pqc-inventory-agent-cd06",
            },
        )
        assert ext_attempt.status_code == 403

        # Explicitly server-authorized admin in PQC_ADMIN_EMAILS IS permitted
        _, admin_headers = _login_user(client, "designated-admin@google.com")
        admin_attempt = client.post(
            "/api/connection",
            headers=admin_headers,
            json={
                "mode": "adc",
                "organization_id": "31564119954",
                "project_id": "pqc-inventory-agent-cd06",
            },
        )
        assert admin_attempt.status_code == 200
        assert admin_attempt.json()["mode"] == "adc"
    app.state.auth_store.close()


def test_08_client_controlled_fields_headers_scopes_and_session_ids_cannot_establish_adc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 8: Forged headers, admin user_id fields, demo scopes, or session_ids cannot establish ADC."""
    monkeypatch.setenv("PQC_ADMIN_EMAILS", "real-admin@google.com")
    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, ext_headers = _login_user(client, "attacker@google.com")

        spoofed_headers = {
            **ext_headers,
            "X-PQC-Admin": "true",
            "X-Admin-User": "real-admin@google.com",
            "X-PQC-User-Id": "real-admin@google.com",
            "X-Goog-Authenticated-User-Email": "accounts.google.com:real-admin@google.com",
        }

        # Spoofed user_id in payload -> 403 cross-tenant mismatch
        r_spoof_uid = client.post(
            "/api/connection",
            headers=spoofed_headers,
            json={
                "user_id": "real-admin@google.com",
                "mode": "adc",
                "organization_id": "31564119954",
                "project_id": "pqc-inventory-agent-cd06",
            },
        )
        assert r_spoof_uid.status_code == 403

        # Own user_id with spoofed headers and demo project/org -> 403 ADC_UNAUTHORIZED
        r_spoof_hdr = client.post(
            "/api/connection",
            headers=spoofed_headers,
            json={
                "mode": "adc",
                "organization_id": "31564119954",
                "project_id": "pqc-inventory-agent-cd06",
            },
        )
        assert r_spoof_hdr.status_code == 403

        # Spoofed session_id & scope in /api/chat -> 403
        r_spoof_chat = client.post(
            "/api/chat",
            headers=spoofed_headers,
            json={
                "message": "Audit keys",
                "session_id": "admin-adc-session-31564119954",
                "scope": "organizations/31564119954",
                "project_id": "pqc-inventory-agent-cd06",
                "connection_mode": "adc",
                "model_id": "fake-ok-model",
            },
        )
        assert r_spoof_chat.status_code == 403
        assert app.state.auth_store.get_user_connection("attacker@google.com") is None
    app.state.auth_store.close()


# =============================================================================
# PART 2: EXECUTION & TENANT ISOLATION TESTS (SCENARIOS 9–18)
# =============================================================================


def test_09_no_subprocess_invoked_after_unauthorized_adc_request_attack_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 9: Full Section 2 attack chain executes ZERO subprocesses."""
    subproc_invocations: List[Any] = []
    monkeypatch.setattr(
        gcloud_bridge.subprocess,
        "run",
        lambda *a, **kw: subproc_invocations.append((a, kw)),
    )
    monkeypatch.setattr(
        gcloud_bridge.subprocess,
        "Popen",
        lambda *a, **kw: subproc_invocations.append((a, kw)),
    )

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, headers = _login_user(client, "external.attacker@google.com")

        # Step 1: Attacker attempts POST /api/connection with mode=adc -> 403
        step1 = client.post(
            "/api/connection",
            headers=headers,
            json={"mode": "adc", "project_id": "pqc-inventory-agent-cd06", "organization_id": "31564119954"},
        )
        assert step1.status_code == 403

        # Step 2: Attacker invokes POST /api/gcloud anyway -> denied before subprocess execution
        step2 = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud kms keys list --location=global --project=pqc-inventory-agent-cd06 --format=json"},
        )
        assert step2.status_code == 200
        step2_body = step2.json()
        assert step2_body["status"] == "COMMAND_ERROR"
        assert step2_body["error_code"] in ("UNAUTHORIZED_RESOURCE_SCOPE", "ACCESS_TOKEN_REQUIRED")
        assert len(subproc_invocations) == 0
    app.state.auth_store.close()


@pytest.mark.parametrize(
    "unauthorized_cmd",
    [
        "gcloud kms keys list --location=global --project=other-tenant-proj --format=json",
        "gcloud kms keys list --location=global --project other-tenant-proj --format=json",
        "gcloud compute ssl-policies list --project=victim-prod-01 --global",
    ],
)
def test_10_user_cannot_query_unauthorized_project_using_project_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any, unauthorized_cmd: str
) -> None:
    """Scenario 10: Authenticated tenant cannot query an unauthorized project via `--project`."""
    monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "alice@google.com=alice-authorized-proj")
    subproc_invocations: List[Any] = []
    monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/usr/bin/gcloud")
    monkeypatch.setattr(
        gcloud_bridge.subprocess,
        "run",
        lambda *a, **kw: subproc_invocations.append((a, kw)),
    )

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, headers = _login_user(client, "alice@google.com")
        conn_res = client.post(
            "/api/connection",
            headers=headers,
            json={
                "mode": "access_token",
                "project_id": "alice-authorized-proj",
                "access_token": "ya29.alice-scoped-token-123456",
            },
        )
        assert conn_res.status_code == 200

        exec_res = client.post("/api/gcloud", headers=headers, json={"command": unauthorized_cmd})
        body = exec_res.json()
        assert body["status"] == "COMMAND_ERROR"
        assert body["error_code"] == "UNAUTHORIZED_RESOURCE_SCOPE"
        assert len(subproc_invocations) == 0
    app.state.auth_store.close()


@pytest.mark.parametrize(
    "unauthorized_org_cmd",
    [
        "gcloud asset list --organization=999999999999 --format=json",
        "gcloud folders list --organization 999999999999 --format=json",
    ],
)
def test_11_user_cannot_query_unauthorized_organization_using_organization_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any, unauthorized_org_cmd: str
) -> None:
    """Scenario 11: Authenticated tenant cannot query an unauthorized organization via `--organization`."""
    monkeypatch.setenv("PQC_ALLOWED_ORGANIZATIONS", "alice@google.com=111111111111")
    subproc_invocations: List[Any] = []
    monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/usr/bin/gcloud")
    monkeypatch.setattr(
        gcloud_bridge.subprocess,
        "run",
        lambda *a, **kw: subproc_invocations.append((a, kw)),
    )

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, headers = _login_user(client, "alice@google.com")
        conn_res = client.post(
            "/api/connection",
            headers=headers,
            json={
                "mode": "access_token",
                "organization_id": "111111111111",
                "access_token": "ya29.alice-org-token-123456",
            },
        )
        assert conn_res.status_code == 200

        exec_res = client.post("/api/gcloud", headers=headers, json={"command": unauthorized_org_cmd})
        body = exec_res.json()
        assert body["status"] == "COMMAND_ERROR"
        assert body["error_code"] == "UNAUTHORIZED_RESOURCE_SCOPE"
        assert len(subproc_invocations) == 0
    app.state.auth_store.close()


@pytest.mark.parametrize(
    "unauthorized_folder_cmd",
    [
        "gcloud asset list --folder=777777777777 --format=json",
        "gcloud folders list --folder 777777777777 --format=json",
    ],
)
def test_12_user_cannot_query_unauthorized_folder_using_folder_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any, unauthorized_folder_cmd: str
) -> None:
    """Scenario 12: Authenticated tenant cannot query an unauthorized folder via `--folder`."""
    monkeypatch.setenv("PQC_ALLOWED_FOLDERS", "alice@google.com=555555555555")
    subproc_invocations: List[Any] = []
    monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/usr/bin/gcloud")
    monkeypatch.setattr(
        gcloud_bridge.subprocess,
        "run",
        lambda *a, **kw: subproc_invocations.append((a, kw)),
    )

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, headers = _login_user(client, "alice@google.com")
        conn_res = client.post(
            "/api/connection",
            headers=headers,
            json={
                "mode": "access_token",
                "access_token": "ya29.alice-folder-token-123456",
            },
        )
        assert conn_res.status_code == 200

        exec_res = client.post("/api/gcloud", headers=headers, json={"command": unauthorized_folder_cmd})
        body = exec_res.json()
        assert body["status"] == "COMMAND_ERROR"
        assert body["error_code"] == "UNAUTHORIZED_RESOURCE_SCOPE"
        assert len(subproc_invocations) == 0
    app.state.auth_store.close()


@pytest.mark.parametrize(
    "bypass_cmd",
    [
        # --scope hierarchy bypasses
        "gcloud asset search-all-resources --scope=projects/victim-corp-proj --format=json",
        "gcloud asset search-all-resources --scope=organizations/999999999999 --format=json",
        "gcloud asset search-all-iam-policies --scope=folders/777777777777 --format=json",
        # --billing-project & --impersonate-service-account flag bypasses
        "gcloud kms keys list --location=global --project=alice-authorized-proj --billing-project=victim-corp-proj",
        "gcloud kms keys list --location=global --project=alice-authorized-proj --impersonate-service-account=sa@victim-corp-proj.iam.gserviceaccount.com",
        # Positional project / org / folder hierarchy IDs
        "gcloud projects describe victim-corp-proj --format=json",
        "gcloud projects get-iam-policy victim-corp-proj --format=json",
        "gcloud organizations describe 999999999999 --format=json",
        "gcloud folders describe 777777777777 --format=json",
        # Embedded full resource URI in positional/flag value while passing authorized --project
        "gcloud kms keys describe projects/victim-corp-proj/locations/global/keyRings/kr1/cryptoKeys/k1 --project=alice-authorized-proj",
        # Embedded cross-project service account email
        "gcloud iam service-accounts describe prod-sa@victim-corp-proj.iam.gserviceaccount.com --project=alice-authorized-proj",
        # Unscoped enumeration / global namespace commands
        "gcloud projects list --format=json",
        "gcloud organizations list --format=json",
        "gcloud storage buckets describe gs://victim-global-bucket --project=alice-authorized-proj",
    ],
)
def test_13_user_cannot_bypass_scope_validation_via_alternative_flags_or_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any, bypass_cmd: str
) -> None:
    """Scenario 13: Alternative flags, positional IDs, full resource URIs, and unscoped commands cannot bypass scope."""
    monkeypatch.setenv(
        "PQC_TENANT_SCOPE_POLICY",
        json.dumps(
            {
                "alice@google.com": {
                    "projects": ["alice-authorized-proj"],
                    "organizations": ["111111111111"],
                    "folders": ["555555555555"],
                }
            }
        ),
    )
    subproc_invocations: List[Any] = []
    monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/usr/bin/gcloud")
    monkeypatch.setattr(
        gcloud_bridge.subprocess,
        "run",
        lambda *a, **kw: subproc_invocations.append((a, kw)),
    )

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, headers = _login_user(client, "alice@google.com")
        conn_res = client.post(
            "/api/connection",
            headers=headers,
            json={
                "mode": "access_token",
                "organization_id": "111111111111",
                "project_id": "alice-authorized-proj",
                "access_token": "ya29.alice-strict-scope-token-123456",
            },
        )
        assert conn_res.status_code == 200

        exec_res = client.post("/api/gcloud", headers=headers, json={"command": bypass_cmd})
        body = exec_res.json()
        assert body["status"] in ("BLOCKED_DESTRUCTIVE_OR_INVALID_COMMAND", "COMMAND_ERROR")
        if body["status"] == "COMMAND_ERROR":
            assert body["error_code"] == "UNAUTHORIZED_RESOURCE_SCOPE"
        assert len(subproc_invocations) == 0
    app.state.auth_store.close()


def test_14_unauthorized_service_account_impersonation_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 14: SA impersonation is default-deny and enforces principal-bound SA & project scope rules."""
    subproc_invocations: List[Any] = []
    monkeypatch.setattr(
        gcloud_bridge.subprocess,
        "run",
        lambda *a, **kw: subproc_invocations.append((a, kw)),
    )

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, alice_headers = _login_user(client, "alice@google.com")

        # 1. Default-deny when PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS is unset -> HTTP 403
        unset_res = client.post(
            "/api/connection",
            headers=alice_headers,
            json={
                "mode": "impersonation",
                "project_id": "alice-proj-01",
                "impersonated_service_account": "reader@alice-proj-01.iam.gserviceaccount.com",
            },
        )
        assert unset_res.status_code == 403

        # 2. Principal-bound allowlist authorizes Bob's SA for Bob only -> Alice gets HTTP 403
        monkeypatch.setenv(
            "PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS",
            "bob@google.com=reader@bob-proj-01.iam.gserviceaccount.com",
        )
        cross_tenant_sa = client.post(
            "/api/connection",
            headers=alice_headers,
            json={
                "mode": "impersonation",
                "project_id": "bob-proj-01",
                "impersonated_service_account": "reader@bob-proj-01.iam.gserviceaccount.com",
            },
        )
        assert cross_tenant_sa.status_code == 403
        assert len(subproc_invocations) == 0
    app.state.auth_store.close()


def test_15_authorized_read_only_operations_continue_working_within_permitted_tenant_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 15: Legitimate read-only operations succeed within permitted project/org/folder scopes."""
    monkeypatch.setenv(
        "PQC_TENANT_SCOPE_POLICY",
        json.dumps(
            {
                "alice@google.com": {
                    "projects": ["alice-pqc-proj"],
                    "organizations": ["111111111111"],
                    "folders": ["555555555555"],
                }
            }
        ),
    )
    monkeypatch.setenv(
        "PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS",
        "alice@google.com=pqc-reader@alice-pqc-proj.iam.gserviceaccount.com",
    )

    recorded_execs: List[Tuple[List[str], Dict[str, str]]] = []

    def _mock_run(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        recorded_execs.append((list(cmd), dict(kwargs["env"])))
        return subprocess.CompletedProcess(cmd, 0, stdout='[{"ok":true}]', stderr="")

    monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/usr/bin/gcloud")
    monkeypatch.setattr(gcloud_bridge.subprocess, "run", _mock_run)

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, headers = _login_user(client, "alice@google.com")
        assert (
            client.post(
                "/api/connection",
                headers=headers,
                json={
                    "mode": "access_token",
                    "organization_id": "111111111111",
                    "project_id": "alice-pqc-proj",
                    "access_token": "ya29.alice-good-3lo-token-987654",
                },
            ).status_code
            == 200
        )

        # Project-scoped command without explicit --project automatically pins --project=alice-pqc-proj
        r_proj = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud kms keys list --location=global --format=json"},
        ).json()
        assert r_proj["status"] == "SUCCESS"
        assert "--project=alice-pqc-proj" in recorded_execs[-1][0]

        # Organization-scoped Asset Inventory search within permitted org
        r_org = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud asset search-all-resources --scope=organizations/111111111111 --format=json"},
        ).json()
        assert r_org["status"] == "SUCCESS"

        # Folder-scoped Asset IAM search within permitted folder
        r_fld = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud asset search-all-iam-policies --scope=folders/555555555555 --format=json"},
        ).json()
        assert r_fld["status"] == "SUCCESS"

        # Authorized service-account impersonation within permitted project
        assert (
            client.post(
                "/api/connection",
                headers=headers,
                json={
                    "mode": "impersonation",
                    "project_id": "alice-pqc-proj",
                    "impersonated_service_account": "pqc-reader@alice-pqc-proj.iam.gserviceaccount.com",
                },
            ).status_code
            == 200
        )
        r_imp = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud privateca pools list --location=us-central1 --format=json"},
        ).json()
        assert r_imp["status"] == "SUCCESS"
        assert r_imp["connection_mode"] == "impersonation"
        assert (
            recorded_execs[-1][1]["CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"]
            == "pqc-reader@alice-pqc-proj.iam.gserviceaccount.com"
        )
        assert len(recorded_execs) == 4
    app.state.auth_store.close()


def test_16_trusted_server_side_adc_operations_succeed_only_within_authorized_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 16: Explicitly authorized admin ADC works in authorized scope and still blocks out-of-scope queries."""
    monkeypatch.setenv("PQC_ADMIN_EMAILS", "secadmin@google.com")
    monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "secadmin@google.com=pqc-inventory-agent-cd06")

    recorded_execs: List[Tuple[List[str], Dict[str, str]]] = []

    def _mock_run(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        recorded_execs.append((list(cmd), dict(kwargs["env"])))
        return subprocess.CompletedProcess(cmd, 0, stdout='[{"key":"adc-ok"}]', stderr="")

    monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/usr/bin/gcloud")
    monkeypatch.setattr(gcloud_bridge.subprocess, "run", _mock_run)

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, admin_headers = _login_user(client, "secadmin@google.com")
        sw = client.post(
            "/api/connection",
            headers=admin_headers,
            json={"mode": "adc", "project_id": "pqc-inventory-agent-cd06"},
        )
        assert sw.status_code == 200
        assert sw.json()["mode"] == "adc"

        ok_exec = client.post(
            "/api/gcloud",
            headers=admin_headers,
            json={"command": "gcloud kms keyrings list --location=global --format=json"},
        ).json()
        assert ok_exec["status"] == "SUCCESS"
        assert ok_exec["connection_mode"] == "adc"
        assert len(recorded_execs) == 1
        assert "CLOUDSDK_AUTH_ACCESS_TOKEN" not in recorded_execs[0][1]

        # Out-of-scope project is still blocked even for admin!
        recorded_execs.clear()
        out_of_scope = client.post(
            "/api/gcloud",
            headers=admin_headers,
            json={"command": "gcloud kms keyrings list --location=global --project=unapproved-foreign-proj"},
        ).json()
        assert out_of_scope["status"] == "COMMAND_ERROR"
        assert out_of_scope["error_code"] == "UNAUTHORIZED_RESOURCE_SCOPE"
        assert len(recorded_execs) == 0
    app.state.auth_store.close()


def test_17_delegated_oauth_token_permission_and_expiry_failures_remain_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 17: Delegated OAuth 403/PERMISSION_DENIED and expired tokens fail closed."""
    invocations: List[Tuple[List[str], Dict[str, str]]] = []
    monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/usr/bin/gcloud")

    def _denied_run(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        invocations.append((list(cmd), dict(kwargs["env"])))
        return subprocess.CompletedProcess(
            cmd,
            1,
            stdout="",
            stderr="ERROR: (gcloud.kms.keys.list) PERMISSION_DENIED: Caller lacks cloudkms.cryptoKeys.list",
        )

    monkeypatch.setattr(gcloud_bridge.subprocess, "run", _denied_run)

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, headers = _login_user(client, "alice@google.com")
        tok = "ya29.alice-denied-token-secret-value-556677"
        assert (
            client.post(
                "/api/connection",
                headers=headers,
                json={"mode": "access_token", "project_id": "alice-proj-01", "access_token": tok},
            ).status_code
            == 200
        )

        denied = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud kms keys list --location=global --project=alice-proj-01"},
        ).json()
        assert denied["status"] == "COMMAND_ERROR"
        assert denied["exit_code"] == 1
        assert "PERMISSION_DENIED" in denied["stderr"]
        assert tok not in json.dumps(denied)
        assert len(invocations) == 1

        # Expire token -> fail closed with 0 subprocess calls
        cred_id = credential_service.build_credential_id(
            credential_service.DEFAULT_APP_NAME,
            "google.com",
            "alice@google.com",
            credential_service.DEFAULT_GCP_CREDENTIAL_KEY,
        )
        with app.state.auth_store._session_factory() as db:
            rec = db.get(auth_store.DelegatedCredentialRecord, cred_id)
            assert rec is not None
            rec.expires_at = time.time() - 60.0
            db.commit()

        invocations.clear()
        expired = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud kms keys list --location=global --project=alice-proj-01"},
        ).json()
        assert expired["status"] == "COMMAND_ERROR"
        assert expired["error_code"] == "ACCESS_TOKEN_REQUIRED"
        assert len(invocations) == 0
    app.state.auth_store.close()


def test_18_no_delegated_oauth_failure_ever_triggers_adc_fallback_even_for_admin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 18: Even if the caller is in `PQC_ADMIN_EMAILS`, a 3LO failure in `access_token` mode never retries with ADC."""
    monkeypatch.setenv("PQC_ADMIN_EMAILS", "alice@google.com")
    invocations: List[Tuple[List[str], Dict[str, str]]] = []
    monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/usr/bin/gcloud")

    def _unauthenticated_run(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        invocations.append((list(cmd), dict(kwargs["env"])))
        return subprocess.CompletedProcess(
            cmd,
            1,
            stdout="",
            stderr="ERROR: (gcloud.asset.search-all-resources) UNAUTHENTICATED: Request had invalid authentication credentials.",
        )

    monkeypatch.setattr(gcloud_bridge.subprocess, "run", _unauthenticated_run)

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, headers = _login_user(client, "alice@google.com")
        delegated_tok = "ya29.admin-operating-in-3lo-mode-token-999"
        assert (
            client.post(
                "/api/connection",
                headers=headers,
                json={
                    "mode": "access_token",
                    "organization_id": "31564119954",
                    "project_id": "pqc-inventory-agent-cd06",
                    "access_token": delegated_tok,
                },
            ).status_code
            == 200
        )

        res = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud asset search-all-resources --scope=organizations/31564119954 --format=json"},
        ).json()
        assert res["status"] == "COMMAND_ERROR"
        assert res["connection_mode"] == "access_token"
        assert len(invocations) == 1  # Strictly 1 attempt; zero ADC fallback retries!
        assert invocations[0][1].get("CLOUDSDK_AUTH_ACCESS_TOKEN") == delegated_tok
        assert client.get("/api/connection", headers=headers).json()["mode"] == "access_token"
    app.state.auth_store.close()


# =============================================================================
# PART 3: EXECUTABLE RESOLUTION HARDENING TESTS (SCENARIOS 19–21)
# =============================================================================


def test_19_malicious_gcloud_binary_placed_earlier_in_path_is_never_executed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 19: Poisoned `PATH` directory containing an executable `gcloud` script is ignored & never executed."""
    attacker_dir = tmp_path / "attacker_path_bin"
    attacker_dir.mkdir(mode=0o755)
    pwned_marker = tmp_path / "pwned_marker.txt"
    rogue_gcloud = attacker_dir / "gcloud"
    rogue_gcloud.write_text(
        f"#!/bin/sh\necho PWNED > {str(pwned_marker)!r}\nexit 0\n",
        encoding="utf-8",
    )
    rogue_gcloud.chmod(0o755)

    # Prepend attacker directory to process PATH
    monkeypatch.setenv("PATH", f"{attacker_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}")
    # Force trusted candidate list to a non-existent controlled path so any PATH lookup would hit rogue_gcloud
    monkeypatch.setattr(gcloud_bridge, "TRUSTED_GCLOUD_PATHS", ("/usr/lib/google-cloud-sdk/bin/nonexistent-gcloud",))

    assert gcloud_bridge.resolve_trusted_gcloud_binary() is None

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, headers = _login_user(client, "alice@google.com")
        client.post(
            "/api/connection",
            headers=headers,
            json={
                "mode": "access_token",
                "project_id": "alice-proj-01",
                "access_token": "ya29.alice-path-test-token-123456",
            },
        )
        res = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud kms keys list --location=global --project=alice-proj-01"},
        ).json()
        assert res["status"] == "GCLOUD_BINARY_NOT_FOUND"
        assert not pwned_marker.exists(), "Malicious gcloud on PATH must NEVER be executed!"
    app.state.auth_store.close()


def test_20_unexpected_symlinked_or_world_writable_gcloud_executable_paths_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 20: Unexpected locations, relative paths, untrusted symlinks, and world-writable binaries are rejected."""
    # 1. Direct validator rejects relative, /tmp, and user-home paths
    for untrusted in (
        "gcloud",
        "./gcloud",
        "/tmp/gcloud",
        str(tmp_path / "gcloud"),
        "/Users/attacker/google-cloud-sdk/bin/gcloud",
        "/home/attacker/bin/gcloud",
    ):
        with pytest.raises(PermissionError):
            gcloud_bridge.validate_gcloud_executable_path(untrusted, check_filesystem=False)

    # 2a. Symlink inside an allowed candidate slot pointing to a binary with wrong basename -> rejected
    fake_trusted_dir = tmp_path / "trusted_sdk" / "bin"
    fake_trusted_dir.mkdir(parents=True, mode=0o755)
    outside_wrong_name = tmp_path / "untrusted_outside" / "rogue_gcloud"
    outside_wrong_name.parent.mkdir(parents=True, mode=0o755)
    outside_wrong_name.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    outside_wrong_name.chmod(0o755)

    symlink_bin = fake_trusted_dir / "gcloud"
    symlink_bin.symlink_to(outside_wrong_name)

    monkeypatch.setattr(gcloud_bridge, "TRUSTED_GCLOUD_PATHS", (str(symlink_bin),))
    monkeypatch.setattr(
        gcloud_bridge,
        "TRUSTED_GCLOUD_REALPATH_PREFIXES",
        (os.path.realpath(str(fake_trusted_dir)) + "/",),
    )
    with pytest.raises(PermissionError, match="unexpected binary basename"):
        gcloud_bridge.validate_gcloud_executable_path(str(symlink_bin), check_filesystem=True)

    # 2b. Symlink pointing to a file named 'gcloud' outside TRUSTED_GCLOUD_REALPATH_PREFIXES -> rejected
    symlink_bin.unlink()
    outside_same_name = tmp_path / "untrusted_outside" / "gcloud"
    outside_same_name.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    outside_same_name.chmod(0o755)
    symlink_bin.symlink_to(outside_same_name)
    with pytest.raises(PermissionError, match="resolves outside controlled installation directories"):
        gcloud_bridge.validate_gcloud_executable_path(str(symlink_bin), check_filesystem=True)

    # 3. World-writable binary inside an otherwise trusted prefix -> rejected
    symlink_bin.unlink()
    writable_bin = fake_trusted_dir / "gcloud"
    writable_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(writable_bin, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)  # 0o777
    with pytest.raises(PermissionError, match="world-writable"):
        gcloud_bridge.validate_gcloud_executable_path(str(writable_bin), check_filesystem=True)

    # 4. If _resolve_gcloud_binary were ever monkeypatched/corrupted to return /tmp/gcloud, execute_gcloud_command blocks it
    subproc_calls: List[Any] = []
    monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/tmp/gcloud")
    monkeypatch.setattr(
        gcloud_bridge.subprocess,
        "run",
        lambda *a, **kw: subproc_calls.append((a, kw)),
    )

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, headers = _login_user(client, "alice@google.com")
        client.post(
            "/api/connection",
            headers=headers,
            json={
                "mode": "access_token",
                "project_id": "alice-proj-01",
                "access_token": "ya29.alice-exec-path-token-123456",
            },
        )
        res = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud kms keys list --location=global --project=alice-proj-01"},
        ).json()
        assert res["status"] == "COMMAND_ERROR"
        assert res["error_code"] == "GCLOUD_UNTRUSTED_EXECUTABLE"
        assert len(subproc_calls) == 0
    app.state.auth_store.close()


def test_21_validated_executable_path_used_consistently_by_subprocess_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 21: Validated absolute executable path, `shell=False`, and pinned `PATH` are enforced consistently."""
    # Create a controlled, non-world-writable directory and binary simulating a system SDK install
    controlled_root = tmp_path / "system_cloud_sdk"
    controlled_bin_dir = controlled_root / "bin"
    controlled_bin_dir.mkdir(parents=True, mode=0o755)
    os.chmod(controlled_root, 0o755)
    os.chmod(controlled_bin_dir, 0o755)
    controlled_gcloud = controlled_bin_dir / "gcloud"
    controlled_gcloud.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(controlled_gcloud, 0o755)

    expected_realpath = os.path.realpath(str(controlled_gcloud))
    monkeypatch.setattr(gcloud_bridge, "TRUSTED_GCLOUD_PATHS", (str(controlled_gcloud),))
    monkeypatch.setattr(
        gcloud_bridge,
        "TRUSTED_GCLOUD_REALPATH_PREFIXES",
        (os.path.realpath(str(controlled_root)) + "/",),
    )
    # Poison ambient process PATH to verify subprocess receives pinned TRUSTED_SUBPROCESS_PATH instead
    monkeypatch.setenv("PATH", "/tmp/evil_bin:/var/tmp/hijack")

    captured_calls: List[Tuple[List[str], Dict[str, Any]]] = []

    def _capture_run(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured_calls.append((list(cmd), dict(kwargs)))
        return subprocess.CompletedProcess(cmd, 0, stdout='{"version":"500.0.0"}', stderr="")

    monkeypatch.setattr(gcloud_bridge.subprocess, "run", _capture_run)

    app = _create_hotfix_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        _, headers = _login_user(client, "alice@google.com")
        client.post(
            "/api/connection",
            headers=headers,
            json={
                "mode": "access_token",
                "project_id": "alice-proj-01",
                "access_token": "ya29.alice-consistent-bin-token-123456",
            },
        )
        res = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud kms keyrings list --location=global --project=alice-proj-01 --format=json"},
        ).json()
        assert res["status"] == "SUCCESS"
        assert res["executable_path"] == expected_realpath
        assert len(captured_calls) == 1

        argv, run_kwargs = captured_calls[0]
        assert isinstance(argv, list)
        assert argv[0] == expected_realpath
        assert run_kwargs["shell"] is False
        assert run_kwargs["env"]["PATH"] == gcloud_bridge.TRUSTED_SUBPROCESS_PATH
        assert "/tmp/evil_bin" not in run_kwargs["env"]["PATH"]
    app.state.auth_store.close()
