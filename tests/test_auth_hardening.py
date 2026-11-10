"""Regression tests for the portal authentication hardening (S1-S8) and the Gemini Pro-only model catalog.

S1 email-only sign-in            S5 ADK DevServer on Cloud Run
S2 user-id spoofing              S6 constant HMAC fallback key
S3 forged IAP headers            S7 OAuth tokens at rest
S4 unauthenticated ADK routes    S8 wildcard CORS
plus: admin-only OAuth client config, private tenant directory, signed + browser-bound OAuth state, reflected XSS in
the OAuth popup, authenticated model re-verification, strict session lookup.
"""

import io
import json
import os
import pathlib
import stat
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ALICE = "alice@google.com"
BOB = "bob@google.com"
LEGACY_CONSTANT_KEY = b"pqc-workspace-fallback-hmac-key-2026"


@pytest.fixture(autouse=True)
def _isolated_auth_state(tmp_path, monkeypatch):
    """Fresh data dir + clean auth env + empty in-memory connection/token stores for every test."""
    from tools import gcloud_bridge

    monkeypatch.setenv("PQC_DATA_DIR", str(tmp_path / "data"))
    for name in (
        "K_SERVICE",
        "PQC_ALLOW_UNVERIFIED_SIGNIN",
        "PQC_ENABLE_ADK_API",
        "PQC_ENABLE_ADK_DEV_UI",
        "PQC_ALLOWED_ORIGINS",
        "PQC_IAP_AUDIENCE",
        "PQC_ADMIN_EMAILS",
        "PQC_GOOGLE_ID_TOKEN_AUDIENCES",
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(gcloud_bridge, "_USER_CONNECTIONS", {})
    monkeypatch.setattr(gcloud_bridge, "_USER_ACCESS_TOKENS", {})
    monkeypatch.setattr(gcloud_bridge, "_USER_CONNECTIONS_LOADED", False)


def _registry():
    from pqc_agent.model_registry import ModelRegistry

    return ModelRegistry(
        candidates=[{"model": "fake-ok-model", "label": "Fake OK", "thinking_levels": [None]}],
        probe=lambda model, level: (True, {"model_version": f"{model}-001"}),
        default_model="fake-ok-model",
        default_thinking_level="",
    )


def _app(tmp_path):
    from pqc_agent.workspace_server import create_workspace_app

    return create_workspace_app(
        session_db_url=f"sqlite:///{tmp_path / 'sessions.db'}",
        artifact_bucket=None,  # local fallback: no GCS calls
        model_registry=_registry(),
        verify_models_on_startup=False,
    )


def _hdr(token):
    return {"X-PQC-User-Token": token}


# ---------------------------------------------------------------------------------------------------------------
# S1 - sign-in requires a verified Google credential
# ---------------------------------------------------------------------------------------------------------------
def test_s1_email_only_signin_is_rejected_by_default(tmp_path):
    with TestClient(_app(tmp_path)) as client:
        resp = client.post("/api/auth/google", json={"email": "victim@google.com", "region": "NorthAm"})
        assert resp.status_code == 401
        assert "gcloud auth print-access-token" in resp.json()["detail"]
        assert "token" not in resp.json()
        assert "pqc_session_token" not in resp.headers.get("set-cookie", "")
        assert client.get("/api/sessions").status_code == 401
        cfg = client.get("/api/auth/config").json()
        assert cfg["allow_unverified_signin"] is False
        assert cfg["access_token_command"] == "gcloud auth print-access-token"


def test_s1_dev_flag_re_enables_email_only_signin_for_allowed_domains(tmp_path, monkeypatch):
    monkeypatch.setenv("PQC_ALLOW_UNVERIFIED_SIGNIN", "true")
    with TestClient(_app(tmp_path)) as client:
        assert client.get("/api/auth/config").json()["allow_unverified_signin"] is True
        ok = client.post("/api/auth/google", json={"email": "dev@google.com"})
        assert ok.status_code == 200
        assert ok.json()["user"]["auth_method"] == "unverified_email_dev_only"
        assert client.post("/api/auth/google", json={"email": "x@evil.example.com"}).status_code == 403


def test_s1_verified_credential_checks(tmp_path, google_verifier):
    with TestClient(_app(tmp_path)) as client:
        assert client.post("/api/auth/google", json={"google_access_token": "garbage"}).status_code == 401
        unverified = client.post("/api/auth/google", json={"google_access_token": f"unverified:{ALICE}"})
        assert unverified.status_code == 401
        assert client.post("/api/auth/google", json={"google_access_token": "valid:eve@evil.example.com"}).status_code == 403
        # The verified email wins over any email the client claims.
        resp = client.post("/api/auth/google", json={"google_access_token": f"valid:{ALICE}", "email": BOB})
        assert resp.status_code == 200
        body = resp.json()
        assert body["user_id"] == ALICE and body["token"]
        cookie = resp.headers["set-cookie"].lower()
        assert "pqc_session_token=" in cookie and "httponly" in cookie and "samesite=lax" in cookie
        assert (None, f"valid:{ALICE}") in google_verifier


def test_s1_real_verifier_enforces_verified_email_issuer_and_audience(monkeypatch):
    from pqc_agent import workspace_server as ws

    responses = {}

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        key = "id" if "id_token=" in url else "access"
        return _Resp(json.dumps(responses[key]).encode("utf-8"))

    monkeypatch.setattr(ws.urllib.request, "urlopen", fake_urlopen)

    responses["access"] = {"email": ALICE, "email_verified": "false", "expires_in": "3000"}
    info, err = ws._verify_google_oauth_or_id_token(None, "ya29.x")
    assert info is None and "verified" in err
    responses["access"] = {"aud": "gcloud", "expires_in": "3000"}
    assert ws._verify_google_oauth_or_id_token(None, "ya29.x")[0] is None
    responses["access"] = {"email": ALICE, "email_verified": "true", "expires_in": "3000"}
    info, err = ws._verify_google_oauth_or_id_token(None, "Bearer ya29.x")
    assert err is None and info["email"] == ALICE and info["email_verified"] is True and info["expires_in"] == 3000

    responses["id"] = {"iss": "https://evil.example.com", "aud": "a", "email": ALICE, "email_verified": True}
    assert ws._verify_google_oauth_or_id_token("jwt", None)[0] is None
    monkeypatch.setenv("PQC_GOOGLE_ID_TOKEN_AUDIENCES", "portal-client.apps.googleusercontent.com")
    responses["id"] = {"iss": "accounts.google.com", "aud": "other-app", "email": ALICE, "email_verified": "true"}
    info, err = ws._verify_google_oauth_or_id_token("jwt", None)
    assert info is None and "audience" in err
    responses["id"]["aud"] = "portal-client.apps.googleusercontent.com"
    assert ws._verify_google_oauth_or_id_token("jwt", None)[0]["email"] == ALICE


# ---------------------------------------------------------------------------------------------------------------
# S2 - the authenticated identity is the only source of user_id
# ---------------------------------------------------------------------------------------------------------------
def test_s2_spoofed_user_ids_cannot_reach_other_tenants(tmp_path, signin):
    with TestClient(_app(tmp_path)) as client:
        bob = _hdr(signin(client, BOB))
        bob_sid = client.post("/api/sessions", headers=bob, json={"title": "Bob secret review"}).json()["session_id"]
        alice = _hdr(signin(client, ALICE))
        client.cookies.clear()

        # Unauthenticated: header / param spoofing gives nothing.
        assert client.get("/api/sessions", headers={"X-PQC-User-Id": BOB}).status_code == 401
        assert client.get("/api/sessions", params={"user_id": BOB}).status_code == 401
        assert client.get(f"/api/sessions/{bob_sid}", params={"user_id": BOB}).status_code == 401

        # Authenticated as Alice: X-PQC-User-Id is ignored entirely.
        listed = client.get("/api/sessions", headers={**alice, "X-PQC-User-Id": BOB}).json()
        assert listed["user_id"] == ALICE
        assert all(s["session_id"] != bob_sid for s in listed["sessions"])
        assert client.get(f"/api/sessions/{bob_sid}", headers={**alice, "X-PQC-User-Id": BOB}).status_code == 404

        # Explicit user_id naming someone else -> 403 on every tenant-scoped endpoint.
        forbidden = [
            client.get("/api/sessions", headers=alice, params={"user_id": BOB}),
            client.get(f"/api/sessions/{bob_sid}", headers=alice, params={"user_id": BOB}),
            client.delete(f"/api/sessions/{bob_sid}", headers=alice, params={"user_id": BOB}),
            client.post("/api/sessions", headers=alice, json={"user_id": BOB, "title": "x"}),
            client.post("/api/chat", headers=alice, json={"user_id": BOB, "message": "hi", "model": "fake-ok-model"}),
            client.post("/api/chat", headers=alice, data={"user_id": BOB, "message": "hi", "model_id": "fake-ok-model"}),
            client.get("/api/connection", headers=alice, params={"user_id": BOB}),
            client.post("/api/connection", headers=alice, json={"user_id": BOB, "mode": "adc"}),
            client.post("/api/gcloud", headers=alice, json={"user_id": BOB, "command": "gcloud version"}),
            client.get("/api/gcloud/traces", headers=alice, params={"user_id": BOB}),
            client.post("/api/auth/tool-consent", headers=alice, json={"user_id": BOB, "access_token": "ya29.x"}),
            client.get("/api/auth/oauth/authorize", headers=alice, params={"user_id": BOB, "format": "json"}),
        ]
        assert [r.status_code for r in forbidden] == [403] * len(forbidden)

        # Matching explicit ids are fine, and Bob's data is untouched.
        assert client.get("/api/sessions", headers=alice, params={"user_id": ALICE}).status_code == 200
        bob_detail = client.get(f"/api/sessions/{bob_sid}", headers=bob)
        assert bob_detail.status_code == 200 and bob_detail.json()["title"] == "Bob secret review"


def test_s2_every_tenant_endpoint_requires_authentication(tmp_path):
    with TestClient(_app(tmp_path)) as client:
        calls = [
            client.get("/api/sessions"),
            client.post("/api/sessions", json={"title": "x"}),
            client.get("/api/sessions/some-id"),
            client.delete("/api/sessions/some-id"),
            client.post("/api/chat", json={"message": "hi"}),
            client.get("/api/connection"),
            client.post("/api/connection", json={"mode": "adc"}),
            client.post("/api/gcloud", json={"command": "gcloud version"}),
            client.get("/api/gcloud/traces"),
            client.post("/api/auth/tool-consent", json={"access_token": "ya29.x"}),
            client.get("/api/auth/oauth/authorize", params={"format": "json"}),
            client.get("/api/auth/tenants"),
            client.post("/api/auth/oauth/config", json={"client_id": "x"}),
            client.get("/api/models", params={"refresh": "true"}),
        ]
        assert [r.status_code for r in calls] == [401] * len(calls)
        # Public routes stay public.
        for path in ("/", "/api/health", "/api/models", "/api/auth/config", "/api/auth/me", "/api/auth/oauth/config"):
            assert client.get(path).status_code == 200, path
        assert client.get("/api/health").json()["connection"] is None


# ---------------------------------------------------------------------------------------------------------------
# S3 - Cloud IAP identity only from a verified signed JWT
# ---------------------------------------------------------------------------------------------------------------
def test_s3_forged_iap_headers_do_not_authenticate(tmp_path, monkeypatch):
    from pqc_agent import auth_guard

    calls = []

    def reject(token, request, audience=None, certs_url=None, **kw):
        calls.append((token, audience, certs_url))
        raise ValueError("Could not verify token signature.")

    monkeypatch.setattr(auth_guard.google_id_token, "verify_token", reject)
    with TestClient(_app(tmp_path)) as client:
        forged = {"X-Goog-Authenticated-User-Email": f"accounts.google.com:{ALICE}"}
        me = client.get("/api/auth/me", headers=forged).json()
        assert me["authenticated"] is False and me["iap_active"] is False and me["user"] is None
        assert client.get("/api/sessions", headers=forged).status_code == 401
        bad_jwt = {**forged, "X-Goog-IAP-JWT-Assertion": "eyJhbGciOiJFUzI1NiJ9.forged.sig"}
        assert client.get("/api/sessions", headers=bad_jwt).status_code == 401
        assert calls and calls[-1][2] == "https://www.gstatic.com/iap/verify/public_key"


def test_s3_verify_iap_jwt_contract_and_verified_identity(tmp_path, monkeypatch):
    import google.auth.transport.requests

    from pqc_agent import auth_guard

    seen = {}
    claims = {"iss": auth_guard.IAP_ISSUER, "email": ALICE, "sub": "accounts.google.com:123", "aud": "/projects/1/apps/p"}

    def fake_verify(token, request, audience=None, certs_url=None, **kw):
        seen.update(token=token, request=request, audience=audience, certs_url=certs_url)
        if token == "good":
            return dict(claims)
        if token == "wrong-issuer":
            return {**claims, "iss": "https://accounts.google.com"}
        if token == "no-email":
            return {k: v for k, v in claims.items() if k != "email"}
        raise ValueError("bad token")

    monkeypatch.setattr(auth_guard.google_id_token, "verify_token", fake_verify)
    monkeypatch.setenv("PQC_IAP_AUDIENCE", "/projects/1/apps/p")
    assert auth_guard.verify_iap_jwt("good")["email"] == ALICE
    assert seen["audience"] == "/projects/1/apps/p"
    assert seen["certs_url"] == "https://www.gstatic.com/iap/verify/public_key"
    assert isinstance(seen["request"], google.auth.transport.requests.Request)
    assert auth_guard.verify_iap_jwt("wrong-issuer") is None
    assert auth_guard.verify_iap_jwt("no-email") is None
    assert auth_guard.verify_iap_jwt("bad") is None
    monkeypatch.delenv("PQC_IAP_AUDIENCE")
    auth_guard.verify_iap_jwt("good")
    assert seen["audience"] is None

    with TestClient(_app(tmp_path)) as client:
        me = client.get(
            "/api/auth/me",
            headers={"X-Goog-IAP-JWT-Assertion": "good", "X-Goog-Authenticated-User-Email": f"accounts.google.com:{BOB}"},
        ).json()
        assert me["authenticated"] is True and me["iap_active"] is True
        assert me["user_id"] == ALICE  # email from the verified claims, never from the plain header
        assert client.get("/api/sessions", headers={"X-Goog-IAP-JWT-Assertion": "good"}).json()["user_id"] == ALICE


# ---------------------------------------------------------------------------------------------------------------
# S4 / S5 - ADK-native routes and DevServer
# ---------------------------------------------------------------------------------------------------------------
ADK_PROBES = [
    ("GET", "/list-apps"),
    ("GET", f"/apps/pqc_agent/users/{ALICE}/sessions"),
    ("POST", f"/apps/pqc_agent/users/{ALICE}/sessions"),
    ("GET", "/apps/pqc_agent/app-info"),
    ("POST", "/run"),
    ("POST", "/run_sse"),
    ("GET", "/health"),
    ("GET", "/version"),
    ("GET", "/docs"),
    ("GET", "/openapi.json"),
    ("POST", "/agent-identity/finalize"),
    ("GET", "/dev-ui/"),
    ("POST", "/dev/apps/pqc_agent/builder/save"),
    ("POST", "/dev/apps/pqc_agent/deploy/cloud_run"),
    ("GET", "/dev/apps/pqc_agent/debug/trace/session/x"),
]


def test_s4_s5_adk_routes_and_dev_server_are_off_on_cloud_run(tmp_path, monkeypatch, signin):
    monkeypatch.setenv("K_SERVICE", "pqc-inventory-agent")
    app = _app(tmp_path)
    assert app.state.adk_dev_ui_enabled is False and app.state.adk_api_enabled is False
    paths = [str(getattr(r, "path", "")) for r in app.router.routes]
    assert not [p for p in paths if p.startswith(("/dev/", "/dev-ui"))]
    with TestClient(app) as client:
        alice = _hdr(signin(client, ALICE))
        for method, path in ADK_PROBES:
            for headers in ({}, alice):
                assert client.request(method, path, headers=headers, json={}).status_code == 404, (method, path)
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/run_live?app_name=pqc_agent&user_id={ALICE}&session_id=s", headers=alice):
                pass
        health = client.get("/api/health").json()
        assert health["dev_ui_url"] is None and health["dev_ui_available"] is False
        assert client.get("/").status_code == 200
        assert client.get("/api/sessions", headers=alice).status_code == 200


def test_s4_enabled_adk_routes_require_identity_and_bind_user(tmp_path, monkeypatch, signin):
    monkeypatch.setenv("K_SERVICE", "pqc-inventory-agent")
    monkeypatch.setenv("PQC_ENABLE_ADK_API", "true")
    app = _app(tmp_path)
    assert app.state.adk_api_enabled is True and app.state.adk_dev_ui_enabled is False
    with TestClient(app) as client:
        bob = _hdr(signin(client, BOB))
        bob_sid = client.post("/api/sessions", headers=bob, json={"title": "b"}).json()["session_id"]
        alice = _hdr(signin(client, ALICE))
        client.cookies.clear()

        assert client.get("/list-apps").status_code == 401
        assert client.get(f"/apps/pqc_agent/users/{ALICE}/sessions").status_code == 401
        forged = {"X-Goog-Authenticated-User-Email": f"accounts.google.com:{BOB}", "X-PQC-User-Id": BOB}
        assert client.get(f"/apps/pqc_agent/users/{BOB}/sessions", headers=forged).status_code == 401

        assert client.get("/list-apps", headers=alice).status_code == 200
        assert client.get(f"/apps/pqc_agent/users/{ALICE}/sessions", headers=alice).status_code == 200
        assert client.get(f"/apps/pqc_agent/users/{BOB}/sessions", headers=alice).status_code == 403
        assert client.get(f"/apps/pqc_agent/users/{BOB}/sessions/{bob_sid}", headers=alice).status_code == 403
        assert client.delete(f"/apps/pqc_agent/users/{BOB}/sessions/{bob_sid}", headers=alice).status_code == 403
        message = {"role": "user", "parts": [{"text": "hi"}]}
        run_body = {"app_name": "pqc_agent", "user_id": BOB, "session_id": bob_sid, "new_message": message}
        assert client.post("/run", headers=alice, json=run_body).status_code == 403
        camel = {"appName": "pqc_agent", "userId": BOB, "sessionId": bob_sid, "newMessage": message}
        assert client.post("/run_sse", headers=alice, json=camel).status_code == 403
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/run_live?app_name=pqc_agent&user_id={BOB}&session_id={bob_sid}", headers=alice):
                pass
        assert client.get(f"/apps/pqc_agent/users/{BOB}/sessions/{bob_sid}", headers=bob).status_code == 200


def test_s5_dev_ui_switch_and_local_dev_server_requires_identity(tmp_path, monkeypatch):
    from pqc_agent.workspace_server import _adk_dev_ui_enabled

    matrix = [
        ({"PQC_ENABLE_ADK_DEV_UI": "true", "K_SERVICE": "svc"}, True),
        ({"PQC_ENABLE_ADK_DEV_UI": "1", "K_SERVICE": "svc"}, True),
        ({"PQC_ENABLE_ADK_DEV_UI": "yes"}, True),
        ({"PQC_ENABLE_ADK_DEV_UI": "false"}, False),
        ({"PQC_ENABLE_ADK_DEV_UI": "0"}, False),
        ({"PQC_ENABLE_ADK_DEV_UI": "no"}, False),
        ({"K_SERVICE": "svc"}, False),
        ({"PQC_ENABLE_ADK_DEV_UI": "maybe", "K_SERVICE": "svc"}, False),
        ({}, True),
    ]
    for env, expected in matrix:
        for name in ("PQC_ENABLE_ADK_DEV_UI", "K_SERVICE"):
            monkeypatch.delenv(name, raising=False)
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        assert _adk_dev_ui_enabled() is expected, env

    for name in ("PQC_ENABLE_ADK_DEV_UI", "K_SERVICE"):
        monkeypatch.delenv(name, raising=False)
    app = _app(tmp_path)  # local development defaults
    assert app.state.adk_dev_ui_enabled is True and app.state.adk_api_enabled is True
    with TestClient(app) as client:
        assert client.get("/api/health").json()["dev_ui_url"] == "/dev-ui/?app=pqc_agent"
        assert client.post("/dev/apps/pqc_agent/builder/save", json={}).status_code == 401
        assert client.post("/dev/apps/pqc_agent/deploy/cloud_run", json={}).status_code == 401
        assert client.get("/list-apps").status_code == 401


# ---------------------------------------------------------------------------------------------------------------
# S6 - HMAC secret
# ---------------------------------------------------------------------------------------------------------------
def test_s6_hmac_secret_is_never_a_constant(tmp_path, monkeypatch):
    from pqc_agent import auth_guard
    from pqc_agent import workspace_server as ws

    monkeypatch.delenv("PQC_AUTH_SECRET", raising=False)
    first, second = auth_guard.load_or_create_hmac_secret(None), auth_guard.load_or_create_hmac_secret(None)
    assert first != second and len(first) == 64 and LEGACY_CONSTANT_KEY not in (first, second)

    read_only = tmp_path / "ro"
    read_only.mkdir()
    read_only.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        ephemeral = auth_guard.load_or_create_hmac_secret(str(read_only))
        assert len(ephemeral) == 64 and ephemeral != LEGACY_CONSTANT_KEY
        assert not (read_only / ".pqc_auth_secret").exists()
    finally:
        read_only.chmod(stat.S_IRWXU)

    persisted_dir = tmp_path / "persisted"
    persisted_dir.mkdir()
    created = auth_guard.load_or_create_hmac_secret(str(persisted_dir))
    assert auth_guard.load_or_create_hmac_secret(str(persisted_dir)) == created
    assert stat.S_IMODE((persisted_dir / ".pqc_auth_secret").stat().st_mode) == 0o600

    monkeypatch.setenv("PQC_AUTH_SECRET", "x" * 40)
    assert auth_guard.load_or_create_hmac_secret(str(persisted_dir)) == b"x" * 40

    assert LEGACY_CONSTANT_KEY.decode() not in (REPO_ROOT / "pqc_agent" / "workspace_server.py").read_text(encoding="utf-8")
    monkeypatch.delenv("PQC_AUTH_SECRET")
    monkeypatch.setattr(ws, "_AUTH_SECRET_CACHE", None)
    monkeypatch.setattr(ws, "_get_data_dir", lambda: (_ for _ in ()).throw(OSError("read-only filesystem")))
    assert ws._get_auth_secret() not in (LEGACY_CONSTANT_KEY, b"")


def test_s6_tokens_are_typed_and_bound_to_the_secret(monkeypatch):
    from pqc_agent import auth_guard
    from pqc_agent import workspace_server as ws

    profile = {"email": ALICE, "name": "Alice", "region": "NorthAm"}
    token = ws.sign_tenant_session_token(profile)
    assert ws.verify_tenant_session_token(token)["email"] == ALICE
    assert ws.verify_tenant_session_token(token + "0") is None
    # An OAuth state value can never be replayed as a session token (typ claim).
    state = ws.sign_oauth_state({"mode": "3lo", "uid": ALICE, "email": ALICE, "nonce": "n"})
    assert ws.verify_tenant_session_token(state) is None
    # Legacy (untyped) tokens and tokens signed with another key are rejected.
    legacy = auth_guard.sign_payload({"uid": ALICE, "email": ALICE, "exp": int(time.time()) + 60}, ws._get_auth_secret())
    assert ws.verify_tenant_session_token(legacy) is None
    forged = auth_guard.sign_payload(
        {"uid": ALICE, "email": ALICE, "typ": ws.SESSION_TOKEN_TYPE, "exp": int(time.time()) + 60}, LEGACY_CONSTANT_KEY
    )
    assert ws.verify_tenant_session_token(forged) is None
    expired = auth_guard.sign_payload(
        {"uid": ALICE, "email": ALICE, "typ": ws.SESSION_TOKEN_TYPE, "exp": int(time.time()) - 1}, ws._get_auth_secret()
    )
    assert ws.verify_tenant_session_token(expired) is None


# ---------------------------------------------------------------------------------------------------------------
# S7 - OAuth access tokens are never persisted
# ---------------------------------------------------------------------------------------------------------------
def test_s7_access_tokens_live_in_memory_only(tmp_path, signin):
    from tools import gcloud_bridge as gb

    secret_token = "ya29.super-secret-delegated-token-123456"
    state = gb.set_gcp_connection_config(mode="access_token", access_token=secret_token, user_id="carol@google.com")
    assert state["has_access_token"] is True and secret_token not in json.dumps(state)
    assert state["access_token_storage"] == "in_memory_only" and state["access_token_expires_at"]
    assert gb.get_gcp_connection_config(mask_token=False, user_id="carol@google.com")["access_token_preview"] == secret_token
    store = pathlib.Path(gb._get_user_connections_path()).read_text(encoding="utf-8")
    assert secret_token not in store
    assert '"access_token":' not in store  # no token field (the mode *value* "access_token" is fine)
    assert json.loads(store)["carol@google.com"]["mode"] == "access_token"

    gb._USER_ACCESS_TOKENS["dave@google.com"] = ("ya29.expired", time.time() - 1)
    assert gb.get_gcp_connection_config(user_id="dave@google.com")["has_access_token"] is False
    assert "dave@google.com" not in gb._USER_ACCESS_TOKENS

    with TestClient(_app(tmp_path)) as client:
        signin(client, ALICE, use_token_for_gcp_connection=True)
        assert gb.get_gcp_connection_config(user_id=ALICE)["has_access_token"] is True
        alice = {"X-PQC-User-Token": client.cookies.get("pqc_session_token")}
        consent = client.post("/api/auth/tool-consent", headers=alice, json={"access_token": "ya29.consented-token-999"})
        assert consent.status_code == 200 and consent.json()["token_storage"] == "in_memory_only"
        for path in pathlib.Path(os.environ["PQC_DATA_DIR"]).rglob("*"):
            if path.is_file():
                content = path.read_bytes()
                assert b"ya29." not in content and b"valid:" not in content, path
        client.post("/api/auth/logout", headers=alice)
        assert gb.get_gcp_connection_config(user_id=ALICE)["has_access_token"] is False


def test_s7_legacy_plaintext_tokens_are_purged_from_disk(monkeypatch):
    from tools import gcloud_bridge as gb

    store = pathlib.Path(gb._get_user_connections_path())
    store.write_text(json.dumps({"legacy@google.com": {"mode": "access_token", "access_token": "ya29.legacy-plaintext"}}))
    conn = gb.get_gcp_connection_config(user_id="legacy@google.com")
    assert conn["mode"] == "access_token" and conn["has_access_token"] is False
    assert "ya29.legacy-plaintext" not in store.read_text(encoding="utf-8")


def test_s7_session_state_never_returns_credentials():
    from pqc_agent import workspace_server as ws

    state = {
        "title": "t",
        ws.GCP_OAUTH_CREDENTIAL_KEY: {"oauth2": {"access_token": "ya29.x"}},
        f"auth_{ws.GCP_OAUTH_CREDENTIAL_KEY}": {},
        "temp:access_token": "ya29.y",
        "client_secret": "s",
    }
    assert ws._redact_session_state(state) == {"title": "t"}


# ---------------------------------------------------------------------------------------------------------------
# S8 - CORS
# ---------------------------------------------------------------------------------------------------------------
def test_s8_no_cross_origin_access_by_default(tmp_path, signin):
    from pqc_agent import auth_guard

    with TestClient(_app(tmp_path)) as client:
        alice = _hdr(signin(client, ALICE))
        evil = "https://evil.example.com"
        preflight = client.options(
            "/api/sessions", headers={"Origin": evil, "Access-Control-Request-Method": "GET"}
        )
        assert "access-control-allow-origin" not in {k.lower() for k in preflight.headers}
        cross = client.get("/api/sessions", headers={**alice, "Origin": evil})
        assert cross.status_code == 403 and "access-control-allow-origin" not in {k.lower() for k in cross.headers}
        assert client.get("/api/sessions", headers={**alice, "Origin": "http://testserver"}).status_code == 200
    assert auth_guard.allowed_cors_origins() is None


def test_s8_explicit_allowlist_never_includes_wildcards(tmp_path, monkeypatch):
    monkeypatch.setenv("PQC_ALLOWED_ORIGINS", "https://portal.example.com, *, https://*.evil.com, ftp://x")
    app = _app(tmp_path)
    assert app.state.cors_allowed_origins == ["https://portal.example.com"]
    with TestClient(app) as client:
        ok = client.options(
            "/api/health", headers={"Origin": "https://portal.example.com", "Access-Control-Request-Method": "GET"}
        )
        assert ok.headers.get("access-control-allow-origin") == "https://portal.example.com"
        bad = client.options(
            "/api/health", headers={"Origin": "https://evil.example.com", "Access-Control-Request-Method": "GET"}
        )
        assert bad.headers.get("access-control-allow-origin") is None


# ---------------------------------------------------------------------------------------------------------------
# Gemini Pro only
# ---------------------------------------------------------------------------------------------------------------
def test_model_catalog_is_gemini_pro_only(monkeypatch):
    from pqc_agent.model_registry import GEMINI_MODEL_CANDIDATES, ModelRegistry, is_gemini_pro_model

    assert [c["model"] for c in GEMINI_MODEL_CANDIDATES] == [
        "gemini-3.1-pro-preview-customtools",
        "gemini-3.1-pro-preview",
        "gemini-3-pro-preview",
        "gemini-2.5-pro",
    ]
    monkeypatch.setenv("PQC_GEMINI_MODEL_CANDIDATES", "gemini-2.5-flash,gemini-3-flash-preview,gemini-2.5-flash-lite")
    registry = ModelRegistry(probe=lambda m, l: (False, {"error": "offline"}))
    assert all(is_gemini_pro_model(c["model"]) for c in registry.candidates)
    assert len(registry.candidates) == 4
    for model in ("gemini-2.5-flash", "gemini-3.1-flash-lite-preview", "claude-opus", "gemini-pro-vision"):
        assert is_gemini_pro_model(model) is False, model
    for folder in ("pqc_agent", "tools"):
        for path in (REPO_ROOT / folder).glob("*.py"):
            assert "flash" not in path.read_text(encoding="utf-8").lower(), path


# ---------------------------------------------------------------------------------------------------------------
# Other routes reviewed during the audit
# ---------------------------------------------------------------------------------------------------------------
def test_oauth_client_config_and_tenant_directory_are_restricted(tmp_path, monkeypatch, signin):
    with TestClient(_app(tmp_path)) as client:
        alice, bob = _hdr(signin(client, ALICE)), _hdr(signin(client, BOB))
        monkeypatch.setenv("K_SERVICE", "pqc-inventory-agent")  # Cloud Run: no implicit administrators
        assert client.post("/api/auth/oauth/config", headers=alice, json={"client_id": "evil"}).status_code == 403
        directory = client.get("/api/auth/tenants", headers=alice).json()
        assert directory["full_directory"] is False
        assert [t["user_id"] for t in directory["tenants"]] == [ALICE] and directory["total_tenants"] == 2
        monkeypatch.setenv("PQC_ADMIN_EMAILS", ALICE)
        assert client.post("/api/auth/oauth/config", headers=bob, json={"client_id": "evil"}).status_code == 403
        assert client.post("/api/auth/oauth/config", headers=alice, json={"client_id": "good-client"}).status_code == 200
        assert client.get("/api/auth/tenants", headers=alice).json()["full_directory"] is True
        assert client.get("/api/auth/oauth/config").json()["client_id"] == "good-client"


def test_oauth_state_is_signed_single_use_and_browser_bound(tmp_path, monkeypatch, signin):
    import base64

    from pqc_agent import workspace_server as ws

    monkeypatch.setattr(ws, "_exchange_oauth_code", lambda code, redirect_uri: ({"access_token": f"ya29.from-{code}", "expires_in": 3599}, None))
    with TestClient(_app(tmp_path)) as client:
        alice = _hdr(signin(client, ALICE))
        monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "portal-client.apps.googleusercontent.com")
        monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "test-secret")
        unsigned = base64.urlsafe_b64encode(json.dumps({"uid": BOB, "nonce": "n"}).encode()).decode().rstrip("=")
        assert client.get("/api/auth/oauth/callback", params={"code": "c", "state": unsigned}).status_code == 400
        assert client.get("/api/auth/oauth/callback", params={"code": "c", "state": "a.b"}).status_code == 400

        authz = client.get("/api/auth/oauth/authorize", headers=alice, params={"format": "json"}).json()
        assert "state=" in authz["google_auth_url"] and "access_type=online" in authz["google_auth_url"]
        nonce_cookie = client.cookies.get("pqc_oauth_nonce")
        assert nonce_cookie
        client.cookies.delete("pqc_oauth_nonce")
        assert client.get("/api/auth/oauth/callback", params={"code": "c1", "state": authz["state"]}).status_code == 400
        client.cookies.set("pqc_oauth_nonce", nonce_cookie, path="/api/auth")
        done = client.get("/api/auth/oauth/callback", params={"code": "c2", "state": authz["state"]})
        assert done.status_code == 200 and "ya29.from-c2" not in done.text and "PQC_OAUTH_3LO_AUTHORIZED" in done.text
        from tools import gcloud_bridge as gb

        assert gb.get_gcp_connection_config(mask_token=False, user_id=ALICE)["access_token_preview"] == "ya29.from-c2"
        client.cookies.set("pqc_oauth_nonce", nonce_cookie, path="/api/auth")
        assert client.get("/api/auth/oauth/callback", params={"code": "c3", "state": authz["state"]}).status_code == 400


def test_google_oauth_signin_popup_flow(tmp_path, monkeypatch, google_verifier):
    with TestClient(_app(tmp_path)) as client:
        assert client.get("/api/auth/oauth/signin", follow_redirects=False).status_code == 404
        monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "portal-client.apps.googleusercontent.com")
        assert client.get("/api/auth/config").json()["google_oauth_client_configured"] is True
        start = client.get("/api/auth/oauth/signin", params={"region": "EMEA"}, follow_redirects=False)
        assert start.status_code == 302 and start.headers["location"].startswith("https://accounts.google.com/")
        assert "response_type=token" in start.headers["location"]
        from urllib.parse import parse_qs, urlparse

        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        signed_in = client.post("/api/auth/google", json={"google_access_token": f"valid:{ALICE}", "oauth_state": state})
        assert signed_in.status_code == 200 and signed_in.json()["user_id"] == ALICE
        replay = client.post("/api/auth/google", json={"google_access_token": f"valid:{ALICE}", "oauth_state": state})
        assert replay.status_code == 400
        page = client.get("/api/auth/oauth/callback")  # implicit flow landing page (token is in the URL fragment)
        assert page.status_code == 200 and "/api/auth/google" in page.text and "oauth_state" in page.text


def test_oauth_popup_escapes_reflected_values(tmp_path, signin):
    payload = "</b><script>alert(document.cookie)</script>"
    with TestClient(_app(tmp_path)) as client:
        alice = _hdr(signin(client, ALICE))
        page = client.get("/api/auth/oauth/authorize", headers=alice, params={"scope": payload, "session_id": payload}).text
        assert "<script>alert(document.cookie)</script>" not in page
        assert "&lt;script&gt;alert(document.cookie)&lt;/script&gt;" in page
        assert "\\u003cscript\\u003e" in page


def test_portal_ui_sign_in_dialog_follows_the_new_rules(tmp_path):
    with TestClient(_app(tmp_path)) as client:
        html = client.get("/").text
        assert "X-PQC-User-Id" not in html
        assert "user_id=${encodeURIComponent(currentUserId)}" not in html
        for snippet in (
            "/api/auth/config",
            "gcloud auth print-access-token",
            "startGoogleOAuthSignIn",
            "handleUnauthorizedResponse",
            "response.status === 401",
            "PQC_SIGNIN_COMPLETE",
        ):
            assert snippet in html, snippet
