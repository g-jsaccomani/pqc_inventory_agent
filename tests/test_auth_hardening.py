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
    """Fresh data dir + isolated SQLite DB + clean auth/KMS env for every unit test."""
    from pqc_agent import auth_store
    from pqc_agent import workspace_server as ws

    auth_store.clear_fallback_auth_stores()
    monkeypatch.setenv("PQC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SESSION_DB_URL", f"sqlite:///{tmp_path / 'sessions.db'}")
    monkeypatch.setenv("PQC_AUTH_SECRET", "test-only-256-bit-hmac-secret-key-0123456789abcdef")
    for name in (
        "K_SERVICE",
        "PQC_PRODUCTION_MODE",
        "PQC_ENV",
        "DATABASE_URL",
        "PQC_CLOUD_SQL_CONNECTION_NAME",
        "PQC_DB_HOST",
        "PQC_KMS_KEY_NAME",
        "PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS",
        "PQC_ALLOW_UNVERIFIED_SIGNIN",
        "PQC_ENABLE_ADK_API",
        "PQC_ENABLE_ADK_DEV_UI",
        "PQC_ENABLE_GIS_JAVASCRIPT_CLIENT",
        "PQC_ALLOWED_ORIGINS",
        "PQC_OAUTH_REDIRECT_URIS",
        "PQC_OAUTH_STATE_TTL_SECONDS",
        "PQC_IAP_AUDIENCE",
        "PQC_REQUIRE_IAP_AUDIENCE",
        "PQC_AUTH_SECRET_FILE",
        "PQC_AUTH_SECRET_PREVIOUS",
        "PQC_ADMIN_EMAILS",
        "PQC_GOOGLE_ID_TOKEN_AUDIENCES",
        "PQC_GOOGLE_OAUTH_CLIENT_ID",
        "PQC_GOOGLE_OAUTH_CLIENT_SECRET",
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(ws, "_AUTH_SECRET_CACHE", None)
    monkeypatch.setattr(ws, "_AUTH_SECRET_CACHE_KEY", None)
    yield
    auth_store.clear_fallback_auth_stores()


def _registry():
    from pqc_agent.model_registry import ModelRegistry

    return ModelRegistry(
        candidates=[{"model": "fake-ok-model", "label": "Fake OK", "thinking_levels": [None]}],
        probe=lambda model, level: (True, {"model_version": f"{model}-001"}),
        default_model="fake-ok-model",
        default_thinking_level="",
    )


def _allow_unit_test_db_when_no_live_pg(monkeypatch):
    """Allows route/cookie unit tests that toggle K_SERVICE to use tmp_path SQLite when PQC_TEST_POSTGRES_URL is unset."""
    if os.getenv("PQC_TEST_POSTGRES_URL"):
        return
    from pqc_agent import auth_store

    monkeypatch.setattr(auth_store, "validate_production_postgres_only", lambda _url: None)


def _app(tmp_path):
    from pqc_agent.migration_tool import run_alembic_upgrade_head
    from pqc_agent.workspace_server import create_workspace_app

    db_url = os.getenv("PQC_TEST_POSTGRES_URL") or f"sqlite:///{tmp_path / 'sessions.db'}"
    if os.getenv("K_SERVICE"):
        run_alembic_upgrade_head(db_url)
    bucket = "gs://test-unit-bucket" if os.getenv("K_SERVICE") else None
    return create_workspace_app(
        session_db_url=db_url,
        artifact_bucket=bucket,
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
        # The verified email wins over any email the client claims, and no session token appears in JSON.
        resp = client.post("/api/auth/google", json={"google_access_token": f"valid:{ALICE}", "email": BOB})
        assert resp.status_code == 200
        body = resp.json()
        assert body["user_id"] == ALICE and "token" not in body and resp.cookies.get("pqc_session_token")
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
    _allow_unit_test_db_when_no_live_pg(monkeypatch)
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
    _allow_unit_test_db_when_no_live_pg(monkeypatch)
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
    from pqc_agent import auth_guard, auth_store
    from pqc_agent import workspace_server as ws

    profile = {"email": ALICE, "name": "Alice", "region": "NorthAm"}
    token = ws.sign_tenant_session_token(profile)
    assert ws.verify_tenant_session_token(token)["email"] == ALICE
    assert ws.verify_tenant_session_token(token + "0") is None
    # An opaque OAuth state_id and any differently typed signed payload can never be replayed as a session token.
    tx = auth_store.get_active_auth_store().create_oauth_transaction(
        flow_mode="3lo", redirect_uri="http://testserver/api/auth/oauth/callback", initiating_user_id=ALICE
    )
    assert ws.verify_tenant_session_token(tx.state_id) is None
    other_typed = auth_guard.sign_payload(
        {"uid": ALICE, "email": ALICE, "typ": "account_jar_v2", "exp": int(time.time()) + 60}, ws._get_auth_secret()
    )
    assert ws.verify_tenant_session_token(other_typed) is None
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
# S7 - Delegated OAuth credentials are envelope-encrypted in DB and never stored in plaintext
# ---------------------------------------------------------------------------------------------------------------
def test_s7_access_tokens_are_envelope_encrypted_and_never_stored_in_plaintext(tmp_path, signin):
    from sqlalchemy import select
    from pqc_agent import auth_store, credential_service
    from tools import gcloud_bridge as gb

    secret_token = "ya29.super-secret-delegated-token-123456"
    state = gb.set_gcp_connection_config(mode="access_token", access_token=secret_token, user_id="carol@google.com")
    assert state["has_access_token"] is True and secret_token not in json.dumps(state)
    assert state["access_token_storage"] == "encrypted_db_envelope" and state["access_token_expires_at"]
    assert gb.get_gcp_connection_config(mask_token=False, user_id="carol@google.com")["access_token_preview"] == secret_token

    # Inspect raw database rows: neither pqc_user_connections nor pqc_delegated_credentials contains plaintext token!
    store = auth_store.get_active_auth_store()
    with store._session_factory() as db:
        conn_row = db.get(auth_store.UserConnectionRecord, "carol@google.com")
        assert conn_row is not None and conn_row.mode == "access_token"
        cred_rows = db.scalars(
            select(auth_store.DelegatedCredentialRecord).where(
                auth_store.DelegatedCredentialRecord.user_id == "carol@google.com"
            )
        ).all()
        assert len(cred_rows) == 1
        assert secret_token not in cred_rows[0].ciphertext_b64
        assert secret_token not in cred_rows[0].wrapped_dek_b64

    # Expired credential fails closed and is automatically revoked/wiped on load
    svc = credential_service.get_active_credential_service()
    svc.store_delegated_token(user_id="dave@google.com", access_token="ya29.expired", expires_in=10.0)
    assert svc.load_delegated_token(user_id="dave@google.com", now_override=time.time() + 60.0) is None
    assert gb.get_gcp_connection_config(user_id="dave@google.com")["has_access_token"] is False

    with TestClient(_app(tmp_path)) as client:
        signin(client, ALICE, use_token_for_gcp_connection=True)
        assert gb.get_gcp_connection_config(user_id=ALICE)["has_access_token"] is True
        alice = {"X-PQC-User-Token": client.cookies.get("pqc_session_token")}
        consent = client.post("/api/auth/tool-consent", headers=alice, json={"access_token": "ya29.consented-token-999"})
        assert consent.status_code == 200 and consent.json()["token_storage"] == "encrypted_db_envelope"
        for path in pathlib.Path(os.environ["PQC_DATA_DIR"]).rglob("*"):
            if path.is_file():
                content = path.read_bytes()
                assert b"ya29." not in content and b"valid:" not in content, path
        db_bytes = (tmp_path / "sessions.db").read_bytes()
        assert b"ya29.consented-token-999" not in db_bytes
        client.post("/api/auth/logout", headers=alice)
        assert gb.get_gcp_connection_config(user_id=ALICE)["has_access_token"] is False


def test_s7_legacy_plaintext_tokens_are_stripped_during_migration(tmp_path):
    from pqc_agent.migration_tool import migrate_legacy_persistence

    legacy_dir = tmp_path / "legacy_data"
    legacy_dir.mkdir()
    legacy_file = legacy_dir / "pqc_user_connections.json"
    legacy_file.write_text(
        json.dumps({"legacy@google.com": {"mode": "access_token", "access_token": "ya29.legacy-plaintext"}}),
        encoding="utf-8",
    )
    target_db = f"sqlite:///{tmp_path / 'migrated.db'}"
    report = migrate_legacy_persistence(target_db_url=target_db, source_data_dir=str(legacy_dir))
    assert report.status == "SUCCESS"
    assert any(a["code"] == "LEGACY_PLAINTEXT_TOKEN_STRIPPED" for a in report.anomalies)
    assert b"ya29.legacy-plaintext" not in (tmp_path / "migrated.db").read_bytes()


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
    from urllib.parse import parse_qs, urlparse

    from pqc_agent import workspace_server as ws

    exchanged = []

    def fake_exchange(code, redirect_uri, code_verifier=None):
        exchanged.append((code, redirect_uri, code_verifier or ws._ACTIVE_PKCE_VERIFIER.get()))
        return {"access_token": "ya29.public-pkce", "id_token": f"valid:{ALICE}", "expires_in": 3599}, None

    monkeypatch.setattr(ws, "_exchange_oauth_code", fake_exchange)
    with TestClient(_app(tmp_path)) as client:
        assert client.get("/api/auth/oauth/signin", follow_redirects=False).status_code == 404
        # Public OAuth client (client_id ONLY, no client_secret) MUST use Authorization Code + PKCE (never response_type=token)
        monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "portal-client.apps.googleusercontent.com")
        assert client.get("/api/auth/config").json()["google_oauth_client_configured"] is True
        start = client.get("/api/auth/oauth/signin", params={"region": "EMEA"}, follow_redirects=False)
        assert start.status_code == 302 and start.headers["location"].startswith("https://accounts.google.com/")
        assert "response_type=code" in start.headers["location"]
        assert "response_type=token" not in start.headers["location"]
        assert "code_challenge_method=S256" in start.headers["location"]

        qs = parse_qs(urlparse(start.headers["location"]).query)
        state = qs["state"][0]
        assert "." not in state  # opaque server-side state, never signed JSON

        # Legacy implicit flow parameters are explicitly rejected
        assert client.post("/api/auth/google", json={"google_access_token": f"valid:{ALICE}", "oauth_state": state}).status_code == 400
        assert client.get("/api/auth/oauth/callback").status_code == 400
        assert client.get("/api/auth/oauth/callback", params={"access_token": "ya29.x", "state": state}).status_code == 400

        # Valid Authorization Code + PKCE callback signs Alice in and sets HttpOnly cookie
        cb_ok = client.get("/api/auth/oauth/callback", params={"code": "pub-code-1", "state": state})
        assert cb_ok.status_code == 200 and "PQC_SIGNIN_COMPLETE" in cb_ok.text
        assert exchanged and exchanged[-1][2]  # PKCE code_verifier supplied from server-side transaction
        assert client.get("/api/auth/me").json()["user_id"] == ALICE
        # Replaying the consumed state fails closed
        assert client.get("/api/auth/oauth/callback", params={"code": "pub-code-2", "state": state}).status_code == 400


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
            "/api/auth/auto",
            "/api/auth/switch",
            "gcloud auth print-access-token",
            "startGoogleOAuthSignIn",
            "handleUnauthorizedResponse",
            "response.status === 401",
            "PQC_SIGNIN_COMPLETE",
            "Gerenciado por google.com",
            "gemini-account-popover",
            "Adicionar outra conta",
            "Desconectado",
            "Fazer login",
            "Remover",
        ):
            assert snippet in html, snippet


def test_auto_signin_account_switcher_and_partitioned_tenant_storage(tmp_path, monkeypatch, google_verifier):
    from pqc_agent import workspace_server as ws

    with TestClient(_app(tmp_path)) as client:
        # 1. When no workstation token is present and no cookie is set, /api/auth/auto returns authenticated=False
        r0 = client.post("/api/auth/auto")
        assert r0.status_code == 200 and r0.json()["authenticated"] is False

        # 2. When workstation auto-gcloud token is present, /api/auth/auto logs in automatically (cookie only, no JSON token)
        monkeypatch.setattr(ws, "_try_workstation_auto_gcloud_token", lambda: f"valid:{ALICE}")
        r_auto = client.post("/api/auth/auto", headers={"X-PQC-User-Region": "NorthAm"})
        assert r_auto.status_code == 200
        auto_data = r_auto.json()
        assert auto_data["authenticated"] is True
        assert auto_data["user_id"] == ALICE
        assert "token" not in auto_data
        alice_token = r_auto.cookies.get("pqc_session_token")
        assert alice_token

        # 3. Sign in Bob (EMEA) and verify both Alice and Bob have isolated partitioned directories on disk
        r_bob = client.post(
            "/api/auth/google",
            json={"google_access_token": f"valid:{BOB}", "region": "EMEA"},
        )
        assert r_bob.status_code == 200
        assert "token" not in r_bob.json()
        bob_token = r_bob.cookies.get("pqc_session_token")
        bob_csrf = r_bob.json()["csrf_token"]
        assert bob_token

        # Create a session for Bob and update Bob's connection
        bob_sess = client.post("/api/sessions", headers=_hdr(bob_token), json={"title": "EMEA Banking PQC"}).json()
        client.post(
            "/api/connection",
            headers=_hdr(bob_token),
            json={"mode": "impersonation", "organization_id": "222222222", "impersonated_service_account": "emea@p.iam.gserviceaccount.com"},
        )

        # Verify authoritative records live in transactional DB tables and zero JSON dual-writes occur on disk
        from pqc_agent import auth_store

        store = auth_store.get_active_auth_store()
        assert store.get_tenant_user(BOB)["region"] == "EMEA"
        assert store.get_tenant_user(ALICE)["region"] == "NorthAm"
        assert store.get_user_connection(BOB)["organization_id"] == "222222222"
        assert store.get_session_metadata(bob_sess["session_id"], user_id=BOB)["title"] == "EMEA Banking PQC"
        assert store.get_session_metadata(bob_sess["session_id"], user_id=ALICE) is None
        assert not (tmp_path / "data" / "tenants").exists()

        # 4. Passing bearer tokens in JSON to /api/auth/switch is rejected; switching uses HttpOnly pqc_account_jar + CSRF
        assert client.post("/api/auth/switch", json={"token": alice_token, "region": "LATAM"}).status_code == 400
        r_switch = client.post(
            "/api/auth/switch",
            headers={"X-PQC-CSRF-Token": bob_csrf},
            json={"email": ALICE, "region": "LATAM"},
        )
        assert r_switch.status_code == 200
        sw_data = r_switch.json()
        assert "token" not in sw_data
        assert sw_data["authenticated"] is True
        assert sw_data["user_id"] == ALICE
        assert sw_data["user"]["region"] == "LATAM"
        assert sw_data["connection"]["organization_id"] == "31564119954"


# ---------------------------------------------------------------------------------------------------------------
# Phase 1 - OAuth popup postMessage, PKCE, localStorage removal, CSRF, fixation, logout, fail-closed secrets & IAP
# ---------------------------------------------------------------------------------------------------------------
def test_phase1_no_wildcard_postmessage_and_popup_origin_source_and_credential_stripping(tmp_path, signin):
    from pqc_agent import workspace_server as ws

    # 1. No wildcard postMessage anywhere in server or UI source
    for rel in ("pqc_agent/workspace_server.py", "pqc_agent/portal_ui.py"):
        src = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "postMessage(msg, '*')" not in src
        assert 'postMessage(msg, "*")' not in src

    # 2. Popup result sanitizer strips all credentials and session tokens
    sanitized = ws._sanitize_popup_postmessage_payload(
        {
            "authenticated": True,
            "user_id": ALICE,
            "token": "secret-session-token",
            "csrf_token": "secret-csrf",
            "access_token": "ya29.secret",
            "id_token": "eyJ.secret",
            "refresh_token": "1//secret",
            "credential": "eyJ.cred",
            "code": "4/code",
            "nested": {"token": "nested-secret", "ok": True},
        }
    )
    assert sanitized == {"authenticated": True, "user_id": ALICE, "nested": {"ok": True}}
    html_popup = ws._oauth_popup_result_html("PQC_SIGNIN_COMPLETE", {"authenticated": True, "token": "secret-tok"}, "ok", True)
    assert "secret-tok" not in html_popup

    with TestClient(_app(tmp_path)) as client:
        # 3. /api/auth/bridge rejects untrusted and wildcard origins, accepts same-origin, and never uses '*'
        assert client.get("/api/auth/bridge", params={"origin": "https://evil.example.com"}).status_code == 400
        assert client.get("/api/auth/bridge", params={"origin": "*"}).status_code == 400
        ok_bridge = client.get("/api/auth/bridge", params={"origin": "http://testserver"})
        assert ok_bridge.status_code == 200
        assert "postMessage(msg, '*')" not in ok_bridge.text
        assert "PQC_SIGNIN_COMPLETE" in ok_bridge.text

        # 4. Portal UI message listener validates exact origin, expected WindowProxy source, and rejects credential payloads
        portal_html = client.get("/").text
        assert "event.origin !== window.location.origin" in portal_html
        assert "!activeAuthPopupWindow || event.source !== activeAuthPopupWindow" in portal_html
        assert "hasForbiddenPopupCredentialFields" in portal_html
        assert "activeAuthPopupWindow = null;" in portal_html


def test_phase1_oauth_pkce_oidc_nonce_expiry_and_redirect_uri_mismatch(tmp_path, monkeypatch):
    import io
    from urllib.parse import parse_qs, urlparse

    from pqc_agent import auth_guard
    from pqc_agent import auth_store as as_mod
    from pqc_agent import workspace_server as ws

    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "portal-client.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "portal-client-secret")

    exchanged_requests = []

    class _FakeResp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url == "https://oauth2.googleapis.com/token":
            body_params = parse_qs((req.data or b"").decode("utf-8"))
            exchanged_requests.append(body_params)
            return _FakeResp(
                json.dumps({"access_token": "ya29.pkce-verified", "id_token": "jwt-from-code", "expires_in": 3599}).encode("utf-8")
            )
        if "id_token=" in url:
            return _FakeResp(
                json.dumps(
                    {
                        "iss": "https://accounts.google.com",
                        "aud": "portal-client.apps.googleusercontent.com",
                        "email": ALICE,
                        "email_verified": "true",
                        "exp": str(int(time.time()) + fake_urlopen.exp_offset),
                        "nonce": fake_urlopen.expected_nonce,
                    }
                ).encode("utf-8")
            )
        raise AssertionError(f"Unexpected URL: {url}")

    fake_urlopen.expected_nonce = ""
    fake_urlopen.exp_offset = 600
    monkeypatch.setattr(ws.urllib.request, "urlopen", fake_urlopen)

    app_inst = _app(tmp_path)
    with TestClient(app_inst) as client:
        # 1. Open redirect / redirect_uri mismatch is rejected on signin and authorize
        assert (
            client.get("/api/auth/oauth/signin", params={"redirect_uri": "https://evil.example.com/cb"}, follow_redirects=False).status_code
            == 400
        )
        alice_hdr = _hdr(ws.sign_tenant_session_token({"email": ALICE, "region": "NorthAm"}))
        assert (
            client.get(
                "/api/auth/oauth/authorize",
                headers=alice_hdr,
                params={"redirect_uri": "https://evil.example.com/cb", "format": "json"},
            ).status_code
            == 400
        )

        # 2. /api/auth/oauth/signin uses an opaque random state and stores PKCE S256 verifier ONLY server-side in DB
        start = client.get("/api/auth/oauth/signin", params={"region": "NorthAm"}, follow_redirects=False)
        assert start.status_code == 302
        qs = parse_qs(urlparse(start.headers["location"]).query)
        assert qs["response_type"] == ["code"]
        assert qs["code_challenge_method"] == ["S256"]
        state = qs["state"][0]
        assert "." not in state
        with app_inst.state.auth_store._session_factory() as db:
            tx_row = db.get(as_mod.OAuthTransactionRecord, state)
            assert tx_row is not None
            assert tx_row.code_verifier not in state
            assert auth_guard.compute_pkce_challenge(tx_row.code_verifier) == qs["code_challenge"][0]
            assert tx_row.oidc_nonce == qs["nonce"][0]

        # Mismatched redirect_uri on callback is rejected without consuming or exchanging code
        bad_redir = client.get(
            "/api/auth/oauth/callback",
            params={"code": "auth-code-1", "state": state, "redirect_uri": "https://evil.example.com/cb"},
        )
        assert bad_redir.status_code == 400

        # Issue a fresh signin state and test valid PKCE + OIDC nonce verification
        start2 = client.get("/api/auth/oauth/signin", params={"region": "EMEA"}, follow_redirects=False)
        qs2 = parse_qs(urlparse(start2.headers["location"]).query)
        state2 = qs2["state"][0]
        with app_inst.state.auth_store._session_factory() as db:
            tx_row2 = db.get(as_mod.OAuthTransactionRecord, state2)
            expected_verifier2 = tx_row2.code_verifier
            fake_urlopen.expected_nonce = tx_row2.oidc_nonce

        cb_ok = client.get("/api/auth/oauth/callback", params={"code": "auth-code-2", "state": state2})
        assert cb_ok.status_code == 200
        assert exchanged_requests and exchanged_requests[-1]["code_verifier"] == [expected_verifier2]
        assert exchanged_requests[-1]["client_secret"] == ["portal-client-secret"]
        # Popup HTML must NOT contain the session token or OAuth tokens
        assert "ya29.pkce-verified" not in cb_ok.text
        assert "jwt-from-code" not in cb_ok.text
        assert '"token"' not in cb_ok.text

        # 3. Wrong OIDC nonce and expired ID token are rejected
        start3 = client.get("/api/auth/oauth/signin", follow_redirects=False)
        state3 = parse_qs(urlparse(start3.headers["location"]).query)["state"][0]
        fake_urlopen.expected_nonce = "wrong-oidc-nonce"
        cb_bad_nonce = client.get("/api/auth/oauth/callback", params={"code": "auth-code-3", "state": state3})
        assert cb_bad_nonce.status_code == 401

        start4 = client.get("/api/auth/oauth/signin", follow_redirects=False)
        state4 = parse_qs(urlparse(start4.headers["location"]).query)["state"][0]
        with app_inst.state.auth_store._session_factory() as db:
            fake_urlopen.expected_nonce = db.get(as_mod.OAuthTransactionRecord, state4).oidc_nonce
        fake_urlopen.exp_offset = -600
        cb_expired = client.get("/api/auth/oauth/callback", params={"code": "auth-code-4", "state": state4})
        assert cb_expired.status_code == 401


def test_phase1_no_localstorage_session_token_exposure_and_cookie_flags(tmp_path, monkeypatch, google_verifier):
    # 1. Verify no localStorage session token read/write in portal_ui.py or workspace_server.py
    portal_src = (REPO_ROOT / "pqc_agent" / "portal_ui.py").read_text(encoding="utf-8")
    server_src = (REPO_ROOT / "pqc_agent" / "workspace_server.py").read_text(encoding="utf-8")
    assert 'localStorage.getItem("pqc_session_token")' not in portal_src
    assert 'localStorage.setItem("pqc_session_token"' not in portal_src
    assert "localStorage.getItem('pqc_session_token')" not in server_src
    assert "localStorage.setItem('pqc_session_token'" not in server_src

    # 2. Verify Secure, HttpOnly, SameSite=lax cookies on HTTPS / production requests
    monkeypatch.setenv("K_SERVICE", "pqc-inventory-agent")
    _allow_unit_test_db_when_no_live_pg(monkeypatch)
    with TestClient(_app(tmp_path)) as client:
        resp = client.post(
            "/api/auth/google",
            headers={"X-Forwarded-Proto": "https"},
            json={"google_access_token": f"valid:{ALICE}"},
        )
        assert resp.status_code == 200
        assert "token" not in resp.json()
        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]
        joined = " ; ".join(set_cookies).lower()
        assert "pqc_session_token=" in joined
        assert "httponly" in joined
        assert "samesite=lax" in joined
        assert "secure" in joined
        assert "pqc_csrf_token=" in joined
        assert "pqc_account_jar=" in joined


def test_phase1_csrf_protection_session_fixation_rotation_and_logout_revocation(tmp_path, google_verifier):
    from pqc_agent import workspace_server as ws

    with TestClient(_app(tmp_path)) as client:
        # 1. Plant a pre-existing session cookie (fixation attempt) before signing in
        planted_token = ws.sign_tenant_session_token({"email": BOB, "name": "Bob", "region": "NorthAm"})
        client.cookies.set("pqc_session_token", planted_token)

        login_resp = client.post(
            "/api/auth/google",
            headers={"X-PQC-Rotate-Session": "1"},
            json={"google_access_token": f"valid:{ALICE}"},
        )
        assert login_resp.status_code == 200
        alice_data = login_resp.json()
        assert "token" not in alice_data
        alice_token = login_resp.cookies.get("pqc_session_token")
        csrf_token = alice_data["csrf_token"]
        assert alice_token and alice_token != planted_token
        # The pre-planted token was revoked during login rotation
        assert ws.verify_tenant_session_token(planted_token) is None

        # 2. Cookie-authenticated state-changing requests WITHOUT X-PQC-CSRF-Token are rejected with 403
        assert client.post("/api/sessions", json={"title": "CSRF attempt"}).status_code == 403
        assert client.post("/api/connection", json={"mode": "adc"}).status_code == 403
        assert client.post("/api/gcloud", json={"command": "gcloud version"}).status_code == 403
        assert client.post("/api/auth/logout").status_code == 403

        # 3. Cross-origin or Sec-Fetch-Site: cross-site requests are rejected even if X-PQC-CSRF-Token is present
        assert (
            client.post(
                "/api/sessions",
                headers={"X-PQC-CSRF-Token": csrf_token, "Origin": "https://evil.example.com"},
                json={"title": "Cross-origin"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/sessions",
                headers={"X-PQC-CSRF-Token": csrf_token, "Sec-Fetch-Site": "cross-site"},
                json={"title": "Cross-site fetch"},
            ).status_code
            == 403
        )

        # 4. Same-origin cookie-authenticated request WITH valid X-PQC-CSRF-Token succeeds
        ok_sess = client.post(
            "/api/sessions",
            headers={"X-PQC-CSRF-Token": csrf_token, "Origin": "http://testserver"},
            json={"title": "Legitimate Session"},
        )
        assert ok_sess.status_code == 200

        # 5. Logout revokes the session token server-side (cannot be reused via cookie OR X-PQC-User-Token header)
        logout_resp = client.post("/api/auth/logout", headers={"X-PQC-CSRF-Token": csrf_token})
        assert logout_resp.status_code == 200
        assert ws.verify_tenant_session_token(alice_token) is None
        assert client.get("/api/sessions", headers={"X-PQC-User-Token": alice_token}).status_code == 401
        client.cookies.set("pqc_session_token", alice_token)
        assert client.get("/api/sessions").status_code == 401


def test_phase1_production_fail_closed_hmac_secret_rotation_and_iap_audience_enforcement(tmp_path, monkeypatch):
    from pqc_agent import auth_guard
    from pqc_agent import workspace_server as ws
    from pqc_agent.migration_tool import run_alembic_upgrade_head

    run_alembic_upgrade_head(os.environ["SESSION_DB_URL"])

    # 1. Production fails closed when PQC_AUTH_SECRET is missing or too short (< 32 chars)
    monkeypatch.setenv("K_SERVICE", "pqc-inventory-agent")
    _allow_unit_test_db_when_no_live_pg(monkeypatch)
    monkeypatch.delenv("PQC_AUTH_SECRET", raising=False)
    monkeypatch.setattr(ws, "_AUTH_SECRET_CACHE", None)
    with pytest.raises(RuntimeError, match="PQC_AUTH_SECRET"):
        auth_guard.load_or_create_hmac_secret(str(tmp_path))
    with pytest.raises(RuntimeError, match="PQC_AUTH_SECRET"):
        ws._get_auth_secret()

    monkeypatch.setenv("PQC_AUTH_SECRET", "short-secret")
    monkeypatch.setattr(ws, "_AUTH_SECRET_CACHE", None)
    with pytest.raises(RuntimeError, match="32 characters"):
        auth_guard.load_or_create_hmac_secret(str(tmp_path))

    # 2. Key rotation via PQC_AUTH_SECRET_PREVIOUS validates tokens signed with the previous secret
    old_secret = "old-256-bit-hmac-secret-key-for-rotation-0123456789"
    new_secret = "new-256-bit-hmac-secret-key-for-rotation-9876543210"
    monkeypatch.setenv("PQC_AUTH_SECRET", old_secret)
    monkeypatch.setattr(ws, "_AUTH_SECRET_CACHE", None)
    old_token = ws.sign_tenant_session_token({"email": ALICE, "name": "Alice", "region": "NorthAm"})

    monkeypatch.setenv("PQC_AUTH_SECRET", new_secret)
    monkeypatch.setenv("PQC_AUTH_SECRET_PREVIOUS", old_secret)
    monkeypatch.setattr(ws, "_AUTH_SECRET_CACHE", None)
    assert ws.verify_tenant_session_token(old_token)["email"] == ALICE

    # 3. Cloud IAP audience enforcement in production: missing or wrong audience is rejected
    claims = {
        "iss": auth_guard.IAP_ISSUER,
        "email": ALICE,
        "sub": "accounts.google.com:123",
        "aud": "/projects/110254026096/locations/us-central1/services/agentic-pqc",
        "exp": int(time.time()) + 600,
    }
    monkeypatch.setattr(auth_guard.google_id_token, "verify_token", lambda tok, req, audience=None, certs_url=None, **kw: dict(claims))

    # Missing PQC_IAP_AUDIENCE in production (K_SERVICE set) -> rejected (None)
    monkeypatch.delenv("PQC_IAP_AUDIENCE", raising=False)
    assert auth_guard.verify_iap_jwt("iap-jwt") is None

    # Wrong PQC_IAP_AUDIENCE -> rejected (None)
    monkeypatch.setenv("PQC_IAP_AUDIENCE", "/projects/999/locations/us-central1/services/other-app")
    assert auth_guard.verify_iap_jwt("iap-jwt") is None

    # Exact matching PQC_IAP_AUDIENCE -> accepted
    monkeypatch.setenv("PQC_IAP_AUDIENCE", "/projects/110254026096/locations/us-central1/services/agentic-pqc")
    assert auth_guard.verify_iap_jwt("iap-jwt")["email"] == ALICE

    # Expired IAP JWT -> rejected (None)
    claims["exp"] = int(time.time()) - 120
    assert auth_guard.verify_iap_jwt("iap-jwt") is None
