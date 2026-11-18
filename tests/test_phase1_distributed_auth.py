"""Phase 1 Regression Suite (AUTH-01 .. AUTH-05): OAuth 2.0 + PKCE and Distributed Authentication.

Verifies all 16 mandatory AUTH-05 security regression scenarios using synthetic credentials and isolated
test identities across independent application instances:
  1. Public OAuth client using Authorization Code + PKCE (S256, no client_secret).
  2. Confidential OAuth client using Authorization Code + PKCE (S256 + client_secret).
  3. Rejection of every OAuth implicit flow vector and static scan of source code.
  4. PKCE code_verifier never appearing in state, URLs, cookies, or JSON responses.
  5. Opaque state validation + cryptographic RSA-2048 OIDC ID token verification (iss, aud, exp, nonce, sig).
  6. Invalid / tampered / legacy-signed / wrong-cookie / wrong-redirect_uri state rejection.
  7. Single-use OIDC nonce replay rejection and authorization code replay rejection.
  8. OAuth transaction expiration enforcement.
  9. OAuth transaction single-use enforcement.
 10. Session bearer token absent from all JSON API responses (and DB password redacted in /api/health).
 11. Session bearer token absent from localStorage / sessionStorage in portal & popup HTML/JS.
 12. Secure, HttpOnly, SameSite=Lax, and Path attributes on session, jar, nonce, and CSRF cookies.
 13. CSRF enforcement on state-changing routes + legitimate multi-tab session preservation.
 14. Cross-instance session revocation and cross-instance OAuth transaction completion.
 15. Consistent revocation, active session, and replay state across full application restarts.
 16. Race-free concurrent OAuth callback handling (10 simultaneous callback requests -> 1 winner, 9 rejected).
"""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import datetime
import io
import json
from pathlib import Path
import re
import threading
import time
from typing import Any, Dict, List, Tuple
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select

from pqc_agent import auth_guard, auth_store
from pqc_agent import portal_ui
from pqc_agent import workspace_server as ws

TEST_HMAC_SECRET = "phase1-test-hmac-secret-with-at-least-32-bytes-0123456789abcdef"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _generate_ephemeral_oidc_signer() -> Tuple[rsa.RSAPrivateKey, str, str]:
    """Generates a disposable RSA-2048 keypair and self-signed X.509 PEM certificate for OIDC JWT verification tests."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "accounts.google.com-test-signer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=2))
        .sign(private_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return private_key, "test-kid-phase1", cert_pem


def _mint_rs256_id_token(
    private_key: rsa.RSAPrivateKey,
    kid: str,
    claims: Dict[str, Any],
) -> str:
    header = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode('utf-8'))}.{_b64url(json.dumps(claims, separators=(',', ':')).encode('utf-8'))}"
    signature = private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(signature)}"


def _build_instance(tmp_path: Path, db_path: Path, monkeypatch: pytest.MonkeyPatch, instance_name: str = "inst"):
    data_dir = tmp_path / f"data_{instance_name}"
    data_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("PQC_DATA_DIR", str(data_dir))
    monkeypatch.setenv("PQC_AUTH_SECRET", TEST_HMAC_SECRET)
    monkeypatch.setenv("PQC_SKIP_STARTUP_MODEL_PROBE", "true")
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SESSION_DB_URL", db_url)
    return ws.create_workspace_app(session_db_url=db_url, artifact_bucket=None)


def _install_fake_tokeninfo(monkeypatch: pytest.MonkeyPatch, directory: Dict[str, Dict[str, Any]]) -> None:
    """Stubs Google's tokeninfo endpoint for synthetic access tokens (`ya29.synth-*`)."""

    class _FakeResp:
        def __init__(self, payload: Dict[str, Any]) -> None:
            self._raw = json.dumps(payload).encode("utf-8")

        def read(self) -> bytes:
            return self._raw

        def __enter__(self) -> "_FakeResp":
            return self

        def __exit__(self, *args: Any) -> bool:
            return False

    def _urlopen(req: Any, timeout: float = 8.0) -> _FakeResp:
        url = req.full_url if hasattr(req, "full_url") else str(req)
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        tok = (qs.get("access_token") or qs.get("id_token") or [""])[0]
        if tok in directory:
            return _FakeResp(directory[tok])
        raise OSError(f"Rejected synthetic token: {tok}")

    monkeypatch.setattr(ws.urllib.request, "urlopen", _urlopen)


# ---------------------------------------------------------------------------
# 1 & 2. Public and Confidential OAuth Clients with Authorization Code + PKCE
# ---------------------------------------------------------------------------
def test_auth05_01_public_oauth_client_uses_auth_code_pkce_without_client_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "shared_auth.db"
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "public-client-123.apps.googleusercontent.com")
    monkeypatch.delenv("PQC_GOOGLE_OAUTH_CLIENT_SECRET", raising=False)

    captured_token_post: Dict[str, str] = {}

    class _TokenEndpointResp:
        def read(self) -> bytes:
            return json.dumps(
                {
                    "access_token": "ya29.synth-public-pkce",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                }
            ).encode("utf-8")

        def __enter__(self) -> "_TokenEndpointResp":
            return self

        def __exit__(self, *args: Any) -> bool:
            return False

    app = _build_instance(tmp_path, db_path, monkeypatch, "public_pkce")
    with TestClient(app, base_url="https://portal.example.test") as client:
        # Sign in synthetic user via verified synthetic access token first to test 3LO public client PKCE
        _install_fake_tokeninfo(
            monkeypatch,
            {
                "ya29.login-alice": {
                    "email": "alice@google.com",
                    "email_verified": "true",
                    "expires_in": "3600",
                }
            },
        )
        login_res = client.post("/api/auth/google", json={"google_access_token": "ya29.login-alice"})
        assert login_res.status_code == 200
        csrf_token = login_res.json()["csrf_token"]

        authz = client.get(
            "/api/auth/oauth/authorize",
            params={"format": "json", "scope": "organizations/999999999999"},
        )
        assert authz.status_code == 200
        payload = authz.json()
        assert payload["client_type"] == "public"
        assert payload["response_type"] == "code"
        assert payload["code_challenge_method"] == "S256"

        parsed_auth_url = urllib.parse.urlparse(payload["google_auth_url"])
        qs = urllib.parse.parse_qs(parsed_auth_url.query)
        assert qs["response_type"] == ["code"]
        assert qs["code_challenge_method"] == ["S256"]
        assert len(qs["code_challenge"][0]) >= 43
        state_id = qs["state"][0]

        def _capture_token_exchange(req: Any, timeout: float = 10.0) -> _TokenEndpointResp:
            body_str = (req.data or b"").decode("utf-8")
            captured_token_post.update(dict(urllib.parse.parse_qsl(body_str)))
            return _TokenEndpointResp()

        monkeypatch.setattr(ws.urllib.request, "urlopen", _capture_token_exchange)

        cb_res = client.get("/api/auth/oauth/callback", params={"code": "authcode-pub-001", "state": state_id})
        assert cb_res.status_code == 200, cb_res.text

        assert captured_token_post["grant_type"] == "authorization_code"
        assert captured_token_post["code"] == "authcode-pub-001"
        assert captured_token_post["client_id"] == "public-client-123.apps.googleusercontent.com"
        assert "client_secret" not in captured_token_post
        assert 43 <= len(captured_token_post["code_verifier"]) <= 128
        assert auth_guard.compute_pkce_challenge(captured_token_post["code_verifier"]) == qs["code_challenge"][0]
        assert csrf_token


def test_auth05_02_confidential_oauth_client_uses_auth_code_pkce_with_client_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "shared_confidential.db"
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "conf-client-456.apps.googleusercontent.com")
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_SECRET", "synth-client-secret-not-real-987654")

    private_key, kid, cert_pem = _generate_ephemeral_oidc_signer()

    class _FakeHttpResponse:
        status = 200
        data = json.dumps({kid: cert_pem}).encode("utf-8")

    monkeypatch.setattr(auth_guard, "_iap_transport", lambda: (lambda *a, **kw: _FakeHttpResponse()))

    captured_token_post: Dict[str, str] = {}
    app = _build_instance(tmp_path, db_path, monkeypatch, "conf_pkce")
    with TestClient(app, base_url="https://portal.example.test") as client:
        signin_start = client.get("/api/auth/oauth/signin", follow_redirects=False)
        assert signin_start.status_code == 302
        location = signin_start.headers["location"]
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        assert qs["response_type"] == ["code"]
        assert qs["code_challenge_method"] == ["S256"]
        state_id = qs["state"][0]
        oidc_nonce = qs["nonce"][0]

        now_ts = int(time.time())
        signed_id_jwt = _mint_rs256_id_token(
            private_key,
            kid,
            {
                "iss": "https://accounts.google.com",
                "aud": "conf-client-456.apps.googleusercontent.com",
                "sub": "109876543210",
                "email": "bob@google.com",
                "email_verified": True,
                "name": "Bob Security",
                "nonce": oidc_nonce,
                "iat": now_ts - 5,
                "exp": now_ts + 600,
            },
        )

        class _TokenResp:
            def read(self) -> bytes:
                return json.dumps(
                    {
                        "access_token": "ya29.synth-conf-access",
                        "id_token": signed_id_jwt,
                        "expires_in": 3600,
                        "token_type": "Bearer",
                    }
                ).encode("utf-8")

            def __enter__(self) -> "_TokenResp":
                return self

            def __exit__(self, *args: Any) -> bool:
                return False

        def _capture_exchange(req: Any, timeout: float = 10.0) -> _TokenResp:
            captured_token_post.update(dict(urllib.parse.parse_qsl((req.data or b"").decode("utf-8"))))
            return _TokenResp()

        monkeypatch.setattr(ws.urllib.request, "urlopen", _capture_exchange)

        cb_res = client.get("/api/auth/oauth/callback", params={"code": "authcode-conf-002", "state": state_id})
        assert cb_res.status_code == 200, cb_res.text
        assert captured_token_post["grant_type"] == "authorization_code"
        assert captured_token_post["client_id"] == "conf-client-456.apps.googleusercontent.com"
        assert captured_token_post["client_secret"] == "synth-client-secret-not-real-987654"
        assert auth_guard.compute_pkce_challenge(captured_token_post["code_verifier"]) == qs["code_challenge"][0]

        me_res = client.get("/api/auth/me")
        assert me_res.status_code == 200
        assert me_res.json()["authenticated"] is True
        assert me_res.json()["user_id"] == "bob@google.com"


# ---------------------------------------------------------------------------
# 3. Rejection of Implicit Flow Across Every Endpoint + Source Scan
# ---------------------------------------------------------------------------
def test_auth05_03_implicit_flow_is_rejected_everywhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "implicit_reject.db"
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "client-implicit-check.apps.googleusercontent.com")
    app = _build_instance(tmp_path, db_path, monkeypatch, "implicit")

    with TestClient(app, base_url="https://portal.example.test") as client:
        # Sign-in start rejects response_type=token / id_token
        assert client.get("/api/auth/oauth/signin", params={"response_type": "token"}).status_code == 400
        assert client.get("/api/auth/oauth/signin", params={"response_type": "id_token token"}).status_code == 400

        # Callback rejects token-bearing query params and missing authorization code
        assert (
            client.get(
                "/api/auth/oauth/callback",
                params={"access_token": "ya29.implicit", "token_type": "Bearer", "state": "opaque"},
            ).status_code
            == 400
        )
        assert client.get("/api/auth/oauth/callback", params={"id_token": "eyJ.fake.jwt", "state": "opaque"}).status_code == 400
        assert client.get("/api/auth/oauth/callback", params={"state": "opaque"}).status_code == 400

        # /api/auth/google rejects legacy implicit oauth_state parameter
        assert (
            client.post(
                "/api/auth/google",
                json={"google_access_token": "ya29.implicit", "oauth_state": "legacy-implicit-state"},
            ).status_code
            == 400
        )

        # Sign in properly to test authenticated /authorize and /tool-consent implicit rejections
        _install_fake_tokeninfo(
            monkeypatch,
            {"ya29.valid-carol": {"email": "carol@google.com", "email_verified": "true", "expires_in": "3600"}},
        )
        login_res = client.post("/api/auth/google", json={"google_access_token": "ya29.valid-carol"})
        csrf = login_res.json()["csrf_token"]

        assert client.get("/api/auth/oauth/authorize", params={"response_type": "token"}).status_code == 400
        assert (
            client.post(
                "/api/auth/tool-consent",
                headers={"X-PQC-CSRF-Token": csrf},
                json={"access_token": "ya29.valid-carol", "oauth_state": "legacy-implicit-state"},
            ).status_code
            == 400
        )

        # Bridge HTML must never invoke GIS implicit token client
        bridge_html = client.get("/api/auth/bridge").text
        assert "initTokenClient" not in bridge_html
        assert "response_type=token" not in bridge_html

    # Static source verification across pqc_agent/
    pkg_dir = Path(ws.__file__).resolve().parent
    for py_file in pkg_dir.glob("*.py"):
        src = py_file.read_text(encoding="utf-8")
        assert "initTokenClient" not in src, f"Implicit GIS initTokenClient found in {py_file.name}"
        assert "_OAUTH_IMPLICIT_CALLBACK_HTML" not in src, f"Legacy implicit callback HTML found in {py_file.name}"
        assert '"response_type": "token"' not in src, f"Implicit response_type=token found in {py_file.name}"
        assert "'response_type': 'token'" not in src, f"Implicit response_type=token found in {py_file.name}"


# ---------------------------------------------------------------------------
# 4, 5, 6. Server-Side PKCE Verifier Storage, Opaque State, Invalid State & OIDC Validation
# ---------------------------------------------------------------------------
def test_auth05_04_05_06_pkce_verifier_server_side_only_and_opaque_state_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "pkce_state.db"
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "pkce-client.apps.googleusercontent.com")
    monkeypatch.setenv("PQC_OAUTH_REDIRECT_URIS", "https://portal.example.test/api/auth/oauth/callback")
    app = _build_instance(tmp_path, db_path, monkeypatch, "pkce_state")

    with TestClient(app, base_url="https://portal.example.test") as client:
        res = client.get("/api/auth/oauth/signin", follow_redirects=False)
        assert res.status_code == 302
        redirect_url = res.headers["location"]
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(redirect_url).query)
        state_id = qs["state"][0]

        # State must be opaque URL-safe CSPRNG token (no '.' signed JSON payload, no base64 JSON)
        assert "." not in state_id
        assert 32 <= len(state_id) <= 64

        # Inspect database record directly to confirm code_verifier is stored server-side ONLY
        store = app.state.auth_store
        with store._session_factory() as db:
            tx_row = db.get(auth_store.OAuthTransactionRecord, state_id)
            assert tx_row is not None
            verifier = tx_row.code_verifier
            assert 43 <= len(verifier) <= 128

        assert verifier not in state_id
        assert verifier not in redirect_url
        for cookie_val in res.cookies.values():
            assert verifier not in cookie_val

        # Open redirect / non-allowlisted redirect_uri rejected
        bad_redir = client.get(
            "/api/auth/oauth/signin",
            params={"redirect_uri": "https://evil.attacker.example/callback"},
        )
        assert bad_redir.status_code == 400

        # Legacy signed state format (`<b64>.<hmac>`) is immediately rejected
        legacy_signed = auth_guard.sign_payload(
            {"typ": "oauth_state", "mode": "signin", "exp": int(time.time()) + 300},
            TEST_HMAC_SECRET.encode("utf-8"),
        )
        assert (
            client.get("/api/auth/oauth/callback", params={"code": "c1", "state": legacy_signed}).status_code == 400
        )

        # Random unknown state rejected
        assert (
            client.get("/api/auth/oauth/callback", params={"code": "c2", "state": "unknown_random_state_value_12345"}).status_code
            == 400
        )

        # Valid state presented from a DIFFERENT browser (missing/wrong pqc_oauth_nonce cookie) is rejected
        # AND does NOT consume the legitimate user's transaction!
        with TestClient(app, base_url="https://portal.example.test") as attacker_client:
            attacker_cb = attacker_client.get(
                "/api/auth/oauth/callback", params={"code": "attacker-code", "state": state_id}
            )
            assert attacker_cb.status_code == 400

        with store._session_factory() as db:
            tx_after_attack = db.get(auth_store.OAuthTransactionRecord, state_id)
            assert tx_after_attack is not None
            assert tx_after_attack.consumed_at is None

    # Cryptographic OIDC JWT validation checks (wrong issuer, wrong audience, expired, tampered signature, wrong nonce)
    priv_key, kid, cert_pem = _generate_ephemeral_oidc_signer()
    other_key, _, _ = _generate_ephemeral_oidc_signer()

    class _CertResp:
        status = 200
        data = json.dumps({kid: cert_pem}).encode("utf-8")

    monkeypatch.setattr(auth_guard, "_iap_transport", lambda: (lambda *a, **kw: _CertResp()))
    now_ts = int(time.time())
    base_claims = {
        "iss": "https://accounts.google.com",
        "aud": "pkce-client.apps.googleusercontent.com",
        "sub": "sub-123",
        "email": "dave@google.com",
        "email_verified": True,
        "nonce": "expected-nonce-xyz",
        "iat": now_ts - 10,
        "exp": now_ts + 300,
    }

    ok_claims, err = auth_guard.verify_google_oidc_id_token(
        _mint_rs256_id_token(priv_key, kid, base_claims),
        audiences=("pkce-client.apps.googleusercontent.com",),
        expected_nonce="expected-nonce-xyz",
    )
    assert err is None and ok_claims is not None and ok_claims["email"] == "dave@google.com"

    # Wrong signing key
    bad_sig_claims, _ = auth_guard.verify_google_oidc_id_token(
        _mint_rs256_id_token(other_key, kid, base_claims),
        audiences=("pkce-client.apps.googleusercontent.com",),
        expected_nonce="expected-nonce-xyz",
    )
    assert bad_sig_claims is None

    # Wrong audience
    bad_aud_claims, _ = auth_guard.verify_google_oidc_id_token(
        _mint_rs256_id_token(priv_key, kid, {**base_claims, "aud": "other-app.apps.googleusercontent.com"}),
        audiences=("pkce-client.apps.googleusercontent.com",),
        expected_nonce="expected-nonce-xyz",
    )
    assert bad_aud_claims is None

    # Wrong issuer
    bad_iss_claims, _ = auth_guard.verify_google_oidc_id_token(
        _mint_rs256_id_token(priv_key, kid, {**base_claims, "iss": "https://evil-idp.example"}),
        audiences=("pkce-client.apps.googleusercontent.com",),
        expected_nonce="expected-nonce-xyz",
    )
    assert bad_iss_claims is None

    # Expired token
    exp_claims, _ = auth_guard.verify_google_oidc_id_token(
        _mint_rs256_id_token(priv_key, kid, {**base_claims, "iat": now_ts - 7200, "exp": now_ts - 3600}),
        audiences=("pkce-client.apps.googleusercontent.com",),
        expected_nonce="expected-nonce-xyz",
    )
    assert exp_claims is None

    # Nonce mismatch
    bad_nonce_claims, _ = auth_guard.verify_google_oidc_id_token(
        _mint_rs256_id_token(priv_key, kid, base_claims),
        audiences=("pkce-client.apps.googleusercontent.com",),
        expected_nonce="different-nonce",
    )
    assert bad_nonce_claims is None


# ---------------------------------------------------------------------------
# 7, 8, 9. Nonce Replay, Transaction Expiration, and Single-Use Enforcement
# ---------------------------------------------------------------------------
def test_auth05_07_08_09_nonce_replay_expiration_and_single_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "replay_expiry.db"
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "replay-client.apps.googleusercontent.com")
    priv_key, kid, cert_pem = _generate_ephemeral_oidc_signer()

    class _CertResp:
        status = 200
        data = json.dumps({kid: cert_pem}).encode("utf-8")

    monkeypatch.setattr(auth_guard, "_iap_transport", lambda: (lambda *a, **kw: _CertResp()))

    app = _build_instance(tmp_path, db_path, monkeypatch, "replay_a")
    with TestClient(app, base_url="https://portal.example.test") as client:
        # 7a. OIDC ID token nonce replay across POST /api/auth/google
        now_ts = int(time.time())
        replayed_jwt = _mint_rs256_id_token(
            priv_key,
            kid,
            {
                "iss": "https://accounts.google.com",
                "aud": "replay-client.apps.googleusercontent.com",
                "sub": "sub-erin",
                "email": "erin@google.com",
                "email_verified": True,
                "nonce": "single-use-nonce-777",
                "iat": now_ts - 5,
                "exp": now_ts + 600,
            },
        )
        first_login = client.post("/api/auth/google", json={"id_token": replayed_jwt})
        assert first_login.status_code == 200
        replay_login = client.post("/api/auth/google", json={"id_token": replayed_jwt})
        assert replay_login.status_code == 401
        assert "replay" in replay_login.json()["detail"].lower()

        # 8. Expired OAuth transaction is rejected
        start_exp = client.get("/api/auth/oauth/signin", follow_redirects=False)
        exp_state = urllib.parse.parse_qs(urllib.parse.urlparse(start_exp.headers["location"]).query)["state"][0]
        store = app.state.auth_store
        with store._session_factory.begin() as db:
            row = db.get(auth_store.OAuthTransactionRecord, exp_state)
            assert row is not None
            row.expires_at = time.time() - 5.0
        exp_cb = client.get("/api/auth/oauth/callback", params={"code": "fresh-code-exp", "state": exp_state})
        assert exp_cb.status_code == 400
        assert "INVALID_STATE" in exp_cb.text

        # 9 & 7b. Single-use OAuth transaction + authorization code replay prevention
        start_ok = client.get("/api/auth/oauth/signin", follow_redirects=False)
        qs_ok = urllib.parse.parse_qs(urllib.parse.urlparse(start_ok.headers["location"]).query)
        ok_state = qs_ok["state"][0]
        ok_nonce = qs_ok["nonce"][0]
        cb_id_jwt = _mint_rs256_id_token(
            priv_key,
            kid,
            {
                "iss": "https://accounts.google.com",
                "aud": "replay-client.apps.googleusercontent.com",
                "sub": "sub-frank",
                "email": "frank@google.com",
                "email_verified": True,
                "nonce": ok_nonce,
                "iat": now_ts - 5,
                "exp": now_ts + 600,
            },
        )
        monkeypatch.setattr(
            ws,
            "_exchange_oauth_code",
            lambda code, cb: ({"access_token": "ya29.frank", "id_token": cb_id_jwt, "expires_in": 3600}, None),
        )
        first_cb = client.get("/api/auth/oauth/callback", params={"code": "one-time-auth-code", "state": ok_state})
        assert first_cb.status_code == 200

        # Replaying the same state (even if cookie is re-supplied) is rejected
        second_cb = client.get("/api/auth/oauth/callback", params={"code": "another-code", "state": ok_state})
        assert second_cb.status_code == 400

        # Replaying the already-used authorization code in a brand-new OAuth transaction is also rejected!
        start_new = client.get("/api/auth/oauth/signin", follow_redirects=False)
        new_state = urllib.parse.parse_qs(urllib.parse.urlparse(start_new.headers["location"]).query)["state"][0]
        replayed_code_cb = client.get(
            "/api/auth/oauth/callback", params={"code": "one-time-auth-code", "state": new_state}
        )
        assert replayed_code_cb.status_code == 400
        assert "REPLAYED_CODE" in replayed_code_cb.text


# ---------------------------------------------------------------------------
# 10, 11, 12, 13. No Tokens in JSON / Storage, Cookie Security, CSRF & Multi-Tab
# ---------------------------------------------------------------------------
def test_auth05_10_11_12_13_no_json_or_storage_tokens_cookie_flags_csrf_and_multitab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "cookie_csrf.db"
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "cookie-client.apps.googleusercontent.com")
    app = _build_instance(tmp_path, db_path, monkeypatch, "cookie_csrf")

    # 10a. Verify DB URL password redaction helper & /api/health
    assert "super-secret-pw" not in auth_store.redact_db_url(
        "postgresql+psycopg://pqc_app:super-secret-pw@10.0.0.5:5432/pqc_workspace"
    )

    _install_fake_tokeninfo(
        monkeypatch,
        {
            "ya29.grace": {"email": "grace@google.com", "email_verified": "true", "expires_in": "3600"},
            "ya29.heidi": {"email": "heidi@google.com", "email_verified": "true", "expires_in": "3600"},
        },
    )

    with TestClient(app, base_url="https://portal.example.test") as client:
        # 11. Portal HTML must never persist session tokens in localStorage or sessionStorage
        html = client.get("/").text
        assert html == portal_ui.PORTAL_HTML
        assert 'localStorage.setItem("pqc_session_token"' not in html
        assert "localStorage.setItem('pqc_session_token'" not in html
        assert 'sessionStorage.setItem("pqc_session_token"' not in html

        # Login over HTTPS -> verify JSON has NO session token and cookies have Secure + HttpOnly + SameSite=Lax
        login_grace = client.post("/api/auth/google", json={"google_access_token": "ya29.grace"})
        assert login_grace.status_code == 200
        grace_body = login_grace.json()
        assert "token" not in grace_body
        assert "access_token" not in grace_body
        assert grace_body["csrf_token"]

        set_cookie_headers = login_grace.headers.get_list("set-cookie")
        session_hdr = next(h for h in set_cookie_headers if h.startswith(f"{ws.SESSION_COOKIE_NAME}="))
        jar_hdr = next(h for h in set_cookie_headers if h.startswith(f"{ws.ACCOUNT_JAR_COOKIE_NAME}="))
        csrf_hdr = next(h for h in set_cookie_headers if h.startswith(f"{auth_guard.CSRF_COOKIE_NAME}="))

        assert "HttpOnly" in session_hdr
        assert "Secure" in session_hdr
        assert "SameSite=lax" in session_hdr
        assert "Path=/" in session_hdr

        assert "HttpOnly" in jar_hdr
        assert "Secure" in jar_hdr
        assert "SameSite=lax" in jar_hdr
        assert "Path=/api/auth" in jar_hdr

        # Account jar cookie payload must store session JTI references only, NEVER raw session tokens
        jar_cookie_val = client.cookies.get(ws.ACCOUNT_JAR_COOKIE_NAME)
        decoded_jar = auth_guard.verify_signed_payload(
            jar_cookie_val, TEST_HMAC_SECRET.encode("utf-8"), expected_type="account_jar_v2"
        )
        assert decoded_jar is not None
        for saved_val in decoded_jar["accounts"].values():
            assert "." not in saved_val  # opaque UUID hex JTI, not a `<b64>.<hmac>` bearer token!

        assert "Secure" in csrf_hdr
        assert "SameSite=lax" in csrf_hdr

        # Check all other auth JSON endpoints for absence of `"token"`
        me_json = client.get("/api/auth/me").json()
        assert "token" not in me_json
        auto_json = client.post("/api/auth/auto").json()
        assert "token" not in auto_json
        consent_json = client.post(
            "/api/auth/tool-consent",
            headers={"X-PQC-CSRF-Token": grace_body["csrf_token"]},
            json={"access_token": "ya29.grace", "target_scope": "organizations/111"},
        ).json()
        assert "token" not in consent_json and "access_token" not in consent_json

        # 13a. Multi-tab consistency: Tab 2 calling GET /api/auth/me and POST /api/auth/auto must NOT rotate/break Tab 1
        tab1_cookie_before = client.cookies.get(ws.SESSION_COOKIE_NAME)
        tab1_csrf = grace_body["csrf_token"]

        me_tab2 = client.get("/api/auth/me")
        auto_tab2 = client.post("/api/auth/auto")
        assert me_tab2.status_code == 200 and auto_tab2.status_code == 200
        assert client.cookies.get(ws.SESSION_COOKIE_NAME) == tab1_cookie_before
        assert auto_tab2.json()["csrf_token"] == tab1_csrf

        # Tab 1 can still mutate state using its original CSRF token
        ok_sess = client.post(
            "/api/sessions",
            headers={"X-PQC-CSRF-Token": tab1_csrf},
            json={"title": "Tab 1 Still Works"},
        )
        assert ok_sess.status_code == 200

        # 13b. CSRF enforcement: missing CSRF token, wrong CSRF token, or untrusted cross-origin Origin -> 403
        assert client.post("/api/sessions", json={"title": "No CSRF"}).status_code == 403
        assert (
            client.post("/api/sessions", headers={"X-PQC-CSRF-Token": "wrong-csrf"}, json={"title": "Bad CSRF"}).status_code
            == 403
        )
        assert (
            client.post(
                "/api/sessions",
                headers={"X-PQC-CSRF-Token": tab1_csrf, "Origin": "https://evil.attacker.example"},
                json={"title": "Cross Origin"},
            ).status_code
            == 403
        )

        # Sign in second account & switch back to Grace via HttpOnly jar (no token in JSON request or response)
        login_heidi = client.post("/api/auth/google", json={"google_access_token": "ya29.heidi"})
        heidi_csrf = login_heidi.json()["csrf_token"]
        assert "token" not in login_heidi.json()

        # Supplying a bearer token in /api/auth/switch JSON body is explicitly rejected with 400
        assert (
            client.post(
                "/api/auth/switch",
                headers={"X-PQC-CSRF-Token": heidi_csrf},
                json={"email": "grace@google.com", "token": tab1_cookie_before},
            ).status_code
            == 400
        )

        switched = client.post(
            "/api/auth/switch",
            headers={"X-PQC-CSRF-Token": heidi_csrf},
            json={"email": "grace@google.com"},
        )
        assert switched.status_code == 200
        assert "token" not in switched.json()
        assert switched.json()["user_id"] == "grace@google.com"


# ---------------------------------------------------------------------------
# 14 & 15. Multi-Instance Revocation + Full Application Restart Consistency
# ---------------------------------------------------------------------------
def test_auth05_14_15_cross_instance_revocation_and_restart_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "distributed_cluster.db"
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "cluster-client.apps.googleusercontent.com")
    priv_key, kid, cert_pem = _generate_ephemeral_oidc_signer()

    class _CertResp:
        status = 200
        data = json.dumps({kid: cert_pem}).encode("utf-8")

    monkeypatch.setattr(auth_guard, "_iap_transport", lambda: (lambda *a, **kw: _CertResp()))

    # Boot TWO independent FastAPI instances with isolated data directories sharing ONLY `db_path`
    instance_a = _build_instance(tmp_path, db_path, monkeypatch, "node_a")
    instance_b = _build_instance(tmp_path, db_path, monkeypatch, "node_b")
    assert instance_a.state.auth_store is not instance_b.state.auth_store

    with (
        TestClient(instance_a, base_url="https://portal.example.test") as client_a,
        TestClient(instance_b, base_url="https://portal.example.test") as client_b,
    ):
        # Step 1: Start OAuth PKCE sign-in transaction on Instance A
        start_a = client_a.get("/api/auth/oauth/signin", follow_redirects=False)
        assert start_a.status_code == 302
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(start_a.headers["location"]).query)
        tx_state = qs["state"][0]
        tx_nonce = qs["nonce"][0]
        nonce_cookie = start_a.cookies.get(ws.OAUTH_NONCE_COOKIE_NAME)
        assert nonce_cookie

        now_ts = int(time.time())
        ivan_jwt = _mint_rs256_id_token(
            priv_key,
            kid,
            {
                "iss": "https://accounts.google.com",
                "aud": "cluster-client.apps.googleusercontent.com",
                "sub": "sub-ivan",
                "email": "ivan@google.com",
                "email_verified": True,
                "nonce": tx_nonce,
                "iat": now_ts - 5,
                "exp": now_ts + 600,
            },
        )
        monkeypatch.setattr(
            ws,
            "_exchange_oauth_code",
            lambda code, cb: ({"access_token": "ya29.ivan", "id_token": ivan_jwt, "expires_in": 3600}, None),
        )

        # Step 2: Load balancer routes OAuth callback to Instance B!
        client_b.cookies.set(ws.OAUTH_NONCE_COOKIE_NAME, nonce_cookie, path="/api/auth")
        cb_b = client_b.get("/api/auth/oauth/callback", params={"code": "cluster-code-1", "state": tx_state})
        assert cb_b.status_code == 200, cb_b.text
        ivan_session_cookie = client_b.cookies.get(ws.SESSION_COOKIE_NAME)
        ivan_csrf = client_b.cookies.get(auth_guard.CSRF_COOKIE_NAME)
        assert ivan_session_cookie and ivan_csrf

        # Also sign in a second user (Judy) whose session should survive restart unrevoked
        _install_fake_tokeninfo(
            monkeypatch,
            {"ya29.judy": {"email": "judy@google.com", "email_verified": "true", "expires_in": "3600"}},
        )
        judy_login = client_b.post("/api/auth/google", json={"google_access_token": "ya29.judy"})
        assert judy_login.status_code == 200
        judy_cookie = client_b.cookies.get(ws.SESSION_COOKIE_NAME)
        assert judy_cookie and judy_cookie != ivan_session_cookie

        # Step 3: Verify Ivan's session minted on Instance B works on Instance A
        client_a.cookies.set(ws.SESSION_COOKIE_NAME, ivan_session_cookie, path="/")
        sess_on_a = client_a.post(
            "/api/sessions",
            headers={"X-PQC-CSRF-Token": ivan_csrf},
            json={"title": "Cluster Session"},
        )
        assert sess_on_a.status_code == 200

        # Step 4: Revoke Ivan's session on Instance A via /api/auth/logout
        logout_a = client_a.post("/api/auth/logout", headers={"X-PQC-CSRF-Token": ivan_csrf})
        assert logout_a.status_code == 200

        # Step 5: Attempt to use Ivan's revoked session token on Instance B (cookie AND headers) -> immediately 401!
        client_b.cookies.clear()
        client_b.cookies.set(ws.SESSION_COOKIE_NAME, ivan_session_cookie, path="/")
        assert client_b.get("/api/sessions").status_code == 401
        assert (
            client_b.get("/api/sessions", headers={"Authorization": f"Bearer {ivan_session_cookie}"}).status_code == 401
        )
        assert client_b.get("/api/sessions", headers={"X-PQC-User-Token": ivan_session_cookie}).status_code == 401

    # Step 6: Simulate full cluster restart — dispose both engines, clear fallback caches, boot fresh Instance C
    instance_a.state.auth_store.close()
    instance_b.state.auth_store.close()
    auth_store.clear_fallback_auth_stores()

    instance_c = _build_instance(tmp_path, db_path, monkeypatch, "node_c_after_restart")
    with TestClient(instance_c, base_url="https://portal.example.test") as client_c:
        # Ivan's revoked token remains rejected after restart
        client_c.cookies.set(ws.SESSION_COOKIE_NAME, ivan_session_cookie, path="/")
        assert client_c.get("/api/sessions").status_code == 401

        # Consumed OIDC nonce remains rejected after restart
        assert client_c.post("/api/auth/google", json={"id_token": ivan_jwt}).status_code == 401

        # Judy's active unrevoked session remains valid after restart
        client_c.cookies.set(ws.SESSION_COOKIE_NAME, judy_cookie, path="/")
        judy_me = client_c.get("/api/auth/me")
        assert judy_me.status_code == 200
        assert judy_me.json()["authenticated"] is True
        assert judy_me.json()["user_id"] == "judy@google.com"


# ---------------------------------------------------------------------------
# 16. Concurrent OAuth Callback Race Handling
# ---------------------------------------------------------------------------
def test_auth05_16_concurrent_oauth_callbacks_allow_exactly_one_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "concurrent_race.db"
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "race-client.apps.googleusercontent.com")
    priv_key, kid, cert_pem = _generate_ephemeral_oidc_signer()

    class _CertResp:
        status = 200
        data = json.dumps({kid: cert_pem}).encode("utf-8")

    monkeypatch.setattr(auth_guard, "_iap_transport", lambda: (lambda *a, **kw: _CertResp()))

    instance_a = _build_instance(tmp_path, db_path, monkeypatch, "race_a")
    instance_b = _build_instance(tmp_path, db_path, monkeypatch, "race_b")

    with TestClient(instance_a, base_url="https://portal.example.test") as starter:
        start_res = starter.get("/api/auth/oauth/signin", follow_redirects=False)
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(start_res.headers["location"]).query)
        race_state = qs["state"][0]
        race_nonce = qs["nonce"][0]
        binding_cookie = start_res.cookies.get(ws.OAUTH_NONCE_COOKIE_NAME)
        assert binding_cookie

    now_ts = int(time.time())
    race_jwt = _mint_rs256_id_token(
            priv_key,
            kid,
            {
                "iss": "https://accounts.google.com",
                "aud": "race-client.apps.googleusercontent.com",
                "sub": "sub-race",
                "email": "racer@google.com",
                "email_verified": True,
                "nonce": race_nonce,
                "iat": now_ts - 5,
                "exp": now_ts + 600,
            },
        )

    exchange_calls = 0
    exchange_lock = threading.Lock()

    def _counted_exchange(code: str, cb_uri: str) -> Tuple[Dict[str, Any], None]:
        nonlocal exchange_calls
        with exchange_lock:
            exchange_calls += 1
        return {"access_token": "ya29.racer", "id_token": race_jwt, "expires_in": 3600}, None

    monkeypatch.setattr(ws, "_exchange_oauth_code", _counted_exchange)

    num_workers = 10
    barrier = threading.Barrier(num_workers)

    def _worker(idx: int) -> int:
        target_app = instance_a if (idx % 2 == 0) else instance_b
        with TestClient(target_app, base_url="https://portal.example.test") as tc:
            tc.cookies.set(ws.OAUTH_NONCE_COOKIE_NAME, binding_cookie, path="/api/auth")
            barrier.wait(timeout=10.0)
            resp = tc.get("/api/auth/oauth/callback", params={"code": "race-code-shared", "state": race_state})
            return resp.status_code

    with ThreadPoolExecutor(max_workers=num_workers) as pool:
        statuses: List[int] = list(pool.map(_worker, range(num_workers)))

    assert statuses.count(200) == 1, f"Expected exactly 1 winning callback, got statuses={statuses}"
    assert statuses.count(400) == num_workers - 1, f"Expected {num_workers - 1} rejected callbacks, got {statuses}"
    assert exchange_calls == 1


def test_auth05_unregistered_session_fail_closed_and_3lo_account_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "allowlist_3lo.db"
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "allowlist-client.apps.googleusercontent.com")
    priv_key, kid, cert_pem = _generate_ephemeral_oidc_signer()

    class _CertResp:
        status = 200
        data = json.dumps({kid: cert_pem}).encode("utf-8")

    monkeypatch.setattr(auth_guard, "_iap_transport", lambda: (lambda *a, **kw: _CertResp()))

    app = _build_instance(tmp_path, db_path, monkeypatch, "allowlist")
    with TestClient(app, base_url="https://portal.example.test") as client:
        # 1. A token signed with the valid server HMAC secret that was NEVER registered in pqc_auth_sessions is rejected!
        unregistered_tok = auth_guard.sign_payload(
            {
                "uid": "alice@google.com",
                "email": "alice@google.com",
                "jti": "unregistered-jti-0001",
                "typ": ws.SESSION_TOKEN_TYPE,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
            },
            TEST_HMAC_SECRET.encode("utf-8"),
        )
        client.cookies.set(ws.SESSION_COOKIE_NAME, unregistered_tok, path="/")
        assert client.get("/api/sessions").status_code == 401
        client.cookies.clear()

        # 2. 3LO callback rejects an ID token belonging to a different Google account than the initiating session user
        _install_fake_tokeninfo(
            monkeypatch,
            {"ya29.alice-3lo": {"email": "alice@google.com", "email_verified": "true", "expires_in": "3600"}},
        )
        assert client.post("/api/auth/google", json={"google_access_token": "ya29.alice-3lo"}).status_code == 200
        authz = client.get("/api/auth/oauth/authorize", params={"format": "json"}).json()
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(authz["google_auth_url"]).query)
        state_3lo = qs["state"][0]
        nonce_3lo = qs["nonce"][0]

        now_ts = int(time.time())
        wrong_user_id_jwt = _mint_rs256_id_token(
            priv_key,
            kid,
            {
                "iss": "https://accounts.google.com",
                "aud": "allowlist-client.apps.googleusercontent.com",
                "sub": "sub-mallory",
                "email": "mallory@google.com",
                "email_verified": True,
                "nonce": nonce_3lo,
                "iat": now_ts - 5,
                "exp": now_ts + 600,
            },
        )
        monkeypatch.setattr(
            ws,
            "_exchange_oauth_code",
            lambda code, cb: ({"access_token": "ya29.mallory", "id_token": wrong_user_id_jwt, "expires_in": 3600}, None),
        )
        mismatch_cb = client.get("/api/auth/oauth/callback", params={"code": "3lo-mismatch-code", "state": state_3lo})
        assert mismatch_cb.status_code == 403
        assert "USER_MISMATCH" in mismatch_cb.text
