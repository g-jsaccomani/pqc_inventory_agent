"""Phase 2 & Multi-Instance Integration Test Suite (DB-01..DB-04, ID-01, Section 4).

Verifies:
1. Full 11-step Multi-Instance Workflow across independent FastAPI instances (Instance A, Instance B) + full restart.
2. Concurrent OAuth callbacks & concurrent multi-instance database writes (sessions, profiles, connections, calibration).
3. Database interruption (fail-closed), atomic transaction rollback, and database recovery.
4. Cloud KMS envelope encryption (CloudKmsDekWrapper + AAD), production fail-closed without PQC_KMS_KEY_NAME,
   server-side refresh-token rotation, credential expiration, immediate cross-instance revocation, cross-user session
   isolation, cross-tenant AAD transplant rejection, and SA impersonation allowlist enforcement.
5. Production PostgreSQL fail-closed checks (rejects missing DB, SQLite, /data GCS FUSE, unreachable PG), Cloud SQL
   Unix socket URL translation (psycopg + asyncpg), and Alembic online + PostgreSQL offline DDL migrations.
6. Safe, idempotent, non-destructive SQLite + JSON/JSONL data migration (dry-run, count/FK validation, conflict/orphan
   detection, plaintext token stripping, SHA-256 source immutability, JSON + Markdown reports).
7. Live PostgreSQL daemon integration test (runs when PQC_TEST_POSTGRES_URL is set; honestly skipped/blocked when local
   PostgreSQL daemon is unavailable).
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import time
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError

from pqc_agent import auth_guard, auth_store, credential_service
from pqc_agent.migration_tool import migrate_legacy_persistence
from pqc_agent.model_registry import ModelRegistry
from pqc_agent import workspace_server as ws
from tools import calibration_engine, gcloud_bridge

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ALICE = "alice@google.com"
BOB = "bob@google.com"
MALLORY_OTHER_TENANT = "mallory@othercorp.example.com"
SHARED_HMAC_SECRET = "phase2-multi-instance-256-bit-hmac-secret-key-0123456789abcdef"


def _make_registry() -> ModelRegistry:
    return ModelRegistry(
        candidates=[{"model": "fake-ok-model", "label": "Fake OK", "thinking_levels": [None]}],
        probe=lambda model, level: (True, {"model_version": f"{model}-001"}),
        default_model="fake-ok-model",
        default_thinking_level="",
    )


class _DeterministicCloudKmsStub:
    """In-memory AEAD stub matching Google Cloud KMS KeyManagementServiceClient encrypt/decrypt + AAD semantics."""

    def __init__(self) -> None:
        self._keys: Dict[str, bytes] = {}
        self.encrypt_calls: list[Dict[str, Any]] = []
        self.decrypt_calls: list[Dict[str, Any]] = []

    def _kek_for(self, key_name: str) -> bytes:
        # Normalize primary key path (strip /cryptoKeyVersions/* if present)
        base_key = key_name.split("/cryptoKeyVersions/")[0]
        if base_key not in self._keys:
            self._keys[base_key] = hashlib.sha256(f"kms-kek:{base_key}".encode("utf-8")).digest()
        return self._keys[base_key]

    def encrypt(self, request: Dict[str, Any]) -> Any:
        key_name = str(request["name"])
        pt = bytes(request["plaintext"])
        aad = bytes(request.get("additional_authenticated_data") or b"")
        self.encrypt_calls.append({"name": key_name, "aad": aad, "pt_len": len(pt)})
        iv = os.urandom(12)
        ct = AESGCM(self._kek_for(key_name)).encrypt(iv, pt, aad)

        class _Resp:
            ciphertext = iv + ct
            name = f"{key_name}/cryptoKeyVersions/1"

        return _Resp()

    def decrypt(self, request: Dict[str, Any]) -> Any:
        key_name = str(request["name"])
        blob = bytes(request["ciphertext"])
        aad = bytes(request.get("additional_authenticated_data") or b"")
        self.decrypt_calls.append({"name": key_name, "aad": aad, "ct_len": len(blob)})
        iv, ct = blob[:12], blob[12:]
        pt = AESGCM(self._kek_for(key_name)).decrypt(iv, ct, aad)

        class _Resp:
            plaintext = pt

        return _Resp()


@pytest.fixture(autouse=True)
def _clean_phase2_env(tmp_path, monkeypatch):
    auth_store.clear_fallback_auth_stores()
    monkeypatch.setenv("PQC_DATA_DIR", str(tmp_path / "local_data"))
    monkeypatch.setenv("SESSION_DB_URL", f"sqlite:///{tmp_path / 'unit.db'}")
    monkeypatch.setenv("PQC_AUTH_SECRET", SHARED_HMAC_SECRET)
    for key in (
        "K_SERVICE",
        "PQC_PRODUCTION_MODE",
        "PQC_ENV",
        "DATABASE_URL",
        "PQC_CLOUD_SQL_CONNECTION_NAME",
        "PQC_DB_HOST",
        "PQC_KMS_KEY_NAME",
        "PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS",
        "PQC_ALLOW_UNVERIFIED_SIGNIN",
        "PQC_ENABLE_GIS_JAVASCRIPT_CLIENT",
        "PQC_ADMIN_EMAILS",
        "PQC_IAP_AUDIENCE",
        "PQC_GOOGLE_OAUTH_CLIENT_ID",
        "PQC_GOOGLE_OAUTH_CLIENT_SECRET",
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_SECRET",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(ws, "_AUTH_SECRET_CACHE", None)
    monkeypatch.setattr(ws, "_AUTH_SECRET_CACHE_KEY", None)
    yield
    auth_store.clear_fallback_auth_stores()


def _create_independent_instance(db_url: str, artifact_dir: pathlib.Path):
    """Creates an isolated FastAPI application instance backed only by ``db_url`` (zero shared in-memory state)."""
    os.environ["PQC_EXPORT_DIR"] = str(artifact_dir)
    return ws.create_workspace_app(
        session_db_url=db_url,
        artifact_bucket=None,
        model_registry=_make_registry(),
        verify_models_on_startup=False,
    )


def _run_11_step_multi_instance_workflow(db_url: str, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Executes the mandatory 11-step Multi-Instance Workflow from PHASE1.md Section 4."""
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "multi-inst-client.apps.googleusercontent.com")
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_SECRET", "multi-inst-client-secret")

    class _FakeHttpResp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    expected_oidc: Dict[str, str] = {"nonce": ""}

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url == "https://oauth2.googleapis.com/token":
            return _FakeHttpResp(
                json.dumps(
                    {
                        "access_token": "ya29.multi-instance-3lo-access-token",
                        "refresh_token": "1//multi-instance-3lo-refresh-token",
                        "id_token": "jwt-3lo-alice",
                        "expires_in": 3600,
                    }
                ).encode("utf-8")
            )
        if "id_token=" in url:
            return _FakeHttpResp(
                json.dumps(
                    {
                        "iss": "https://accounts.google.com",
                        "aud": "multi-inst-client.apps.googleusercontent.com",
                        "email": ALICE,
                        "email_verified": "true",
                        "exp": str(int(time.time()) + 600),
                        "nonce": expected_oidc["nonce"],
                    }
                ).encode("utf-8")
            )
        if "access_token=" in url:
            qs_tok = parse_qs(urlparse(url).query)
            raw_at = (qs_tok.get("access_token") or [""])[0]
            if raw_at.startswith("valid:"):
                em = raw_at.split(":", 1)[1]
                return _FakeHttpResp(
                    json.dumps(
                        {
                            "email": em,
                            "email_verified": "true",
                            "expires_in": "3599",
                        }
                    ).encode("utf-8")
                )
        raise AssertionError(f"Unexpected outbound URL: {url}")

    monkeypatch.setattr(ws.urllib.request, "urlopen", fake_urlopen)

    app_a = _create_independent_instance(db_url, tmp_path / "exports_a")
    app_b = _create_independent_instance(db_url, tmp_path / "exports_b")
    assert app_a.state.auth_store is not app_b.state.auth_store
    assert app_a.state.credential_service is not app_b.state.credential_service

    with TestClient(app_a) as client_a, TestClient(app_b) as client_b:
        # Step 1: Authenticate synthetic user through Instance A
        login_a = client_a.post(
            "/api/auth/google",
            json={"google_access_token": f"valid:{ALICE}", "name": "Alice MultiInstance", "region": "NorthAm"},
        )
        assert login_a.status_code == 200, login_a.text
        session_cookie = login_a.cookies.get("pqc_session_token")
        csrf_token = login_a.json()["csrf_token"]
        assert session_cookie and "token" not in login_a.json()

        # Propagate browser cookies to Instance B (simulating Cloud Run load balancer routing to Instance B)
        for cname, cval in client_a.cookies.items():
            client_b.cookies.set(cname, cval)

        # Step 2: Create an OAuth 3LO transaction on Instance A
        authz_a = client_a.get(
            "/api/auth/oauth/authorize",
            params={"format": "json", "scope": "organizations/31564119954"},
        )
        assert authz_a.status_code == 200, authz_a.text
        binding_cookie = authz_a.cookies.get(ws.OAUTH_NONCE_COOKIE_NAME)
        assert binding_cookie
        client_b.cookies.set(ws.OAUTH_NONCE_COOKIE_NAME, binding_cookie)
        qs = parse_qs(urlparse(authz_a.json()["google_auth_url"]).query)
        state_id = qs["state"][0]
        expected_oidc["nonce"] = qs["nonce"][0]

        # Step 3: Complete the OAuth transaction through Instance B
        cb_b = client_b.get("/api/auth/oauth/callback", params={"code": "code-from-google-3lo", "state": state_id})
        assert cb_b.status_code == 200, cb_b.text
        assert "PQC_OAUTH_3LO_AUTHORIZED" in cb_b.text
        assert "ya29.multi-instance-3lo-access-token" not in cb_b.text
        assert "1//multi-instance-3lo-refresh-token" not in cb_b.text

        # Verify Instance A immediately sees the envelope-encrypted 3LO credential persisted by Instance B!
        conn_on_a = client_a.get("/api/connection").json()
        assert conn_on_a["mode"] == "access_token"
        assert conn_on_a["has_access_token"] is True
        assert conn_on_a["access_token_storage"] == "encrypted_db_envelope"

        # Step 4: Create a session through Instance A
        created_sess = client_a.post(
            "/api/sessions",
            headers={"X-PQC-CSRF-Token": csrf_token, "Origin": "http://testserver"},
            json={"title": "Cross-Instance PQC Assessment", "scope": "organizations/31564119954"},
        )
        assert created_sess.status_code == 200, created_sess.text
        sid = created_sess.json()["session_id"]

        # Step 5: Retrieve the session from Instance B
        fetched_b = client_b.get(f"/api/sessions/{sid}")
        assert fetched_b.status_code == 200, fetched_b.text
        assert fetched_b.json()["title"] == "Cross-Instance PQC Assessment"
        assert fetched_b.json()["user_id"] == ALICE

        # Step 6: Update the session from Instance B (run a real chat turn persisting ADK events + metadata)
        chat_b = client_b.post(
            "/api/chat",
            headers={"X-PQC-CSRF-Token": csrf_token, "Origin": "http://testserver"},
            data={
                "message": "Evaluate ML-KEM readiness across Instance B",
                "session_id": sid,
                "model_id": "fake-ok-model",
                "scope": "organizations/31564119954",
            },
        )
        assert chat_b.status_code == 200, chat_b.text
        assert chat_b.json()["status"] == "OK"

        # Step 7: Retrieve the update from Instance A
        updated_on_a = client_a.get(f"/api/sessions/{sid}")
        assert updated_on_a.status_code == 200, updated_on_a.text
        detail_a = updated_on_a.json()
        assert detail_a["message_count"] >= 2
        assert any("Evaluate ML-KEM readiness across Instance B" in m.get("content", "") for m in detail_a["messages"])
        assert any("Fake model answer" in m.get("content", "") for m in detail_a["messages"])

        # Step 8: Revoke the session from Instance A
        logout_a = client_a.post(
            "/api/auth/logout",
            headers={"X-PQC-CSRF-Token": csrf_token, "Origin": "http://testserver"},
        )
        assert logout_a.status_code == 200

        # Step 9: Attempt to access the session through Instance B (both cookie and header must be rejected!)
        assert client_b.get(f"/api/sessions/{sid}").status_code == 401
        assert client_b.get("/api/sessions", headers={"X-PQC-User-Token": session_cookie}).status_code == 401

    # Dispose both instances completely (simulating full container shutdown/scale-to-zero)
    app_a.state.auth_store.close()
    app_b.state.auth_store.close()

    # Step 10: Restart fresh application instances (Instance A2 and Instance B2) against the same database
    app_a2 = _create_independent_instance(db_url, tmp_path / "exports_a2")
    app_b2 = _create_independent_instance(db_url, tmp_path / "exports_b2")
    with TestClient(app_a2) as client_a2, TestClient(app_b2) as client_b2:
        # Step 11: Verify revocation AND persisted session state remain consistent across restarted instances!
        assert client_a2.get("/api/sessions", headers={"X-PQC-User-Token": session_cookie}).status_code == 401
        assert client_b2.get(f"/api/sessions/{sid}", headers={"X-PQC-User-Token": session_cookie}).status_code == 401
        # Verify delegated token was wiped on logout across restarts as well
        assert app_b2.state.credential_service.load_delegated_token(user_id=ALICE) is None

        # Re-authenticate Alice on Instance B2 -> previously persisted session & messages are intact!
        relogin_b2 = client_b2.post(
            "/api/auth/google",
            json={"google_access_token": f"valid:{ALICE}", "region": "NorthAm"},
        )
        assert relogin_b2.status_code == 200
        resumed = client_b2.get(f"/api/sessions/{sid}")
        assert resumed.status_code == 200
        assert resumed.json()["message_count"] >= 2
        assert any("Evaluate ML-KEM readiness across Instance B" in m.get("content", "") for m in resumed.json()["messages"])

    app_a2.state.auth_store.close()
    app_b2.state.auth_store.close()


def test_phase2_multi_instance_11_step_workflow_and_restart_consistency(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'shared_cluster.db'}"
    _run_11_step_multi_instance_workflow(db_url, tmp_path, monkeypatch)


def test_phase2_concurrent_oauth_callbacks_and_concurrent_multi_instance_db_writes(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'concurrent_cluster.db'}"
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "conc-client.apps.googleusercontent.com")
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_SECRET", "conc-secret")

    class _FakeResp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    nonce_holder: Dict[str, str] = {"nonce": ""}

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url == "https://oauth2.googleapis.com/token":
            return _FakeResp(
                json.dumps({"access_token": "ya29.conc-tok", "id_token": "jwt-conc", "expires_in": 3600}).encode("utf-8")
            )
        return _FakeResp(
            json.dumps(
                {
                    "iss": "https://accounts.google.com",
                    "aud": "conc-client.apps.googleusercontent.com",
                    "email": ALICE,
                    "email_verified": "true",
                    "exp": str(int(time.time()) + 600),
                    "nonce": nonce_holder["nonce"],
                }
            ).encode("utf-8")
        )

    monkeypatch.setattr(ws.urllib.request, "urlopen", fake_urlopen)

    app_a = _create_independent_instance(db_url, tmp_path / "exp_a")
    app_b = _create_independent_instance(db_url, tmp_path / "exp_b")

    # 1. Concurrent OAuth callback race across Instance A and Instance B: exactly 1 succeeds (200), 7 fail (400)
    with TestClient(app_a) as init_client:
        start = init_client.get("/api/auth/oauth/signin", follow_redirects=False)
        assert start.status_code == 302
        binding = start.cookies.get(ws.OAUTH_NONCE_COOKIE_NAME)
        qs = parse_qs(urlparse(start.headers["location"]).query)
        state = qs["state"][0]
        nonce_holder["nonce"] = qs["nonce"][0]

    def _hit_callback(idx: int) -> int:
        target = app_a if idx % 2 == 0 else app_b
        with TestClient(target) as c:
            c.cookies.set(ws.OAUTH_NONCE_COOKIE_NAME, binding)
            r = c.get("/api/auth/oauth/callback", params={"code": "shared-auth-code", "state": state})
            return r.status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(_hit_callback, range(8)))
    assert statuses.count(200) == 1
    assert statuses.count(400) == 7

    # 2. Concurrent database writes across two independent store instances (users, session metadata, calibrations)
    store_a = app_a.state.auth_store
    store_b = app_b.state.auth_store

    def _concurrent_writer(idx: int) -> str:
        st = store_a if idx % 2 == 0 else store_b
        uid = f"engineer{idx}@google.com"
        st.upsert_tenant_user(user_id=uid, email=uid, name=f"Engineer {idx}", region="NorthAm")
        sid = f"conc-sess-{idx:03d}"
        st.upsert_session_metadata(session_id=sid, user_id=uid, title=f"Concurrent Session {idx}", message_count=2)
        st.upsert_user_connection(user_id=uid, mode="adc", organization_id=f"10000{idx}", project_id=f"proj-{idx}")
        st.append_calibration_event(
            scope="organizations/31564119954",
            user_id=uid,
            entry={
                "scope": "organizations/31564119954",
                "industry_sector": "BFSI_BANKING",
                "sector_label": "Banking",
                "confidentiality_years_x": 10 + idx,
                "migration_years_y": 3.0,
                "crqc_horizon_years_z": 10.0,
                "gateway_header_limit_kb": 16,
                "timestamp_utc": f"2026-11-17T21:00:{idx:02d}+00:00",
            },
        )
        return sid

    with ThreadPoolExecutor(max_workers=6) as pool:
        created_sids = list(pool.map(_concurrent_writer, range(12)))

    assert len(created_sids) == 12
    cal_events = store_a.list_calibration_events(scope="organizations/31564119954")
    assert len(cal_events) == 12
    for idx in range(12):
        uid = f"engineer{idx}@google.com"
        assert store_b.get_tenant_user(uid)["name"] == f"Engineer {idx}"
        assert store_a.get_session_metadata(f"conc-sess-{idx:03d}", user_id=uid)["message_count"] == 2
        assert store_b.get_user_connection(uid)["project_id"] == f"proj-{idx}"

    app_a.state.auth_store.close()
    app_b.state.auth_store.close()


def test_phase2_database_interruption_fail_closed_rollback_and_recovery(tmp_path, google_verifier, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'resilience.db'}"
    app_a = _create_independent_instance(db_url, tmp_path / "exp_a")
    app_b = _create_independent_instance(db_url, tmp_path / "exp_b")

    with TestClient(app_a) as client_a, TestClient(app_b, raise_server_exceptions=False) as client_b:
        login = client_a.post("/api/auth/google", json={"google_access_token": f"valid:{ALICE}"})
        assert login.status_code == 200
        tok = login.cookies.get("pqc_session_token")
        csrf = login.json()["csrf_token"]
        sess = client_a.post(
            "/api/sessions",
            headers={"X-PQC-CSRF-Token": csrf, "Origin": "http://testserver"},
            json={"title": "Pre-Outage Session"},
        ).json()

        # 1. Atomic Transaction Rollback: mid-transaction exception leaves ZERO partial records in DB
        store_b = app_b.state.auth_store
        with pytest.raises(RuntimeError, match="Simulated mid-transaction failure"):
            with store_b._session_factory.begin() as db:
                db.add(
                    auth_store.TenantUserRecord(
                        user_id="rollback.victim@google.com",
                        email="rollback.victim@google.com",
                        tenant_domain="google.com",
                        name="Rollback Victim",
                        region="EMEA",
                        timezone="UTC",
                        auth_method="cloud_iap",
                        picture="",
                        created_at="2026-11-17T00:00:00+00:00",
                        last_login_at="2026-11-17T00:00:00+00:00",
                    )
                )
                db.flush()
                raise RuntimeError("Simulated mid-transaction failure")
        assert app_a.state.auth_store.get_tenant_user("rollback.victim@google.com") is None

        # 2. Database Interruption on Instance B -> MUST fail closed (401 on session auth), never fail open!
        real_session_factory = store_b._session_factory

        def _broken_session_factory(*args, **kwargs):
            raise OperationalError("SELECT 1", {}, Exception("server closed the connection unexpectedly"))

        monkeypatch.setattr(store_b, "_session_factory", _broken_session_factory)
        outage_resp = client_b.get("/api/sessions", headers={"X-PQC-User-Token": tok})
        assert outage_resp.status_code == 401, "Database outage during session verification must fail closed (HTTP 401)"
        health_outage = client_b.get("/api/health")
        assert health_outage.status_code in (200, 503)
        if health_outage.status_code == 200:
            assert health_outage.json().get("database_healthy") is False

        # 3. Database Recovery on Instance B -> service resumes cleanly with zero data loss
        monkeypatch.setattr(store_b, "_session_factory", real_session_factory)
        recovered_resp = client_b.get("/api/sessions", headers={"X-PQC-User-Token": tok})
        assert recovered_resp.status_code == 200
        assert any(s["session_id"] == sess["session_id"] for s in recovered_resp.json()["sessions"])

    app_a.state.auth_store.close()
    app_b.state.auth_store.close()


def test_phase2_kms_envelope_encryption_refresh_expiry_revocation_and_cross_tenant_isolation(tmp_path, monkeypatch):
    from google.adk.auth.auth_credential import AuthCredentialTypes
    from google.adk.auth.auth_tool import AuthConfig
    from google.adk.auth.credential_service.in_memory_credential_service import InMemoryCredentialService
    from unittest.mock import MagicMock

    # 1. Verify production workspace app NEVER uses InMemoryCredentialService
    app_inst = _create_independent_instance(f"sqlite:///{tmp_path / 'cred_app.db'}", tmp_path / "exp")
    assert not isinstance(app_inst.state.credential_service, InMemoryCredentialService)
    assert isinstance(app_inst.state.credential_service, credential_service.EncryptedDatabaseCredentialService)
    app_inst.state.auth_store.close()

    # 2. Production fails closed if PQC_KMS_KEY_NAME is missing when wrapping credentials
    store = auth_store.DistributedAuthStore(f"sqlite:///{tmp_path / 'kms_vault.db'}")
    monkeypatch.setenv("PQC_PRODUCTION_MODE", "true")
    monkeypatch.delenv("PQC_KMS_KEY_NAME", raising=False)
    prod_svc_no_kms = credential_service.EncryptedDatabaseCredentialService(store=store)
    with pytest.raises(RuntimeError, match="PQC_KMS_KEY_NAME"):
        prod_svc_no_kms.store_delegated_token(user_id=ALICE, access_token="ya29.should-fail-closed")

    # 3. Configure Cloud KMS KEK + deterministic KMS AEAD client shared across two independent service instances
    kms_key = "projects/pqc-prod/locations/us-central1/keyRings/pqc-portal-kr/cryptoKeys/pqc-cred-kek"
    monkeypatch.setenv("PQC_KMS_KEY_NAME", kms_key)
    kms_stub = _DeterministicCloudKmsStub()

    refreshed_calls: list[str] = []

    def _fake_refresh_handler(refresh_tok: str, client_id: str, client_secret: str, token_uri: str):
        refreshed_calls.append(refresh_tok)
        assert client_id == "kms-client-id"
        assert client_secret == "kms-client-secret"
        return {
            "access_token": "ya29.rotated-fresh-access-token",
            "refresh_token": "1//rotated-refresh-token",
            "expires_in": 3600,
        }

    svc_instance_a = credential_service.EncryptedDatabaseCredentialService(
        store=store, kms_client=kms_stub, refresh_handler=_fake_refresh_handler
    )
    svc_instance_b = credential_service.EncryptedDatabaseCredentialService(
        store=store, kms_client=kms_stub, refresh_handler=_fake_refresh_handler
    )

    stored = svc_instance_a.store_delegated_token(
        user_id=ALICE,
        access_token="ya29.initial-kms-protected-access-token",
        refresh_token="1//initial-kms-protected-refresh-token",
        expires_in=120.0,
        client_id="kms-client-id",
        client_secret="kms-client-secret",
        caller_user_id=ALICE,
    )
    assert stored is not None
    assert stored.kek_provider == "gcp_kms"
    assert stored.has_refresh_token is True
    assert len(kms_stub.encrypt_calls) == 1
    assert b"tenant=google.com|user=alice@google.com" in kms_stub.encrypt_calls[0]["aad"]

    # Raw DB inspection: zero plaintext tokens or secrets in SQLite/PostgreSQL columns!
    raw_bytes = (tmp_path / "kms_vault.db").read_bytes()
    for secret_str in (
        b"ya29.initial-kms-protected-access-token",
        b"1//initial-kms-protected-refresh-token",
        b"kms-client-secret",
    ):
        assert secret_str not in raw_bytes

    # Instance B decrypts Alice's credential via Cloud KMS
    loaded_b = svc_instance_b.load_delegated_token(
        user_id=ALICE, caller_user_id=ALICE, caller_tenant_domain="google.com"
    )
    assert loaded_b is not None
    assert loaded_b.access_token == "ya29.initial-kms-protected-access-token"

    # ADK BaseCredentialService.load_credential NEVER exposes refresh_token to ToolContext
    fake_cb_ctx = MagicMock()
    fake_cb_ctx._invocation_context.app_name = "pqc_agent"
    fake_cb_ctx._invocation_context.user_id = ALICE
    auth_cfg = ws.build_gcp_oauth_auth_config(ALICE)
    adk_cred = asyncio.run(svc_instance_b.load_credential(auth_cfg, fake_cb_ctx))
    assert adk_cred is not None and adk_cred.auth_type == AuthCredentialTypes.OAUTH2
    assert adk_cred.oauth2.access_token == "ya29.initial-kms-protected-access-token"
    assert adk_cred.oauth2.refresh_token is None

    # 4. Server-side refresh-token rotation when access_token expires
    rotated = svc_instance_b.load_delegated_token(
        user_id=ALICE,
        caller_user_id=ALICE,
        caller_tenant_domain="google.com",
        now_override=time.time() + 300.0,
    )
    assert rotated is not None
    assert rotated.access_token == "ya29.rotated-fresh-access-token"
    assert refreshed_calls == ["1//initial-kms-protected-refresh-token"]

    # 5. Unauthorized cross-user and cross-tenant credential access are strictly rejected
    with pytest.raises(PermissionError, match="cannot access delegated credentials"):
        svc_instance_b.load_delegated_token(user_id=ALICE, caller_user_id=BOB)
    with pytest.raises(PermissionError, match="cross-tenant"):
        svc_instance_b.load_delegated_token(user_id=ALICE, caller_tenant_domain="othercorp.example.com")

    # 6. Cross-tenant / cross-user ciphertext transplant attack in DB fails AAD authentication!
    svc_instance_a.store_delegated_token(
        user_id=MALLORY_OTHER_TENANT,
        access_token="ya29.mallory-own-token",
        expires_in=600.0,
        caller_user_id=MALLORY_OTHER_TENANT,
    )
    with store._session_factory.begin() as db:
        alice_row = db.scalars(
            select(auth_store.DelegatedCredentialRecord).where(auth_store.DelegatedCredentialRecord.user_id == ALICE)
        ).one()
        mallory_row = db.scalars(
            select(auth_store.DelegatedCredentialRecord).where(
                auth_store.DelegatedCredentialRecord.user_id == MALLORY_OTHER_TENANT
            )
        ).one()
        # Attacker transplants Alice's wrapped DEK, nonce, and ciphertext into Mallory's row (even forging aad_sha256!)
        mallory_row.wrapped_dek_b64 = alice_row.wrapped_dek_b64
        mallory_row.payload_nonce_b64 = alice_row.payload_nonce_b64
        mallory_row.ciphertext_b64 = alice_row.ciphertext_b64
        mallory_row.aad_sha256 = hashlib.sha256(
            credential_service.build_credential_aad(
                "pqc_agent", "othercorp.example.com", MALLORY_OTHER_TENANT, ws.GCP_OAUTH_CREDENTIAL_KEY
            )
        ).hexdigest()

    with pytest.raises(PermissionError, match="decryption failed"):
        svc_instance_b.load_delegated_token(
            user_id=MALLORY_OTHER_TENANT,
            caller_user_id=MALLORY_OTHER_TENANT,
            caller_tenant_domain="othercorp.example.com",
        )

    # 7. Immediate cross-instance credential revocation wipes ciphertext + wrapped DEK
    revoked_count = svc_instance_a.revoke_delegated_tokens(user_id=ALICE, reason="security_logout")
    assert revoked_count == 1
    assert svc_instance_b.load_delegated_token(user_id=ALICE) is None
    with store._session_factory() as db:
        wiped = db.scalars(
            select(auth_store.DelegatedCredentialRecord).where(auth_store.DelegatedCredentialRecord.user_id == ALICE)
        ).one()
        assert wiped.revoked_at is not None
        assert wiped.ciphertext_b64 == ""
        assert wiped.wrapped_dek_b64 == ""

    # 8. Service Account impersonation allowlist enforcement & zero temp token files on disk
    monkeypatch.delenv("PQC_PRODUCTION_MODE", raising=False)
    monkeypatch.setenv("PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS", "pqc-scanner-sa@pqc-inventory-agent-cd06.iam.gserviceaccount.com")
    assert (
        gcloud_bridge.validate_impersonated_service_account(
            "pqc-scanner-sa@pqc-inventory-agent-cd06.iam.gserviceaccount.com"
        )
        == "pqc-scanner-sa@pqc-inventory-agent-cd06.iam.gserviceaccount.com"
    )
    with pytest.raises(PermissionError, match="PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS"):
        gcloud_bridge.validate_impersonated_service_account("rogue-sa@other-proj.iam.gserviceaccount.com")
    with pytest.raises(ValueError, match="Invalid GCP service account"):
        gcloud_bridge.validate_impersonated_service_account("not-a-service-account@gmail.com")

    store.close()


def test_phase2_production_postgres_fail_closed_url_normalization_and_alembic_ddl(tmp_path, monkeypatch):
    from sqlalchemy.dialects.postgresql.asyncpg import PGDialect_asyncpg
    from sqlalchemy.engine import make_url

    # 1. SQLite on /data (Cloud Storage FUSE) is rejected unconditionally in ALL environments
    with pytest.raises(RuntimeError, match="Cloud Storage FUSE"):
        auth_store.validate_production_postgres_only("sqlite:///data/pqc_sessions.db")
    with pytest.raises(RuntimeError, match="Cloud Storage FUSE"):
        auth_store.validate_production_postgres_only("sqlite+aiosqlite:////data/pqc_sessions.db")

    # 2. Production mode fails closed on missing DB URL, SQLite URL, or unreachable PostgreSQL server
    monkeypatch.setenv("K_SERVICE", "agentic-pqc")
    monkeypatch.delenv("SESSION_DB_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("PQC_CLOUD_SQL_CONNECTION_NAME", raising=False)

    with pytest.raises(RuntimeError, match="Refusing silent fallback to SQLite"):
        auth_store.resolve_configured_database_url()

    with pytest.raises(RuntimeError, match="prohibited in production"):
        auth_store.validate_production_postgres_only(f"sqlite:///{tmp_path / 'forbidden_prod.db'}")

    monkeypatch.setenv("PQC_DB_CONNECT_TIMEOUT", "2")
    with pytest.raises(RuntimeError, match="Database connectivity verification failed"):
        auth_store.DistributedAuthStore(
            "postgresql+psycopg://pqc_app:super_secret_pw@127.0.0.1:1/pqc_workspace",
            create_schema=False,
        )

    # 3. Cloud SQL Auth Proxy Unix socket URL generation for both psycopg (sync) and asyncpg (ADK DatabaseSessionService)
    monkeypatch.setenv("PQC_CLOUD_SQL_CONNECTION_NAME", "pqc-inventory-agent-cd06:us-central1:pqc-postgres-prod")
    monkeypatch.setenv("PQC_DB_NAME", "pqc_workspace")
    monkeypatch.setenv("PQC_DB_USER", "pqc_app")
    monkeypatch.setenv("PQC_DB_PASSWORD", "s3cr3t-p@ss:word")

    sync_pg = auth_store.resolve_configured_database_url(async_driver=False)
    async_pg = auth_store.resolve_configured_database_url(async_driver=True)
    assert sync_pg.startswith("postgresql+psycopg://")
    assert async_pg.startswith("postgresql+asyncpg://")
    assert "s3cr3t" not in auth_store.redact_db_url(sync_pg)

    _, asyncpg_kwargs = PGDialect_asyncpg().create_connect_args(make_url(async_pg))
    assert asyncpg_kwargs["host"] == "/cloudsql/pqc-inventory-agent-cd06:us-central1:pqc-postgres-prod"
    assert asyncpg_kwargs["database"] == "pqc_workspace"
    assert asyncpg_kwargs["user"] == "pqc_app"
    assert asyncpg_kwargs["password"] == "s3cr3t-p@ss:word"

    # 4. Verify Alembic offline PostgreSQL DDL generation & online upgrade/downgrade/upgrade cycle
    monkeypatch.delenv("K_SERVICE", raising=False)
    alembic_bin = str(REPO_ROOT / ".venv" / "bin" / "alembic")
    sql_proc = subprocess.run(
        [alembic_bin, "upgrade", "head", "--sql"],
        cwd=str(REPO_ROOT),
        env={
            **os.environ,
            "DATABASE_URL": "postgresql+psycopg://pqc_app:placeholder@127.0.0.1:5432/pqc_workspace",
        },
        capture_output=True,
        text=True,
        check=True,
    )
    ddl = sql_proc.stdout
    for expected_table in (
        "CREATE TABLE pqc_schema_metadata",
        "CREATE TABLE pqc_oauth_transactions",
        "CREATE TABLE pqc_consumed_nonces",
        "CREATE TABLE pqc_auth_sessions",
        "CREATE TABLE pqc_tenant_users",
        "CREATE TABLE pqc_session_metadata",
        "CREATE TABLE pqc_user_connections",
        "CREATE TABLE pqc_oauth_client_configs",
        "CREATE TABLE pqc_calibration_events",
        "CREATE TABLE pqc_delegated_credentials",
        "CREATE TABLE adk_internal_metadata",
        "CREATE TABLE sessions",
        "CREATE TABLE events",
        "CREATE TABLE app_states",
        "CREATE TABLE user_states",
        "FOREIGN KEY(user_id) REFERENCES pqc_tenant_users (user_id) ON DELETE CASCADE",
    ):
        assert expected_table in ddl, expected_table

    mig_db = f"sqlite:///{tmp_path / 'alembic_cycle.db'}"
    for subcmd in (["upgrade", "head"], ["downgrade", "base"], ["upgrade", "head"]):
        subprocess.run(
            [alembic_bin, "-x", f"db_url={mig_db}", *subcmd],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        )


def test_phase2_alembic_sole_production_schema_authority_and_migration_cli(tmp_path, monkeypatch):
    """Explicit regression suite for Step 3 (DB-01: Alembic as sole production schema authority):
    1. Production startup with missing schema fails closed without creating tables.
    2. Production startup with outdated Alembic revision (20261117_0001) or missing table fails closed.
    3. Production startup and ADK session operations NEVER invoke metadata.create_all().
    4. Explicit migration CLI (scripts/run_db_migrations.py) creates expected revision (20261117_0002).
    5. Re-running migration CLI is safe and idempotent.
    6. SQLite production configuration remains rejected by both startup and --require-postgres migration CLI.
    7. Local development convenience initialization continues working when production flags are unset.
    """
    import asyncio
    from google.adk.sessions.schemas import v1 as adk_schema_v1
    from scripts import run_db_migrations

    alembic_bin = str(REPO_ROOT / ".venv" / "bin" / "alembic")

    # 6. SQLite remains rejected in production (before testing schema checks with mock validate_production_postgres_only)
    sqlite_prod_reject = f"sqlite:///{tmp_path / 'rejected_prod.db'}"
    assert run_db_migrations.main(["--db-url", sqlite_prod_reject, "--require-postgres"]) == 2
    monkeypatch.setenv("PQC_PRODUCTION_MODE", "true")
    monkeypatch.setenv("PQC_AUTH_SECRET", "prod-alembic-test-secret-with-at-least-36-bytes!!")
    monkeypatch.setenv("PQC_KMS_KEY_NAME", "projects/p/locations/us-central1/keyRings/kr/cryptoKeys/kek")
    with pytest.raises(RuntimeError, match="database backend 'sqlite' is prohibited in production"):
        ws.create_workspace_app(
            session_db_url=sqlite_prod_reject,
            artifact_bucket="gs://test-bucket",
            model_registry=_make_registry(),
            verify_models_on_startup=False,
            kms_client=_DeterministicCloudKmsStub(),
        )

    # Allow disposable local SQLAlchemy engine ONLY to exercise production schema-authority logic offline
    monkeypatch.setattr(auth_store, "validate_production_postgres_only", lambda _url: None)
    monkeypatch.setattr(
        ws.ResilientGcsArtifactService,
        "__init__",
        lambda self, bucket_name, **kw: (
            setattr(self, "_local_fallback_store", {})
            or setattr(self, "_gcs_online", False)
            or setattr(self, "bucket_name", bucket_name)
        ),
    )

    # Spy on BOTH PqcPersistenceBase.metadata.create_all AND ADK BaseV1.metadata.create_all!
    create_all_calls: List[str] = []

    def _forbid_pqc_create_all(*args, **kwargs):
        create_all_calls.append("pqc_create_all")
        raise AssertionError("PqcPersistenceBase.metadata.create_all() must NEVER be called in production!")

    def _forbid_adk_create_all(*args, **kwargs):
        create_all_calls.append("adk_create_all")
        raise AssertionError("ADK BaseV1.metadata.create_all() must NEVER be called in production!")

    monkeypatch.setattr(auth_store.PqcPersistenceBase.metadata, "create_all", _forbid_pqc_create_all)
    monkeypatch.setattr(adk_schema_v1.Base.metadata, "create_all", _forbid_adk_create_all)

    # 1. Production startup with missing schema fails closed and creates ZERO tables
    empty_db_path = tmp_path / "empty_unmigrated.db"
    empty_db_url = f"sqlite:///{empty_db_path}"
    with pytest.raises(RuntimeError, match="alembic_version"):
        auth_store.DistributedAuthStore(empty_db_url)
    with pytest.raises(RuntimeError, match="alembic_version"):
        ws.create_workspace_app(
            session_db_url=empty_db_url,
            artifact_bucket="gs://test-bucket",
            model_registry=_make_registry(),
            verify_models_on_startup=False,
            kms_client=_DeterministicCloudKmsStub(),
        )
    with pytest.raises(RuntimeError, match="prohibited in production"):
        auth_store.DistributedAuthStore(empty_db_url, create_schema=True)

    check_eng = auth_store.build_sync_sqlalchemy_engine(empty_db_url)
    try:
        with check_eng.connect() as conn:
            assert auth_store.sa_inspect(conn).get_table_names() == []
    finally:
        check_eng.dispose()
    assert create_all_calls == []

    # 2. Production startup with outdated Alembic revision (20261117_0001 instead of 20261117_0002) fails closed
    outdated_db_url = f"sqlite:///{tmp_path / 'outdated_rev.db'}"
    subprocess.run(
        [alembic_bin, "-x", f"db_url={outdated_db_url}", "upgrade", "20261117_0001"],
        cwd=str(REPO_ROOT),
        env={k: v for k, v in os.environ.items() if k != "PQC_PRODUCTION_MODE"},
        capture_output=True,
        text=True,
        check=True,
    )
    with pytest.raises(RuntimeError, match="expected Alembic revision '20261117_0002'"):
        auth_store.DistributedAuthStore(outdated_db_url)
    with pytest.raises(RuntimeError, match="expected Alembic revision '20261117_0002'"):
        ws.create_workspace_app(
            session_db_url=outdated_db_url,
            artifact_bucket="gs://test-bucket",
            model_registry=_make_registry(),
            verify_models_on_startup=False,
            kms_client=_DeterministicCloudKmsStub(),
        )
    assert create_all_calls == []

    # 4 & 5. Explicit Alembic migration creates expected schema (20261117_0002) and re-running is safe & idempotent
    monkeypatch.delenv("PQC_PRODUCTION_MODE", raising=False)
    migrated_db_url = f"sqlite:///{tmp_path / 'explicit_migrated.db'}"
    assert run_db_migrations.main(["--db-url", migrated_db_url]) == 0
    assert run_db_migrations.main(["--db-url", migrated_db_url]) == 0
    assert run_db_migrations.main(["--db-url", migrated_db_url, "--verify-only"]) == 0
    assert create_all_calls == []

    # 3. Booting production app + running ADK session creation after explicit migration succeeds with ZERO create_all calls!
    monkeypatch.setenv("PQC_PRODUCTION_MODE", "true")
    prod_app = ws.create_workspace_app(
        session_db_url=migrated_db_url,
        artifact_bucket="gs://test-bucket",
        model_registry=_make_registry(),
        verify_models_on_startup=False,
        kms_client=_DeterministicCloudKmsStub(),
    )
    with pytest.raises(RuntimeError, match="prohibited in production"):
        prod_app.state.auth_store.ensure_schema()

    created_adk_sess = asyncio.run(
        prod_app.state.session_service.create_session(
            app_name=ws.APP_NAME,
            user_id=ALICE,
            state={"title": "Alembic Managed Session"},
        )
    )
    assert created_adk_sess.id
    assert create_all_calls == []
    prod_app.state.auth_store.close()

    # Inconsistent schema (missing required table despite head revision) fails closed
    drop_eng = auth_store.build_sync_sqlalchemy_engine(migrated_db_url)
    try:
        with drop_eng.begin() as conn:
            conn.execute(text("DROP TABLE pqc_calibration_events"))
    finally:
        drop_eng.dispose()
    with pytest.raises(RuntimeError, match="missing required tables: pqc_calibration_events"):
        auth_store.DistributedAuthStore(migrated_db_url)

    # 7. Local development convenience initialization continues working when production flags are unset
    monkeypatch.undo()
    monkeypatch.setenv("PQC_AUTH_SECRET", "dev-alembic-test-secret-with-at-least-36-bytes!!")
    dev_db_url = f"sqlite:///{tmp_path / 'local_dev_convenience.db'}"
    dev_app = _create_independent_instance(dev_db_url, tmp_path / "dev_exports")
    with TestClient(dev_app) as dev_client:
        h = dev_client.get("/api/health")
        assert h.status_code == 200
        assert h.json()["database_healthy"] is True
    dev_app.state.auth_store.close()


def test_phase2_safe_idempotent_data_migration_and_conflict_detection(tmp_path, monkeypatch):
    # 1. Build realistic disposable legacy SQLite + JSON/JSONL dataset (including duplicates, conflicts & orphans)
    legacy_dir = tmp_path / "legacy_source"
    legacy_dir.mkdir()
    legacy_sqlite = legacy_dir / "pqc_sessions.db"

    conn = sqlite3.connect(str(legacy_sqlite))
    try:
        conn.executescript(
            """
            CREATE TABLE app_states (app_name TEXT PRIMARY KEY, state TEXT, update_time TEXT);
            CREATE TABLE user_states (app_name TEXT, user_id TEXT, state TEXT, update_time TEXT, PRIMARY KEY (app_name, user_id));
            CREATE TABLE sessions (app_name TEXT, user_id TEXT, id TEXT, state TEXT, create_time TEXT, update_time TEXT, PRIMARY KEY (app_name, user_id, id));
            CREATE TABLE events (id TEXT, app_name TEXT, user_id TEXT, session_id TEXT, invocation_id TEXT, timestamp TEXT, event_data TEXT, PRIMARY KEY (id, app_name, user_id, session_id));
            """
        )
        conn.execute(
            "INSERT INTO app_states VALUES (?, ?, ?)",
            ("pqc_agent", json.dumps({"global_flag": True}), "2026-11-10T10:00:00+00:00"),
        )
        conn.execute(
            "INSERT INTO user_states VALUES (?, ?, ?, ?)",
            ("pqc_agent", ALICE, json.dumps({"preferred_region": "NorthAm"}), "2026-11-10T10:00:00+00:00"),
        )
        conn.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)",
            (
                "pqc_agent",
                ALICE,
                "sess-legacy-001",
                json.dumps({"scope": "organizations/31564119954"}),
                "2026-11-10T10:01:00+00:00",
                "2026-11-10T10:05:00+00:00",
            ),
        )
        # Session owned by an ADK user lacking a profile.json -> tests parent user synthesis for FK integrity!
        conn.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)",
            (
                "pqc_agent",
                "charlie@google.com",
                "sess-legacy-002",
                json.dumps({}),
                "2026-11-11T08:00:00+00:00",
                "2026-11-11T08:10:00+00:00",
            ),
        )
        conn.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "ev-001",
                "pqc_agent",
                ALICE,
                "sess-legacy-001",
                "inv-001",
                "2026-11-10T10:02:00+00:00",
                json.dumps({"id": "ev-001", "author": "user", "content": {"role": "user", "parts": [{"text": "Hello PQC"}]}}),
            ),
        )
        # Orphan event referencing non-existent session -> must be detected & skipped without breaking FK integrity!
        conn.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "ev-orphan-999",
                "pqc_agent",
                ALICE,
                "sess-missing-999",
                "inv-999",
                "2026-11-10T10:03:00+00:00",
                json.dumps({"id": "ev-orphan-999", "author": "user"}),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    # Legacy JSON files
    (legacy_dir / "pqc_tenant_users.json").write_text(
        json.dumps(
            {
                ALICE: {
                    "email": ALICE,
                    "name": "Alice Legacy",
                    "region": "NorthAm",
                    "created_at": "2026-11-01T00:00:00+00:00",
                    "last_login_at": "2026-11-10T00:00:00+00:00",
                },
                "malformed-not-an-email": {"email": "malformed-not-an-email"},
            }
        ),
        encoding="utf-8",
    )
    bob_part = legacy_dir / "tenants" / BOB
    (bob_part / "sessions").mkdir(parents=True)
    (bob_part / "profile.json").write_text(
        json.dumps(
            {
                "email": BOB,
                "name": "Bob EMEA",
                "region": "EMEA",
                "created_at": "2026-11-02T00:00:00+00:00",
                "last_login_at": "2026-11-12T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    # Global session metadata for Alice + conflicting duplicate claimed by Bob!
    (legacy_dir / "pqc_session_metadata.json").write_text(
        json.dumps(
            {
                "sess-legacy-001": {
                    "session_id": "sess-legacy-001",
                    "user_id": ALICE,
                    "title": "Alice Legacy Banking Scan",
                    "scope": "organizations/31564119954",
                    "message_count": 4,
                    "created_at": "2026-11-10T10:01:00+00:00",
                    "updated_at": "2026-11-10T10:05:00+00:00",
                },
                "sess-orphan-no-owner": {"title": "No Owner"},
            }
        ),
        encoding="utf-8",
    )
    # Cross-user duplicate session ID under Bob's partition -> must be flagged as conflict & rejected!
    (bob_part / "sessions" / "sess-legacy-001.json").write_text(
        json.dumps({"session_id": "sess-legacy-001", "user_id": BOB, "title": "Hijack Attempt"}),
        encoding="utf-8",
    )
    (bob_part / "sessions" / "sess-bob-valid.json").write_text(
        json.dumps(
            {
                "session_id": "sess-bob-valid",
                "user_id": BOB,
                "title": "Bob Valid EMEA Scan",
                "scope": "organizations/31564119954",
                "message_count": 2,
            }
        ),
        encoding="utf-8",
    )
    (legacy_dir / "pqc_user_connections.json").write_text(
        json.dumps(
            {
                ALICE: {
                    "mode": "access_token",
                    "organization_id": "31564119954",
                    "project_id": "alice-proj",
                    "access_token": "ya29.legacy-plaintext-must-be-stripped",
                }
            }
        ),
        encoding="utf-8",
    )
    (legacy_dir / "pqc_oauth_config.json").write_text(
        json.dumps(
            {
                "client_id": "migrated-client.apps.googleusercontent.com",
                "client_secret": "migrated-super-secret-oauth-secret",
            }
        ),
        encoding="utf-8",
    )
    cal_event_1 = json.dumps(
        {
            "scope": "organizations/31564119954",
            "user_id": ALICE,
            "industry_sector": "BFSI_BANKING",
            "sector_label": "Banking",
            "confidentiality_years_x": 15.0,
            "migration_years_y": 3.0,
            "crqc_horizon_years_z": 8.5,
            "gateway_header_limit_kb": 16,
            "timestamp_utc": "2026-11-10T12:00:00+00:00",
        }
    )
    (legacy_dir / "calibration-history.jsonl").write_text(
        f"{cal_event_1}\n{cal_event_1}\n{{not-valid-json\n",
        encoding="utf-8",
    )

    target_db_path = tmp_path / "migrated_target.db"
    target_url = f"sqlite:///{target_db_path}"
    json_rep = tmp_path / "reports" / "migration.json"
    md_rep = tmp_path / "reports" / "migration.md"

    # 2. Dry-Run first: validates everything, rolls back transaction, leaves target empty & source untouched
    dry = migrate_legacy_persistence(
        target_db_url=target_url,
        source_sqlite_path=str(legacy_sqlite),
        source_data_dir=str(legacy_dir),
        dry_run=True,
        report_json_path=str(json_rep),
        report_markdown_path=str(md_rep),
    )
    assert dry.status == "DRY_RUN_OK"
    assert dry.referential_integrity["passed"] is True
    assert dry.source_files_untouched is True
    assert json_rep.is_file() and md_rep.is_file()

    # 3. Real Migration Run #1
    run1 = migrate_legacy_persistence(
        target_db_url=target_url,
        source_sqlite_path=str(legacy_sqlite),
        source_data_dir=str(legacy_dir),
        dry_run=False,
        report_json_path=str(json_rep),
        report_markdown_path=str(md_rep),
    )
    assert run1.status == "SUCCESS"
    assert run1.referential_integrity["passed"] is True
    assert run1.source_files_untouched is True
    assert run1.counts["tenant_users"]["inserted"] == 3  # Alice, Bob, synthesized Charlie
    assert run1.counts["session_metadata"]["inserted"] == 2  # sess-legacy-001 (Alice) + sess-bob-valid (Bob)
    assert run1.counts["adk_sessions"]["inserted"] == 2
    assert run1.counts["adk_events"]["inserted"] == 1
    assert run1.counts["calibration_events"]["inserted"] == 1

    anomaly_codes = {a["code"] for a in run1.anomalies}
    assert "DUPLICATE_SESSION_ID_CROSS_USER_CONFLICT" in anomaly_codes
    assert "ORPHAN_ADK_EVENT_SKIPPED" in anomaly_codes
    assert "LEGACY_PLAINTEXT_TOKEN_STRIPPED" in anomaly_codes
    assert "MALFORMED_CALIBRATION_JSONL_LINE" in anomaly_codes

    # Verify OAuth client_secret was envelope-encrypted and plaintext tokens were stripped!
    db_raw = target_db_path.read_bytes()
    assert b"ya29.legacy-plaintext-must-be-stripped" not in db_raw
    assert b"migrated-super-secret-oauth-secret" not in db_raw

    # 4. Idempotent Re-Run #2 -> zero duplicate inserts!
    run2 = migrate_legacy_persistence(
        target_db_url=target_url,
        source_sqlite_path=str(legacy_sqlite),
        source_data_dir=str(legacy_dir),
        dry_run=False,
    )
    assert run2.status == "SUCCESS"
    assert run2.referential_integrity["passed"] is True
    assert run2.source_files_untouched is True
    for entity_name, c in run2.counts.items():
        assert c["inserted"] == 0, f"Expected 0 new inserts on idempotent re-run for {entity_name}, got {c}"

    # 5. Production safety guard blocks accidental execution without explicit --allow-production-target
    monkeypatch.setenv("PQC_PRODUCTION_MODE", "true")
    with pytest.raises(RuntimeError, match="Refusing automatic migration execution"):
        migrate_legacy_persistence(
            target_db_url="postgresql+psycopg://pqc_app:pw@127.0.0.1:5432/pqc_workspace",
            source_data_dir=str(legacy_dir),
        )


@pytest.mark.skipif(
    not os.getenv("PQC_TEST_POSTGRES_URL"),
    reason=(
        "BLOCKED: Live PostgreSQL 16 server (PQC_TEST_POSTGRES_URL) is not available on this workstation "
        "(corporate macOS lacks postgres/initdb/docker/podman, and Google Santa blocks unsigned embedded initdb binaries with SIGKILL 9)."
    ),
)
def test_phase2_live_postgresql_multi_instance_integration(tmp_path, monkeypatch):
    """Step 4 PostgreSQL 16 Integration Validation across two independent application instances against a real PostgreSQL DB."""
    from scripts import run_db_migrations

    pg_url = os.environ["PQC_TEST_POSTGRES_URL"]
    assert run_db_migrations.main(["--db-url", pg_url, "--require-postgres"]) == 0

    pg_engine = auth_store.build_sync_sqlalchemy_engine(auth_store.normalize_sync_db_url(pg_url))
    try:
        with pg_engine.connect() as conn:
            pg_version = str(conn.execute(text("SELECT version()")).scalar() or "")
            assert "PostgreSQL" in pg_version
    finally:
        pg_engine.dispose()

    # 1. Multi-instance 11-step workflow (OAuth tx A->B, session CRUD across A/B, revocation across A/B, full restart)
    _run_11_step_multi_instance_workflow(pg_url, tmp_path, monkeypatch)

    # 2. Concurrent OAuth callback consumption across independent PostgreSQL-backed instances
    store_a = auth_store.DistributedAuthStore(pg_url, create_schema=False, verify_schema=True)
    store_b = auth_store.DistributedAuthStore(pg_url, create_schema=False, verify_schema=True)
    try:
        cb_uri = "https://portal.example.test/api/auth/oauth/callback"
        race_tx = store_a.create_oauth_transaction(flow_mode="signin", redirect_uri=cb_uri, ttl_seconds=600)
        assert (race_tx.expires_at - race_tx.created_at) <= 600.0

        def _consume_pg(idx: int) -> bool:
            target = store_a if idx % 2 == 0 else store_b
            res = target.consume_oauth_transaction(
                state_id=race_tx.state_id,
                browser_binding_token=race_tx.browser_binding_token,
                expected_redirect_uri=cb_uri,
            )
            return res is not None

        with ThreadPoolExecutor(max_workers=8) as pool:
            winners = list(pool.map(_consume_pg, range(8)))
        assert winners.count(True) == 1
        assert winners.count(False) == 7

        # 3. Transactional rollback on PostgreSQL
        rb_uid = f"pg-rollback-{int(time.time())}@google.com"
        with pytest.raises(RuntimeError, match="abort-pg-tx"):
            with store_a._session_factory.begin() as db:
                db.add(
                    auth_store.TenantUserRecord(
                        user_id=rb_uid,
                        email=rb_uid,
                        tenant_domain="google.com",
                        name="Rolled Back PG User",
                        region="NorthAm",
                        timezone="UTC",
                        auth_method="oauth",
                        picture="",
                        created_at="2026-11-17T00:00:00+00:00",
                        last_login_at="2026-11-17T00:00:00+00:00",
                    )
                )
                db.flush()
                raise RuntimeError("abort-pg-tx")
        assert store_b.get_tenant_user(rb_uid) is None

        # 4. Credential envelope encryption, retrieval, expiration, revocation & cross-tenant AAD isolation on PostgreSQL
        kms_mock = _DeterministicCloudKmsStub()
        monkeypatch.setenv("PQC_KMS_KEY_NAME", "projects/p/locations/us-central1/keyRings/kr/cryptoKeys/pg-kek")
        cred_a = credential_service.EncryptedDatabaseCredentialService(store=store_a, kms_client=kms_mock)
        cred_b = credential_service.EncryptedDatabaseCredentialService(store=store_b, kms_client=kms_mock)
        cred_a.save_delegated_token(user_id=ALICE, access_token="ya29.pg-live-secret-token", expires_in_seconds=300)
        assert cred_b.load_delegated_token(user_id=ALICE) == "ya29.pg-live-secret-token"
        with pytest.raises(PermissionError):
            cred_b.load_delegated_token(user_id=BOB, requested_owner_id=ALICE)
        with pytest.raises(PermissionError):
            cred_b.load_delegated_token(user_id=EXT_TENANT_USER, requested_owner_id=ALICE)

        cred_a.save_delegated_token(user_id=BOB, access_token="ya29.pg-expiring", expires_in_seconds=1)
        time.sleep(1.15)
        assert cred_b.load_delegated_token(user_id=BOB) is None

        assert cred_a.revoke_user_credentials(ALICE) >= 1
        assert cred_b.load_delegated_token(user_id=ALICE) is None
    finally:
        store_a.close()
        store_b.close()
