"""Phase 4.1.1 Security Validation Suite — Delegated Token Flow & Server-Side Scope Binding.

100% offline, deterministic, and hermetic: uses mocked identity providers, mocked Google Cloud SDK
clients, and isolated SQLite auth/credential stores. Zero live GCP APIs, PostgreSQL servers,
Vertex AI endpoints, or Docker daemons are contacted.

Covers all 14 mandatory Phase 4.1.1 scenarios:
  1. Successful delegated-token authentication with a server-bound project scope.
  2. Successful delegated-token authentication with a server-bound organization scope.
  3. Missing organization/project scope (fails closed with actionable error, local & production).
  4. Client attempts to override the server-bound scope across all API/tool surfaces.
  5. Cross-tenant organization access (including cache & tool-consent identity mismatch).
  6. Cross-tenant project access (including cache, API, & gcloud CLI).
  7. Expired, revoked, or invalid/malformed delegated tokens.
  8. Unauthorized scope after an existing connection was established (scope re-binding denied).
  9. Scope revocation after cache population across all 5 live collectors.
 10. Zero SDK client creation on any denied request (CAI, KMS, Compute SSL Policies).
 11. Zero ambient ADC fallback under all delegated-token error/tampering paths.
 12. Regression of authorized administrator ADC mode (allowlist preserved & enforced).
 13. Regression of explicit demo/simulation mode (demo-pqc-project & PQC_SIMULATION_MODE).
 14. Existing scorecard and CycloneDX CBOM workflows under authorized delegated access.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from google.cloud import kms_v1
from google.oauth2 import credentials as oauth2_credentials
import pytest

from pqc_agent import auth_store, credential_service, workspace_server as ws
from pqc_agent.model_registry import ModelRegistry
from tools import gcloud_bridge, gcp_inventory, pqc_detectors


@pytest.fixture(autouse=True)
def _hermetic_phase411_env(monkeypatch: pytest.MonkeyPatch):
    """Resets security/scope env vars, scan cache, and active tenant ContextVar around every test."""
    for env_key in (
        "K_SERVICE",
        "PQC_PRODUCTION_MODE",
        "PQC_ENV",
        "PQC_ADMIN_EMAILS",
        "PQC_ALLOWED_PROJECTS",
        "PQC_ALLOWED_ORGANIZATIONS",
        "PQC_ALLOWED_FOLDERS",
        "PQC_TENANT_SCOPE_POLICY",
        "PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS",
        "PQC_SIMULATION_MODE",
        "PQC_EXCLUDED_KEY_RINGS",
        "PQC_CONNECTION_MODE",
        "PQC_GOOGLE_OAUTH_CLIENT_ID",
        "PQC_GOOGLE_OAUTH_CLIENT_SECRET",
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_SECRET",
    ):
        monkeypatch.delenv(env_key, raising=False)
    gcp_inventory._SCAN_CACHE.clear()
    prev_uid = gcloud_bridge.get_current_tenant_user()
    gcloud_bridge.set_current_tenant_user("sec-architect")
    yield
    gcp_inventory._SCAN_CACHE.clear()
    gcloud_bridge.set_current_tenant_user(prev_uid)
    auth_store.clear_fallback_auth_stores()


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


def _create_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str = "phase411"):
    db_path = tmp_path / f"{name}.db"
    monkeypatch.setenv("SESSION_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("PQC_DATA_DIR", str(tmp_path / f"data_{name}"))
    monkeypatch.setenv("PQC_EXPORT_DIR", str(tmp_path / f"exports_{name}"))
    monkeypatch.setenv("PQC_AUTH_SECRET", "phase411-delegated-token-hmac-secret-material-32bytes!!")
    monkeypatch.setenv("PQC_CREDENTIAL_KEK", "phase411-delegated-token-local-kek-material-32bytes!!")
    auth_store.clear_fallback_auth_stores()
    return ws.create_workspace_app(
        session_db_url=f"sqlite:///{db_path}",
        model_registry=_make_fake_registry(),
        verify_models_on_startup=False,
    )


def _login_delegated(
    client: TestClient,
    email: str,
    *,
    bind_gcp: bool = True,
    token_override: str | None = None,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    tok = token_override if token_override is not None else f"valid:{email}"
    resp = client.post(
        "/api/auth/google",
        json={
            "google_access_token": tok,
            "use_token_for_gcp_connection": bind_gcp,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    headers = {
        "X-PQC-CSRF-Token": body["csrf_token"],
        "Origin": "http://testserver",
    }
    return headers, body


def _make_fake_cai_items(project_id: str, location: str = "us-central1", *, omit_pq_in_cai: bool = False) -> Dict[str, List[Any]]:
    ssl_policy_resource: Dict[str, Any] = {
        "minTlsVersion": "TLS_1_3",
        "profile": "RESTRICTED",
    }
    if not omit_pq_in_cai:
        ssl_policy_resource["postQuantumKeyExchange"] = "ENABLED"
    return {
        "kms": [
            SimpleNamespace(
                asset_type="cloudkms.googleapis.com/KeyRing",
                name=f"//cloudkms.googleapis.com/projects/{project_id}/locations/{location}/keyRings/kr-delegated",
                display_name="kr-delegated",
                project=f"projects/{project_id}",
                location=location,
                state="ACTIVE",
                labels={},
                versioned_resources=[],
            )
        ],
        "workload": [
            SimpleNamespace(
                asset_type="run.googleapis.com/Service",
                name=f"//run.googleapis.com/projects/{project_id}/locations/{location}/services/payments-svc",
                display_name="payments-svc",
                project=f"projects/{project_id}",
                location=location,
                labels={"env": "prod"},
                kms_key=f"projects/{project_id}/locations/{location}/keyRings/kr-delegated/cryptoKeys/pqc-sign-key",
                kms_keys=[],
            )
        ],
        "crypto": [
            SimpleNamespace(
                asset_type="compute.googleapis.com/SslCertificate",
                name=f"//compute.googleapis.com/projects/{project_id}/global/sslCertificates/edge-cert",
                display_name="edge-cert",
                project=f"projects/{project_id}",
                location="global",
                state="ACTIVE",
                labels={},
                versioned_resources=[SimpleNamespace(resource={"type": "MANAGED", "state": "ACTIVE"})],
            )
        ],
        "tls": [
            SimpleNamespace(
                asset_type="compute.googleapis.com/SslPolicy",
                name=f"//compute.googleapis.com/projects/{project_id}/global/sslPolicies/strict-tls13",
                display_name="strict-tls13",
                project=f"projects/{project_id}",
                location="global",
                labels={},
                versioned_resources=[SimpleNamespace(resource=ssl_policy_resource)],
            ),
            SimpleNamespace(
                asset_type="compute.googleapis.com/TargetHttpsProxy",
                name=f"//compute.googleapis.com/projects/{project_id}/global/targetHttpsProxies/edge-proxy",
                display_name="edge-proxy",
                project=f"projects/{project_id}",
                location="global",
                labels={},
                versioned_resources=[
                    SimpleNamespace(
                        resource={
                            "sslPolicy": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/sslPolicies/strict-tls13"
                        }
                    )
                ],
            ),
        ],
    }


def _install_mock_sdk(
    monkeypatch: pytest.MonkeyPatch,
    project_id: str,
    *,
    location: str = "us-central1",
    key_name: str = "pqc-sign-key",
    omit_pq_in_cai: bool = False,
) -> Dict[str, List[Any]]:
    """Installs recording mock CAI, KMS, and Compute SSL Policy SDK clients + hard google.auth.default tripwire."""
    import google.auth

    telemetry: Dict[str, List[Any]] = {
        "adc_calls": [],
        "cai_inits": [],
        "cai_requests": [],
        "kms_inits": [],
        "compute_inits": [],
    }
    items_by_kind = _make_fake_cai_items(project_id, location=location, omit_pq_in_cai=omit_pq_in_cai)

    def _tripwire_adc(*args: Any, **kwargs: Any):
        telemetry["adc_calls"].append((args, kwargs))
        raise AssertionError("google.auth.default() must NEVER be invoked during delegated-token execution!")

    class _MockCaiClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            telemetry["cai_inits"].append(dict(kwargs))

        def search_all_resources(self, request: Dict[str, Any]):
            telemetry["cai_requests"].append(dict(request))
            asset_types = set(request.get("asset_types") or [])
            if "cloudkms.googleapis.com/KeyRing" in asset_types:
                return list(items_by_kind["kms"])
            if "run.googleapis.com/Service" in asset_types:
                return list(items_by_kind["workload"])
            if "compute.googleapis.com/TargetHttpsProxy" in asset_types:
                return list(items_by_kind["tls"])
            if "compute.googleapis.com/SslCertificate" in asset_types:
                return list(items_by_kind["crypto"])
            return []

    class _MockKmsClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            telemetry["kms_inits"].append(dict(kwargs))

        def list_key_rings(self, request: Dict[str, Any]):
            expected_parent = f"projects/{project_id}/locations/{location}"
            if request["parent"] != expected_parent:
                return []
            return [SimpleNamespace(name=f"{expected_parent}/keyRings/kr-delegated")]

        def list_crypto_keys(self, request: Dict[str, Any]):
            parent = request["parent"]
            if not parent.startswith(f"projects/{project_id}/"):
                return []
            return [
                SimpleNamespace(
                    name=f"{parent}/cryptoKeys/{key_name}",
                    purpose=kms_v1.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
                    version_template=SimpleNamespace(
                        algorithm=kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_65,
                        protection_level=kms_v1.ProtectionLevel.HSM,
                    ),
                    primary=None,
                    rotation_period=None,
                    labels={"owner": "pqc-team"},
                )
            ]

        def list_crypto_key_versions(self, request: Dict[str, Any]):
            return [
                SimpleNamespace(
                    name=f"{request['parent']}/cryptoKeyVersions/1",
                    state=kms_v1.CryptoKeyVersion.CryptoKeyVersionState.ENABLED,
                    algorithm=kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_65,
                    protection_level=kms_v1.ProtectionLevel.HSM,
                )
            ]

        def get_iam_policy(self, request: Dict[str, Any]):
            return SimpleNamespace(bindings=[])

        def list_import_jobs(self, request: Dict[str, Any]):
            parent = request["parent"]
            return [
                SimpleNamespace(
                    name=f"{parent}/importJobs/ij-hpke-01",
                    state=kms_v1.ImportJob.ImportJobState.ACTIVE,
                    import_method=kms_v1.ImportJob.ImportMethod.HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM,
                    protection_level=kms_v1.ProtectionLevel.HSM,
                    expire_time=None,
                )
            ]

    class _MockSslPoliciesClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            telemetry["compute_inits"].append(dict(kwargs))

        def get(self, project: str, ssl_policy: str):
            return SimpleNamespace(post_quantum_key_exchange="ENABLED")

    monkeypatch.setattr(google.auth, "default", _tripwire_adc)
    monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _MockCaiClient)
    monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", _MockKmsClient)
    monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", _MockCaiClient)
    monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", _MockKmsClient)
    monkeypatch.setattr(pqc_detectors.compute_v1, "SslPoliciesClient", _MockSslPoliciesClient)
    monkeypatch.setattr(pqc_detectors.compute_v1, "RegionSslPoliciesClient", _MockSslPoliciesClient)
    return telemetry


def _install_sdk_tripwires(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    """Installs hard failure tripwires on google.auth.default and all GCP SDK clients."""
    import google.auth

    hits: List[str] = []

    def _adc_fail(*args: Any, **kwargs: Any):
        hits.append("google.auth.default")
        raise AssertionError("google.auth.default() must NOT be called on denied requests!")

    class _ClientTripwire:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            hits.append("sdk_client_init")
            raise AssertionError(f"GCP SDK client must NOT be created on denied requests! kwargs={kwargs}")

    monkeypatch.setattr(google.auth, "default", _adc_fail)
    monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _ClientTripwire)
    monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", _ClientTripwire)
    monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", _ClientTripwire)
    monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", _ClientTripwire)
    monkeypatch.setattr(pqc_detectors.compute_v1, "SslPoliciesClient", _ClientTripwire)
    monkeypatch.setattr(pqc_detectors.compute_v1, "RegionSslPoliciesClient", _ClientTripwire)
    return hits


def _run_all_collectors(scope: str) -> Dict[str, Dict[str, Any]]:
    return {
        "kms": json.loads(gcp_inventory.collect_kms_inventory(scope)),
        "workloads": json.loads(gcp_inventory.collect_workload_evidence(scope)),
        "crypto": json.loads(gcp_inventory.discover_all_crypto_assets(scope)),
        "tls": json.loads(pqc_detectors.collect_tls_policies(scope)),
        "imports": json.loads(pqc_detectors.collect_kms_import_jobs(scope)),
    }


# ---------------------------------------------------------------------------
# Scenario 1: Delegated-token auth with server-bound PROJECT scope
# ---------------------------------------------------------------------------
def test_01_delegated_token_auth_with_server_bound_project_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 1: Delegated-token login automatically inherits server-bound project scope and blocks partial-policy org bypass."""
    monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "alice@google.com=tenant-a-proj-01")
    app = _create_app(tmp_path, monkeypatch, "s01_proj")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        telemetry = _install_mock_sdk(monkeypatch, "tenant-a-proj-01")
        with TestClient(app) as client:
            headers, login_body = _login_delegated(client, "alice@google.com", bind_gcp=True)
            conn = login_body["connection"]
            assert conn["mode"] == "access_token"
            assert conn["has_access_token"] is True
            assert conn["project_id"] == "tenant-a-proj-01"
            assert conn["organization_id"] == ""
            assert conn["active_scope_uri"] == "projects/tenant-a-proj-01"
            assert conn["scope_bound_by_server"] is True
            assert conn["authorized_scope"] == {
                "organizations": [],
                "projects": ["tenant-a-proj-01"],
                "folders": [],
            }

            # Creating a session without explicit scope binds the tenant's server-authorized project (never malformed "organizations/")
            sess = client.post("/api/sessions", headers=headers, json={"title": "Project Scan"}).json()
            assert sess["scope"] == "projects/tenant-a-proj-01"

            # All 5 live collectors succeed on explicit project scope AND on symbolic default scope
            gcloud_bridge.set_current_tenant_user("alice@google.com")
            for target in ("projects/tenant-a-proj-01", "default"):
                gcp_inventory._SCAN_CACHE.clear()
                results = _run_all_collectors(target)
                assert results["kms"]["scope"] == "projects/tenant-a-proj-01" and results["kms"]["key_count"] == 1
                assert results["workloads"]["workload_count"] == 1
                assert results["crypto"]["asset_count"] == 1
                assert len(results["tls"]["target_proxies"]) == 1
                assert len(results["imports"]["import_jobs"]) == 1

            # Verify delegated OAuth2 credentials (with quota_project and expiry) were passed to SDK clients, 0 ADC calls
            assert telemetry["adc_calls"] == []
            assert len(telemetry["cai_inits"]) > 0
            for kw in telemetry["cai_inits"] + telemetry["kms_inits"]:
                creds = kw.get("credentials")
                assert isinstance(creds, oauth2_credentials.Credentials)
                assert creds.token == "valid:alice@google.com"
                assert creds.quota_project_id == "tenant-a-proj-01"
                assert creds.expiry is not None

            # Security invariant (partial-policy bypass closed): project-only policy MUST deny self-binding ANY org!
            org_bypass = client.post(
                "/api/connection",
                headers=headers,
                json={"mode": "access_token", "organization_id": "999999999999"},
            )
            assert org_bypass.status_code == 403
            assert "UNAUTHORIZED_RESOURCE_SCOPE" in org_bypass.json()["detail"]

            # Direct collector call on arbitrary org also fails closed with 0 new SDK calls
            prior_cai = len(telemetry["cai_inits"])
            denied_org = json.loads(gcp_inventory.collect_kms_inventory("organizations/999999999999"))
            assert "UNAUTHORIZED_RESOURCE_SCOPE" in denied_org["error"]
            assert len(telemetry["cai_inits"]) == prior_cai
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 2: Delegated-token auth with server-bound ORGANIZATION scope
# ---------------------------------------------------------------------------
def test_02_delegated_token_auth_with_server_bound_organization_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 2: Delegated-token login automatically inherits server-bound org scope and blocks partial-policy project bypass."""
    monkeypatch.setenv("PQC_ALLOWED_ORGANIZATIONS", "bob@google.com=222222222222")
    app = _create_app(tmp_path, monkeypatch, "s02_org")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        telemetry = _install_mock_sdk(monkeypatch, "org222-prod-01")
        with TestClient(app) as client:
            headers, login_body = _login_delegated(client, "bob@google.com", bind_gcp=True)
            conn = login_body["connection"]
            assert conn["mode"] == "access_token"
            assert conn["has_access_token"] is True
            assert conn["organization_id"] == "222222222222"
            assert conn["project_id"] == ""
            assert conn["active_scope_uri"] == "organizations/222222222222"
            assert conn["scope_bound_by_server"] is True

            sess = client.post("/api/sessions", headers=headers, json={"title": "Org Scan"}).json()
            assert sess["scope"] == "organizations/222222222222"

            gcloud_bridge.set_current_tenant_user("bob@google.com")
            for target in ("organizations/222222222222", "org"):
                gcp_inventory._SCAN_CACHE.clear()
                results = _run_all_collectors(target)
                assert results["kms"]["scope"] == "organizations/222222222222" and results["kms"]["key_count"] == 1
                assert results["workloads"]["workload_count"] == 1
                assert results["crypto"]["asset_count"] == 1
                assert len(results["tls"]["target_proxies"]) == 1
                assert len(results["imports"]["import_jobs"]) == 1

            assert telemetry["adc_calls"] == []
            assert all(r["scope"] == "organizations/222222222222" for r in telemetry["cai_requests"])

            # Security invariant (partial-policy bypass closed): org-only policy MUST deny self-binding ANY arbitrary project!
            proj_bypass = client.post(
                "/api/connection",
                headers=headers,
                json={"mode": "access_token", "project_id": "foreign-victim-proj"},
            )
            assert proj_bypass.status_code == 403
            assert "UNAUTHORIZED_RESOURCE_SCOPE" in proj_bypass.json()["detail"]

            prior_cai = len(telemetry["cai_inits"])
            denied_proj = json.loads(gcp_inventory.collect_kms_inventory("projects/foreign-victim-proj"))
            assert "UNAUTHORIZED_RESOURCE_SCOPE" in denied_proj["error"]
            assert len(telemetry["cai_inits"]) == prior_cai
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 3: Missing organization/project scope fails closed
# ---------------------------------------------------------------------------
def test_03_missing_organization_and_project_scope_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 3: Valid delegated token with no bound org/project fails closed with actionable error and zero SDK calls."""
    app = _create_app(tmp_path, monkeypatch, "s03_missing")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        tripwire_hits = _install_sdk_tripwires(monkeypatch)
        with TestClient(app) as client:
            headers, login_body = _login_delegated(client, "unscoped@google.com", bind_gcp=True)
            conn = login_body["connection"]
            assert conn["mode"] == "access_token"
            assert conn["has_access_token"] is True
            assert conn["organization_id"] == ""
            assert conn["project_id"] == ""
            assert conn["active_scope_uri"] == ""

            # Creating a session without scope does NOT fabricate malformed "organizations/"
            sess = client.post("/api/sessions", headers=headers, json={"title": "Unbound"}).json()
            assert sess["scope"] == ""

            # Live collectors fail closed on empty/default/explicit scopes with MISSING_AUTHORIZED_SCOPE
            gcloud_bridge.set_current_tenant_user("unscoped@google.com")
            for target in ("", "default", "org", "organizations/111111111111", "projects/some-proj-01"):
                for name, res in _run_all_collectors(target).items():
                    assert "error" in res, f"{name} unexpectedly succeeded for missing scope target={target!r}"
                    assert "UNAUTHORIZED_RESOURCE_SCOPE" in res["error"]
                    assert "MISSING_AUTHORIZED_SCOPE" in res["error"]

            # In production (K_SERVICE) with Cloud KMS envelope wrapper configured, an unscoped delegated tenant
            # CANNOT self-bind via POST /api/connection!
            app.state.credential_service._explicit_wrapper = credential_service.LocalHkdfKekWrapper(
                b"phase411-delegated-token-local-kek-material-32bytes!!"
            )
            monkeypatch.setenv("K_SERVICE", "pqc-inventory-agent")
            prod_org_bind = client.post(
                "/api/connection",
                headers=headers,
                json={"mode": "access_token", "organization_id": "111111111111"},
            )
            assert prod_org_bind.status_code == 403
            assert "MISSING_AUTHORIZED_SCOPE" in prod_org_bind.json()["detail"]

            prod_proj_bind = client.post(
                "/api/connection",
                headers=headers,
                json={"mode": "access_token", "project_id": "arbitrary-prod-proj"},
            )
            assert prod_proj_bind.status_code == 403
            assert "MISSING_AUTHORIZED_SCOPE" in prod_proj_bind.json()["detail"]

            # Even if DB row were directly tampered in production without server scope policy, collectors still fail closed
            app.state.auth_store.upsert_user_connection(
                user_id="unscoped@google.com",
                mode="access_token",
                organization_id="111111111111",
                project_id="arbitrary-prod-proj",
            )
            prod_conn = client.get("/api/connection", headers=headers).json()
            assert prod_conn["organization_id"] == ""
            assert prod_conn["project_id"] == ""
            prod_kms = json.loads(gcp_inventory.collect_kms_inventory("organizations/111111111111"))
            assert "MISSING_AUTHORIZED_SCOPE" in prod_kms["error"]

        assert tripwire_hits == []
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 4: Client attempts to override server-bound scope
# ---------------------------------------------------------------------------
def test_04_client_cannot_override_server_bound_scope_via_any_request_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 4: Client-supplied scope parameters on /api/connection, /api/chat, /api/sessions, /oauth/authorize, /tool-consent, and tools cannot override server-bound scope."""
    monkeypatch.setenv(
        "PQC_TENANT_SCOPE_POLICY",
        json.dumps({"alice@google.com": {"projects": ["tenant-a-proj-01"], "organizations": [], "folders": []}}),
    )
    app = _create_app(tmp_path, monkeypatch, "s04_override")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        tripwire_hits = _install_sdk_tripwires(monkeypatch)
        with TestClient(app) as client:
            headers, _ = _login_delegated(client, "alice@google.com", bind_gcp=True)

            # 1. /api/connection override attempts -> 403, bound project unchanged
            for bad_payload in (
                {"project_id": "attacker-proj-99"},
                {"organization_id": "999999999999"},
                {"mode": "access_token", "project_id": "attacker-proj-99", "organization_id": "999999999999"},
            ):
                r = client.post("/api/connection", headers=headers, json=bad_payload)
                assert r.status_code == 403
                assert "UNAUTHORIZED_RESOURCE_SCOPE" in r.json()["detail"]

            after_conn = client.get("/api/connection", headers=headers).json()
            assert after_conn["project_id"] == "tenant-a-proj-01"
            assert after_conn["organization_id"] == ""

            # 2. /api/chat scope & project_id override attempts (JSON and multipart FormData) -> 403
            for bad_chat in (
                {"message": "Scan KMS", "model": "fake-ok-model", "scope": "projects/attacker-proj-99"},
                {"message": "Scan KMS", "model": "fake-ok-model", "project_id": "attacker-proj-99"},
                {"message": "Scan KMS", "model": "fake-ok-model", "scope": "organizations/999999999999"},
                {"message": "Scan KMS", "model": "fake-ok-model", "scope": "folders/555555555555"},
            ):
                rc = client.post("/api/chat", headers=headers, json=bad_chat)
                assert rc.status_code == 403, f"Expected 403 for chat payload {bad_chat}, got {rc.status_code}"
                assert "UNAUTHORIZED_RESOURCE_SCOPE" in rc.json()["detail"]

            rc_form = client.post(
                "/api/chat",
                headers=headers,
                data={"message": "Scan", "model_id": "fake-ok-model", "scope": "organizations/999999999999"},
            )
            assert rc_form.status_code == 403

            # Legitimate /api/chat omitting scope inherits server-bound scope cleanly!
            ok_chat = client.post(
                "/api/chat",
                headers=headers,
                json={"message": "Hello", "model": "fake-ok-model"},
            )
            assert ok_chat.status_code == 200
            assert ok_chat.json()["scope"] == "projects/tenant-a-proj-01"

            # 3. /api/sessions override -> 403
            rs = client.post("/api/sessions", headers=headers, json={"title": "Override", "scope": "organizations/999999999999"})
            assert rs.status_code == 403

            # 4. /api/auth/tool-consent override -> 403
            rt = client.post(
                "/api/auth/tool-consent",
                headers=headers,
                json={"access_token": "ya29.alice-fresh-token-12345", "target_scope": "projects/attacker-proj-99"},
            )
            assert rt.status_code == 403

            # 5. /api/auth/oauth/authorize override -> 403
            ra = client.get(
                "/api/auth/oauth/authorize",
                headers=headers,
                params={"format": "json", "scope": "organizations/999999999999"},
            )
            assert ra.status_code == 403

            # 6. PqcOAuth3LOPlugin.before_tool_callback rejects unauthorized scope before consent/execution
            plugin = ws.PqcOAuth3LOPlugin()
            fake_tool = MagicMock()
            fake_tool.name = "collect_kms_inventory"
            fake_inv = MagicMock()
            fake_inv.user_id = "alice@google.com"
            fake_inv.session.id = "sess-override"
            fake_tool_ctx = MagicMock()
            fake_tool_ctx._invocation_context = fake_inv
            fake_tool_ctx.state = {}
            gate = asyncio.run(
                plugin.before_tool_callback(
                    tool=fake_tool,
                    tool_args={"scope": "projects/attacker-proj-99"},
                    tool_context=fake_tool_ctx,
                )
            )
            assert gate is not None
            assert gate["status"] == "SCOPE_AUTHORIZATION_DENIED"
            assert "UNAUTHORIZED_RESOURCE_SCOPE" in gate["error"]

            # 7. Direct collector calls with overridden scope -> UNAUTHORIZED_RESOURCE_SCOPE, 0 SDK calls
            gcloud_bridge.set_current_tenant_user("alice@google.com")
            for bad_scope in ("projects/attacker-proj-99", "organizations/999999999999", "folders/555555555555"):
                for res in _run_all_collectors(bad_scope).values():
                    assert "UNAUTHORIZED_RESOURCE_SCOPE" in res["error"]

        assert tripwire_hits == []
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 5: Cross-tenant ORGANIZATION access denied
# ---------------------------------------------------------------------------
def test_05_cross_tenant_organization_access_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 5: Cross-tenant organization access (live, cached, APIs, gcloud CLI, and tool-consent identity swap) is denied."""
    monkeypatch.setenv(
        "PQC_TENANT_SCOPE_POLICY",
        json.dumps(
            {
                "alice@google.com": {"organizations": ["111111111111"], "projects": []},
                "bob@google.com": {"organizations": ["222222222222"], "projects": []},
            }
        ),
    )
    app = _create_app(tmp_path, monkeypatch, "s05_cross_org")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        subproc_calls: List[Any] = []
        monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/usr/bin/gcloud")
        monkeypatch.setattr(gcloud_bridge.subprocess, "run", lambda *a, **kw: subproc_calls.append((a, kw)))

        bob_telemetry = _install_mock_sdk(monkeypatch, "org222-prod-01", key_name="bob-org-secret-key")
        with TestClient(app) as client_bob:
            _login_delegated(client_bob, "bob@google.com", bind_gcp=True)
            gcloud_bridge.set_current_tenant_user("bob@google.com")
            bob_org_res = json.loads(gcp_inventory.collect_kms_inventory("organizations/222222222222"))
            assert bob_org_res["keys"][0]["key_name"] == "bob-org-secret-key"
            assert bob_telemetry["adc_calls"] == []

        tripwire_hits = _install_sdk_tripwires(monkeypatch)
        with TestClient(app) as client_alice:
            alice_headers, _ = _login_delegated(client_alice, "alice@google.com", bind_gcp=True)
            assert client_alice.post("/api/connection", headers=alice_headers, json={"organization_id": "222222222222"}).status_code == 403
            assert client_alice.post("/api/chat", headers=alice_headers, json={"message": "Scan Bob org", "model": "fake-ok-model", "scope": "organizations/222222222222"}).status_code == 403
            assert client_alice.post("/api/sessions", headers=alice_headers, json={"scope": "organizations/222222222222"}).status_code == 403

            # Alice cannot inject Bob's verified Google token via /api/auth/tool-consent
            cross_consent = client_alice.post(
                "/api/auth/tool-consent",
                headers=alice_headers,
                json={"access_token": "valid:bob@google.com", "verify_with_google": True},
            )
            assert cross_consent.status_code == 403

            gc = client_alice.post(
                "/api/gcloud",
                headers=alice_headers,
                json={"command": "gcloud asset search-all-resources --scope=organizations/222222222222 --format=json"},
            ).json()
            assert gc["status"] == "COMMAND_ERROR" and gc["error_code"] == "UNAUTHORIZED_RESOURCE_SCOPE"

            gcloud_bridge.set_current_tenant_user("alice@google.com")
            for name, res in _run_all_collectors("organizations/222222222222").items():
                assert "error" in res, f"{name} leaked cross-tenant organization!"
                assert "UNAUTHORIZED_RESOURCE_SCOPE" in res["error"]
                assert "bob-org-secret-key" not in json.dumps(res)

        assert subproc_calls == []
        assert tripwire_hits == []
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 6: Cross-tenant PROJECT access denied
# ---------------------------------------------------------------------------
def test_06_cross_tenant_project_access_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 6: Cross-tenant project access (live, cached, APIs, and gcloud CLI) is denied with zero SDK/subprocess calls."""
    monkeypatch.setenv(
        "PQC_TENANT_SCOPE_POLICY",
        json.dumps(
            {
                "alice@google.com": {"organizations": [], "projects": ["tenant-a-proj-01"]},
                "bob@google.com": {"organizations": [], "projects": ["tenant-b-proj-02"]},
            }
        ),
    )
    app = _create_app(tmp_path, monkeypatch, "s06_cross_proj")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        subproc_calls: List[Any] = []
        monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/usr/bin/gcloud")
        monkeypatch.setattr(gcloud_bridge.subprocess, "run", lambda *a, **kw: subproc_calls.append((a, kw)))

        bob_telemetry = _install_mock_sdk(monkeypatch, "tenant-b-proj-02", key_name="bob-proj-secret-key")
        with TestClient(app) as client_bob:
            _login_delegated(client_bob, "bob@google.com", bind_gcp=True)
            gcloud_bridge.set_current_tenant_user("bob@google.com")
            bob_proj_res = json.loads(gcp_inventory.collect_kms_inventory("projects/tenant-b-proj-02"))
            assert bob_proj_res["keys"][0]["key_name"] == "bob-proj-secret-key"
            assert bob_telemetry["adc_calls"] == []

        tripwire_hits = _install_sdk_tripwires(monkeypatch)
        with TestClient(app) as client_alice:
            alice_headers, _ = _login_delegated(client_alice, "alice@google.com", bind_gcp=True)
            assert client_alice.post("/api/connection", headers=alice_headers, json={"project_id": "tenant-b-proj-02"}).status_code == 403
            assert client_alice.post("/api/chat", headers=alice_headers, json={"message": "Scan Bob proj", "model": "fake-ok-model", "project_id": "tenant-b-proj-02"}).status_code == 403
            assert client_alice.post("/api/sessions", headers=alice_headers, json={"scope": "projects/tenant-b-proj-02"}).status_code == 403

            gc = client_alice.post(
                "/api/gcloud",
                headers=alice_headers,
                json={"command": "gcloud kms keys list --location=global --project=tenant-b-proj-02 --format=json"},
            ).json()
            assert gc["status"] == "COMMAND_ERROR" and gc["error_code"] == "UNAUTHORIZED_RESOURCE_SCOPE"

            gcloud_bridge.set_current_tenant_user("alice@google.com")
            for name, res in _run_all_collectors("projects/tenant-b-proj-02").items():
                assert "error" in res, f"{name} leaked cross-tenant project!"
                assert "UNAUTHORIZED_RESOURCE_SCOPE" in res["error"]
                assert "bob-proj-secret-key" not in json.dumps(res)

        assert subproc_calls == []
        assert tripwire_hits == []
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 7: Expired, revoked, or invalid/malformed delegated tokens
# ---------------------------------------------------------------------------
def test_07_expired_revoked_and_invalid_delegated_tokens_never_create_sdk_clients(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 7: Invalid, malformed, expired, and revoked delegated tokens fail closed with zero SDK client creation."""
    monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "alice@google.com=tenant-a-proj-01")
    app = _create_app(tmp_path, monkeypatch, "s07_tokens")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        tripwire_hits = _install_sdk_tripwires(monkeypatch)
        with TestClient(app) as client:
            # 1. Invalid token on /api/auth/google -> 401
            bad_login = client.post(
                "/api/auth/google",
                json={"google_access_token": "not-a-valid-token", "use_token_for_gcp_connection": True},
            )
            assert bad_login.status_code == 401

            # 2. Sign in cleanly, then test malformed tokens on /api/connection and /api/auth/tool-consent -> 400
            headers, _ = _login_delegated(client, "alice@google.com", bind_gcp=True)
            for malformed in ("bad token with spaces", "ya29.newline\ninjection", "short"):
                r_conn = client.post("/api/connection", headers=headers, json={"access_token": malformed})
                assert r_conn.status_code == 400
                assert "ACCESS_TOKEN_INVALID" in r_conn.json()["detail"]

                r_cons = client.post("/api/auth/tool-consent", headers=headers, json={"access_token": malformed})
                assert r_cons.status_code == 400
                assert "ACCESS_TOKEN_INVALID" in r_cons.json()["detail"]

            # 3. Already-expired token (expires_in <= 0) rejected by store_delegated_token & set_gcp_connection_config
            with pytest.raises(ValueError, match="ACCESS_TOKEN_EXPIRED"):
                app.state.credential_service.store_delegated_token(
                    user_id="alice@google.com",
                    access_token="ya29.already-expired-token-12345",
                    expires_in=0,
                    caller_user_id="alice@google.com",
                )
            with pytest.raises(ValueError, match="ACCESS_TOKEN_EXPIRED"):
                gcloud_bridge.set_gcp_connection_config(
                    mode="access_token",
                    access_token="ya29.already-expired-token-12345",
                    access_token_expires_in=-5,
                    user_id="alice@google.com",
                )

            # 4. Expire Alice's stored delegated token in DB -> all 5 collectors & credential resolver fail closed
            cred_id = credential_service.build_credential_id(
                credential_service.DEFAULT_APP_NAME,
                "google.com",
                "alice@google.com",
                credential_service.DEFAULT_GCP_CREDENTIAL_KEY,
            )
            with app.state.auth_store._session_factory() as db:
                row = db.get(auth_store.DelegatedCredentialRecord, cred_id)
                assert row is not None
                row.expires_at = time.time() - 120.0
                db.commit()

            gcloud_bridge.set_current_tenant_user("alice@google.com")
            with pytest.raises(PermissionError, match="ACCESS_TOKEN_REQUIRED"):
                gcloud_bridge.get_active_gcp_credentials(user_id="alice@google.com")
            for name, res in _run_all_collectors("projects/tenant-a-proj-01").items():
                assert "error" in res, f"{name} succeeded with expired token!"
                assert "ACCESS_TOKEN_REQUIRED" in res["error"]

            # 5. Re-bind a valid token, then logout (revoking token) -> all 5 collectors fail closed
            ok_rebind = client.post(
                "/api/auth/tool-consent",
                headers=headers,
                json={"access_token": "ya29.alice-rebound-token-999999"},
            )
            assert ok_rebind.status_code == 200
            assert client.post("/api/auth/logout", headers=headers).status_code == 200

            with pytest.raises(PermissionError, match="ACCESS_TOKEN_REQUIRED"):
                gcloud_bridge.get_active_gcp_credentials(user_id="alice@google.com")
            for name, res in _run_all_collectors("projects/tenant-a-proj-01").items():
                assert "error" in res, f"{name} succeeded after logout token revocation!"
                assert "ACCESS_TOKEN_REQUIRED" in res["error"]

        assert tripwire_hits == []
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 8: Unauthorized scope after an existing connection was established
# ---------------------------------------------------------------------------
def test_08_unauthorized_scope_after_existing_connection_established_is_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 8: Even without env scope policies in local mode, once a tenant connection scope is established, re-binding or scanning another org/project fails closed."""
    app = _create_app(tmp_path, monkeypatch, "s08_existing")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        telemetry = _install_mock_sdk(monkeypatch, "tenant-a-proj-01")
        with TestClient(app) as client:
            headers, _ = _login_delegated(client, "alice@google.com", bind_gcp=False)
            # Initial connection binding establishes org 111111111111
            init_res = client.post(
                "/api/connection",
                headers=headers,
                json={
                    "mode": "access_token",
                    "organization_id": "111111111111",
                    "access_token": "ya29.alice-established-conn-token-01",
                },
            )
            assert init_res.status_code == 200
            assert init_res.json()["organization_id"] == "111111111111"

            # Authorized scan on established org works
            gcloud_bridge.set_current_tenant_user("alice@google.com")
            ok_kms = json.loads(gcp_inventory.collect_kms_inventory("organizations/111111111111"))
            assert ok_kms["key_count"] == 1 and "error" not in ok_kms

            # Now install hard tripwires and verify Alice CANNOT re-bind to a different org or pivot to an arbitrary project!
            tripwire_hits = _install_sdk_tripwires(monkeypatch)

            rebind_org = client.post("/api/connection", headers=headers, json={"organization_id": "222222222222"})
            assert rebind_org.status_code == 403
            assert "UNAUTHORIZED_RESOURCE_SCOPE" in rebind_org.json()["detail"]

            pivot_proj = client.post("/api/connection", headers=headers, json={"project_id": "tenant-b-proj-02"})
            assert pivot_proj.status_code == 403
            assert "UNAUTHORIZED_RESOURCE_SCOPE" in pivot_proj.json()["detail"]

            # Persisted connection remains strictly locked to org 111111111111
            persisted = app.state.auth_store.get_user_connection("alice@google.com")
            assert persisted is not None
            assert persisted["organization_id"] == "111111111111"
            assert persisted["project_id"] == ""

            # Chat, sessions, and all 5 collectors deny the unauthorized org/project
            assert client.post("/api/chat", headers=headers, json={"message": "Scan", "model": "fake-ok-model", "scope": "organizations/222222222222"}).status_code == 403
            assert client.post("/api/sessions", headers=headers, json={"scope": "projects/tenant-b-proj-02"}).status_code == 403
            for bad in ("organizations/222222222222", "projects/tenant-b-proj-02"):
                for res in _run_all_collectors(bad).values():
                    assert "UNAUTHORIZED_RESOURCE_SCOPE" in res["error"]

            assert telemetry["adc_calls"] == []
            assert tripwire_hits == []
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 9: Scope revocation after cache population
# ---------------------------------------------------------------------------
def test_09_scope_revocation_after_cache_population_blocks_all_collectors_and_apis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 9: Revoking a tenant's scope immediately invalidates cached reads across all 5 collectors and HTTP APIs."""
    monkeypatch.setenv(
        "PQC_TENANT_SCOPE_POLICY",
        json.dumps(
            {
                "alice@google.com": {
                    "organizations": ["111111111111"],
                    "projects": ["tenant-a-proj-01"],
                }
            }
        ),
    )
    app = _create_app(tmp_path, monkeypatch, "s09_revoke_cache")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        _install_mock_sdk(monkeypatch, "tenant-a-proj-01", key_name="cached-secret-key")
        with TestClient(app) as client:
            headers, _ = _login_delegated(client, "alice@google.com", bind_gcp=True)
            gcloud_bridge.set_current_tenant_user("alice@google.com")

            # Warm _SCAN_CACHE across ALL 5 collectors for BOTH org and project
            for warm_scope in ("organizations/111111111111", "projects/tenant-a-proj-01"):
                warmed = _run_all_collectors(warm_scope)
                assert warmed["kms"]["key_count"] == 1
                assert warmed["workloads"]["workload_count"] == 1
                assert warmed["crypto"]["asset_count"] == 1
                assert len(warmed["tls"]["target_proxies"]) == 1
                assert len(warmed["imports"]["import_jobs"]) == 1
            assert len(gcp_inventory._SCAN_CACHE) >= 10

            # Operator revokes Alice's previous scopes completely (empty allowlist in PQC_TENANT_SCOPE_POLICY)
            monkeypatch.setenv(
                "PQC_TENANT_SCOPE_POLICY",
                json.dumps({"alice@google.com": {"organizations": [], "projects": [], "folders": []}}),
            )
            tripwire_hits = _install_sdk_tripwires(monkeypatch)

            # GET /api/connection immediately reflects revoked scopes (never exposing stale DB values)
            conn_after = client.get("/api/connection", headers=headers).json()
            assert conn_after["organization_id"] == ""
            assert conn_after["project_id"] == ""
            assert conn_after["authorized_scope"] == {"organizations": [], "projects": [], "folders": []}

            # HTTP endpoints reject the revoked scopes
            assert client.post("/api/chat", headers=headers, json={"message": "Scan", "model": "fake-ok-model", "scope": "organizations/111111111111"}).status_code == 403
            assert client.post("/api/sessions", headers=headers, json={"scope": "projects/tenant-a-proj-01"}).status_code == 403

            # All 5 collectors fail closed (ZERO cached data returned, ZERO SDK clients created)
            for revoked_scope in ("organizations/111111111111", "projects/tenant-a-proj-01"):
                for name, res in _run_all_collectors(revoked_scope).items():
                    assert "error" in res, f"{name} returned stale cached data after scope revocation!"
                    assert "UNAUTHORIZED_RESOURCE_SCOPE" in res["error"]
                    assert "cached-secret-key" not in json.dumps(res)

            assert tripwire_hits == []
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 10: No SDK client creation on any denied request
# ---------------------------------------------------------------------------
def test_10_no_sdk_client_creation_on_any_denied_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 10: Denied requests (unauth, missing token, unauthorized scope, malformed scope, tampered ADC) construct zero SDK clients."""
    monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "alice@google.com=tenant-a-proj-01")
    app = _create_app(tmp_path, monkeypatch, "s10_zero_sdk")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        tripwire_hits = _install_sdk_tripwires(monkeypatch)
        with TestClient(app) as client:
            # 1. Unauthenticated caller -> 0 SDK clients
            gcloud_bridge.set_current_tenant_user("sec-architect")
            for res in _run_all_collectors("projects/tenant-a-proj-01").values():
                assert "UNAUTHENTICATED_EXECUTION_CONTEXT" in res["error"]

            # 2. Authenticated delegated user WITHOUT token -> 0 SDK clients
            _login_delegated(client, "alice@google.com", bind_gcp=False)
            gcloud_bridge.set_current_tenant_user("alice@google.com")
            for res in _run_all_collectors("projects/tenant-a-proj-01").values():
                assert "ACCESS_TOKEN_REQUIRED" in res["error"]

            # 3. Authenticated user WITH token requesting unauthorized / malformed scopes -> 0 SDK clients
            app.state.credential_service.store_delegated_token(
                user_id="alice@google.com",
                access_token="ya29.alice-valid-token-for-s10-check",
                caller_user_id="alice@google.com",
            )
            for bad_scope in (
                "projects/victim-proj-99",
                "organizations/999999999999",
                "folders/555555555555",
                "organizations/",
                "projects/../victim-proj-99",
            ):
                for res in _run_all_collectors(bad_scope).values():
                    assert "UNAUTHORIZED_RESOURCE_SCOPE" in res["error"]

            # 4. Standalone Compute SSL policy helper on unauthorized project -> returns None, 0 SDK clients
            assert pqc_detectors._fetch_compute_pq_key_exchange("victim-proj-99", "global", "ssl-pol") is None

        assert tripwire_hits == []
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 11: No ambient ADC fallback
# ---------------------------------------------------------------------------
def test_11_no_ambient_adc_fallback_under_any_delegated_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 11: Even with GOOGLE_APPLICATION_CREDENTIALS present, missing/expired/tampered/failing delegated credentials NEVER fall back to ambient ADC."""
    fake_sa_file = tmp_path / "ambient_adc.json"
    fake_sa_file.write_text('{"type":"service_account","project_id":"ambient-server-proj"}', encoding="utf-8")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(fake_sa_file))
    monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "alice@google.com=tenant-a-proj-01")

    app = _create_app(tmp_path, monkeypatch, "s11_no_adc")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        tripwire_hits = _install_sdk_tripwires(monkeypatch)
        with TestClient(app) as client:
            headers, _ = _login_delegated(client, "alice@google.com", bind_gcp=False)
            gcloud_bridge.set_current_tenant_user("alice@google.com")

            # 1. Tampered DB mode='adc' for non-admin -> ADC_UNAUTHORIZED, 0 ADC calls
            app.state.auth_store.upsert_user_connection(
                user_id="alice@google.com",
                mode="adc",
                project_id="tenant-a-proj-01",
            )
            for res in _run_all_collectors("projects/tenant-a-proj-01").values():
                assert "ADC_UNAUTHORIZED" in res["error"]
            assert client.get("/api/connection", headers=headers).json()["mode"] == "access_token"
            assert tripwire_hits == []

            # 2. Delegated token returns 403 PermissionDenied from CAI -> executes once with user token, ZERO ambient ADC retries
            app.state.auth_store.upsert_user_connection(
                user_id="alice@google.com",
                mode="access_token",
                project_id="tenant-a-proj-01",
            )
            app.state.credential_service.store_delegated_token(
                user_id="alice@google.com",
                access_token="ya29.alice-lacks-cai-perm-token-1234",
                caller_user_id="alice@google.com",
            )
            cai_attempts: List[Dict[str, Any]] = []

            class _DeniedOnceCaiClient:
                def __init__(self, *args: Any, **kwargs: Any) -> None:
                    cai_attempts.append(dict(kwargs))

                def search_all_resources(self, request: Dict[str, Any]):
                    raise RuntimeError("403 PERMISSION_DENIED: caller lacks cloudasset.assets.searchAllResources")

            monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _DeniedOnceCaiClient)
            wl_res = json.loads(gcp_inventory.collect_workload_evidence("projects/tenant-a-proj-01"))
            assert "PERMISSION_DENIED" in wl_res["error"]
            assert len(cai_attempts) == 1
            assert isinstance(cai_attempts[0].get("credentials"), oauth2_credentials.Credentials)
            assert tripwire_hits == []  # google.auth.default was STILL never called!
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 12: Regression of authorized administrator ADC mode
# ---------------------------------------------------------------------------
def test_12_authorized_administrator_adc_mode_regression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 12: Existing PQC_ADMIN_EMAILS ADC authorization works within allowlisted scope and stays blocked outside it."""
    monkeypatch.setenv("PQC_ADMIN_EMAILS", "secadmin@google.com")
    monkeypatch.setenv("PQC_ALLOWED_ORGANIZATIONS", "secadmin@google.com=111111111111")
    app = _create_app(tmp_path, monkeypatch, "s12_admin_adc")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        cai_inits: List[Dict[str, Any]] = []
        items = _make_fake_cai_items("admin-org-proj")

        class _AdminCaiClient:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                cai_inits.append(dict(kwargs))

            def search_all_resources(self, request: Dict[str, Any]):
                asset_types = set(request.get("asset_types") or [])
                if "cloudkms.googleapis.com/KeyRing" in asset_types:
                    return list(items["kms"])
                return []

        class _AdminKmsClient:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            def list_key_rings(self, request: Dict[str, Any]):
                return [SimpleNamespace(name="projects/admin-org-proj/locations/us-central1/keyRings/kr-delegated")]

            def list_crypto_keys(self, request: Dict[str, Any]):
                return []

        monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _AdminCaiClient)
        monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", _AdminKmsClient)

        with TestClient(app) as client:
            headers, login_body = _login_delegated(client, "secadmin@google.com", bind_gcp=False)
            conn = login_body["connection"]
            assert conn["mode"] == "adc"
            assert conn["adc_authorized"] is True
            assert conn["organization_id"] == "111111111111"
            assert conn["active_scope_uri"] == "organizations/111111111111"

            # Admin succeeds on allowlisted organization (client_kwargs={} -> ADC)
            gcloud_bridge.set_current_tenant_user("secadmin@google.com")
            admin_res = json.loads(gcp_inventory.collect_kms_inventory("organizations/111111111111"))
            assert admin_res["scope"] == "organizations/111111111111" and "error" not in admin_res
            assert cai_inits == [{}]

            # Admin is STILL denied on non-allowlisted org and non-allowlisted project (0 additional SDK calls)
            denied_org = json.loads(gcp_inventory.collect_kms_inventory("organizations/999999999999"))
            denied_proj = json.loads(gcp_inventory.collect_kms_inventory("projects/foreign-proj-99"))
            assert "UNAUTHORIZED_RESOURCE_SCOPE" in denied_org["error"]
            assert "UNAUTHORIZED_RESOURCE_SCOPE" in denied_proj["error"]
            assert len(cai_inits) == 1
            assert client.post("/api/connection", headers=headers, json={"mode": "adc", "organization_id": "999999999999"}).status_code == 403
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 13: Regression of explicit demo/simulation mode
# ---------------------------------------------------------------------------
def test_13_explicit_demo_and_simulation_mode_regression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 13: Explicit demo scope (`demo-pqc-project`) and `PQC_SIMULATION_MODE=TRUE` work with zero live SDK/ADC calls."""
    app = _create_app(tmp_path, monkeypatch, "s13_demo")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        tripwire_hits = _install_sdk_tripwires(monkeypatch)
        with TestClient(app) as client:
            headers, _ = _login_delegated(client, "demo.viewer@google.com", bind_gcp=False)
            demo_sess = client.post("/api/sessions", headers=headers, json={"title": "Demo", "scope": "demo-pqc-project"})
            assert demo_sess.status_code == 200
            assert demo_sess.json()["scope"] == "projects/demo-pqc-project"

            gcloud_bridge.set_current_tenant_user("demo.viewer@google.com")
            for name, res in _run_all_collectors("demo-pqc-project").items():
                assert res["data_source"] == gcp_inventory.SIMULATED_DATA_SOURCE, f"{name} did not return demo data"
                assert "simulation_notice" in res
                assert "error" not in res

            demo_sc = json.loads(gcp_inventory.compute_pqc_scorecard("demo-pqc-project"))
            demo_cbom = json.loads(gcp_inventory.export_cyclonedx_cbom("demo-pqc-project"))
            assert demo_sc["data_sources"]["kms_inventory"] == gcp_inventory.SIMULATED_DATA_SOURCE
            assert demo_cbom["bomFormat"] == "CycloneDX"
            assert demo_cbom["export_notes"]["data_source"] == gcp_inventory.SIMULATED_DATA_SOURCE

            monkeypatch.setenv("PQC_SIMULATION_MODE", "TRUE")
            gcp_inventory._SCAN_CACHE.clear()
            sim_kms = json.loads(gcp_inventory.collect_kms_inventory("organizations/111111111111"))
            assert sim_kms["data_source"] == gcp_inventory.SIMULATED_DATA_SOURCE

        assert tripwire_hits == []
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# Scenario 14: Scorecard and CycloneDX CBOM workflows under authorized delegated access
# ---------------------------------------------------------------------------
def test_14_scorecard_and_cyclonedx_workflows_under_authorized_delegated_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """Scenario 14: Scorecard (KMS + TLS + Compute PQ lookup + BYOK) and CycloneDX CBOM succeed under authorized delegated access and fail closed outside scope."""
    monkeypatch.setenv(
        "PQC_TENANT_SCOPE_POLICY",
        json.dumps(
            {
                "alice@google.com": {"projects": ["tenant-a-proj-01"], "organizations": []},
                "bob@google.com": {"organizations": ["222222222222"], "projects": []},
            }
        ),
    )
    app = _create_app(tmp_path, monkeypatch, "s14_sc_cbom")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        telemetry = _install_mock_sdk(monkeypatch, "tenant-a-proj-01", omit_pq_in_cai=True)

        with TestClient(app) as client:
            _login_delegated(client, "alice@google.com", bind_gcp=True)
            gcloud_bridge.set_current_tenant_user("alice@google.com")

            sc_proj = json.loads(gcp_inventory.compute_pqc_scorecard("projects/tenant-a-proj-01", include_network_and_byok=True))
            assert sc_proj["scope"] == "projects/tenant-a-proj-01"
            assert sc_proj["completeness_status"] == "COMPLETE"
            assert sc_proj["inventory_complete"] is True
            assert sc_proj["counts"]["active_asymmetric_pqc_keys"] == 1
            assert sc_proj["metrics"]["https_proxies_pqc_ready_tls_1_3"]["numerator"] == 1
            assert sc_proj["metrics"]["byok_import_jobs_using_pqc_wrapping"]["numerator"] == 1
            assert len(telemetry["compute_inits"]) == 1
            assert isinstance(telemetry["compute_inits"][0].get("credentials"), oauth2_credentials.Credentials)

            cbom_proj = json.loads(gcp_inventory.export_cyclonedx_cbom("projects/tenant-a-proj-01"))
            assert cbom_proj["bomFormat"] == "CycloneDX"
            assert cbom_proj["specVersion"] == "1.6"
            assert cbom_proj["metadata"]["component"]["name"] == "projects/tenant-a-proj-01"
            assert len(cbom_proj["components"]) == 1

            prior_cai = len(telemetry["cai_inits"])
            denied_sc = json.loads(gcp_inventory.compute_pqc_scorecard("organizations/222222222222"))
            denied_cbom = json.loads(gcp_inventory.export_cyclonedx_cbom("organizations/222222222222"))
            assert denied_sc["completeness_status"] == "COLLECTION_FAILED"
            assert "UNAUTHORIZED_RESOURCE_SCOPE" in denied_sc["error"]
            assert "UNAUTHORIZED_RESOURCE_SCOPE" in denied_cbom["error"]
            assert len(telemetry["cai_inits"]) == prior_cai

            _login_delegated(client, "bob@google.com", bind_gcp=True)
            gcloud_bridge.set_current_tenant_user("bob@google.com")
            sc_org = json.loads(gcp_inventory.compute_pqc_scorecard("organizations/222222222222", include_network_and_byok=True))
            cbom_org = json.loads(gcp_inventory.export_cyclonedx_cbom("organizations/222222222222"))
            assert sc_org["scope"] == "organizations/222222222222"
            assert sc_org["completeness_status"] == "COMPLETE"
            assert cbom_org["metadata"]["component"]["name"] == "organizations/222222222222"
            assert len(cbom_org["components"]) == 1

        assert telemetry["adc_calls"] == []
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()


# ---------------------------------------------------------------------------
# End-to-End 3LO OAuth PKCE Callback Scope Binding & Mid-Flow Revocation
# ---------------------------------------------------------------------------
def test_15_oauth_3lo_pkce_callback_enforces_server_bound_scope_and_midflow_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    """End-to-end 3LO OAuth PKCE authorize -> callback binds server-authorized scope and fails closed if scope is revoked mid-flow."""
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "pkce-3lo-client.apps.googleusercontent.com")
    monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "alice@google.com=tenant-a-proj-01")
    app = _create_app(tmp_path, monkeypatch, "s15_pkce_3lo")
    tok_store = auth_store.set_active_auth_store(app.state.auth_store)
    tok_cred = credential_service.set_active_credential_service(app.state.credential_service)
    try:
        telemetry = _install_mock_sdk(monkeypatch, "tenant-a-proj-01")
        monkeypatch.setattr(
            ws,
            "_exchange_oauth_code",
            lambda code, cb_uri: ({"access_token": "ya29.pkce-3lo-delegated-token-123456", "expires_in": 3600}, None),
        )
        with TestClient(app) as client:
            headers, _ = _login_delegated(client, "alice@google.com", bind_gcp=False)

            # 1. Authorize omitting scope -> automatically binds server-authorized project scope
            authz = client.get("/api/auth/oauth/authorize", headers=headers, params={"format": "json"})
            assert authz.status_code == 200
            authz_body = authz.json()
            assert authz_body["target_scope"] == "projects/tenant-a-proj-01"

            # Complete callback -> token bound + server scope active -> collector succeeds!
            cb_ok = client.get(
                "/api/auth/oauth/callback",
                params={"code": "pkce-code-ok-01", "state": authz_body["state"]},
            )
            assert cb_ok.status_code == 200, cb_ok.text
            gcloud_bridge.set_current_tenant_user("alice@google.com")
            kms = json.loads(gcp_inventory.collect_kms_inventory("projects/tenant-a-proj-01"))
            assert kms["key_count"] == 1 and "error" not in kms
            assert telemetry["adc_calls"] == []

            # 2. Start another 3LO flow, then operator revokes Alice's scope BEFORE callback returns -> 403!
            authz2 = client.get("/api/auth/oauth/authorize", headers=headers, params={"format": "json"})
            assert authz2.status_code == 200
            monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "alice@google.com=different-proj-99")
            cb_revoked = client.get(
                "/api/auth/oauth/callback",
                params={"code": "pkce-code-revoked-02", "state": authz2.json()["state"]},
            )
            assert cb_revoked.status_code == 403
            assert "UNAUTHORIZED_RESOURCE_SCOPE" in cb_revoked.text
    finally:
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        app.state.auth_store.close()
