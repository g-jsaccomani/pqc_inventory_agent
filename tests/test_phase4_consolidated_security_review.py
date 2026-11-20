"""Phase 4.1 — Consolidated End-to-End Security Review & Regression Test Suite.

Covers all 20 required verification scenarios across authentication, explicit execution-context
classification, mandatory connection `user_id` ownership binding, delegated token lifecycle,
cryptographically segregated `_SCAN_CACHE` concurrency isolation, standalone SDK helpers,
portal/API onboarding without `POST /api/connection`, startup warmup elimination, and
admin ADC / demo-simulation compatibility.

All tests are deterministic and mock GCP SDK/IAM calls; zero real GCP calls are made.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from pqc_agent import auth_guard, auth_store, credential_service, workspace_server as ws
from tools import gcloud_bridge, gcp_inventory, pqc_detectors


# ---------------------------------------------------------------------------
# Deterministic fixtures & mock helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_env_and_state(monkeypatch: pytest.MonkeyPatch) -> Any:
    for var in (
        "K_SERVICE",
        "PQC_PRODUCTION_MODE",
        "PQC_ENV",
        "PQC_ADMIN_EMAILS",
        "PQC_ALLOWED_PROJECTS",
        "PQC_ALLOWED_ORGANIZATIONS",
        "PQC_ALLOWED_FOLDERS",
        "PQC_TENANT_SCOPE_POLICY",
        "PQC_ALLOW_UNVERIFIED_SIGNIN",
        "PQC_SIMULATION_MODE",
        "PQC_GCP_CONNECTION_MODE",
        "PQC_GCP_ORGANIZATION_ID",
        "PQC_GCP_PROJECT_ID",
        "PQC_OAUTH_CLIENT_ID",
        "PQC_OAUTH_CLIENT_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PQC_AUTH_SECRET", "phase41-consolidated-review-secret-material-64-chars-minimum-01")
    monkeypatch.setenv("PQC_SIMULATION_MODE", "FALSE")
    gcp_inventory._SCAN_CACHE.clear()
    prev_uid = gcloud_bridge.get_current_tenant_user()
    gcloud_bridge.set_current_tenant_user(gcloud_bridge.DEFAULT_TENANT_USER_ID)
    yield
    gcp_inventory._SCAN_CACHE.clear()
    gcloud_bridge.set_current_tenant_user(prev_uid)


def _make_app(tmp_path: Path, *, verify_models_on_startup: bool = False) -> Any:
    class _FakeRegistry:
        def __init__(self) -> None:
            self.bg_started = False

        def start_background_verification(self) -> None:
            self.bg_started = True

        def catalog_response(self) -> Dict[str, Any]:
            return {
                "models": [{"id": "gemini-2.5-flash", "model": "gemini-2.5-flash", "label": "Gemini 2.5 Flash", "tier": "Fast"}],
                "verified": True,
            }

        def verified_entries(self) -> List[Dict[str, Any]]:
            return [{"id": "gemini-2.5-flash", "model": "gemini-2.5-flash", "label": "Gemini 2.5 Flash", "tier": "Fast"}]

        def resolve(self, model_id: Any) -> Dict[str, Any]:
            return {"id": "gemini-2.5-flash", "model": "gemini-2.5-flash", "label": "Gemini 2.5 Flash", "tier": "Fast"}

        def verify_all(self) -> None:
            return None

    return ws.create_workspace_app(
        session_db_url=f"sqlite:///{tmp_path / 'consolidated_review.db'}",
        verify_models_on_startup=verify_models_on_startup,
        model_registry=_FakeRegistry(),
    )


def _bind_app_stores(app: Any):
    t_store = auth_store.set_active_auth_store(app.state.auth_store)
    t_cred = credential_service.set_active_credential_service(app.state.credential_service)
    return t_store, t_cred


def _unbind_app_stores(tokens: Any, app: Any) -> None:
    t_store, t_cred = tokens
    credential_service.reset_active_credential_service(t_cred)
    auth_store.reset_active_auth_store(t_store)
    app.state.auth_store.close()


def _install_google_verifier(monkeypatch: pytest.MonkeyPatch, valid_tokens: Dict[str, Dict[str, Any]]) -> None:
    def _fake_verify(id_tok: Any = None, access_tok: Any = None):
        raw = id_tok or access_tok or ""
        if raw in valid_tokens:
            return dict(valid_tokens[raw]), None
        return None, "Invalid Google token."

    monkeypatch.setattr(ws, "_verify_google_oauth_or_id_token", _fake_verify)


def _signin_with_oauth_token(client: TestClient, oauth_token: str) -> Dict[str, str]:
    res = client.post(
        "/api/auth/google",
        json={"access_token": oauth_token, "use_token_for_gcp_connection": True},
    )
    assert res.status_code == 200, res.text
    csrf = res.json()["csrf_token"]
    return {"X-PQC-CSRF-Token": csrf}


def _install_tripwires(monkeypatch: pytest.MonkeyPatch) -> Dict[str, List[str]]:
    import google.auth

    hits: Dict[str, List[str]] = {
        "adc_default": [],
        "asset_client": [],
        "kms_client": [],
        "ssl_client": [],
        "region_ssl_client": [],
        "cai_search": [],
        "cache_get": [],
        "cache_put": [],
    }

    def _adc_trap(*a: Any, **kw: Any):
        hits["adc_default"].append("google.auth.default")
        raise AssertionError("google.auth.default() must NOT be invoked!")

    class _AssetTrap:
        def __init__(self, *a: Any, **kw: Any) -> None:
            hits["asset_client"].append("AssetServiceClient")
            raise AssertionError("AssetServiceClient must NOT be instantiated!")

    class _KmsTrap:
        def __init__(self, *a: Any, **kw: Any) -> None:
            hits["kms_client"].append("KeyManagementServiceClient")
            raise AssertionError("KeyManagementServiceClient must NOT be instantiated!")

    class _SslTrap:
        def __init__(self, *a: Any, **kw: Any) -> None:
            hits["ssl_client"].append("SslPoliciesClient")
            raise AssertionError("SslPoliciesClient must NOT be instantiated!")

    class _RegionSslTrap:
        def __init__(self, *a: Any, **kw: Any) -> None:
            hits["region_ssl_client"].append("RegionSslPoliciesClient")
            raise AssertionError("RegionSslPoliciesClient must NOT be instantiated!")

    def _cai_trap(*a: Any, **kw: Any):
        hits["cai_search"].append("cai")
        raise AssertionError("_cai_search_all_resources must NOT be called!")

    def _cache_get_trap(*a: Any, **kw: Any):
        hits["cache_get"].append(str(a[0]) if a else "")
        raise AssertionError("_cache_get must NOT be called!")

    def _cache_put_trap(*a: Any, **kw: Any):
        hits["cache_put"].append(str(a[0]) if a else "")
        raise AssertionError("_cache_put must NOT be called!")

    monkeypatch.setattr(google.auth, "default", _adc_trap)
    monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _AssetTrap)
    monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", _KmsTrap)
    monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", _AssetTrap)
    monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", _KmsTrap)
    monkeypatch.setattr(pqc_detectors.compute_v1, "SslPoliciesClient", _SslTrap)
    monkeypatch.setattr(pqc_detectors.compute_v1, "RegionSslPoliciesClient", _RegionSslTrap)
    monkeypatch.setattr(gcp_inventory, "_cai_search_all_resources", _cai_trap)
    monkeypatch.setattr(pqc_detectors, "_cai_search_all_resources", _cai_trap)
    monkeypatch.setattr(gcp_inventory, "_cache_get", _cache_get_trap)
    monkeypatch.setattr(gcp_inventory, "_cache_put", _cache_put_trap)
    monkeypatch.setattr(pqc_detectors, "_cache_get", _cache_get_trap)
    monkeypatch.setattr(pqc_detectors, "_cache_put", _cache_put_trap)
    return hits


def _install_mock_sdk(monkeypatch: pytest.MonkeyPatch, *, token_recorder: List[str], scope_recorder: List[str]) -> None:
    """Installs lightweight deterministic GCP SDK mocks returning scope-tagged synthetic assets."""

    class _MockCaiItem:
        def __init__(self, asset_type: str, name: str, project: str, location: str = "global") -> None:
            self.asset_type = asset_type
            self.name = name
            self.display_name = name.split("/")[-1]
            self.project = project
            self.location = location
            self.labels = {"env": "test"}
            self.state = "ACTIVE"
            self.kms_key = ""
            self.kms_keys = []
            self.versioned_resources = []

    class _MockAssetClient:
        def __init__(self, **kwargs: Any) -> None:
            creds = kwargs.get("credentials")
            token_recorder.append(str(getattr(creds, "token", "ADC")))

        def search_all_resources(self, request: Dict[str, Any]):
            scope = request["scope"]
            scope_recorder.append(scope)
            asset_types = set(request.get("asset_types") or [])
            proj_tag = scope.replace("/", "-")
            if "cloudkms.googleapis.com/KeyRing" in asset_types:
                return [
                    _MockCaiItem(
                        "cloudkms.googleapis.com/KeyRing",
                        f"//cloudkms.googleapis.com/projects/{proj_tag}/locations/global/keyRings/kr-1",
                        proj_tag,
                    )
                ]
            if "compute.googleapis.com/SslPolicy" in asset_types and "compute.googleapis.com/TargetHttpsProxy" in asset_types:
                return [
                    _MockCaiItem(
                        "compute.googleapis.com/TargetHttpsProxy",
                        f"//compute.googleapis.com/projects/{proj_tag}/global/targetHttpsProxies/proxy-1",
                        proj_tag,
                    )
                ]
            return [
                _MockCaiItem(
                    "run.googleapis.com/Service",
                    f"//run.googleapis.com/projects/{proj_tag}/locations/us-central1/services/svc-1",
                    proj_tag,
                    "us-central1",
                )
            ]

    class _MockKmsClient:
        def __init__(self, **kwargs: Any) -> None:
            creds = kwargs.get("credentials")
            token_recorder.append(str(getattr(creds, "token", "ADC")))

        def list_key_rings(self, request: Dict[str, Any]):
            return []

        def list_crypto_keys(self, request: Dict[str, Any]):
            return []

        def list_import_jobs(self, request: Dict[str, Any]):
            return []

    monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _MockAssetClient)
    monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", _MockKmsClient)
    monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", _MockAssetClient)
    monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", _MockKmsClient)


def _run_all_collectors(scope: str) -> Dict[str, Dict[str, Any]]:
    return {
        "kms": json.loads(gcp_inventory.collect_kms_inventory(scope=scope)),
        "workloads": json.loads(gcp_inventory.collect_workload_evidence(scope=scope)),
        "crypto": json.loads(gcp_inventory.discover_all_crypto_assets(scope=scope)),
        "tls": json.loads(pqc_detectors.collect_tls_policies(scope=scope)),
        "import_jobs": json.loads(pqc_detectors.collect_kms_import_jobs(scope=scope)),
    }


# ---------------------------------------------------------------------------
# Req 1 & 2: Valid delegated project & organization scopes succeed
# ---------------------------------------------------------------------------


def test_01_02_valid_delegated_project_and_org_scopes_succeed_with_scorecard_and_cbom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reqs 1 & 2: Valid delegated project and organization scopes succeed across all 5 collectors, scorecard, and CBOM."""
    monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "alice@tenant-a.example=tenant-a-proj-01")
    monkeypatch.setenv("PQC_ALLOWED_ORGANIZATIONS", "bob@tenant-b.example=222222222222")

    app = _make_app(tmp_path)
    tokens = _bind_app_stores(app)
    try:
        tok_rec: List[str] = []
        scope_rec: List[str] = []
        _install_mock_sdk(monkeypatch, token_recorder=tok_rec, scope_recorder=scope_rec)

        # Req 1: Alice delegated project scope
        gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")
        gcloud_bridge.set_gcp_connection_config(
            mode="access_token",
            access_token="ya29.alice-delegated-project-token-0001",
            access_token_expires_in=3600,
            user_id="alice@tenant-a.example",
        )
        alice_results = _run_all_collectors("projects/tenant-a-proj-01")
        for name, res in alice_results.items():
            assert "error" not in res, f"Alice project {name} failed: {res}"
            assert res["scope"] == "projects/tenant-a-proj-01"
            assert res["data_source"] == gcp_inventory.LIVE_DATA_SOURCE
        sc_a = json.loads(gcp_inventory.compute_pqc_scorecard("projects/tenant-a-proj-01"))
        cbom_a = json.loads(gcp_inventory.export_cyclonedx_cbom("projects/tenant-a-proj-01"))
        assert "error" not in sc_a and sc_a["scope"] == "projects/tenant-a-proj-01"
        assert cbom_a["bomFormat"] == "CycloneDX"
        assert "ya29.alice-delegated-project-token-0001" in tok_rec
        assert "projects/tenant-a-proj-01" in scope_rec

        # Req 2: Bob delegated organization scope
        gcloud_bridge.set_current_tenant_user("bob@tenant-b.example")
        gcloud_bridge.set_gcp_connection_config(
            mode="access_token",
            access_token="ya29.bob-delegated-org-token-0002",
            access_token_expires_in=3600,
            user_id="bob@tenant-b.example",
        )
        bob_results = _run_all_collectors("organizations/222222222222")
        for name, res in bob_results.items():
            assert "error" not in res, f"Bob org {name} failed: {res}"
            assert res["scope"] == "organizations/222222222222"
            assert res["data_source"] == gcp_inventory.LIVE_DATA_SOURCE
        sc_b = json.loads(gcp_inventory.compute_pqc_scorecard("organizations/222222222222"))
        cbom_b = json.loads(gcp_inventory.export_cyclonedx_cbom("organizations/222222222222"))
        assert "error" not in sc_b and sc_b["scope"] == "organizations/222222222222"
        assert cbom_b["bomFormat"] == "CycloneDX"
        assert "ya29.bob-delegated-org-token-0002" in tok_rec
        assert "organizations/222222222222" in scope_rec
    finally:
        _unbind_app_stores(tokens, app)


# ---------------------------------------------------------------------------
# Req 3, 4, 5, 6, 7: Missing connection, missing user_id binding (CR-01),
# mismatched identity, malformed scope, and lookup exception fail closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_conn",
    [
        {"organization_id": "222222222222", "mode": "access_token"},  # missing user_id key
        {"user_id": None, "organization_id": "222222222222", "mode": "access_token"},  # None user_id
        {"user_id": "", "project_id": "tenant-b-proj-02", "mode": "access_token"},  # empty user_id
        {"user_id": "   ", "project_id": "tenant-b-proj-02", "mode": "access_token"},  # whitespace user_id
        {"user_id": 12345, "organization_id": "222222222222", "mode": "access_token"},  # non-str user_id
        {"user_id": "bob@tenant-b.example", "organization_id": "222222222222", "mode": "access_token"},  # mismatched user_id
    ],
)
def test_04_05_missing_or_mismatched_user_id_ownership_binding_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_conn: Dict[str, Any]
) -> None:
    """Reqs 4 & 5 (CR-01): Missing, empty, None, non-string, or mismatched connection user_id NEVER bypasses ownership checks."""
    app = _make_app(tmp_path)
    tokens = _bind_app_stores(app)
    try:
        hits = _install_tripwires(monkeypatch)
        gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")

        # 1. resolve_authorized_tenant_scope rejects missing/mismatched user_id
        with pytest.raises(PermissionError, match="ownership binding"):
            gcloud_bridge.resolve_authorized_tenant_scope("alice@tenant-a.example", bad_conn)

        # 2. authorize_gcp_scope rejects missing/mismatched user_id (direct conn_cfg and monkeypatched getter)
        with pytest.raises(PermissionError, match="ownership binding"):
            gcloud_bridge.authorize_gcp_scope("organizations/222222222222", conn_cfg=bad_conn)

        monkeypatch.setattr(gcloud_bridge, "get_gcp_connection_config", lambda **kw: bad_conn)
        with pytest.raises(PermissionError, match="ownership binding"):
            gcloud_bridge.authorize_gcp_scope("organizations/222222222222")

        # 3. _active_tenant_default_scope fails closed as UNBOUND (never accepts missing user_id or DEFAULT_ORGANIZATION_ID)
        assert gcp_inventory._active_tenant_default_scope() == ("UNBOUND", "", "")
        assert gcp_inventory._active_tenant_org_id() == ""

        # 4. All 5 live collectors fail closed with zero SDK/ADC/CAI/cache access
        for res in _run_all_collectors("org").values():
            assert "error" in res
            assert gcp_inventory.DEFAULT_ORGANIZATION_ID not in json.dumps(res)
        assert all(len(v) == 0 for v in hits.values()), hits
    finally:
        _unbind_app_stores(tokens, app)


def test_03_06_07_missing_connection_malformed_scope_and_lookup_exception_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reqs 3, 6, 7: Missing tenant connection, malformed scopes, and identity lookup exceptions fail closed with 0 tripwire hits."""
    app = _make_app(tmp_path)
    tokens = _bind_app_stores(app)
    try:
        hits = _install_tripwires(monkeypatch)
        gcloud_bridge.set_current_tenant_user("unbound@tenant-a.example")

        # Req 3: Missing connection
        assert gcp_inventory._active_tenant_default_scope() == ("UNBOUND", "", "")
        for res in _run_all_collectors("org").values():
            assert "MISSING_AUTHORIZED_SCOPE" in res["error"] or "UNAUTHORIZED_RESOURCE_SCOPE" in res["error"]

        # Req 6: Malformed scopes
        for bad_scope in ("organizations/", "projects/", "folders/abc", "projects/../victim", "organizations/12345;rm"):
            with pytest.raises(PermissionError):
                gcloud_bridge.authorize_gcp_scope(bad_scope)

        # Req 7: Identity lookup exception fails closed
        monkeypatch.setattr(
            gcloud_bridge,
            "get_current_tenant_user",
            lambda: (_ for _ in ()).throw(RuntimeError("sensitive-secret-in-error-must-not-leak")),
        )
        assert gcp_inventory._active_tenant_default_scope() == ("UNBOUND", "", "")
        for res in _run_all_collectors("org").values():
            assert "error" in res
            assert gcp_inventory.DEFAULT_ORGANIZATION_ID not in json.dumps(res)

        assert all(len(v) == 0 for v in hits.values()), hits
    finally:
        _unbind_app_stores(tokens, app)


# ---------------------------------------------------------------------------
# Req 8: Explicit execution-context classification (CR-02)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "arbitrary_identity",
    [
        "corp-admin",
        "tenant-42",
        "service-worker",
        "bob",
        "admin",
        "guest",
        "@invalid.example",
        "user@",
        "a@@b.example",
        "alice @tenant.example",
    ],
)
def test_08_non_email_identities_cannot_receive_default_org_or_authenticated_privileges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arbitrary_identity: str
) -> None:
    """Req 8 (CR-02): Arbitrary non-email / malformed identities classify as 'invalid', get UNBOUND, and never get privileges."""
    app = _make_app(tmp_path)
    tokens = _bind_app_stores(app)
    try:
        hits = _install_tripwires(monkeypatch)
        gcloud_bridge.set_current_tenant_user(arbitrary_identity)

        ctx_kind, ctx_uid = gcloud_bridge.classify_execution_context()
        assert ctx_kind == "invalid", (arbitrary_identity, ctx_kind, ctx_uid)
        assert ctx_uid == ""
        assert gcp_inventory._active_tenant_default_scope() == ("UNBOUND", "", "")
        assert gcp_inventory._active_tenant_org_id() == ""

        for res in _run_all_collectors("org").values():
            assert "UNAUTHENTICATED_EXECUTION_CONTEXT" in res["error"]
            assert gcp_inventory.DEFAULT_ORGANIZATION_ID not in json.dumps(res)
        assert all(len(v) == 0 for v in hits.values()), hits
    finally:
        _unbind_app_stores(tokens, app)


def test_08b_production_and_http_request_contexts_never_classify_as_unauthenticated_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Req 8 (CR-02): Even 'sec-architect'/'default' NEVER receive DEFAULT_ORGANIZATION_ID in production or inside HTTP requests."""
    app = _make_app(tmp_path)
    tokens = _bind_app_stores(app)
    try:
        hits = _install_tripwires(monkeypatch)

        # 1. Production environment: even explicit CLI placeholders fail closed
        monkeypatch.setenv("PQC_PRODUCTION_MODE", "true")
        for placeholder in ("sec-architect", "default"):
            gcloud_bridge.set_current_tenant_user(placeholder)
            assert gcloud_bridge.classify_execution_context() == ("invalid", "")
            assert gcp_inventory._active_tenant_default_scope() == ("UNBOUND", "", "")

        # 2. Non-production HTTP request entry context: unauthenticated HTTP request is 'unverified', never 'unauthenticated_cli'
        monkeypatch.delenv("PQC_PRODUCTION_MODE", raising=False)
        req_toks = gcloud_bridge.enter_http_request_tenant_context()
        try:
            assert gcloud_bridge.classify_execution_context() == ("invalid", "")
            assert gcp_inventory._active_tenant_default_scope() == ("UNBOUND", "", "")
            # Inside HTTP request, authenticating promotes context to 'authenticated'
            gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")
            assert gcloud_bridge.classify_execution_context() == ("authenticated", "alice@tenant-a.example")
        finally:
            gcloud_bridge.exit_http_request_tenant_context(req_toks)

        # 3. After HTTP request exits, Alice's identity does NOT bleed into outer context!
        assert gcloud_bridge.get_current_tenant_user() != "alice@tenant-a.example"
        assert all(len(v) == 0 for v in hits.values()), hits
    finally:
        _unbind_app_stores(tokens, app)


# ---------------------------------------------------------------------------
# Req 9, 10, 11, 13, 14, 15, 16, 17: Scope overrides, expired/revoked tokens,
# standalone SDK helpers, and zero unauthorized SDK/ADC/CAI/cache calls
# ---------------------------------------------------------------------------


def test_10_11_13_14_15_16_17_expired_revoked_and_explicit_foreign_scopes_blocked_before_cache_or_sdk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reqs 10, 11, 13-17 (CR-06): Expired/revoked tokens (with warm cache) & explicit foreign scopes fail closed with 0 SDK/ADC/CAI/cache calls."""
    monkeypatch.setenv("PQC_ALLOWED_ORGANIZATIONS", "alice@tenant-a.example=111111111111")
    monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "alice@tenant-a.example=tenant-a-proj-01")

    app = _make_app(tmp_path)
    tokens = _bind_app_stores(app)
    try:
        tok_rec: List[str] = []
        scope_rec: List[str] = []
        _install_mock_sdk(monkeypatch, token_recorder=tok_rec, scope_recorder=scope_rec)

        gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")
        gcloud_bridge.set_gcp_connection_config(
            mode="access_token",
            access_token="ya29.alice-warm-token-9999",
            access_token_expires_in=3600,
            user_id="alice@tenant-a.example",
        )
        # Warm _SCAN_CACHE across all 5 collectors
        warmed = _run_all_collectors("organizations/111111111111")
        assert all("error" not in v for v in warmed.values())
        assert len(gcp_inventory._SCAN_CACHE) >= 5

        # Now install hard tripwires BEFORE revoking & testing unauthorized scopes
        hits = _install_tripwires(monkeypatch)

        # Req 17: Explicit foreign organizations/<id> and projects/<id> denied before cache or SDK
        for foreign_scope in ("organizations/222222222222", "projects/tenant-b-proj-02", "folders/777777777777"):
            for res in _run_all_collectors(foreign_scope).values():
                assert "UNAUTHORIZED_RESOURCE_SCOPE" in res["error"]

        # CR-06: Standalone _fetch_compute_pq_key_exchange propagates PermissionError (never swallows to None)
        with pytest.raises(PermissionError, match="UNAUTHORIZED_RESOURCE_SCOPE"):
            pqc_detectors._fetch_compute_pq_key_exchange("tenant-b-proj-02", "global", "pol-1")

        # Req 11: Revoke delegated token -> even previously CACHED org scope is denied with 0 cache/SDK/ADC/CAI access
        gcloud_bridge.clear_user_access_token("alice@tenant-a.example")
        for res in _run_all_collectors("organizations/111111111111").values():
            assert "ACCESS_TOKEN_REQUIRED" in res["error"]

        # Req 10: Store expired token via direct DB row expiry simulation -> denied with 0 cache/SDK/ADC/CAI access
        app.state.credential_service.store_delegated_token(
            user_id="alice@tenant-a.example",
            access_token="ya29.alice-expiring-token-1234",
            expires_in=1.0,
            caller_user_id="alice@tenant-a.example",
        )
        # Advance clock via monkeypatched time.time in credential_service so token is expired
        future_ts = time.time() + 120.0
        monkeypatch.setattr(credential_service.time, "time", lambda: future_ts)
        for res in _run_all_collectors("organizations/111111111111").values():
            assert "ACCESS_TOKEN_REQUIRED" in res["error"]

        assert all(len(v) == 0 for v in hits.values()), hits
    finally:
        _unbind_app_stores(tokens, app)


# ---------------------------------------------------------------------------
# Req 12: Cache isolation across tenants, token rotation, scope changes & concurrency (CR-03)
# ---------------------------------------------------------------------------


def test_12_cache_isolation_across_tenants_token_preview_collisions_scope_changes_and_concurrency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Req 12 (CR-03): Zero cross-tenant cache reuse, zero preview-collision reuse, scope-change segregation, and thread safety."""
    monkeypatch.setenv(
        "PQC_TENANT_SCOPE_POLICY",
        json.dumps(
            {
                "alice@tenant-a.example": {"organizations": ["111111111111"], "projects": ["tenant-a-proj-01"]},
                "bob@tenant-b.example": {"organizations": ["222222222222"], "projects": ["tenant-b-proj-02"]},
            }
        ),
    )

    app = _make_app(tmp_path)
    tokens = _bind_app_stores(app)
    try:
        call_log: List[str] = []
        call_lock = threading.Lock()

        class _TaggingAssetClient:
            def __init__(self, **kwargs: Any) -> None:
                self._tok = str(getattr(kwargs.get("credentials"), "token", ""))

            def search_all_resources(self, request: Dict[str, Any]):
                with call_lock:
                    call_log.append(f"{self._tok}|{request['scope']}")
                item = MagicMock()
                item.asset_type = "run.googleapis.com/Service"
                item.name = f"//run.googleapis.com/projects/{request['scope'].replace('/', '-')}/locations/us-central1/services/tok-{self._tok[-8:]}"
                item.display_name = f"svc-{self._tok[-8:]}"
                item.project = request["scope"]
                item.location = "us-central1"
                item.labels = {"tok_marker": self._tok}
                item.kms_key = ""
                item.kms_keys = []
                item.state = "ACTIVE"
                item.versioned_resources = []
                return [item]

        monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _TaggingAssetClient)

        # 1. Token preview collision attack: two DIFFERENT tokens sharing identical first 6 ("ya29.A") and last 4 ("ZZZZ")
        tok_v1 = "ya29.A-FIRST-SECRET-TOKEN-111111-ZZZZ"
        tok_v2 = "ya29.A-SECOND-ROTATED-TOKEN-22222-ZZZZ"
        assert tok_v1[:6] == tok_v2[:6] and tok_v1[-4:] == tok_v2[-4:]

        gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")
        gcloud_bridge.set_gcp_connection_config(
            mode="access_token", access_token=tok_v1, access_token_expires_in=3600, user_id="alice@tenant-a.example"
        )
        res_v1 = json.loads(gcp_inventory.collect_workload_evidence("projects/tenant-a-proj-01"))
        assert res_v1["workloads"][0]["labels"]["tok_marker"] == tok_v1
        assert len(call_log) == 1

        # Rotate to tok_v2 (same masked preview!) -> MUST NOT reuse tok_v1 cache!
        gcloud_bridge.set_gcp_connection_config(
            mode="access_token", access_token=tok_v2, access_token_expires_in=3600, user_id="alice@tenant-a.example"
        )
        res_v2 = json.loads(gcp_inventory.collect_workload_evidence("projects/tenant-a-proj-01"))
        assert res_v2["workloads"][0]["labels"]["tok_marker"] == tok_v2
        assert len(call_log) == 2

        # 2. Scope policy change immediately segregates cached results (cache miss -> fresh query)
        monkeypatch.setenv(
            "PQC_TENANT_SCOPE_POLICY",
            json.dumps(
                {
                    "alice@tenant-a.example": {"projects": ["tenant-a-proj-01"]},  # org removed!
                    "bob@tenant-b.example": {"organizations": ["222222222222"], "projects": ["tenant-b-proj-02"]},
                }
            ),
        )
        res_v2_new_scope = json.loads(gcp_inventory.collect_workload_evidence("projects/tenant-a-proj-01"))
        assert "error" not in res_v2_new_scope
        assert len(call_log) == 3  # new scope_sig triggered fresh fetch rather than reusing old org+proj cache

        # Verify zero 'unconfigured' keys exist in _SCAN_CACHE
        assert all(not k.startswith("unconfigured:") for k in gcp_inventory._SCAN_CACHE.keys())

        # 3. Concurrent multi-tenant execution (10 Alice threads + 10 Bob threads) -> zero cross-contamination
        tok_bob = "ya29.BOB-EXCLUSIVE-TOKEN-99999"
        gcloud_bridge.set_current_tenant_user("bob@tenant-b.example")
        gcloud_bridge.set_gcp_connection_config(
            mode="access_token", access_token=tok_bob, access_token_expires_in=3600, user_id="bob@tenant-b.example"
        )

        def _worker(uid: str, scope: str, expected_tok: str) -> None:
            t_s = auth_store.set_active_auth_store(app.state.auth_store)
            t_c = credential_service.set_active_credential_service(app.state.credential_service)
            try:
                gcloud_bridge.set_current_tenant_user(uid)
                payload = json.loads(gcp_inventory.collect_workload_evidence(scope))
                assert "error" not in payload, payload
                assert payload["scope"] == scope
                assert payload["workloads"][0]["labels"]["tok_marker"] == expected_tok
            finally:
                credential_service.reset_active_credential_service(t_c)
                auth_store.reset_active_auth_store(t_s)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futs = []
            for i in range(20):
                if i % 2 == 0:
                    futs.append(pool.submit(_worker, "alice@tenant-a.example", "projects/tenant-a-proj-01", tok_v2))
                else:
                    futs.append(pool.submit(_worker, "bob@tenant-b.example", "projects/tenant-b-proj-02", tok_bob))
            for f in futs:
                f.result()
    finally:
        _unbind_app_stores(tokens, app)


# ---------------------------------------------------------------------------
# Req 18 & 19: Admin ADC and Demo/Simulation regression tests
# ---------------------------------------------------------------------------


def test_18_19_admin_adc_and_demo_simulation_regressions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reqs 18 & 19: Authorized admin ADC and demo/simulation modes continue working cleanly and remain segregated."""
    import google.auth

    monkeypatch.setenv("PQC_ADMIN_EMAILS", "secadmin@google.com")
    monkeypatch.setenv("PQC_ALLOWED_ORGANIZATIONS", "secadmin@google.com=111111111111")

    app = _make_app(tmp_path)
    tokens = _bind_app_stores(app)
    try:
        tok_rec: List[str] = []
        scope_rec: List[str] = []
        _install_mock_sdk(monkeypatch, token_recorder=tok_rec, scope_recorder=scope_rec)
        fake_adc_creds = MagicMock()
        fake_adc_creds.token = None
        monkeypatch.setattr(google.auth, "default", lambda scopes=None: (fake_adc_creds, "admin-proj"))

        # Req 18: Authorized Admin ADC succeeds
        gcloud_bridge.set_current_tenant_user("secadmin@google.com")
        cfg = gcloud_bridge.set_gcp_connection_config(
            mode="adc", organization_id="111111111111", user_id="secadmin@google.com"
        )
        assert cfg["mode"] == "adc" and cfg["adc_authorized"] is True
        admin_res = _run_all_collectors("organizations/111111111111")
        assert all("error" not in v and v["data_source"] == gcp_inventory.LIVE_DATA_SOURCE for v in admin_res.values())
        assert any(k.startswith("live:secadmin@google.com:adc:") for k in gcp_inventory._SCAN_CACHE.keys())

        # Req 19: Explicit demo scope succeeds without invoking live SDK and caches ONLY under 'sim:' namespace
        demo_res = _run_all_collectors("demo-pqc-project")
        assert all(
            "error" not in v and v["data_source"] == gcp_inventory.SIMULATED_DATA_SOURCE for v in demo_res.values()
        )
        sc_demo = json.loads(gcp_inventory.compute_pqc_scorecard("demo-pqc-project"))
        cbom_demo = json.loads(gcp_inventory.export_cyclonedx_cbom("demo-pqc-project"))
        assert sc_demo["data_sources"]["kms_inventory"] == gcp_inventory.SIMULATED_DATA_SOURCE
        assert cbom_demo["bomFormat"] == "CycloneDX"
        assert any(k.startswith("sim:") for k in gcp_inventory._SCAN_CACHE.keys())
        assert all(not k.startswith("unconfigured:") for k in gcp_inventory._SCAN_CACHE.keys())
    finally:
        _unbind_app_stores(tokens, app)


# ---------------------------------------------------------------------------
# Req 9 & 20: End-to-end Portal/API onboarding, client scope override rejection,
# startup warmup removal (CR-04, CR-05, CR-07)
# ---------------------------------------------------------------------------


def test_09_20_portal_ui_onboarding_without_connection_post_and_zero_hardcoded_default_org(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reqs 9 & 20 (CR-04, CR-05, CR-07): Portal UI & API bind server scope without POST /api/connection, reject overrides, and skip startup warmup."""
    monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "alice@google.com=tenant-a-proj-01")
    monkeypatch.setenv("PQC_PRODUCTION_MODE", "true")
    monkeypatch.setenv("PQC_AUTH_SECRET", "prod-test-secret-0123456789abcdef0123456789abcdef")

    # CR-05: Even with verify_models_on_startup=True, ZERO unauthenticated inventory warmup threads or collector calls run!
    collector_calls: List[str] = []
    monkeypatch.setattr(gcp_inventory, "collect_kms_inventory", lambda *a, **kw: collector_calls.append("kms") or "{}")
    monkeypatch.setattr(ws, "_verify_startup_db_ready", lambda *a, **kw: None) if hasattr(ws, "_verify_startup_db_ready") else None

    # Off production for SQLite local test DB creation + schema init, then turn on production mode with mocked Cloud KMS
    monkeypatch.delenv("PQC_PRODUCTION_MODE", raising=False)
    app = _make_app(tmp_path, verify_models_on_startup=True)
    asyncio.run(app.state.session_service.prepare_tables())

    class _StubKmsClient:
        def encrypt(self, request: Dict[str, Any]):
            aad = bytes(request.get("additional_authenticated_data") or b"")
            pt = bytes(request["plaintext"])
            resp = MagicMock()
            resp.ciphertext = b"KMS1:" + aad + b"::" + pt
            return resp

        def decrypt(self, request: Dict[str, Any]):
            aad = bytes(request.get("additional_authenticated_data") or b"")
            ct = bytes(request["ciphertext"])
            prefix = b"KMS1:" + aad + b"::"
            assert ct.startswith(prefix), "KMS AAD mismatch"
            resp = MagicMock()
            resp.plaintext = ct[len(prefix) :]
            return resp

    monkeypatch.setenv("PQC_KMS_KEY_NAME", "projects/pqc-test/locations/us-central1/keyRings/kr/cryptoKeys/cred-kek")
    app.state.credential_service._kms_client = _StubKmsClient()
    monkeypatch.setenv("PQC_PRODUCTION_MODE", "true")

    _install_google_verifier(
        monkeypatch,
        {
            "ya29.alice-portal-signin-token": {
                "email": "alice@google.com",
                "email_verified": True,
                "name": "Alice Security",
                "expires_in": 3600,
                "auth_method": "google_oauth_token",
            }
        },
    )

    with TestClient(app, base_url="https://testserver") as client:
        # 1. CR-05: Zero unauthenticated startup warmup threads or collector calls
        assert collector_calls == []
        assert not any(t.name == "pqc-inventory-warmup" for t in threading.enumerate())

        # 2. CR-04: Portal UI HTML contains ZERO hardcoded '31564119954' or 'pqc-inventory-agent-cd06'
        portal_html = client.get("/").text
        assert "31564119954" not in portal_html
        assert "pqc-inventory-agent-cd06" not in portal_html
        assert "getActiveTenantScopeUri" in portal_html
        assert "currentActiveScopeUri" in portal_html

        # 3. Alice signs in via OAuth token — NEVER calls POST /api/connection
        csrf_headers = _signin_with_oauth_token(client, "ya29.alice-portal-signin-token")

        # 4. GET /api/connection automatically reports server-bound project scope & token ready
        conn = client.get("/api/connection").json()
        assert conn["user_id"] == "alice@google.com"
        assert conn["project_id"] == "tenant-a-proj-01"
        assert conn["organization_id"] == ""
        assert conn["active_scope_uri"] == "projects/tenant-a-proj-01"
        assert conn["scope_bound_by_server"] is True
        assert conn["has_access_token"] is True

        # 5. POST /api/sessions omitting scope (just like Portal UI) binds server scope (NOT 31564119954)
        sess_res = client.post("/api/sessions", headers=csrf_headers, json={"title": "Onboarding Scan"})
        assert sess_res.status_code == 200, sess_res.text
        sess_body = sess_res.json()
        assert sess_body["scope"] == "projects/tenant-a-proj-01"
        sess_detail = client.get(f"/api/sessions/{sess_body['session_id']}").json()
        assert sess_detail["scope"] == "projects/tenant-a-proj-01"

        # 6. Req 9: Client-supplied foreign org or project override is rejected with HTTP 403
        assert client.post(
            "/api/sessions", headers=csrf_headers, json={"title": "Hijack", "scope": "organizations/31564119954"}
        ).status_code == 403
        assert client.post(
            "/api/chat",
            headers=csrf_headers,
            data={"message": "Scan foreign", "model_id": "gemini-2.5-flash", "scope": "organizations/222222222222"},
        ).status_code == 403
        assert client.post(
            "/api/connection",
            headers=csrf_headers,
            json={"organization_id": "222222222222"},
        ).status_code == 403

        # 7. CR-04: build_oauth_authorize_uri with empty target_scope omits scope (never injects 31564119954)
        auth_uri = ws.build_oauth_authorize_uri(user_id="alice@google.com", session_id="s-1", target_scope="")
        assert "31564119954" not in auth_uri
        assert "scope=" not in auth_uri

        # 8. CR-04: auth_store.upsert_session_metadata with empty scope stores "" (never 31564119954)
        app.state.auth_store.upsert_session_metadata(session_id="unbound-meta-1", user_id="alice@google.com", scope="")
        stored_meta = app.state.auth_store.get_session_metadata("unbound-meta-1", user_id="alice@google.com")
        assert stored_meta is not None and stored_meta["scope"] == ""

        # 9. CR-07: PqcOAuth3LOPlugin.before_tool_callback rejects unauthenticated inv_uid AND unbound omitted scope
        t_s, t_c = _bind_app_stores(app)
        try:
            plugin = ws.PqcOAuth3LOPlugin()
            fake_tool = MagicMock()
            fake_tool.name = "collect_kms_inventory"

            # Unauthenticated inv_uid -> SCOPE_AUTHORIZATION_DENIED
            fake_inv_unauth = MagicMock()
            fake_inv_unauth.user_id = "sec-architect"
            fake_inv_unauth.session.id = "sess-unauth"
            fake_ctx_unauth = MagicMock()
            fake_ctx_unauth._invocation_context = fake_inv_unauth
            gate_unauth = asyncio.run(
                plugin.before_tool_callback(tool=fake_tool, tool_args={}, tool_context=fake_ctx_unauth)
            )
            assert gate_unauth is not None
            assert gate_unauth["status"] == "SCOPE_AUTHORIZATION_DENIED"
            assert "UNAUTHENTICATED_EXECUTION_CONTEXT" in gate_unauth["error"]

            # Authenticated but unbound tenant omitting scope -> SCOPE_AUTHORIZATION_DENIED (no consent card!)
            fake_inv_unbound = MagicMock()
            fake_inv_unbound.user_id = "unbound@google.com"
            fake_inv_unbound.session.id = "sess-unbound"
            fake_ctx_unbound = MagicMock()
            fake_ctx_unbound._invocation_context = fake_inv_unbound
            gate_unbound = asyncio.run(
                plugin.before_tool_callback(tool=fake_tool, tool_args={}, tool_context=fake_ctx_unbound)
            )
            assert gate_unbound is not None
            assert gate_unbound["status"] == "SCOPE_AUTHORIZATION_DENIED"
            assert "MISSING_AUTHORIZED_SCOPE" in gate_unbound["error"]
        finally:
            credential_service.reset_active_credential_service(t_c)
            auth_store.reset_active_auth_store(t_s)

        # 10. CR-02: HTTP middleware reset leaves outer ContextVar clean after Alice's HTTP requests
        assert gcloud_bridge.get_current_tenant_user() != "alice@google.com"
    app.state.auth_store.close()
