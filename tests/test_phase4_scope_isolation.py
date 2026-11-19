"""Phase 4.1 Security Tests: Strict CAI Scope Isolation & Legacy Functional Lab Fallback Removal.

100% offline and deterministic: uses isolated temporary SQLite auth/credential stores and mocked
Google Cloud SDK clients. Zero live GCP APIs, Vertex AI endpoints, or cloud resources are contacted.
"""

from __future__ import annotations

import ast
import inspect
import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest
from google.cloud import kms_v1

from pqc_agent import auth_store, credential_service
from tools import gcloud_bridge, gcp_inventory, pqc_detectors


REPO_ROOT = Path(__file__).resolve().parents[1]


class SimulatedCaiPermissionDenied(Exception):
    """Deterministic stand-in for google.api_core.exceptions.PermissionDenied."""


class CustomCaiUnavailableError(RuntimeError):
    """Distinct exception type to verify exact original exception propagation."""


def _clear_inventory_cache() -> None:
    gcp_inventory._SCAN_CACHE.clear()


def _make_auth_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Creates an isolated auth + credential store and resets scope/ADC env vars to fail-closed defaults."""
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
    ):
        monkeypatch.delenv(env_key, raising=False)

    monkeypatch.setenv("PQC_AUTH_SECRET", "phase4-scope-isolation-test-hmac-secret-32chars!")
    monkeypatch.setenv("PQC_CREDENTIAL_KEK", "phase4-scope-isolation-test-local-kek-32chars!")

    db_url = f"sqlite:///{tmp_path / 'phase4_auth.db'}"
    store = auth_store.DistributedAuthStore(db_url=db_url, create_schema=True)
    dek_wrapper = credential_service.LocalHkdfKekWrapper(b"phase4-scope-isolation-test-local-kek-32chars!")
    cred_svc = credential_service.EncryptedDatabaseCredentialService(store=store, dek_wrapper=dek_wrapper)
    tok_store = auth_store.set_active_auth_store(store)
    tok_cred = credential_service.set_active_credential_service(cred_svc)
    _clear_inventory_cache()
    return store, cred_svc, tok_store, tok_cred


def _teardown_auth_env(store: auth_store.DistributedAuthStore, tok_store: Any, tok_cred: Any) -> None:
    _clear_inventory_cache()
    gcloud_bridge.set_current_tenant_user("default")
    credential_service.reset_active_credential_service(tok_cred)
    auth_store.reset_active_auth_store(tok_store)
    store.close()


def _bind_tenant_token(
    user_id: str,
    *,
    organization_id: str = "",
    project_id: str = "",
    token: str = "ya29.phase4-synthetic-delegated-token-1234567890",
) -> None:
    gcloud_bridge.set_current_tenant_user(user_id)
    gcloud_bridge.set_gcp_connection_config(
        mode="access_token",
        organization_id=organization_id,
        project_id=project_id,
        access_token=token,
        user_id=user_id,
    )


def _fake_kms_client_factory(project_id: str, location: str = "us-central1", key_name: str = "app-signing-key"):
    """Builds a minimal deterministic Cloud KMS client mock for one project/location."""

    class _FakeKmsClient:
        listed_parents: List[str] = []

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.kwargs = kwargs

        def list_key_rings(self, request: Dict[str, Any]):
            parent = request["parent"]
            self.__class__.listed_parents.append(parent)
            expected_parent = f"projects/{project_id}/locations/{location}"
            if parent != expected_parent:
                return []
            return [SimpleNamespace(name=f"{expected_parent}/keyRings/kr-core")]

        def list_crypto_keys(self, request: Dict[str, Any]):
            parent = request["parent"]
            if not parent.startswith(f"projects/{project_id}/"):
                return []
            key = SimpleNamespace(
                name=f"{parent}/cryptoKeys/{key_name}",
                purpose=kms_v1.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
                version_template=SimpleNamespace(
                    algorithm=kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_65,
                    protection_level=kms_v1.ProtectionLevel.HSM,
                ),
                primary=None,
                rotation_period=None,
                labels={"env": "prod"},
            )
            return [key]

        def list_crypto_key_versions(self, request: Dict[str, Any]):
            ver = SimpleNamespace(
                name=f"{request['parent']}/cryptoKeyVersions/1",
                state=kms_v1.CryptoKeyVersion.CryptoKeyVersionState.ENABLED,
                algorithm=kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_65,
                protection_level=kms_v1.ProtectionLevel.HSM,
            )
            return [ver]

        def get_iam_policy(self, request: Dict[str, Any]):
            return SimpleNamespace(bindings=[])

        def list_import_jobs(self, request: Dict[str, Any]):
            parent = request["parent"]
            ij = SimpleNamespace(
                name=f"{parent}/importJobs/ij-pqc-01",
                state=kms_v1.ImportJob.ImportJobState.ACTIVE,
                import_method=kms_v1.ImportJob.ImportMethod.RSA_OAEP_3072_SHA256,
                protection_level=kms_v1.ProtectionLevel.HSM,
                expire_time=None,
            )
            return [ij]

    return _FakeKmsClient


def _make_fake_cai_items(project_id: str, location: str = "us-central1") -> Dict[str, List[Any]]:
    return {
        "kms": [
            SimpleNamespace(
                asset_type="cloudkms.googleapis.com/KeyRing",
                name=f"//cloudkms.googleapis.com/projects/{project_id}/locations/{location}/keyRings/kr-core",
                display_name="kr-core",
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
                name=f"//run.googleapis.com/projects/{project_id}/locations/{location}/services/billing-api",
                display_name="billing-api",
                project=f"projects/{project_id}",
                location=location,
                labels={"tier": "backend"},
                kms_key=f"projects/{project_id}/locations/{location}/keyRings/kr-core/cryptoKeys/app-signing-key",
                kms_keys=[],
            )
        ],
        "crypto": [
            SimpleNamespace(
                asset_type="compute.googleapis.com/SslCertificate",
                name=f"//compute.googleapis.com/projects/{project_id}/global/sslCertificates/cert-edge",
                display_name="cert-edge",
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
                name=f"//compute.googleapis.com/projects/{project_id}/global/sslPolicies/pqc-strict-tls13",
                display_name="pqc-strict-tls13",
                project=f"projects/{project_id}",
                location="global",
                labels={},
                versioned_resources=[
                    SimpleNamespace(
                        resource={
                            "minTlsVersion": "TLS_1_3",
                            "profile": "RESTRICTED",
                            "postQuantumKeyExchange": "ENABLED",
                        }
                    )
                ],
            ),
            SimpleNamespace(
                asset_type="compute.googleapis.com/TargetHttpsProxy",
                name=f"//compute.googleapis.com/projects/{project_id}/global/targetHttpsProxies/edge-https-proxy",
                display_name="edge-https-proxy",
                project=f"projects/{project_id}",
                location="global",
                labels={},
                versioned_resources=[
                    SimpleNamespace(
                        resource={
                            "sslPolicy": f"https://www.googleapis.com/compute/v1/projects/{project_id}/global/sslPolicies/pqc-strict-tls13"
                        }
                    )
                ],
            ),
        ],
    }


def _fake_cai_client_class(recorded_requests: List[Dict[str, Any]], items_by_kind: Dict[str, List[Any]]):
    class _FakeCaiClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.kwargs = kwargs

        def search_all_resources(self, request: Dict[str, Any]):
            recorded_requests.append(dict(request))
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

    return _FakeCaiClient


def test_01_authorized_org_scope_queried_exact_across_all_collectors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Req 1: An authorized organization scope is queried verbatim across all CAI collectors."""
    store, _, tok_store, tok_cred = _make_auth_env(tmp_path, monkeypatch)
    try:
        _bind_tenant_token("alice@tenant-a.example", organization_id="111111111111")
        recorded: List[Dict[str, Any]] = []
        fake_cai_cls = _fake_cai_client_class(recorded, _make_fake_cai_items("tenant-a-prod-01"))
        fake_kms_cls = _fake_kms_client_factory("tenant-a-prod-01")

        monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", fake_cai_cls)
        monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", fake_kms_cls)
        monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", fake_cai_cls)
        monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", fake_kms_cls)

        target_org = "organizations/111111111111"

        direct_items = gcp_inventory._cai_search_all_resources(
            cai_client=fake_cai_cls(),
            scope_uri=target_org,
            asset_types=["cloudkms.googleapis.com/KeyRing"],
        )
        assert len(direct_items) == 1

        kms = json.loads(gcp_inventory.collect_kms_inventory(target_org))
        workloads = json.loads(gcp_inventory.collect_workload_evidence(target_org))
        crypto = json.loads(gcp_inventory.discover_all_crypto_assets(target_org))
        tls = json.loads(pqc_detectors.collect_tls_policies(target_org))
        imports = json.loads(pqc_detectors.collect_kms_import_jobs(target_org))

        assert kms["scope"] == target_org and kms["key_count"] == 1 and "error" not in kms
        assert kms["organization_domain"] is None
        assert workloads["scope"] == target_org and workloads["workload_count"] == 1 and "error" not in workloads
        assert crypto["scope"] == target_org and crypto["asset_count"] == 1 and "error" not in crypto
        assert tls["scope"] == target_org and len(tls["target_proxies"]) == 1 and "error" not in tls
        assert imports["scope"] == target_org and len(imports["import_jobs"]) == 1 and "error" not in imports

        # Exactly 6 CAI queries (1 direct + 5 collectors), every single one strictly on target_org
        assert len(recorded) == 6
        assert [r["scope"] for r in recorded] == [target_org] * 6
    finally:
        _teardown_auth_env(store, tok_store, tok_cred)


@pytest.mark.parametrize(
    "org_id",
    [
        "111111111111",
        gcp_inventory.DEFAULT_ORGANIZATION_ID,
    ],
    ids=["tenant_org", "configured_default_org"],
)
def test_02_failed_org_cai_never_falls_back_to_folder_or_project_scopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, org_id: str
) -> None:
    """Req 2: A failed org-level CAI request (including DEFAULT_ORGANIZATION_ID) triggers zero fallback queries."""
    store, _, tok_store, tok_cred = _make_auth_env(tmp_path, monkeypatch)
    try:
        _bind_tenant_token("alice@tenant-a.example", organization_id=org_id)
        recorded_scopes: List[str] = []
        kms_location_calls: List[str] = []

        class _OrgFailFallbackTrapCaiClient:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            def search_all_resources(self, request: Dict[str, Any]):
                scope = request["scope"]
                recorded_scopes.append(scope)
                if scope.startswith("organizations/"):
                    raise SimulatedCaiPermissionDenied(
                        f"403 caller lacks cloudasset.assets.searchAllResources on {scope}"
                    )
                # If a legacy fallback ever queried a folder/project, it would return foreign resources here!
                return [
                    SimpleNamespace(
                        asset_type="cloudkms.googleapis.com/KeyRing",
                        name="//cloudkms.googleapis.com/projects/foreign-lab-proj/locations/global/keyRings/kr-leak",
                        display_name="kr-leak",
                        project="projects/foreign-lab-proj",
                        location="global",
                        state="ACTIVE",
                        labels={},
                        versioned_resources=[],
                    )
                ]

        class _TripwireKmsClient:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            def list_key_rings(self, request: Dict[str, Any]):
                kms_location_calls.append(request["parent"])
                raise AssertionError(f"Unexpected KMS listing after org CAI failure: {request}")

        monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _OrgFailFallbackTrapCaiClient)
        monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", _TripwireKmsClient)
        monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", _OrgFailFallbackTrapCaiClient)
        monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", _TripwireKmsClient)

        org_scope = f"organizations/{org_id}"

        collectors = [
            ("kms", lambda: json.loads(gcp_inventory.collect_kms_inventory(org_scope))),
            ("workloads", lambda: json.loads(gcp_inventory.collect_workload_evidence(org_scope))),
            ("crypto", lambda: json.loads(gcp_inventory.discover_all_crypto_assets(org_scope))),
            ("tls", lambda: json.loads(pqc_detectors.collect_tls_policies(org_scope))),
            ("imports", lambda: json.loads(pqc_detectors.collect_kms_import_jobs(org_scope))),
        ]

        for name, fn in collectors:
            recorded_scopes.clear()
            payload = fn()
            assert recorded_scopes == [org_scope], f"{name} issued unexpected fallback scopes: {recorded_scopes}"
            assert payload["scope"] == org_scope
            assert payload["data_source"] == gcp_inventory.LIVE_DATA_SOURCE
            assert "error" in payload
            assert "required_roles" in payload
            assert "foreign-lab-proj" not in json.dumps(payload)
            if name == "kms":
                assert payload["keys"] == []
                assert payload["key_count"] == 0
                assert any("SimulatedCaiPermissionDenied" in e and org_scope in e for e in payload["collection_errors"])
            else:
                assert "SimulatedCaiPermissionDenied" in payload["error"]
                assert not payload.get("workloads")
                assert not payload.get("assets")
                assert not payload.get("ssl_policies")
                assert not payload.get("import_jobs")

        # Verify failed KMS org error payload was NOT cached in _SCAN_CACHE (retry still attempts CAI)
        recorded_scopes.clear()
        retry_kms = json.loads(gcp_inventory.collect_kms_inventory(org_scope))
        assert recorded_scopes == [org_scope]
        assert "error" in retry_kms
        assert kms_location_calls == []
    finally:
        _teardown_auth_env(store, tok_store, tok_cred)


def test_03_original_cai_exception_propagated_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Req 3: The exact original CAI exception instance is propagated without substitution."""
    store, _, tok_store, tok_cred = _make_auth_env(tmp_path, monkeypatch)
    try:
        for scope in (
            "organizations/111111111111",
            f"organizations/{gcp_inventory.DEFAULT_ORGANIZATION_ID}",
            "folders/555555555555",
            "projects/tenant-a-prod-01",
        ):
            original_exc = CustomCaiUnavailableError(f"upstream CAI failure for {scope}")
            seen_scopes: List[str] = []

            class _RaisingCaiClient:
                def search_all_resources(self, request: Dict[str, Any]):
                    seen_scopes.append(request["scope"])
                    raise original_exc

            with pytest.raises(CustomCaiUnavailableError) as exc_info:
                gcp_inventory._cai_search_all_resources(
                    cai_client=_RaisingCaiClient(),
                    scope_uri=scope,
                    asset_types=["cloudkms.googleapis.com/KeyRing"],
                )
            assert exc_info.value is original_exc
            assert seen_scopes == [scope]

        # Empty scope rejected before touching CAI client
        touched = False

        class _NeverCalledCai:
            def search_all_resources(self, request: Dict[str, Any]):
                nonlocal touched
                touched = True
                return []

        with pytest.raises(ValueError, match="non-empty explicit scope"):
            gcp_inventory._cai_search_all_resources(_NeverCalledCai(), "   ", ["cloudkms.googleapis.com/KeyRing"])
        assert touched is False

        # _discover_key_rings_via_cai propagates the exact original CAI exception too
        _bind_tenant_token("alice@tenant-a.example", organization_id="111111111111")
        org_exc = CustomCaiUnavailableError("direct keyring CAI propagation sentinel")
        kr_scopes: List[str] = []

        class _RaisingAssetServiceClient:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            def search_all_resources(self, request: Dict[str, Any]):
                kr_scopes.append(request["scope"])
                raise org_exc

        monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", _RaisingAssetServiceClient)
        with pytest.raises(CustomCaiUnavailableError) as kr_exc_info:
            pqc_detectors._discover_key_rings_via_cai("organizations/111111111111")
        assert kr_exc_info.value is org_exc
        assert kr_scopes == ["organizations/111111111111"]
    finally:
        _teardown_auth_env(store, tok_store, tok_cred)


def test_04_no_hardcoded_functional_lab_fallback_scopes_in_active_code() -> None:
    """Req 4: No hardcoded Functional Lab fallback scopes or legacy helper remain in active implementation."""
    assert not hasattr(gcp_inventory, "DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES")
    assert not hasattr(gcp_inventory, "_cai_search_all_resources_with_fallback")
    assert hasattr(gcp_inventory, "_cai_search_all_resources")

    cai_helper_src = inspect.getsource(gcp_inventory._cai_search_all_resources)
    assert "DEFAULT_ORGANIZATION_ID" not in cai_helper_src
    assert "DEFAULT_FUNCTIONAL_LAB" not in cai_helper_src
    helper_ast = ast.parse(cai_helper_src)
    assert not any(isinstance(n, (ast.Try, ast.ExceptHandler)) for n in ast.walk(helper_ast))

    forbidden_tokens = (
        "DEFAULT_FUNCTIONAL_LAB_FALLBACK_SCOPES",
        "_cai_search_all_resources_with_fallback",
        "Functional Lab",
    )
    hardcoded_scope_patterns = (
        re.compile(r"\borganizations/[0-9]{6,}\b"),
        re.compile(r"\bfolders/[0-9]{6,}\b"),
        re.compile(r"\bprojects/[a-z][a-z0-9-]{4,}\b"),
    )
    for rel_path in ("tools/gcp_inventory.py", "tools/pqc_detectors.py"):
        content = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
        for token in forbidden_tokens:
            assert token not in content, f"Legacy fallback token {token!r} still present in {rel_path}"
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for pat in hardcoded_scope_patterns:
                    matches = pat.findall(node.value)
                    assert not matches, f"Hardcoded scope literal {matches} found at {rel_path}:{node.lineno}"


def test_05_explicit_project_scope_collection_and_failure_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Req 5: Project-level inventory works when explicitly supplied and preserves project failure semantics."""
    store, _, tok_store, tok_cred = _make_auth_env(tmp_path, monkeypatch)
    try:
        proj_id = "tenant-a-prod-01"
        proj_scope = f"projects/{proj_id}"
        _bind_tenant_token("alice@tenant-a.example", project_id=proj_id)

        # Part A: Happy path with explicit project scope (and bare project ID)
        recorded: List[Dict[str, Any]] = []
        fake_cai_cls = _fake_cai_client_class(recorded, _make_fake_cai_items(proj_id))
        fake_kms_cls = _fake_kms_client_factory(proj_id)
        monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", fake_cai_cls)
        monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", fake_kms_cls)
        monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", fake_cai_cls)
        monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", fake_kms_cls)

        kms = json.loads(gcp_inventory.collect_kms_inventory(proj_scope))
        workloads = json.loads(gcp_inventory.collect_workload_evidence(proj_id))
        crypto = json.loads(gcp_inventory.discover_all_crypto_assets(proj_scope))
        tls = json.loads(pqc_detectors.collect_tls_policies(proj_scope))
        imports = json.loads(pqc_detectors.collect_kms_import_jobs(proj_scope))

        assert kms["scope"] == proj_scope and kms["scope_mode"] == "PROJECT" and kms["key_count"] == 1
        assert workloads["scope"] == proj_scope and workloads["workload_count"] == 1
        assert crypto["scope"] == proj_scope and crypto["asset_count"] == 1
        assert tls["scope"] == proj_scope and len(tls["target_proxies"]) == 1
        assert imports["scope"] == proj_scope and len(imports["import_jobs"]) == 1
        assert [r["scope"] for r in recorded] == [proj_scope] * 5

        # Part B: Project CAI failure semantics (same-project global KMS probe; no cross-scope queries)
        _clear_inventory_cache()
        fail_scopes: List[str] = []

        class _ProjectCaiFailClient:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            def search_all_resources(self, request: Dict[str, Any]):
                fail_scopes.append(request["scope"])
                raise SimulatedCaiPermissionDenied("403 project CAI disabled")

        global_kms_cls = _fake_kms_client_factory(proj_id, location="global", key_name="global-fallback-same-proj")
        global_kms_cls.listed_parents = []
        monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _ProjectCaiFailClient)
        monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", global_kms_cls)
        monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", _ProjectCaiFailClient)
        monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", global_kms_cls)

        kms_proj_cai_fail = json.loads(gcp_inventory.collect_kms_inventory(proj_scope))
        assert fail_scopes == [proj_scope]
        # Preserves original project-level semantics: probes ONLY the SAME project's global location
        assert global_kms_cls.listed_parents == [f"projects/{proj_id}/locations/global"]
        assert kms_proj_cai_fail["key_count"] == 1
        assert kms_proj_cai_fail["keys"][0]["project_id"] == proj_id
        assert any("SimulatedCaiPermissionDenied" in e for e in kms_proj_cai_fail["collection_errors"])

        for fn in (
            lambda: json.loads(gcp_inventory.collect_workload_evidence(proj_scope)),
            lambda: json.loads(gcp_inventory.discover_all_crypto_assets(proj_scope)),
            lambda: json.loads(pqc_detectors.collect_tls_policies(proj_scope)),
            lambda: json.loads(pqc_detectors.collect_kms_import_jobs(proj_scope)),
        ):
            fail_scopes.clear()
            res = fn()
            assert fail_scopes == [proj_scope]
            assert "error" in res and "SimulatedCaiPermissionDenied" in res["error"]
    finally:
        _teardown_auth_env(store, tok_store, tok_cred)


def test_06_unauthorized_scopes_rejected_before_sdk_or_cache_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Req 6: Unauthorized scopes, unauthenticated callers, and unauthorized ADC are rejected fail-closed."""
    store, _, tok_store, tok_cred = _make_auth_env(tmp_path, monkeypatch)
    try:
        import google.auth

        sdk_calls: List[str] = []

        def _tripwire_adc(*args: Any, **kwargs: Any):
            sdk_calls.append("google.auth.default")
            raise AssertionError("google.auth.default() must never be called for unauthorized scopes or users")

        class _TripwireClient:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                sdk_calls.append("gcp_sdk_client")
                raise AssertionError("GCP SDK client must never be constructed for unauthorized scopes")

        monkeypatch.setattr(google.auth, "default", _tripwire_adc)
        monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _TripwireClient)
        monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", _TripwireClient)
        monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", _TripwireClient)
        monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", _TripwireClient)

        # 1. Unauthenticated caller fails closed
        gcloud_bridge.set_current_tenant_user("default")
        with pytest.raises(PermissionError, match="UNAUTHENTICATED_EXECUTION_CONTEXT"):
            gcloud_bridge.authorize_gcp_scope("organizations/111111111111")
        with pytest.raises(PermissionError, match="UNAUTHENTICATED_EXECUTION_CONTEXT"):
            gcp_inventory._get_client_kwargs("organizations/111111111111")

        # 2. Tampered DB row with mode='adc' for non-admin fails closed via authorize_adc_mode
        store.upsert_user_connection(
            user_id="nonadmin@tenant-a.example",
            mode="adc",
            organization_id="111111111111",
            project_id="tenant-a-prod-01",
        )
        gcloud_bridge.set_current_tenant_user("nonadmin@tenant-a.example")
        with pytest.raises(PermissionError, match="ADC_UNAUTHORIZED"):
            gcloud_bridge.authorize_gcp_scope("organizations/111111111111")
        with pytest.raises(PermissionError, match="ADC_UNAUTHORIZED"):
            gcp_inventory._get_client_kwargs("organizations/111111111111")

        # 3. Authenticated tenant requesting scopes outside their authorized boundary
        _bind_tenant_token(
            "alice@tenant-a.example",
            organization_id="111111111111",
            project_id="tenant-a-prod-01",
        )
        unauthorized_scopes = [
            "organizations/999999999999",
            "folders/555555555555",  # folders are default-deny unless allowlisted
            "projects/tenant-b-prod-02",
            "organizations/",
            "organizations/../999999999999",
            "projects/tenant-a-prod-01?https://evil.example",
        ]
        for bad_scope in unauthorized_scopes:
            with pytest.raises(PermissionError, match="UNAUTHORIZED_RESOURCE_SCOPE"):
                gcloud_bridge.authorize_gcp_scope(bad_scope)
            for fn in (
                gcp_inventory.collect_kms_inventory,
                gcp_inventory.collect_workload_evidence,
                gcp_inventory.discover_all_crypto_assets,
                pqc_detectors.collect_tls_policies,
                pqc_detectors.collect_kms_import_jobs,
            ):
                payload = json.loads(fn(bad_scope))
                assert "error" in payload
                assert "UNAUTHORIZED_RESOURCE_SCOPE" in payload["error"]

        # 4. Server-side allowlist overrides user connection config (and blocks stale cache reads)
        recorded: List[Dict[str, Any]] = []
        fake_cai_cls = _fake_cai_client_class(recorded, _make_fake_cai_items("tenant-a-prod-01"))
        fake_kms_cls = _fake_kms_client_factory("tenant-a-prod-01")
        monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", fake_cai_cls)
        monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", fake_kms_cls)

        # Warm cache while 111111111111 is authorized
        warm_res = json.loads(gcp_inventory.collect_kms_inventory("organizations/111111111111"))
        assert warm_res["key_count"] == 1 and "error" not in warm_res

        # Now operator restricts Alice to a different org via PQC_ALLOWED_ORGANIZATIONS
        monkeypatch.setenv("PQC_ALLOWED_ORGANIZATIONS", "alice@tenant-a.example=333333333333")
        monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _TripwireClient)
        monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", _TripwireClient)
        revoked_res = json.loads(gcp_inventory.collect_kms_inventory("organizations/111111111111"))
        assert "error" in revoked_res
        assert "UNAUTHORIZED_RESOURCE_SCOPE" in revoked_res["error"]
        assert not revoked_res.get("keys")

        # Server PQC_TENANT_SCOPE_POLICY also enforces projects/orgs/folders
        monkeypatch.delenv("PQC_ALLOWED_ORGANIZATIONS", raising=False)
        monkeypatch.setenv(
            "PQC_TENANT_SCOPE_POLICY",
            json.dumps(
                {
                    "alice@tenant-a.example": {
                        "projects": ["tenant-a-prod-01"],
                        "organizations": ["111111111111"],
                        "folders": ["555555555555"],
                    }
                }
            ),
        )
        assert gcloud_bridge.authorize_gcp_scope("folders/555555555555") == "folders/555555555555"
        with pytest.raises(PermissionError, match="UNAUTHORIZED_RESOURCE_SCOPE"):
            gcloud_bridge.authorize_gcp_scope("folders/666666666666")

        assert sdk_calls == []
    finally:
        _teardown_auth_env(store, tok_store, tok_cred)


def test_07_cross_tenant_and_cross_scope_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Req 7: Zero cross-tenant or cross-scope inventory returned, including through cache or org token rewriting."""
    store, _, tok_store, tok_cred = _make_auth_env(tmp_path, monkeypatch)
    try:
        # Tenant B populates cache for org 222222222222 & project tenant-b-prod-02
        _bind_tenant_token(
            "bob@tenant-b.example",
            organization_id="222222222222",
            project_id="tenant-b-prod-02",
            token="ya29.bob-tenant-b-secret-token-9999999999",
        )
        recorded_b: List[Dict[str, Any]] = []
        fake_cai_b = _fake_cai_client_class(recorded_b, _make_fake_cai_items("tenant-b-prod-02"))
        fake_kms_b = _fake_kms_client_factory("tenant-b-prod-02", key_name="tenant-b-secret-key")
        monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", fake_cai_b)
        monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", fake_kms_b)
        monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", fake_cai_b)
        monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", fake_kms_b)

        bob_kms = json.loads(gcp_inventory.collect_kms_inventory("organizations/222222222222"))
        assert bob_kms["key_count"] == 1
        assert bob_kms["keys"][0]["key_name"] == "tenant-b-secret-key"

        # Switch to Tenant A (org 111111111111, project tenant-a-prod-01)
        _bind_tenant_token(
            "alice@tenant-a.example",
            organization_id="111111111111",
            project_id="tenant-a-prod-01",
            token="ya29.alice-tenant-a-secret-token-1111111111",
        )

        # Alice CANNOT read Bob's org or project via live path or cache
        for bob_scope in ("organizations/222222222222", "projects/tenant-b-prod-02"):
            for fn in (
                gcp_inventory.collect_kms_inventory,
                gcp_inventory.collect_workload_evidence,
                gcp_inventory.discover_all_crypto_assets,
                pqc_detectors.collect_tls_policies,
                pqc_detectors.collect_kms_import_jobs,
            ):
                res = json.loads(fn(bob_scope))
                assert "error" in res and "UNAUTHORIZED_RESOURCE_SCOPE" in res["error"]
                assert "tenant-b-secret-key" not in json.dumps(res)
                assert "tenant-b-prod-02" not in json.dumps(res.get("keys", []))

        # Explicit request for organizations/{DEFAULT_ORGANIZATION_ID} is NOT rewritten to Alice's org 111111111111
        default_org_scope = f"organizations/{gcp_inventory.DEFAULT_ORGANIZATION_ID}"
        assert gcp_inventory._resolve_scope(default_org_scope) == (
            "ORG",
            default_org_scope,
            gcp_inventory.DEFAULT_ORGANIZATION_ID,
        )
        default_org_res = json.loads(gcp_inventory.collect_kms_inventory(default_org_scope))
        assert default_org_res["scope"] == default_org_scope
        assert "error" in default_org_res and "UNAUTHORIZED_RESOURCE_SCOPE" in default_org_res["error"]

        # Cross-tenant user_id parameter override rejected
        with pytest.raises(PermissionError, match="cross-tenant scope authorization denied"):
            gcloud_bridge.authorize_gcp_scope("organizations/222222222222", user_id="bob@tenant-b.example")

        # Principal-scoped PQC_ALLOWED_FOLDERS isolates folder access per user
        monkeypatch.setenv("PQC_ALLOWED_FOLDERS", "alice@tenant-a.example=555555555555")
        assert gcloud_bridge.authorize_gcp_scope("folders/555555555555") == "folders/555555555555"
        gcloud_bridge.set_current_tenant_user("bob@tenant-b.example")
        with pytest.raises(PermissionError, match="UNAUTHORIZED_RESOURCE_SCOPE"):
            gcloud_bridge.authorize_gcp_scope("folders/555555555555")
    finally:
        _teardown_auth_env(store, tok_store, tok_cred)


def test_08_supported_workflows_demo_scorecard_cbom_and_admin_adc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Req 8: Demo scope, scorecard, CycloneDX CBOM, and authorized server-side admin ADC remain compatible."""
    store, _, tok_store, tok_cred = _make_auth_env(tmp_path, monkeypatch)
    try:
        # 1. Explicit demo/simulation workflow works without live credentials
        gcloud_bridge.set_current_tenant_user("default")
        demo_kms = json.loads(gcp_inventory.collect_kms_inventory("demo-pqc-project"))
        assert demo_kms["data_source"] == gcp_inventory.SIMULATED_DATA_SOURCE
        assert demo_kms["key_count"] > 0

        # 2. Authorized tenant scorecard + CBOM workflow on explicit org scope
        _bind_tenant_token("alice@tenant-a.example", organization_id="111111111111")
        recorded: List[Dict[str, Any]] = []
        fake_cai_cls = _fake_cai_client_class(recorded, _make_fake_cai_items("tenant-a-prod-01"))
        fake_kms_cls = _fake_kms_client_factory("tenant-a-prod-01")
        monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", fake_cai_cls)
        monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", fake_kms_cls)
        monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", fake_cai_cls)
        monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", fake_kms_cls)

        scorecard = json.loads(gcp_inventory.compute_pqc_scorecard("organizations/111111111111"))
        assert scorecard["scope"] == "organizations/111111111111"
        assert scorecard["completeness_status"] == "COMPLETE"
        assert scorecard["counts"]["active_asymmetric_pqc_keys"] == 1
        assert scorecard["metrics"]["https_proxies_pqc_ready_tls_1_3"]["numerator"] == 1

        cbom = json.loads(gcp_inventory.export_cyclonedx_cbom("organizations/111111111111"))
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["metadata"]["component"]["name"] == "organizations/111111111111"
        assert len(cbom["components"]) == 1

        # 3. Authorized server-side admin in ADC mode succeeds ONLY on allowlisted org
        _clear_inventory_cache()
        monkeypatch.setenv("PQC_ADMIN_EMAILS", "secadmin@tenant-a.example")
        monkeypatch.setenv("PQC_ALLOWED_ORGANIZATIONS", "secadmin@tenant-a.example=111111111111")
        gcloud_bridge.set_current_tenant_user("secadmin@tenant-a.example")
        gcloud_bridge.set_gcp_connection_config(
            mode="adc",
            organization_id="111111111111",
            user_id="secadmin@tenant-a.example",
        )
        admin_ok = json.loads(gcp_inventory.collect_kms_inventory("organizations/111111111111"))
        assert admin_ok["scope"] == "organizations/111111111111"
        assert admin_ok["key_count"] == 1 and "error" not in admin_ok

        admin_denied = json.loads(gcp_inventory.collect_kms_inventory("organizations/999999999999"))
        assert "error" in admin_denied
        assert "UNAUTHORIZED_RESOURCE_SCOPE" in admin_denied["error"]
    finally:
        _teardown_auth_env(store, tok_store, tok_cred)
