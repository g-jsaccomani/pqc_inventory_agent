"""Phase 4.1.2 Regression Suite — Fail-Closed Tenant Scope Resolution.

100% offline, deterministic, and hermetic. Verifies that `tools/gcp_inventory.py::_active_tenant_default_scope()`
eliminates the implicit `DEFAULT_ORGANIZATION_ID` exception fallback and fails closed as `("UNBOUND", "", "")`
on all identity resolution failures, connection lookup exceptions, malformed payloads, and tenant mismatches.

Covers all 12 mandatory Phase 4.1.2 scenarios:
  1. Authenticated tenant with valid organization binding.
  2. Authenticated tenant with valid project binding.
  3. Authenticated tenant with no binding.
  4. Authenticated tenant whose connection lookup raises an exception (plus sanitized logging check).
  5. Authenticated tenant whose connection lookup returns malformed or cross-tenant data.
  6. Tenant identity lookup raises an exception (or returns empty/non-string/malformed identity).
  7. Positively unauthenticated CLI/test context preserves documented legacy behavior.
  8. `_resolve_scope("org")` never substitutes DEFAULT_ORGANIZATION_ID for an authenticated tenant on lookup failure.
  9. Internal runtime project resolution never substitutes DEFAULT_ORGANIZATION_ID after authenticated lookup failure.
 10. Every live collector fails closed when the authenticated tenant scope cannot be resolved.
 11. Denied requests do not instantiate SDK clients, invoke `google.auth.default`, call CAI, or access `_SCAN_CACHE`.
 12. Existing Phase 4.1.1 delegated-token and admin ADC behavior remains intact.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple

from google.cloud import kms_v1
from google.oauth2 import credentials as oauth2_credentials
import pytest

from pqc_agent import auth_store, credential_service
from tools import gcloud_bridge, gcp_inventory, pqc_detectors


@pytest.fixture(autouse=True)
def _isolated_phase412_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolates env vars, SQLite auth/credential stores, scan cache, and active tenant ContextVar."""
    for env_key in (
        "K_SERVICE",
        "PQC_PRODUCTION_MODE",
        "PQC_ENV",
        "PQC_ADMIN_EMAILS",
        "PQC_ALLOWED_PROJECTS",
        "PQC_ALLOWED_ORGANIZATIONS",
        "PQC_ALLOWED_FOLDERS",
        "PQC_TENANT_SCOPE_POLICY",
        "PQC_SIMULATION_MODE",
        "PQC_CONNECTION_MODE",
        "PQC_EXCLUDED_KEY_RINGS",
    ):
        monkeypatch.delenv(env_key, raising=False)

    db_path = tmp_path / "phase412.db"
    monkeypatch.setenv("SESSION_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("PQC_AUTH_SECRET", "phase412-fail-closed-scope-secret-material-32bytes!!")
    monkeypatch.setenv("PQC_CREDENTIAL_KEK", "phase412-fail-closed-local-kek-material-32bytes!!")

    auth_store.clear_fallback_auth_stores()
    store = auth_store.DistributedAuthStore(f"sqlite:///{db_path}")
    cred_svc = credential_service.EncryptedDatabaseCredentialService(store=store)
    tok_store = auth_store.set_active_auth_store(store)
    tok_cred = credential_service.set_active_credential_service(cred_svc)

    gcp_inventory._SCAN_CACHE.clear()
    prev_uid = gcloud_bridge.get_current_tenant_user()
    gcloud_bridge.set_current_tenant_user(gcloud_bridge.DEFAULT_TENANT_USER_ID)
    prev_disabled = gcp_inventory.logger.disabled
    prev_propagate = gcp_inventory.logger.propagate
    gcp_inventory.logger.disabled = False
    gcp_inventory.logger.propagate = True
    try:
        yield store, cred_svc
    finally:
        gcp_inventory.logger.disabled = prev_disabled
        gcp_inventory.logger.propagate = prev_propagate
        gcp_inventory._SCAN_CACHE.clear()
        gcloud_bridge.set_current_tenant_user(prev_uid)
        credential_service.reset_active_credential_service(tok_cred)
        auth_store.reset_active_auth_store(tok_store)
        store.close()
        auth_store.clear_fallback_auth_stores()


def _install_full_tripwires(monkeypatch: pytest.MonkeyPatch) -> Dict[str, int]:
    """Installs hard tripwires for all SDK clients, google.auth.default, CAI calls, and _SCAN_CACHE access."""
    import google.auth

    counts: Dict[str, int] = {
        "google_auth_default": 0,
        "asset_client": 0,
        "kms_client": 0,
        "ssl_policies_client": 0,
        "region_ssl_policies_client": 0,
        "cai_search": 0,
        "cache_get": 0,
        "cache_put": 0,
    }

    def _adc_tripwire(*args: Any, **kwargs: Any):
        counts["google_auth_default"] += 1
        raise AssertionError("google.auth.default() must NEVER be called after denied scope resolution!")

    class _AssetClientTripwire:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            counts["asset_client"] += 1
            raise AssertionError("AssetServiceClient must NEVER be instantiated after denied scope resolution!")

    class _KmsClientTripwire:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            counts["kms_client"] += 1
            raise AssertionError("KeyManagementServiceClient must NEVER be instantiated after denied scope resolution!")

    class _SslClientTripwire:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            counts["ssl_policies_client"] += 1
            raise AssertionError("SslPoliciesClient must NEVER be instantiated after denied scope resolution!")

    class _RegionSslClientTripwire:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            counts["region_ssl_policies_client"] += 1
            raise AssertionError("RegionSslPoliciesClient must NEVER be instantiated after denied scope resolution!")

    def _cai_search_tripwire(*args: Any, **kwargs: Any):
        counts["cai_search"] += 1
        raise AssertionError("_cai_search_all_resources must NEVER be called after denied scope resolution!")

    def _cache_get_tripwire(*args: Any, **kwargs: Any):
        counts["cache_get"] += 1
        raise AssertionError("_cache_get must NEVER be called after denied scope resolution!")

    def _cache_put_tripwire(*args: Any, **kwargs: Any):
        counts["cache_put"] += 1
        raise AssertionError("_cache_put must NEVER be called after denied scope resolution!")

    monkeypatch.setattr(google.auth, "default", _adc_tripwire)
    monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _AssetClientTripwire)
    monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", _KmsClientTripwire)
    monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", _AssetClientTripwire)
    monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", _KmsClientTripwire)
    monkeypatch.setattr(pqc_detectors.compute_v1, "SslPoliciesClient", _SslClientTripwire)
    monkeypatch.setattr(pqc_detectors.compute_v1, "RegionSslPoliciesClient", _RegionSslClientTripwire)
    monkeypatch.setattr(gcp_inventory, "_cai_search_all_resources", _cai_search_tripwire)
    monkeypatch.setattr(pqc_detectors, "_cai_search_all_resources", _cai_search_tripwire)
    monkeypatch.setattr(gcp_inventory, "_cache_get", _cache_get_tripwire)
    monkeypatch.setattr(gcp_inventory, "_cache_put", _cache_put_tripwire)
    monkeypatch.setattr(pqc_detectors, "_cache_get", _cache_get_tripwire)
    monkeypatch.setattr(pqc_detectors, "_cache_put", _cache_put_tripwire)
    return counts


def _run_all_five_collectors(scope: str) -> Dict[str, Dict[str, Any]]:
    return {
        "collect_kms_inventory": json.loads(gcp_inventory.collect_kms_inventory(scope)),
        "collect_workload_evidence": json.loads(gcp_inventory.collect_workload_evidence(scope)),
        "discover_all_crypto_assets": json.loads(gcp_inventory.discover_all_crypto_assets(scope)),
        "collect_tls_policies": json.loads(pqc_detectors.collect_tls_policies(scope)),
        "collect_kms_import_jobs": json.loads(pqc_detectors.collect_kms_import_jobs(scope)),
    }


def _assert_zero_tripwires(counts: Dict[str, int]) -> None:
    assert all(v == 0 for v in counts.values()), f"Unexpected side effects after denial: {counts}"


# ---------------------------------------------------------------------------
# Scenario 1: Authenticated tenant with valid organization binding
# ---------------------------------------------------------------------------
def test_01_authenticated_tenant_with_valid_organization_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scenario 1: Authenticated tenant with server-bound org resolves exclusively to that organization."""
    monkeypatch.setenv("PQC_ALLOWED_ORGANIZATIONS", "alice@tenant-a.example=111111111111")
    gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")

    assert gcp_inventory._active_tenant_default_scope() == ("ORG", "organizations/111111111111", "111111111111")
    assert gcp_inventory._active_tenant_org_id() == "111111111111"
    assert gcp_inventory._resolve_scope("org") == ("ORG", "organizations/111111111111", "111111111111")
    assert gcp_inventory._resolve_scope("vertex-runtime-tp") == ("ORG", "organizations/111111111111", "111111111111")


# ---------------------------------------------------------------------------
# Scenario 2: Authenticated tenant with valid project binding
# ---------------------------------------------------------------------------
def test_02_authenticated_tenant_with_valid_project_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scenario 2: Authenticated tenant with server-bound project resolves exclusively to that project."""
    monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "alice@tenant-a.example=tenant-a-proj-01")
    gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")

    assert gcp_inventory._active_tenant_default_scope() == ("PROJECT", "projects/tenant-a-proj-01", "tenant-a-proj-01")
    assert gcp_inventory._active_tenant_org_id() == ""
    assert gcp_inventory._resolve_scope("org") == ("PROJECT", "projects/tenant-a-proj-01", "tenant-a-proj-01")
    assert gcp_inventory._resolve_scope("vertex-runtime-tp") == (
        "PROJECT",
        "projects/tenant-a-proj-01",
        "tenant-a-proj-01",
    )


# ---------------------------------------------------------------------------
# Scenario 3: Authenticated tenant with no binding
# ---------------------------------------------------------------------------
def test_03_authenticated_tenant_with_no_binding() -> None:
    """Scenario 3: Authenticated tenant with no org/project/folder binding resolves to UNBOUND, never DEFAULT_ORGANIZATION_ID."""
    gcloud_bridge.set_current_tenant_user("unbound@tenant-a.example")

    assert gcp_inventory._active_tenant_default_scope() == ("UNBOUND", "", "")
    assert gcp_inventory._active_tenant_org_id() == ""
    assert gcp_inventory._resolve_scope("org") == ("UNBOUND", "", "")
    assert gcp_inventory._resolve_scope("default") == ("UNBOUND", "", "")
    assert gcp_inventory._resolve_scope("vertex-runtime-tp") == ("UNBOUND", "", "")


# ---------------------------------------------------------------------------
# Scenario 4: Authenticated tenant whose connection lookup raises an exception
# ---------------------------------------------------------------------------
def test_04_authenticated_tenant_connection_lookup_exception_fails_closed_with_sanitized_log(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Scenario 4: Connection lookup exception returns UNBOUND (never DEFAULT_ORGANIZATION_ID) and logs no secrets or emails."""
    gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")

    def _boom(*args: Any, **kwargs: Any):
        raise RuntimeError("db failure token=ya29.super-secret-oauth-bearer user=alice@tenant-a.example")

    monkeypatch.setattr(gcloud_bridge, "get_gcp_connection_config", _boom)

    with caplog.at_level(logging.WARNING, logger="tools.gcp_inventory"):
        res = gcp_inventory._active_tenant_default_scope()
        org_id = gcp_inventory._active_tenant_org_id()

    assert res == ("UNBOUND", "", "")
    assert org_id == ""
    assert res[2] != gcp_inventory.DEFAULT_ORGANIZATION_ID

    # Sanitized diagnostic must mention only safe failure metadata, never tokens, credentials, or tenant emails
    log_text = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "RuntimeError" in log_text
    assert "UNBOUND" in log_text
    assert "ya29.super-secret-oauth-bearer" not in log_text
    assert "alice@tenant-a.example" not in log_text
    assert "db failure" not in log_text


# ---------------------------------------------------------------------------
# Scenario 5: Authenticated tenant whose connection lookup returns malformed or cross-tenant data
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_payload",
    [
        None,
        [],
        "organizations/31564119954",
        42,
        {"user_id": "bob@tenant-b.example", "organization_id": "222222222222"},
        {"user_id": 999, "organization_id": "111111111111"},
        {"user_id": "alice@tenant-a.example", "organization_id": 111111111111},
        {"user_id": "alice@tenant-a.example", "organization_id": "not-a-numeric-org"},
        {"user_id": "alice@tenant-a.example", "organization_id": "organizations/"},
        {"user_id": "alice@tenant-a.example", "project_id": ["tenant-a-proj-01"]},
        {"user_id": "alice@tenant-a.example", "project_id": "INVALID PROJECT!!"},
        {"user_id": "alice@tenant-a.example", "organization_id": "", "project_id": "", "active_scope_uri": 12345},
        {
            "user_id": "alice@tenant-a.example",
            "organization_id": "",
            "project_id": "",
            "active_scope_uri": "organizations/../../etc",
        },
        {
            "user_id": "alice@tenant-a.example",
            "organization_id": "",
            "project_id": "",
            "active_scope_uri": "projects/BAD_PROJ",
        },
    ],
)
def test_05_authenticated_tenant_malformed_or_cross_tenant_connection_payload_fails_closed(
    monkeypatch: pytest.MonkeyPatch, bad_payload: Any
) -> None:
    """Scenario 5: Malformed or mismatched-tenant connection payloads always return UNBOUND, never DEFAULT_ORGANIZATION_ID."""
    gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")
    monkeypatch.setattr(gcloud_bridge, "get_gcp_connection_config", lambda *a, **kw: bad_payload)

    res = gcp_inventory._active_tenant_default_scope()
    assert res == ("UNBOUND", "", "")
    assert gcp_inventory._active_tenant_org_id() == ""


# ---------------------------------------------------------------------------
# Scenario 6: Tenant identity lookup raises an exception (or returns malformed identity)
# ---------------------------------------------------------------------------
def test_06_tenant_identity_lookup_failure_never_classified_as_unauthenticated(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Scenario 6: Identity lookup exceptions or malformed identities return UNBOUND, never legacy DEFAULT_ORGANIZATION_ID."""
    # Case A: get_current_tenant_user raises
    def _uid_boom():
        raise RuntimeError("contextvar corruption secret=ya29.leaked-id-token")

    monkeypatch.setattr(gcloud_bridge, "get_current_tenant_user", _uid_boom)
    with caplog.at_level(logging.WARNING, logger="tools.gcp_inventory"):
        assert gcp_inventory._active_tenant_default_scope() == ("UNBOUND", "", "")
        assert gcp_inventory._active_tenant_org_id() == ""
    log_text = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "RuntimeError" in log_text
    assert "ya29.leaked-id-token" not in log_text

    # Case B: _is_authenticated_email_identity raises
    monkeypatch.setattr(gcloud_bridge, "get_current_tenant_user", lambda: "alice@tenant-a.example")
    monkeypatch.setattr(
        gcloud_bridge,
        "_is_authenticated_email_identity",
        lambda _u: (_ for _ in ()).throw(ValueError("identity validator error")),
    )
    assert gcp_inventory._active_tenant_default_scope() == ("UNBOUND", "", "")

    # Case C: get_current_tenant_user returns empty, non-string, or malformed '@' identity
    monkeypatch.undo()
    for bad_uid in (None, "", "   ", 12345, "@missing-local", "missing-domain@"):
        monkeypatch.setattr(gcloud_bridge, "get_current_tenant_user", lambda v=bad_uid: v)
        assert gcp_inventory._active_tenant_default_scope() == ("UNBOUND", "", "")


# ---------------------------------------------------------------------------
# Scenario 7: Positively unauthenticated CLI/test context preserves documented legacy behavior
# ---------------------------------------------------------------------------
def test_07_positively_unauthenticated_cli_test_context_preserves_legacy_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario 7: Positively unauthenticated CLI/test placeholders keep legacy DEFAULT_ORGANIZATION_ID for scope helpers while live collectors still deny."""
    tripwires = _install_full_tripwires(monkeypatch)
    expected = ("ORG", f"organizations/{gcp_inventory.DEFAULT_ORGANIZATION_ID}", gcp_inventory.DEFAULT_ORGANIZATION_ID)

    for placeholder in (gcloud_bridge.DEFAULT_TENANT_USER_ID, "default"):
        gcloud_bridge.set_current_tenant_user(placeholder)
        assert gcp_inventory._active_tenant_default_scope() == expected
        assert gcp_inventory._active_tenant_org_id() == gcp_inventory.DEFAULT_ORGANIZATION_ID
        assert gcp_inventory._resolve_scope("org") == expected
        assert gcp_inventory._resolve_scope("vertex-runtime-tp") == expected
        assert gcp_inventory._resolve_scope("project-cb232322-97f9-4f78-97f") == expected

        # Live collectors MUST STILL fail closed with UNAUTHENTICATED_EXECUTION_CONTEXT and 0 SDK/cache/ADC calls
        for name, res in _run_all_five_collectors("org").items():
            assert "error" in res, f"{name} unexpectedly succeeded for unauthenticated context"
            assert "UNAUTHENTICATED_EXECUTION_CONTEXT" in res["error"]

    _assert_zero_tripwires(tripwires)


# ---------------------------------------------------------------------------
# Scenario 8: `_resolve_scope("org")` never substitutes default organization on lookup failure
# ---------------------------------------------------------------------------
def test_08_resolve_scope_org_never_substitutes_default_org_on_lookup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario 8: Symbolic org tokens never fall back to DEFAULT_ORGANIZATION_ID when authenticated lookup fails."""
    gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")

    # Failure mode 1: connection lookup raises
    monkeypatch.setattr(
        gcloud_bridge,
        "get_gcp_connection_config",
        lambda *a, **kw: (_ for _ in ()).throw(ConnectionError("postgres pool exhausted")),
    )
    for token in sorted(gcp_inventory.ORG_MODE_TOKENS):
        resolved = gcp_inventory._resolve_scope(token)
        assert resolved == ("UNBOUND", "", ""), f"token={token!r} resolved to {resolved}"

    # Failure mode 2: malformed connection payload
    monkeypatch.setattr(gcloud_bridge, "get_gcp_connection_config", lambda *a, **kw: {"organization_id": 999})
    assert gcp_inventory._resolve_scope("org") == ("UNBOUND", "", "")

    # Failure mode 3: identity lookup raises
    monkeypatch.setattr(
        gcloud_bridge,
        "get_current_tenant_user",
        lambda: (_ for _ in ()).throw(RuntimeError("identity store offline")),
    )
    assert gcp_inventory._resolve_scope("org") == ("UNBOUND", "", "")


# ---------------------------------------------------------------------------
# Scenario 9: Internal runtime project resolution never substitutes default org after lookup failure
# ---------------------------------------------------------------------------
def test_09_internal_runtime_project_resolution_never_substitutes_default_org_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario 9: Internal runtime tenant projects (-tp / project-<hex>) resolve to UNBOUND on authenticated lookup failure."""
    gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")
    internal_targets = (
        "vertex-runtime-tp",
        "projects/vertex-runtime-tp",
        "project-cb232322-97f9-4f78-97f",
        "agent-engine-tenant",
        "reasoning-engine-tenant",
    )

    # Failure mode 1: connection lookup raises
    monkeypatch.setattr(
        gcloud_bridge,
        "get_gcp_connection_config",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("connection timeout")),
    )
    for target in internal_targets:
        assert gcp_inventory._resolve_scope(target) == ("UNBOUND", "", "")

    # Failure mode 2: malformed connection payload
    monkeypatch.setattr(gcloud_bridge, "get_gcp_connection_config", lambda *a, **kw: None)
    for target in internal_targets:
        assert gcp_inventory._resolve_scope(target) == ("UNBOUND", "", "")

    # Failure mode 3: identity lookup raises
    monkeypatch.setattr(
        gcloud_bridge,
        "get_current_tenant_user",
        lambda: (_ for _ in ()).throw(RuntimeError("identity error")),
    )
    for target in internal_targets:
        assert gcp_inventory._resolve_scope(target) == ("UNBOUND", "", "")


# ---------------------------------------------------------------------------
# Scenarios 10 & 11: Every live collector fails closed with ZERO SDK, ADC, CAI, or cache calls
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "failure_mode",
    [
        "unbound_connection",
        "connection_lookup_exception",
        "malformed_connection_none",
        "malformed_connection_bad_org",
        "cross_tenant_connection_payload",
        "identity_lookup_exception",
    ],
)
def test_10_11_all_live_collectors_fail_closed_with_zero_sdk_adc_cai_or_cache_access(
    monkeypatch: pytest.MonkeyPatch, failure_mode: str
) -> None:
    """Scenarios 10 & 11: All 5 live collectors fail closed across every scope-resolution failure mode with 0 SDK, ADC, CAI, or _SCAN_CACHE calls."""
    # Pre-seed _SCAN_CACHE with sentinel entries to verify zero cache lookups occur on denied resolution
    gcp_inventory._SCAN_CACHE["unconfigured:kms::all:False"] = (1e18, '{"sentinel":"MUST_NOT_LEAK"}')
    gcp_inventory._SCAN_CACHE[f"unconfigured:kms:organizations/{gcp_inventory.DEFAULT_ORGANIZATION_ID}:all:False"] = (
        1e18,
        '{"sentinel":"MUST_NOT_LEAK"}',
    )

    tripwires = _install_full_tripwires(monkeypatch)
    gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")

    if failure_mode == "unbound_connection":
        pass  # No server policy and no bound org/project
    elif failure_mode == "connection_lookup_exception":
        monkeypatch.setattr(
            gcloud_bridge,
            "get_gcp_connection_config",
            lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("db connection error")),
        )
    elif failure_mode == "malformed_connection_none":
        monkeypatch.setattr(gcloud_bridge, "get_gcp_connection_config", lambda *a, **kw: None)
    elif failure_mode == "malformed_connection_bad_org":
        monkeypatch.setattr(
            gcloud_bridge,
            "get_gcp_connection_config",
            lambda *a, **kw: {"user_id": "alice@tenant-a.example", "organization_id": "not-valid-org"},
        )
    elif failure_mode == "cross_tenant_connection_payload":
        monkeypatch.setattr(
            gcloud_bridge,
            "get_gcp_connection_config",
            lambda *a, **kw: {"user_id": "bob@tenant-b.example", "organization_id": "222222222222"},
        )
    elif failure_mode == "identity_lookup_exception":
        monkeypatch.setattr(
            gcloud_bridge,
            "get_current_tenant_user",
            lambda: (_ for _ in ()).throw(RuntimeError("identity context error")),
        )

    for requested_scope in ("org", "vertex-runtime-tp"):
        results = _run_all_five_collectors(requested_scope)
        for collector_name, payload in results.items():
            assert "error" in payload, f"{collector_name}({requested_scope!r}) did not fail closed in {failure_mode}"
            assert payload["scope"] == "", f"{collector_name} leaked non-empty scope {payload['scope']!r}"
            assert payload["scope_mode"] == "UNBOUND"
            assert gcp_inventory.DEFAULT_ORGANIZATION_ID not in json.dumps(payload)
            assert "MUST_NOT_LEAK" not in json.dumps(payload)

    _assert_zero_tripwires(tripwires)


# ---------------------------------------------------------------------------
# Scenario 12: Existing Phase 4.1.1 delegated-token and admin ADC behavior remains intact
# ---------------------------------------------------------------------------
def test_12_delegated_token_and_admin_adc_behavior_remains_intact(
    monkeypatch: pytest.MonkeyPatch, _isolated_phase412_env: Tuple[Any, Any]
) -> None:
    """Scenario 12: Authorized delegated-token (project & org) and admin ADC modes continue resolving and collecting cleanly."""
    import google.auth

    _, cred_svc = _isolated_phase412_env
    adc_calls: List[Any] = []
    cai_scopes: List[str] = []
    client_creds_seen: List[Any] = []

    monkeypatch.setattr(
        google.auth,
        "default",
        lambda *a, **kw: adc_calls.append((a, kw)) or (_ for _ in ()).throw(AssertionError("ADC called unexpectedly")),
    )

    class _MockCai:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            client_creds_seen.append(kwargs.get("credentials"))

        def search_all_resources(self, request: Dict[str, Any]):
            cai_scopes.append(request["scope"])
            asset_types = set(request.get("asset_types") or [])
            if "cloudkms.googleapis.com/KeyRing" in asset_types:
                return [
                    SimpleNamespace(
                        asset_type="cloudkms.googleapis.com/KeyRing",
                        name="//cloudkms.googleapis.com/projects/tenant-a-proj-01/locations/us-central1/keyRings/kr-1",
                        display_name="kr-1",
                        project="projects/tenant-a-proj-01",
                        location="us-central1",
                        state="ACTIVE",
                        labels={},
                        versioned_resources=[],
                    )
                ]
            return []

    class _MockKms:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def list_key_rings(self, request: Dict[str, Any]):
            return [SimpleNamespace(name="projects/tenant-a-proj-01/locations/us-central1/keyRings/kr-1")]

        def list_crypto_keys(self, request: Dict[str, Any]):
            return [
                SimpleNamespace(
                    name="projects/tenant-a-proj-01/locations/us-central1/keyRings/kr-1/cryptoKeys/k1",
                    purpose=kms_v1.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
                    version_template=SimpleNamespace(
                        algorithm=kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_65,
                        protection_level=kms_v1.ProtectionLevel.HSM,
                    ),
                    primary=None,
                    rotation_period=None,
                    labels={},
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
            return []

    monkeypatch.setattr(gcp_inventory.asset_v1, "AssetServiceClient", _MockCai)
    monkeypatch.setattr(gcp_inventory.kms_v1, "KeyManagementServiceClient", _MockKms)
    monkeypatch.setattr(pqc_detectors.asset_v1, "AssetServiceClient", _MockCai)
    monkeypatch.setattr(pqc_detectors.kms_v1, "KeyManagementServiceClient", _MockKms)

    # A. Delegated-token user bound to project via PQC_ALLOWED_PROJECTS
    monkeypatch.setenv("PQC_ALLOWED_PROJECTS", "alice@tenant-a.example=tenant-a-proj-01")
    gcloud_bridge.set_current_tenant_user("alice@tenant-a.example")
    cred_svc.store_delegated_token(
        user_id="alice@tenant-a.example",
        access_token="ya29.phase412-delegated-token-alice",
        expires_in=3600,
        caller_user_id="alice@tenant-a.example",
    )
    proj_kms = json.loads(gcp_inventory.collect_kms_inventory("org"))
    assert proj_kms["scope"] == "projects/tenant-a-proj-01"
    assert proj_kms["key_count"] == 1
    assert isinstance(client_creds_seen[-1], oauth2_credentials.Credentials)
    assert client_creds_seen[-1].token == "ya29.phase412-delegated-token-alice"

    # B. Authorized admin ADC user bound to org via PQC_ADMIN_EMAILS + PQC_ALLOWED_ORGANIZATIONS
    monkeypatch.delenv("PQC_ALLOWED_PROJECTS", raising=False)
    monkeypatch.setenv("PQC_ADMIN_EMAILS", "secadmin@tenant-a.example")
    monkeypatch.setenv("PQC_ALLOWED_ORGANIZATIONS", "secadmin@tenant-a.example=111111111111")
    gcloud_bridge.set_current_tenant_user("secadmin@tenant-a.example")
    gcp_inventory._SCAN_CACHE.clear()

    admin_kms = json.loads(gcp_inventory.collect_kms_inventory("org"))
    assert admin_kms["scope"] == "organizations/111111111111"
    assert admin_kms["key_count"] == 1
    assert client_creds_seen[-1] is None  # ADC mode passes no explicit credentials kwarg
    assert "organizations/111111111111" in cai_scopes
    assert adc_calls == []
