"""Phase 3.3 (`P3-03`) Test Suite — PQC Scorecard Denominator Correctness & Edge Cases.

Covers all findings from `PHASE_03_0_AUDIT.md` & `PHASE_03_0_TEST_PLAN.md`:
- Zero-denominator / empty-scope / single-family renormalization safety (no ZeroDivisionError)
- Active UNKNOWN_REQUIRES_REVIEW and EXTERNAL_KEY_MANAGER (Cloud EKM) keys included in denominators with 0 numerator credit
- Asymmetric KMS keys with `primary_state="NO_PRIMARY"` and `versions_listing_error` conservatively stay active
- Genuinely disabled/destroyed asymmetric keys (`versions_listing_error=None, enabled_version_ids=[]`) remain inactive
- Downgrade-aware mixed-version classification (`template=ML_DSA_65` + enabled `RSA_SIGN_PKCS1_2048_SHA256`)
- Uncategorized purpose + unknown algorithm keys proportionally penalize `weighted_kms_pqc_maturity`
- TLS 1.3 proxies with `postQuantumKeyExchange=DEFERRED` excluded from `https_proxies_pqc_ready_tls_1_3`
- Partial `collection_errors` or `versions_listing_error` mark `inventory_complete=False` & `completeness_status="PARTIAL_WITH_ERRORS"`
- Backward compatibility on `demo-pqc-project`
"""

from __future__ import annotations

import json
from typing import Any, Dict

import pytest

from tools import gcp_inventory, pqc_detectors


def _make_key(
    name: str,
    purpose: str,
    algorithm: str,
    *,
    primary_state: str = "ENABLED",
    enabled_version_ids: list[str] | None = None,
    enabled_version_algorithms: list[str] | None = None,
    rotation_period_days: int | None = None,
    versions_listing_error: str | None = None,
) -> Dict[str, Any]:
    v_ids = ["1"] if enabled_version_ids is None and versions_listing_error is None else (enabled_version_ids or [])
    return gcp_inventory.build_key_record(
        project_id="scorecard-test-proj",
        location="global",
        key_ring="ring-01",
        key_name=name,
        purpose=purpose,
        algorithm=algorithm,
        primary_state=primary_state,
        enabled_version_ids=v_ids,
        enabled_version_algorithms=enabled_version_algorithms,
        rotation_period_days=rotation_period_days,
        versions_listing_error=versions_listing_error,
    )


def test_p3_03_unit_empty_and_single_family_denominators_never_divide_by_zero() -> None:
    # 1. Completely empty scope
    empty = gcp_inventory.compute_scorecard_from_keys([])
    for k in (
        "asymmetric_pqc_migration",
        "symmetric_quantum_resistance",
        "symmetric_rotation_hygiene",
        "algorithmic_quantum_safe",
    ):
        assert empty["metrics"][k]["denominator"] == 0
        assert empty["metrics"][k]["value_pct"] is None
    assert empty["metrics"]["weighted_kms_pqc_maturity"]["value_pct"] is None
    assert empty["counts"]["partition_check_sum"] == 0

    # 2. Asymmetric-only scope -> weight renormalizes to asymmetric_pqc_migration = 1.0
    asym_only = gcp_inventory.compute_scorecard_from_keys(
        [
            _make_key("k-pqc", "KEY_ENCAPSULATION", "ML_KEM_768", primary_state="NO_PRIMARY"),
            _make_key("k-rsa", "ASYMMETRIC_SIGN", "RSA_SIGN_PSS_2048_SHA256", primary_state="NO_PRIMARY"),
        ]
    )
    assert asym_only["metrics"]["asymmetric_pqc_migration"]["value_pct"] == 50.0
    assert asym_only["metrics"]["symmetric_quantum_resistance"]["value_pct"] is None
    assert asym_only["metrics"]["symmetric_rotation_hygiene"]["value_pct"] is None
    assert asym_only["metrics"]["weighted_kms_pqc_maturity"]["value_pct"] == 50.0
    assert asym_only["metrics"]["weighted_kms_pqc_maturity"]["weights_used"] == {"asymmetric_pqc_migration": 1.0}

    # 3. MAC-only scope -> symmetric_quantum_resistance applies, symmetric_rotation_hygiene denominator == 0
    mac_only = gcp_inventory.compute_scorecard_from_keys(
        [_make_key("k-mac", "MAC", "HMAC_SHA256", primary_state="NO_PRIMARY")]
    )
    assert mac_only["metrics"]["symmetric_quantum_resistance"]["value_pct"] == 100.0
    assert mac_only["metrics"]["symmetric_rotation_hygiene"]["denominator"] == 0
    assert mac_only["metrics"]["symmetric_rotation_hygiene"]["value_pct"] is None
    assert mac_only["metrics"]["weighted_kms_pqc_maturity"]["value_pct"] == 100.0

    # 4. Inactive-only keys -> zero active keys, no ZeroDivisionError
    inactive_only = gcp_inventory.compute_scorecard_from_keys(
        [_make_key("k-dead", "ASYMMETRIC_SIGN", "RSA_SIGN_PSS_2048_SHA256", primary_state="NO_PRIMARY", enabled_version_ids=[])]
    )
    assert inactive_only["counts"]["active_keys"] == 0
    assert inactive_only["counts"]["inactive_keys"] == 1
    assert inactive_only["metrics"]["weighted_kms_pqc_maturity"]["value_pct"] is None


def test_p3_03_unit_unknown_and_ekm_keys_included_in_denominators_with_zero_numerator() -> None:
    # 1. 1 active ML_KEM_768 + 4 active UNKNOWN_ALGORITHM ASYMMETRIC_SIGN keys -> 1/5 (20.0%), NOT 100.0%!
    keys_asym_unknown = [
        _make_key("k-pqc", "KEY_ENCAPSULATION", "ML_KEM_768", primary_state="NO_PRIMARY"),
    ] + [
        _make_key(f"k-unk-{i}", "ASYMMETRIC_SIGN", "UNKNOWN_FUTURE_SIGN_ALGO", primary_state="NO_PRIMARY")
        for i in range(4)
    ]
    res_asym = gcp_inventory.compute_scorecard_from_keys(keys_asym_unknown)
    assert (
        res_asym["metrics"]["asymmetric_pqc_migration"]["numerator"],
        res_asym["metrics"]["asymmetric_pqc_migration"]["denominator"],
    ) == (1, 5)
    assert res_asym["metrics"]["asymmetric_pqc_migration"]["value_pct"] == 20.0
    assert res_asym["metrics"]["weighted_kms_pqc_maturity"]["value_pct"] == 20.0
    assert res_asym["counts"]["active_keys_unknown_requires_review"] == 4
    assert res_asym["counts"]["partition_check_sum"] == res_asym["counts"]["active_keys"] == 5

    # 2. 1 active GOOGLE_SYMMETRIC_ENCRYPTION + 1 active EXTERNAL_SYMMETRIC_ENCRYPTION (Cloud EKM) -> 1/2 (50.0%), NOT 100.0%!
    keys_ekm = [
        _make_key("k-aes", "ENCRYPT_DECRYPT", "GOOGLE_SYMMETRIC_ENCRYPTION", rotation_period_days=30),
        _make_key("k-ekm", "ENCRYPT_DECRYPT", "EXTERNAL_SYMMETRIC_ENCRYPTION"),
    ]
    res_ekm = gcp_inventory.compute_scorecard_from_keys(keys_ekm)
    assert (
        res_ekm["metrics"]["symmetric_quantum_resistance"]["numerator"],
        res_ekm["metrics"]["symmetric_quantum_resistance"]["denominator"],
    ) == (1, 2)
    assert res_ekm["metrics"]["symmetric_quantum_resistance"]["value_pct"] == 50.0
    assert res_ekm["counts"]["active_ekm_keys"] == 1
    assert res_ekm["metrics"]["algorithmic_quantum_safe"]["value_pct"] == 50.0
    assert res_ekm["metrics"]["weighted_kms_pqc_maturity"]["value_pct"] < 100.0
    assert res_ekm["counts"]["partition_check_sum"] == res_ekm["counts"]["active_keys"] == 2


def test_p3_03_unit_asymmetric_key_with_version_listing_error_stays_active() -> None:
    # Asymmetric key with NO_PRIMARY and versions_listing_error -> MUST stay active and count as Shor-vulnerable!
    asym_err = _make_key(
        "k-rsa-err",
        "ASYMMETRIC_SIGN",
        "RSA_SIGN_PSS_2048_SHA256",
        primary_state="NO_PRIMARY",
        enabled_version_ids=[],
        versions_listing_error="PermissionDenied: 403 cloudkms.cryptoKeyVersions.list",
    )
    assert asym_err["is_active"] is True
    assert asym_err["activity_assumed_due_to_version_error"] is True

    sc = gcp_inventory.compute_scorecard_from_keys([asym_err])
    assert sc["counts"]["active_asymmetric_keys"] == 1
    assert sc["counts"]["active_shor_vulnerable_keys"] == 1
    assert sc["counts"]["active_keys_assumed_active_due_to_version_error"] == 1
    assert sc["metrics"]["asymmetric_pqc_migration"]["value_pct"] == 0.0

    # Contrast: genuinely disabled/destroyed asymmetric key with NO error & empty enabled_version_ids -> inactive
    asym_inactive = _make_key(
        "k-rsa-disabled",
        "ASYMMETRIC_SIGN",
        "RSA_SIGN_PSS_2048_SHA256",
        primary_state="NO_PRIMARY",
        enabled_version_ids=[],
        versions_listing_error=None,
    )
    assert asym_inactive["is_active"] is False

    # Contrast: explicitly DESTROYED primary even with versions_listing_error -> stays inactive
    sym_destroyed = _make_key(
        "k-sym-destroyed",
        "ENCRYPT_DECRYPT",
        "GOOGLE_SYMMETRIC_ENCRYPTION",
        primary_state="DESTROYED",
        enabled_version_ids=[],
        versions_listing_error="PermissionDenied: 403",
    )
    assert sym_destroyed["is_active"] is False


def test_p3_03_adversarial_mixed_versions_and_unrecognized_purpose_cannot_inflate_maturity() -> None:
    # 1. Mixed versions: template=ML_DSA_65 but enabled RSA_SIGN_PKCS1_2048_SHA256 -> downgrade-aware SHOR vulnerable
    downgraded = _make_key(
        "k-mixed",
        "ASYMMETRIC_SIGN",
        "PQ_SIGN_ML_DSA_65",
        primary_state="NO_PRIMARY",
        enabled_version_ids=["1", "2"],
        enabled_version_algorithms=["PQ_SIGN_ML_DSA_65", "RSA_SIGN_PKCS1_2048_SHA256"],
    )
    assert downgraded["algorithm_facts"]["quantum_status"] == "QUANTUM_VULNERABLE_SHOR"
    sc_mixed = gcp_inventory.compute_scorecard_from_keys([downgraded])
    assert sc_mixed["metrics"]["asymmetric_pqc_migration"]["value_pct"] == 0.0
    assert sc_mixed["counts"]["active_shor_vulnerable_keys"] == 1

    # 2. Unrecognized purpose + unrecognized algorithm alongside 1 PQC key -> CANNOT report 100.0% maturity!
    pqc_key = _make_key("k-pqc", "KEY_ENCAPSULATION", "ML_KEM_768", primary_state="NO_PRIMARY")
    mystery_key = _make_key("k-mystery", "CRYPTO_KEY_PURPOSE_UNSPECIFIED", "FUTURE_UNKNOWN_ALGO", primary_state="ENABLED")
    sc_mystery = gcp_inventory.compute_scorecard_from_keys([pqc_key, mystery_key])
    assert sc_mystery["counts"]["active_uncategorized_keys"] == 1
    assert sc_mystery["counts"]["partition_check_sum"] == sc_mystery["counts"]["active_keys"] == 2
    assert sc_mystery["metrics"]["algorithmic_quantum_safe"]["value_pct"] == 50.0
    assert sc_mystery["metrics"]["weighted_kms_pqc_maturity"]["uncategorized_penalty_applied"] is True
    assert sc_mystery["metrics"]["weighted_kms_pqc_maturity"]["value_pct"] == 50.0

    # 3. Scope consisting exclusively of unrecognized-purpose/algorithm active key -> maturity is 0.0%, not None/100%
    sc_only_mystery = gcp_inventory.compute_scorecard_from_keys([mystery_key])
    assert sc_only_mystery["metrics"]["weighted_kms_pqc_maturity"]["value_pct"] == 0.0


def test_p3_03_integration_compute_pqc_scorecard_tls_deferred_and_partial_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_keys = [_make_key("k-pqc", "KEY_ENCAPSULATION", "ML_KEM_768", primary_state="NO_PRIMARY")]
    fake_inventory = {
        "scope": "projects/tls-deferred-test",
        "data_source": gcp_inventory.LIVE_DATA_SOURCE,
        "keys": fake_keys,
        "collection_errors": ["projects/other-proj/locations/us-east1: PermissionDenied"],
    }
    fake_tls = {
        "scope": "projects/tls-deferred-test",
        "data_source": gcp_inventory.LIVE_DATA_SOURCE,
        "target_proxies": [
            {
                "proxy_name": "edge-pqc-ready",
                "effective_requires_tls_1_3": True,
                "effective_post_quantum_key_exchange": "ENABLED",
                "effective_post_quantum_key_exchange_deferred": False,
            },
            {
                "proxy_name": "edge-tls13-deferred",
                "effective_requires_tls_1_3": True,
                "effective_post_quantum_key_exchange": "DEFERRED",
                "effective_post_quantum_key_exchange_deferred": True,
            },
        ],
    }
    fake_ij = {
        "scope": "projects/tls-deferred-test",
        "data_source": gcp_inventory.LIVE_DATA_SOURCE,
        "import_jobs": [],
    }

    monkeypatch.setattr(gcp_inventory, "collect_kms_inventory", lambda **kwargs: json.dumps(fake_inventory))
    monkeypatch.setattr(pqc_detectors, "collect_tls_policies", lambda **kwargs: json.dumps(fake_tls))
    monkeypatch.setattr(pqc_detectors, "collect_kms_import_jobs", lambda **kwargs: json.dumps(fake_ij))

    sc = json.loads(gcp_inventory.compute_pqc_scorecard(scope="projects/tls-deferred-test"))
    # Both require TLS 1.3 (2/2 = 100%), but only 1/2 (50.0%) is PQC-ready because proxy 2 sets DEFERRED!
    assert sc["metrics"]["https_proxies_requiring_tls_1_3"]["value_pct"] == 100.0
    assert (
        sc["metrics"]["https_proxies_pqc_ready_tls_1_3"]["numerator"],
        sc["metrics"]["https_proxies_pqc_ready_tls_1_3"]["denominator"],
    ) == (1, 2)
    assert sc["metrics"]["https_proxies_pqc_ready_tls_1_3"]["value_pct"] == 50.0
    assert sc["counts"]["https_proxies_tls_1_3_with_pqc_deferred"] == 1

    # Partial collection errors MUST flag scorecard as incomplete
    assert sc["inventory_complete"] is False
    assert sc["completeness_status"] == "PARTIAL_WITH_ERRORS"


def test_p3_03_regression_demo_scope_completeness_and_backward_compatibility() -> None:
    gcp_inventory._SCAN_CACHE.clear()
    sc = json.loads(gcp_inventory.compute_pqc_scorecard("demo-pqc-project"))
    assert sc["inventory_complete"] is True
    assert sc["completeness_status"] == "COMPLETE"
    assert sc["counts"]["partition_check_sum"] == sc["counts"]["active_keys"]
    assert sc["metrics"]["asymmetric_pqc_migration"]["value_pct"] == 40.0
    assert sc["metrics"]["symmetric_quantum_resistance"]["value_pct"] == 100.0
    assert sc["metrics"]["symmetric_rotation_hygiene"]["value_pct"] == 50.0
    assert sc["metrics"]["algorithmic_quantum_safe"]["value_pct"] == 62.5
    assert sc["metrics"]["weighted_kms_pqc_maturity"]["value_pct"] == 56.5
    assert sc["metrics"]["https_proxies_pqc_ready_tls_1_3"]["denominator"] == 2
    assert sc["metrics"]["https_proxies_pqc_ready_tls_1_3"]["value_pct"] == 0.0
