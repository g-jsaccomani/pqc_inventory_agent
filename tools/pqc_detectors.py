"""Evidence collection for TLS on Cloud Load Balancing and Cloud KMS BYOK import jobs (facts only).

- `collect_tls_policies`: SSL policies and HTTPS/SSL target proxies with the effective policy each proxy uses.
- `collect_kms_import_jobs`: Cloud KMS ImportJobs with their wrapping (import) method and state.

No runbooks, recommendations or narrative are produced here; the Gemini agents reason over these facts.
Simulation follows the same explicit policy as `tools.gcp_inventory` (never a silent fallback).
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import Any, Dict, List, Optional

from google.cloud import asset_v1, compute_v1, kms_v1

from tools import mock_data
from tools.gcp_inventory import (
    DEFAULT_ORGANIZATION_ID,
    LIVE_DATA_SOURCE,
    SIMULATED_DATA_SOURCE,
    SIMULATION_NOTICE,
    _cache_get,
    _cache_put,
    _cai_search_all_resources_with_fallback,
    _compact_json,
    _get_client_kwargs,
    _now_iso,
    _project_from_cai_name,
    _resolve_scope,
    excluded_key_rings,
    simulation_requested,
)

logger = logging.getLogger(__name__)

TLS_VERSION_RANK = {"TLS_1_0": 0, "TLS_1_1": 1, "TLS_1_2": 2, "TLS_1_3": 3}
GCP_DEFAULT_SSL_POLICY = {
    "min_tls_version": "TLS_1_0",
    "profile": "COMPATIBLE",
    "post_quantum_key_exchange": "DEFAULT",
}
TLS_REFERENCE_FACTS = [
    "Hybrid post-quantum key exchange (X25519MLKEM768) is only negotiated in TLS 1.3 handshakes on supported "
    "Cloud Load Balancing frontends.",
    "SSL policy postQuantumKeyExchange modes: ENABLED (uses X25519MLKEM768 with supporting TLS 1.3 clients), "
    "DEFAULT (enabled by default starting October 2026; also applies when no SSL policy is attached), and "
    "DEFERRED (disallows X25519MLKEM768 until October 2027).",
    "A target proxy without an attached SSL policy uses the Google Cloud default SSL policy "
    "(COMPATIBLE profile, minimum TLS 1.0, postQuantumKeyExchange DEFAULT).",
]

HPKE_PQC_IMPORT_METHODS = {
    "HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM",
    "HPKE_KEM_ML_KEM_768_HKDF_SHA256_AES_256_GCM",
    "HPKE_KEM_ML_KEM_1024_HKDF_SHA256_AES_256_GCM",
}


def _proto_struct_to_dict(resource_obj: Any) -> Dict[str, Any]:
    if not resource_obj:
        return {}
    try:
        return dict(resource_obj)
    except Exception:
        return {}


def _normalize_pq_key_exchange(mode: Optional[str]) -> str:
    norm = (mode or "DEFAULT").strip().upper()
    return norm if norm in ("ENABLED", "DEFAULT", "DEFERRED") else norm


def _policy_record(
    policy_name: str,
    resource_name: str,
    project_id: str,
    location: str,
    min_tls_version: str,
    profile: str,
    custom_features: Optional[List[str]] = None,
    post_quantum_key_exchange: Optional[str] = None,
) -> Dict[str, Any]:
    norm_tls = (min_tls_version or "TLS_1_0").upper()
    pq_mode = _normalize_pq_key_exchange(post_quantum_key_exchange)
    return {
        "policy_name": policy_name,
        "resource_name": resource_name,
        "project_id": project_id,
        "location": location or "global",
        "min_tls_version": norm_tls,
        "profile": (profile or "COMPATIBLE").upper(),
        "post_quantum_key_exchange": pq_mode,
        "post_quantum_key_exchange_deferred": pq_mode == "DEFERRED",
        "custom_features": list(custom_features or []),
        "requires_tls_1_3": norm_tls == "TLS_1_3",
        "allows_pre_tls13_handshakes": TLS_VERSION_RANK.get(norm_tls, 0) < 3,
    }


def _fetch_compute_pq_key_exchange(project_id: str, location: str, policy_name: str) -> Optional[str]:
    """Queries Compute Engine SslPolicies API directly when Cloud Asset Inventory omits postQuantumKeyExchange."""
    try:
        kwargs = _get_client_kwargs()
        loc = (location or "global").lower()
        if loc == "global":
            client = compute_v1.SslPoliciesClient(**kwargs)
            pol = client.get(project=project_id, ssl_policy=policy_name)
        else:
            rclient = compute_v1.RegionSslPoliciesClient(**kwargs)
            pol = rclient.get(project=project_id, region=location, ssl_policy=policy_name)
        val = getattr(pol, "post_quantum_key_exchange", None)
        return str(val).strip().upper() if val else "DEFAULT"
    except Exception:
        return None


def _policy_short_name(ref: Optional[str]) -> Optional[str]:
    if not ref:
        return None
    return str(ref).rstrip("/").split("/")[-1]


def _resolve_proxy_records(policies: List[Dict[str, Any]], proxies_raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_key = {(p["project_id"], p["policy_name"]): p for p in policies}
    records: List[Dict[str, Any]] = []
    for proxy in proxies_raw:
        attached = _policy_short_name(proxy.get("attached_ssl_policy"))
        policy = by_key.get((proxy.get("project_id"), attached)) if attached else None
        if attached and policy:
            effective_tls = policy["min_tls_version"]
            effective_profile = policy["profile"]
            effective_pq = policy["post_quantum_key_exchange"]
            source = "ATTACHED_SSL_POLICY"
        elif attached:
            effective_tls, effective_profile, effective_pq, source = (
                None,
                None,
                None,
                "ATTACHED_SSL_POLICY_NOT_FOUND_IN_SCOPE",
            )
        else:
            effective_tls = GCP_DEFAULT_SSL_POLICY["min_tls_version"]
            effective_profile = GCP_DEFAULT_SSL_POLICY["profile"]
            effective_pq = GCP_DEFAULT_SSL_POLICY["post_quantum_key_exchange"]
            source = "GCP_DEFAULT_SSL_POLICY"
        records.append(
            {
                "proxy_name": proxy.get("proxy_name"),
                "resource_name": proxy.get("resource_name"),
                "project_id": proxy.get("project_id"),
                "proxy_type": proxy.get("proxy_type"),
                "attached_ssl_policy": attached,
                "effective_policy_source": source,
                "effective_min_tls_version": effective_tls,
                "effective_profile": effective_profile,
                "effective_post_quantum_key_exchange": effective_pq,
                "effective_post_quantum_key_exchange_deferred": effective_pq == "DEFERRED",
                "effective_requires_tls_1_3": effective_tls == "TLS_1_3",
            }
        )
    return records


def collect_tls_policies(scope: str = f"organizations/{DEFAULT_ORGANIZATION_ID}") -> str:
    """Collects SSL policies and HTTPS/SSL target proxies with the effective TLS policy of each proxy (facts only).

    Args:
        scope: 'organizations/<id>', 'folders/<id>', 'projects/<id>' or a bare project ID.

    Returns:
        JSON with `ssl_policies` (including `post_quantum_key_exchange`: ENABLED, DEFAULT or DEFERRED),
        `target_proxies` (attached or default policy, effective minimum TLS version and effective
        `post_quantum_key_exchange`), `reference_facts` and `data_source`, or an `error` object.
    """
    mode, scope_uri, clean_id = _resolve_scope(scope)
    simulated = simulation_requested(clean_id)
    cache_key = f"tls:{scope_uri}:{simulated}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if simulated:
        demo = mock_data.get_simulated_tls_evidence(clean_id)
        policies = [
            _policy_record(
                p["policy_name"],
                p["resource_name"],
                p["project_id"],
                p["location"],
                p["min_tls_version"],
                p["profile"],
                p.get("custom_features"),
                p.get("post_quantum_key_exchange"),
            )
            for p in demo["policies"]
        ]
        payload = {
            "scope": scope_uri,
            "scope_mode": mode,
            "data_source": SIMULATED_DATA_SOURCE,
            "simulation_notice": SIMULATION_NOTICE,
            "generated_at": _now_iso(),
            "ssl_policies": policies,
            "target_proxies": _resolve_proxy_records(policies, demo["proxies"]),
            "reference_facts": TLS_REFERENCE_FACTS,
        }
        return _cache_put(cache_key, _compact_json(payload))

    policies: List[Dict[str, Any]] = []
    proxies_raw: List[Dict[str, Any]] = []
    try:
        cai_client = asset_v1.AssetServiceClient(**_get_client_kwargs())
        items = _cai_search_all_resources_with_fallback(
            cai_client=cai_client,
            scope_uri=scope_uri,
            asset_types=[
                "compute.googleapis.com/SslPolicy",
                "compute.googleapis.com/TargetHttpsProxy",
                "compute.googleapis.com/TargetSslProxy",
            ],
            read_mask="*",
            page_size=500,
        )
        for item in items:
            proj = _project_from_cai_name(item.name, item.project or clean_id)
            attrs = _proto_struct_to_dict(item.versioned_resources[0].resource) if item.versioned_resources else {}
            name = item.display_name or item.name.split("/")[-1]
            if item.asset_type == "compute.googleapis.com/SslPolicy":
                features = attrs.get("customFeatures") or attrs.get("custom_features") or []
                loc = item.location or "global"
                raw_pq = attrs.get("postQuantumKeyExchange") or attrs.get("post_quantum_key_exchange")
                if not raw_pq:
                    raw_pq = _fetch_compute_pq_key_exchange(proj, loc, name) or "DEFAULT"
                policies.append(
                    _policy_record(
                        name,
                        item.name,
                        proj,
                        loc,
                        str(attrs.get("minTlsVersion") or attrs.get("min_tls_version") or "TLS_1_0"),
                        str(attrs.get("profile") or "COMPATIBLE"),
                        features if isinstance(features, list) else [],
                        str(raw_pq),
                    )
                )
            else:
                proxies_raw.append(
                    {
                        "proxy_name": name,
                        "resource_name": item.name,
                        "project_id": proj,
                        "proxy_type": item.asset_type,
                        "attached_ssl_policy": attrs.get("sslPolicy") or attrs.get("ssl_policy"),
                    }
                )
    except Exception as exc:
        return _compact_json(
            {
                "scope": scope_uri,
                "scope_mode": mode,
                "data_source": LIVE_DATA_SOURCE,
                "error": f"SSL policy / target proxy search failed: {type(exc).__name__}: {str(exc)[:300]}",
                "required_roles": ["roles/cloudasset.viewer", "roles/compute.viewer"],
            }
        )

    payload = {
        "scope": scope_uri,
        "scope_mode": mode,
        "data_source": LIVE_DATA_SOURCE,
        "generated_at": _now_iso(),
        "ssl_policies": policies,
        "target_proxies": _resolve_proxy_records(policies, proxies_raw),
        "reference_facts": TLS_REFERENCE_FACTS,
    }
    return _cache_put(cache_key, _compact_json(payload))


def _import_job_record(raw: Dict[str, Any], data_source: str) -> Dict[str, Any]:
    method = (raw.get("import_method") or "IMPORT_METHOD_UNSPECIFIED").upper()
    state = (raw.get("state") or "IMPORT_JOB_STATE_UNSPECIFIED").upper()
    if method in HPKE_PQC_IMPORT_METHODS:
        family, status = "HPKE_POST_QUANTUM_KEM", "QUANTUM_SAFE_PQC"
    elif method.startswith("RSA_OAEP"):
        family, status = "RSA_OAEP_CLASSICAL", "QUANTUM_VULNERABLE_SHOR"
    else:
        family, status = "UNRECOGNIZED", "UNKNOWN_REQUIRES_REVIEW"
    return {
        "project_id": raw.get("project_id"),
        "location": raw.get("location"),
        "key_ring": raw.get("key_ring"),
        "import_job_name": raw.get("import_job_name"),
        "resource_name": raw.get("resource_name"),
        "state": state,
        "is_active": state in ("ACTIVE", "PENDING_GENERATION"),
        "import_method": method,
        "wrapping_family": family,
        "transport_quantum_status": status,
        "protection_level": (raw.get("protection_level") or "UNKNOWN").upper(),
        "expire_time": raw.get("expire_time"),
        "data_source": data_source,
    }


def _discover_key_rings_via_cai(scope_uri: str) -> List[Dict[str, str]]:
    keyrings: List[Dict[str, str]] = []
    excluded = excluded_key_rings()
    cai_client = asset_v1.AssetServiceClient(**_get_client_kwargs())
    for item in _cai_search_all_resources_with_fallback(
        cai_client=cai_client,
        scope_uri=scope_uri,
        asset_types=["cloudkms.googleapis.com/KeyRing"],
        page_size=500,
    ):
        parts = item.name.split("/")
        if len(parts) >= 9 and parts[3] == "projects" and parts[5] == "locations" and parts[7] == "keyRings":
            if parts[8] in excluded:
                continue
            keyrings.append(
                {
                    "project_id": parts[4],
                    "location": parts[6],
                    "key_ring": parts[8],
                    "resource_name": f"projects/{parts[4]}/locations/{parts[6]}/keyRings/{parts[8]}",
                }
            )
    return keyrings


def collect_kms_import_jobs(
    scope: str = f"organizations/{DEFAULT_ORGANIZATION_ID}",
    location: str = "all",
) -> str:
    """Collects Cloud KMS ImportJobs (BYOK) with their wrapping method, state and protection level (facts only).

    Args:
        scope: 'organizations/<id>', 'folders/<id>', 'projects/<id>' or a bare project ID.
        location: Cloud KMS location filter or 'all'.

    Returns:
        JSON with `import_jobs` (import_method, wrapping_family, transport_quantum_status, state), `key_rings_inspected`,
        `collection_notes`, `data_source`, or an `error` object.
    """
    mode, scope_uri, clean_id = _resolve_scope(scope)
    loc = (location or "all").strip()
    simulated = simulation_requested(clean_id)
    cache_key = f"importjobs:{scope_uri}:{loc.lower()}:{simulated}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if simulated:
        jobs = [_import_job_record(j, SIMULATED_DATA_SOURCE) for j in mock_data.get_simulated_import_jobs(clean_id)]
        if loc.lower() not in ("all", "*", ""):
            jobs = [j for j in jobs if j["location"] == loc]
        payload = {
            "scope": scope_uri,
            "scope_mode": mode,
            "data_source": SIMULATED_DATA_SOURCE,
            "simulation_notice": SIMULATION_NOTICE,
            "generated_at": _now_iso(),
            "import_jobs": jobs,
            "key_rings_inspected": len({(j["project_id"], j["location"], j["key_ring"]) for j in jobs}),
            "collection_notes": [],
        }
        return _cache_put(cache_key, _compact_json(payload))

    notes: List[str] = []
    try:
        kms_client = kms_v1.KeyManagementServiceClient(**_get_client_kwargs())
        key_rings = _discover_key_rings_via_cai(scope_uri)
        if loc.lower() not in ("all", "*", ""):
            key_rings = [kr for kr in key_rings if kr["location"] == loc]
        if not key_rings and mode == "PROJECT":
            probe_locations = ["global"] if loc.lower() in ("all", "*", "") else [loc]
            notes.append(
                "Cloud Asset Inventory returned no key rings for this project; only "
                f"{', '.join(probe_locations)} was listed directly via the Cloud KMS API."
            )
            for probe_loc in probe_locations:
                for kr in kms_client.list_key_rings(request={"parent": f"projects/{clean_id}/locations/{probe_loc}"}):
                    key_rings.append(
                        {
                            "project_id": clean_id,
                            "location": probe_loc,
                            "key_ring": kr.name.split("/")[-1],
                            "resource_name": kr.name,
                        }
                    )

        def _list_jobs(kr_info: Dict[str, str]) -> List[Dict[str, Any]]:
            results: List[Dict[str, Any]] = []
            try:
                for ij in kms_client.list_import_jobs(request={"parent": kr_info["resource_name"]}):
                    results.append(
                        _import_job_record(
                            {
                                "project_id": kr_info["project_id"],
                                "location": kr_info["location"],
                                "key_ring": kr_info["key_ring"],
                                "import_job_name": ij.name.split("/")[-1],
                                "resource_name": ij.name,
                                "state": kms_v1.ImportJob.ImportJobState(ij.state).name,
                                "import_method": kms_v1.ImportJob.ImportMethod(ij.import_method).name,
                                "protection_level": kms_v1.ProtectionLevel(ij.protection_level).name,
                                "expire_time": str(ij.expire_time) if getattr(ij, "expire_time", None) else None,
                            },
                            LIVE_DATA_SOURCE,
                        )
                    )
            except Exception as exc:
                notes.append(f"Could not list import jobs in {kr_info['resource_name']}: {type(exc).__name__}: {str(exc)[:160]}")
            return results

        jobs: List[Dict[str, Any]] = []
        if key_rings:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(key_rings))) as executor:
                for kr_jobs in executor.map(_list_jobs, key_rings):
                    jobs.extend(kr_jobs)
    except Exception as exc:
        return _compact_json(
            {
                "scope": scope_uri,
                "scope_mode": mode,
                "data_source": LIVE_DATA_SOURCE,
                "error": f"Cloud KMS import job collection failed: {type(exc).__name__}: {str(exc)[:300]}",
                "required_roles": ["roles/cloudkms.viewer", "roles/cloudasset.viewer"],
            }
        )

    payload = {
        "scope": scope_uri,
        "scope_mode": mode,
        "data_source": LIVE_DATA_SOURCE,
        "generated_at": _now_iso(),
        "import_jobs": jobs,
        "key_rings_inspected": len(key_rings),
        "collection_notes": notes,
    }
    return _cache_put(cache_key, _compact_json(payload))
