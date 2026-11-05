"""Quantum cryptanalysis reference estimates and an illustrative CRQC scenario model (auditable calculations).

- Resource estimates come from published literature and are returned WITH citations and caveats.
- The scenario model is an explicitly illustrative stochastic model whose assumptions are returned in full.
- No financial figures are produced and nothing here is a forecast or a recommendation.
- Unknown algorithms are reported as `UNKNOWN_REQUIRES_REVIEW` (fail-closed), never as quantum-safe.
"""

from __future__ import annotations

import functools
import json
import math
import random
from typing import Any, Dict, List, Tuple

from tools.gcp_inventory import (
    DEFAULT_ORGANIZATION_ID,
    SIMULATED_DATA_SOURCE,
    SIMULATION_NOTICE,
    _compact_json,
    _now_iso,
    collect_kms_inventory,
)

LITERATURE = {
    "HANER_2017": "Häner, Roetteler & Svore (2017), 'Factoring using 2n+2 qubits with Toffoli based modular multiplication'.",
    "ROETTELER_2017": "Roetteler, Naehrig, Svore & Lauter (2017), 'Quantum resource estimates for computing elliptic curve discrete logarithms'.",
    "GIDNEY_EKERA_2021": "Gidney & Ekerå (2021), 'How to factor 2048 bit RSA integers in 8 hours using 20 million noisy qubits', Quantum 5, 433.",
    "GIDNEY_2025": "Gidney (2025), 'How to factor 2048 bit RSA integers with less than a million noisy qubits', arXiv:2505.15917.",
}

# Logical-qubit counts follow the cited circuit constructions (RSA: 2n+2; ECC: 9n + 2*ceil(log2 n) + 10).
QUANTUM_RESOURCE_ESTIMATES: Dict[str, Dict[str, Any]] = {
    "RSA_2048": {
        "attack_algorithm": "Shor (integer factorization)",
        "logical_qubits": 4098,
        "logical_qubits_basis": "2n+2 with n=2048 [HANER_2017]",
        "physical_estimates": [
            {"physical_qubits": "~20 million noisy qubits", "runtime": "~8 hours", "source": "GIDNEY_EKERA_2021"},
            {"physical_qubits": "< 1 million noisy qubits", "runtime": "< 1 week", "source": "GIDNEY_2025"},
        ],
    },
    "RSA_3072": {
        "attack_algorithm": "Shor (integer factorization)",
        "logical_qubits": 6146,
        "logical_qubits_basis": "2n+2 with n=3072 [HANER_2017]",
        "physical_estimates": [],
    },
    "RSA_4096": {
        "attack_algorithm": "Shor (integer factorization)",
        "logical_qubits": 8194,
        "logical_qubits_basis": "2n+2 with n=4096 [HANER_2017]",
        "physical_estimates": [],
    },
    "ECC_P256": {
        "attack_algorithm": "Shor (elliptic-curve discrete logarithm)",
        "logical_qubits": 2330,
        "logical_qubits_basis": "9n + 2*ceil(log2 n) + 10 with n=256 [ROETTELER_2017]",
        "physical_estimates": [],
    },
    "ECC_P384": {
        "attack_algorithm": "Shor (elliptic-curve discrete logarithm)",
        "logical_qubits": 3484,
        "logical_qubits_basis": "9n + 2*ceil(log2 n) + 10 with n=384 [ROETTELER_2017]",
        "physical_estimates": [],
    },
    "ED25519": {
        "attack_algorithm": "Shor (elliptic-curve discrete logarithm)",
        "logical_qubits": 2321,
        "logical_qubits_basis": "approximation using 9n + 2*ceil(log2 n) + 10 with n=255 [ROETTELER_2017]",
        "physical_estimates": [],
    },
    "SECP256K1": {
        "attack_algorithm": "Shor (elliptic-curve discrete logarithm)",
        "logical_qubits": 2330,
        "logical_qubits_basis": "9n + 2*ceil(log2 n) + 10 with n=256 [ROETTELER_2017]",
        "physical_estimates": [],
    },
}

ESTIMATE_CAVEATS = [
    "Logical-qubit counts depend on the circuit construction; different constructions trade qubits for gates/time.",
    "Physical-qubit and runtime estimates depend on hardware error rates and architecture and have fallen sharply "
    "over time (RSA-2048: ~20 million noisy qubits in 2021 vs. < 1 million in 2025).",
    "Statements about which algorithm will be broken first are uncertain and should be presented as such.",
    "Post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA) have no known efficient quantum attack; symmetric keys are "
    "affected by Grover's algorithm, which roughly halves their effective security bits.",
]

SCENARIO_MODEL_ASSUMPTIONS = {
    "iterations": 10000,
    "random_seed": 42,
    "start_year": 2026,
    "end_year": 2035,
    "initial_logical_qubits_median_2026": 140.0,
    "initial_logical_qubits_lognormal_sigma": 0.22,
    "annual_growth_rate_mean": 0.55,
    "annual_growth_rate_stddev": 0.11,
    "breakthrough_year_choices": [2028, 2029, 2030, 2031, 2032, None, None],
    "breakthrough_multiplier_range": [1.35, 1.85],
    "breach_thresholds_logical_qubits": {"ECC_P256": 2330, "ECC_P384": 3484, "RSA_2048": 4098, "RSA_4096": 8194},
}
SCENARIO_MODEL_DISCLAIMER = (
    "Illustrative stochastic scenario model with the assumptions listed. It is NOT a forecast of when a "
    "cryptographically relevant quantum computer will exist and must be presented with that caveat."
)


def _estimate_key(algorithm: str) -> str:
    algo = (algorithm or "").upper()
    if algo.startswith("RSA_"):
        return "RSA_4096" if "4096" in algo else ("RSA_3072" if "3072" in algo else "RSA_2048")
    if "P384" in algo:
        return "ECC_P384"
    if "P256" in algo:
        return "ECC_P256"
    if "ED25519" in algo:
        return "ED25519"
    if "SECP256K1" in algo:
        return "SECP256K1"
    return ""


def map_algorithm_to_quantum_profile(algorithm: str) -> Dict[str, Any]:
    """Returns the literature-based quantum profile of an algorithm, or an explicit non-Shor/unknown profile."""
    from tools.gcp_inventory import classify_algorithm

    facts = classify_algorithm(algorithm)
    status = facts["quantum_status"]
    profile: Dict[str, Any] = {
        "algorithm": facts["algorithm"],
        "quantum_status": status,
        "quantum_threat_model": facts["quantum_threat_model"],
    }
    if status == "QUANTUM_VULNERABLE_SHOR":
        estimate = dict(QUANTUM_RESOURCE_ESTIMATES[_estimate_key(algorithm) or "RSA_2048"])
        estimate["physical_estimates"] = [
            {**e, "source": LITERATURE[e["source"]]} for e in estimate.get("physical_estimates", [])
        ]
        profile.update(estimate)
    elif status == "QUANTUM_SAFE_PQC":
        profile["nist_pqc_security_category"] = facts.get("nist_pqc_security_category")
        profile["note"] = "No known efficient quantum attack against this NIST post-quantum algorithm."
    elif status in ("QUANTUM_RESISTANT_SYMMETRIC", "BELOW_PQ_SECURITY_TARGET"):
        profile["estimated_post_quantum_security_bits"] = facts.get("estimated_post_quantum_security_bits")
        profile["note"] = "Grover's algorithm gives a quadratic speedup on key search."
    else:
        profile["note"] = "Algorithm not recognized; quantum posture requires manual review."
    return profile


@functools.lru_cache(maxsize=2)
def _scenario_curve() -> Tuple[Dict[str, Any], ...]:
    a = SCENARIO_MODEL_ASSUMPTIONS
    rng = random.Random(a["random_seed"])
    years = list(range(a["start_year"], a["end_year"] + 1))
    samples_by_year: Dict[int, List[float]] = {y: [] for y in years}
    for _ in range(a["iterations"]):
        q0 = rng.lognormvariate(math.log(a["initial_logical_qubits_median_2026"]), a["initial_logical_qubits_lognormal_sigma"])
        growth = rng.gauss(a["annual_growth_rate_mean"], a["annual_growth_rate_stddev"])
        breakthrough_year = rng.choice(a["breakthrough_year_choices"])
        multiplier = rng.uniform(*a["breakthrough_multiplier_range"]) if breakthrough_year else 1.0
        for y in years:
            boost = multiplier if (breakthrough_year and y >= breakthrough_year) else 1.0
            samples_by_year[y].append(q0 * math.exp(growth * (y - a["start_year"])) * boost)

    curve: List[Dict[str, Any]] = []
    for y in years:
        samples = sorted(samples_by_year[y])
        n = len(samples)
        row: Dict[str, Any] = {
            "year": y,
            "median_logical_qubits": int(round(samples[n // 2])),
            "p95_logical_qubits": int(round(samples[int(n * 0.95)])),
        }
        for label, threshold in a["breach_thresholds_logical_qubits"].items():
            row[f"share_of_scenarios_reaching_{label.lower()}_threshold_pct"] = round(
                sum(1 for q in samples if q >= threshold) / n * 100.0, 1
            )
        curve.append(row)
    return tuple(curve)


def run_quantum_cryptanalysis_simulation(
    scope: str = f"organizations/{DEFAULT_ORGANIZATION_ID}",
    location: str = "all",
) -> str:
    """Profiles every active Cloud KMS key against published quantum-attack resource estimates.

    Returns, for the keys found by `collect_kms_inventory`: literature-based logical-qubit estimates (with the
    formula basis and citations), counts by quantum status, an illustrative CRQC scenario model with all of its
    assumptions, and explicit caveats. It does not prioritize keys or recommend actions.

    Args:
        scope: 'organizations/<id>', 'folders/<id>', 'projects/<id>' or a bare project ID.
        location: Cloud KMS location filter or 'all'.

    Returns:
        JSON with `key_profiles`, `counts_by_quantum_status`, `literature`, `estimate_caveats` and
        `illustrative_crqc_scenario_model`.
    """
    inventory = json.loads(collect_kms_inventory(scope=scope, location=location))
    if inventory.get("error") and not inventory.get("keys"):
        return _compact_json({"scope": inventory.get("scope"), "error": inventory["error"]})

    profiles: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}
    for key in inventory.get("keys", []):
        if not key.get("is_active"):
            continue
        profile = map_algorithm_to_quantum_profile(key["effective_algorithm"])
        profile.update(
            {
                "resource_name": key["resource_name"],
                "purpose": key["purpose"],
                "protection_level": key.get("protection_level"),
            }
        )
        profiles.append(profile)
        counts[profile["quantum_status"]] = counts.get(profile["quantum_status"], 0) + 1

    result: Dict[str, Any] = {
        "scope": inventory.get("scope"),
        "data_source": inventory.get("data_source"),
        "generated_at": _now_iso(),
        "active_keys_profiled": len(profiles),
        "counts_by_quantum_status": counts,
        "key_profiles": profiles,
        "literature": LITERATURE,
        "estimate_caveats": ESTIMATE_CAVEATS,
        "illustrative_crqc_scenario_model": {
            "disclaimer": SCENARIO_MODEL_DISCLAIMER,
            "assumptions": SCENARIO_MODEL_ASSUMPTIONS,
            "annual_curve": list(_scenario_curve()),
        },
    }
    if inventory.get("data_source") == SIMULATED_DATA_SOURCE:
        result["simulation_notice"] = SIMULATION_NOTICE
    return _compact_json(result)
