"""Realistic simulation data for GCP cryptographic inventory (Cloud KMS + Cloud Asset Inventory).

Used when PQC_SIMULATION_MODE=TRUE or in AUTO mode when the target project is a
local test/demo identifier without live KMS keys provisioned.
"""

from typing import Any, Dict, List


def get_simulated_kms_raw_keys(project_id: str, location_id: str = "global") -> List[Dict[str, Any]]:
    """Returns a realistic list of Cloud KMS keys for PQC Agent validation."""
    all_keys = [
        {
            "key_ring": "kr-core-banking-prod",
            "key_name": "cmek-pix-envelope-rsa",
            "location": "southamerica-east1",
            "purpose": "ASYMMETRIC_DECRYPT",
            "algorithm": "RSA_DECRYPT_OAEP_2048_SHA256",
            "protection_level": "HSM",
            "rotation_period_days": None,
            "labels": {"env": "prod", "system": "pix-settlement", "data_classification": "confidential"},
        },
        {
            "key_ring": "kr-core-banking-prod",
            "key_name": "jwt-auth-signing-ecdsa",
            "location": "southamerica-east1",
            "purpose": "ASYMMETRIC_SIGN",
            "algorithm": "EC_SIGN_P256_SHA256",
            "protection_level": "HSM",
            "rotation_period_days": None,
            "labels": {"env": "prod", "system": "iam-federation", "data_classification": "restricted"},
        },
        {
            "key_ring": "kr-digital-signature-global",
            "key_name": "doc-legal-signing-rsa4096",
            "location": "global",
            "purpose": "ASYMMETRIC_SIGN",
            "algorithm": "RSA_SIGN_PSS_4096_SHA256",
            "protection_level": "SOFTWARE",
            "rotation_period_days": None,
            "labels": {"env": "prod", "system": "contracts-pki", "retention": "10y"},
        },
        {
            "key_ring": "kr-data-lake-encryption",
            "key_name": "bq-customer-pii-cmek",
            "location": "us-central1",
            "purpose": "ENCRYPT_DECRYPT",
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
            "protection_level": "SOFTWARE",
            "rotation_period_days": 90,
            "labels": {"env": "prod", "system": "bigquery-dwh", "data_classification": "pii"},
        },
        {
            "key_ring": "kr-api-gateway-mac",
            "key_name": "webhook-hmac-sha256",
            "location": "us-central1",
            "purpose": "MAC",
            "algorithm": "HMAC_SHA256",
            "protection_level": "HSM",
            "rotation_period_days": None,
            "labels": {"env": "prod", "system": "open-finance-gateway"},
        },
        {
            "key_ring": "kr-pqc-pilot-2026",
            "key_name": "kem-xwing-vault-transit",
            "location": "global",
            "purpose": "KEY_ENCAPSULATION",
            "algorithm": "KEM_XWING",
            "protection_level": "SOFTWARE",
            "rotation_period_days": None,
            "labels": {"env": "pilot", "system": "pqc-zero-trust", "nist_standard": "hybrid-ml-kem-768"},
        },
        {
            "key_ring": "kr-pqc-pilot-2026",
            "key_name": "mldsa65-artifact-attestation",
            "location": "global",
            "purpose": "ASYMMETRIC_SIGN",
            "algorithm": "PQ_SIGN_ML_DSA_65",
            "protection_level": "SOFTWARE",
            "rotation_period_days": None,
            "labels": {"env": "pilot", "system": "binary-authorization", "nist_standard": "fips-204"},
        },
        {
            "key_ring": "kr-pqc-pilot-2026",
            "key_name": "slhdsa-root-ca-backup",
            "location": "global",
            "purpose": "ASYMMETRIC_SIGN",
            "algorithm": "PQ_SIGN_SLH_DSA_SHA2_128S",
            "protection_level": "SOFTWARE",
            "rotation_period_days": None,
            "labels": {"env": "pilot", "system": "root-pki", "nist_standard": "fips-205"},
        },
    ]

    if location_id and location_id.lower() not in ("all", "*"):
        filtered = [k for k in all_keys if k["location"] == location_id]
        if location_id == "global":
            return all_keys
        return filtered
    return all_keys


def get_simulated_cai_assets(scope: str) -> List[Dict[str, Any]]:
    """Returns simulated cryptographic assets from Cloud Asset Inventory (Certificates, TLS Policies, CAS)."""
    project_slug = scope.split("/")[-1] if "/" in scope else scope
    return [
        {
            "asset_type": "compute.googleapis.com/SslCertificate",
            "name": f"//compute.googleapis.com/projects/{project_slug}/global/sslCertificates/cert-openbanking-rsa2048",
            "location": "global",
            "display_name": "cert-openbanking-rsa2048",
            "algorithm_details": "RSA-2048 / SHA256withRSA",
            "quantum_status": "VULNERABLE_CLASSICAL_RSA_ECC",
            "hndl_exposure": "HIGH (External TLS traffic exposed to Harvest Now, Decrypt Later without hybrid ML-KEM KEX)",
            "remediation": "Enable Post-Quantum Hybrid Key Exchange (X25519MLKEM768) on Cloud Load Balancing and plan certificate transition to ML-DSA (FIPS 204).",
        },
        {
            "asset_type": "compute.googleapis.com/SslPolicy",
            "name": f"//compute.googleapis.com/projects/{project_slug}/global/sslPolicies/ssl-policy-legacy-tls11",
            "location": "global",
            "display_name": "ssl-policy-legacy-tls11",
            "algorithm_details": "TLS 1.1 Minimum / MODERN Profile",
            "quantum_status": "VULNERABLE_LEGACY_TLS_POLICY",
            "hndl_exposure": "CRITICAL (Allows cipher suites without Forward Secrecy or without TLS 1.3 + PQC Hybrid KEX support)",
            "remediation": "Update SSL Policy to minTlsVersion=TLS_1_3 and profile=RESTRICTED to enforce Post-Quantum hybrid key exchange negotiation (X25519MLKEM768).",
        },
        {
            "asset_type": "privateca.googleapis.com/CertificateAuthority",
            "name": f"//privateca.googleapis.com/projects/{project_slug}/locations/southamerica-east1/caPools/corp-pki/certificateAuthorities/sub-ca-ecdsa-p384",
            "location": "southamerica-east1",
            "display_name": "sub-ca-ecdsa-p384",
            "algorithm_details": "EC_P384_SHA384",
            "quantum_status": "VULNERABLE_CLASSICAL_RSA_ECC",
            "hndl_exposure": "HIGH (Long-lived internal PKI vulnerable to identity forgery via Shor's Algorithm)",
            "remediation": "Plan a parallel/hybrid CA hierarchy in Certificate Authority Service or Cloud KMS using ML-DSA-65/87 (FIPS 204) or SLH-DSA (FIPS 205).",
        },
    ]
