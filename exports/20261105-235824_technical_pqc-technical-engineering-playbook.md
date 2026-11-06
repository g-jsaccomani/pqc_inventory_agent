# PQC Technical Engineering Playbook

## 1. Inventory and Vulnerable Key Resources
The following key resources have been identified as vulnerable and require remediation:
- jwt-signing-rsa2048
- legacy-ecdsa-p256-sign (lab)
- legacy-ecdsa-p256-sign (prod)
- legacy-rsa-oaep-decrypt (lab)
- legacy-rsa-oaep-decrypt (prod)

## 2. Assessment Scorecard
- Weighted KMS PQC Maturity: 66.6%
- Asymmetric PQC Migration: 4/9 = 44.4%
- Symmetric Quantum Resistance: 13/13 = 100%
- Symmetric 90-Day Rotation Hygiene: 11/11 = 100%
- Algorithmic Quantum-Safe: 17/22 = 77.3%

## 3. Literature Quantum Estimates
- **RSA-2048:** 4098 logical qubits, Gidney 2025 arXiv:2505.15917
- **EC P-256:** 2330 logical qubits, Roetteler et al. 2017 arXiv:1706.06752

## 4. Technical Engineering Facts for Remediation
### 4.1. Migration Runbooks
Cloud KMS does not allow changing the algorithm of an existing CryptoKey across algorithm families. Therefore, migrating RSA or ECDSA keys to `PQ_SIGN_ML_DSA_65` (purpose `ASYMMETRIC_SIGN`) or `KEM_XWING` / `ML_KEM_768` (purpose `KEY_ENCAPSULATION`) requires creating a NEW CryptoKey. 

**Creation Command Example:**
```bash
gcloud kms keys create <proposed-new-key> --purpose=asymmetric-sign --default-algorithm=pq-sign-ml-dsa-65 --protection-level=hsm
```

**Rollback Steps:**
Roll back by switching the application configuration back to the legacy CryptoKey before disabling the legacy key version.

### 4.2. Signature Size Considerations
When migrating away from ECDSA P-256:
- **ECDSA P-256 raw signatures:** 64 bytes (~70-72 bytes DER)
- **ML-DSA-65 signatures:** 3,309 bytes

### 4.3. Cloud Load Balancing TLS Policies
For Cloud Load Balancing TLS policies, hybrid post-quantum key exchange (X25519MLKEM768, negotiated on TLS 1.3 handshakes) is controlled by the `--post-quantum-key-exchange` flag.
- `ENABLED` or `DEFAULT`: Enabled by default starting October 2026.
- `DEFERRED`: Disallows X25519MLKEM768 until October 2027.

**Policy Creation Command Example:**
```bash
gcloud compute ssl-policies create pqc-tls13-restricted-policy --profile=RESTRICTED --min-tls-version=1.3 --post-quantum-key-exchange=ENABLED
```

## 5. Validation Checklist and Open Questions
- [ ] Confirm application capability to handle 3,309-byte ML-DSA-65 signatures.
- [ ] Ensure application configurations can switch to the new CryptoKeys and successfully perform rollback if needed.
- [ ] Verify load balancers have appropriate TLS 1.3 policies with Post-Quantum Key Exchange enabled.
- **Open Question:** Have all downstream consumers of signed tokens (e.g., JWT) been updated to verify ML-DSA-65 signatures?
