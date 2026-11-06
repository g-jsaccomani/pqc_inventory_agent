# PQC Executive Board Report

## Bottom Line
This report outlines the Post-Quantum Cryptography (PQC) readiness for the assessed scope. Based on the current inventory of 22 cryptographic keys, we have identified specific risks related to legacy asymmetric algorithms that require modernization to quantum-resistant standards.

## Scorecard
- **Total Keys:** 22
- **Overall Maturity:** 66.6%
- **Asymmetric PQC:** 4/9 keys
- **Symmetric Hygiene:** 13/13 keys
- **Rotation Hygiene:** 13/13 keys
- **Algorithmic Quantum Safe:** 17/22 keys

## Mosca's Theorem Calibration
*Assessing the urgency of PQC migration (X + Y vs Z)*
- **X (Shelf-life of data):** 10 years
- **Y (Migration time):** 2 years
- **Z (Time to CRQC):** 8.5 years (enterprise defaults)
- **Assessment:** Since X + Y (12) > Z (8.5), there is an urgent need to transition to quantum-safe cryptography to protect long-term confidential data against Harvest Now, Decrypt Later (HNDL) attacks.

## Top Risks
1. **Priority 1 (HNDL - Harvest Now, Decrypt Later):**
   - **Assets:** `legacy-rsa-oaep-decrypt` (in lab & prod)
   - **Decision Needed/Action:** Requires immediate move to **ML-KEM**.

2. **Priority 2 (Forgery):**
   - **Assets:** `legacy-ecdsa-p256-sign` (in lab & prod) and `jwt-signing-rsa2048`
   - **Decision Needed/Action:** Requires move to **ML-DSA**.

## Decisions Needed
1. Approve the resource allocation for the immediate migration of Priority 1 `legacy-rsa-oaep-decrypt` keys to ML-KEM.
2. Approve the migration timeline for Priority 2 signing keys to ML-DSA.

## Phased Roadmap
- **Phase 1 (Immediate):** Address Priority 1 HNDL risks. Migrate `legacy-rsa-oaep-decrypt` to ML-KEM.
- **Phase 2 (Short-term):** Address Priority 2 Forgery risks. Migrate `legacy-ecdsa-p256-sign` and `jwt-signing-rsa2048` to ML-DSA.
- **Phase 3 (Ongoing):** Maintain 100% symmetric and rotation hygiene, ensuring all future keys adhere to PQC standards.

*(Note: Findings are strictly based on the provided assessment facts. No demo data was generated.)*
