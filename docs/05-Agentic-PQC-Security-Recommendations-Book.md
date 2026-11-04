# Agentic PQC Security Recommendations Book
**Google Cloud Consulting — Security Architecture, Q-VaR (95%) Risk Model, 3-Wave Roadmap & Golden Sample Report**

> **Google Drive Official Deliverable:** [Agentic PQC Security Recommendations Book](https://docs.google.com/document/d/1D-uN1-0OiTgp9x03F9RWrtDHNmZFRaJ-5dg8UWnuc0I/edit)

> **Executive Summary:** This Agentic PQC Security Recommendations Book translates live Google Cloud control-plane telemetry and 7-domain stakeholder calibration from the Agentic PQC Readiness & CBOM Engine into an actionable security leadership blueprint. Designed as a reusable customer engagement deliverable, it unifies deterministic 7-KPI posture scoring, physical surface-code quantum cryptanalysis (explaining why 256-bit Elliptic Curve cryptography falls before RSA-2048), 10,000-iteration Monte Carlo Quantum Value-at-Risk (Q-VaR 95%) financial modeling, a 5-pillar Google Cloud Security Architecture Bill of Materials (BOM), and a phased 2026–2035 migration roadmap aligned with NIST FIPS 203/204/205, NIST IR 8547, and EO 14412.

---

## 1. Security Executive Context & Customer Environment Parameterization

Adversaries are actively executing Harvest-Now, Decrypt-Later (HNDL) and Store-Now, Decrypt-Later (SNDL) collection against encrypted enterprise traffic, database backups, and identity tokens today. Once Cryptographically Relevant Quantum Computers (CRQCs) reach the ~2,330 to ~4,098 logical qubit threshold required by Shor's algorithm, classical asymmetric primitives (RSA, Diffie-Hellman, ECDH, ECDSA, Ed25519) will be retroactively compromised. This Security Recommendations Book establishes the customer's verified cryptographic baseline and target Google Cloud security architecture.

Consultative Security Advisory Framing (Non-Audit Positioning): Google Cloud Consulting (PSO) provides this document as a Consultative Post-Quantum Security Readiness Assessment, Posture Verification, and Target Architecture Blueprint. It does not constitute a statutory, regulatory, or compliance audit.

| Security Engagement Parameter | Template Configuration Token | Expected Format / Target Scope | Customer Environment Value (Populate per Engagement) |
| --- | --- | --- | --- |
| Customer Legal Entity Name | <CUSTOMER-LEGAL-NAME> | Full legal name of the organization | [ Leave Blank — Populate in Customer Environment ] |
| Primary Regulated Industry Sector | <INDUSTRY-SECTOR> | BFSI | Healthcare & Genomics | Public Sector & Defense | Telecom & 5G | Energy & OT | [ Leave Blank — Populate in Customer Environment ] |
| Assessed GCP Organization Scope | <CUSTOMER-ORG-ID> | organizations/<12-DIGIT-ORG-ID> | [ Leave Blank — Populate in Customer Environment ] |
| Agentic PQC Host Project & Engine | <CUSTOMER-HOST-PROJECT> | Cloud Run / Vertex AI Agent Engine Host Project | [ Leave Blank — Populate in Customer Environment ] |
| Calibrated Mosca Horizons (X, Y, Z) | <MOSCA-HORIZONS> | Shelf-Life X (yrs) + Migration Y (yrs) vs. CRQC Z (yrs) | [ Leave Blank — Populate from Discovery Questionnaire ] |
| Security Leadership Sponsor | <SECURITY-SPONSOR> | VP of Information Security / Head of Cloud Security / GRC Lead | [ Leave Blank — Populate in Customer Environment ] |

## 2. Validated 7-KPI Organization Cryptographic Security Scorecard

Every execution of the Agentic PQC Readiness Engine computes seven deterministic Key Performance Indicators (KPIs) directly in Python across the customer's live GCP telemetry (Cloud KMS/HSM, Cloud Asset Inventory 4-Vector workload dependencies, Compute SSL/TLS policies, Certificate Authority Service, and BYOK ImportJobs). The table below presents the reference benchmark scorecard alongside target security SLAs:

| Security Control Domain (NIST FIPS 203/204/205 & IR 8547) | Benchmark Score | Target Security SLA | Security Posture Verdict & Primary Exposure Vector |
| --- | --- | --- | --- |
| 1. Weighted Overall Agentic PQC Security Maturity | 70.0% | 100.0% | MODERATE — Immediate remediation required on asymmetric signing & KEM keys. |
| 2. Asymmetric Cryptography (Shor Immunity: RSA/ECC -> PQC) | 50.0% | 100.0% | CRITICAL — Classical ECDSA P-256 and RSA-2048 keys exposed to Shor & HNDL. |
| 3. Symmetric Data-at-Rest (AES-256 Grover Resilience) | 100.0% | 100.0% | COMPLIANT — AES-256-GCM provides 128-bit effective post-quantum security. |
| 4. Symmetric Key Rotation Hygiene (<= 90-Day Cryptoperiod) | 66.7% | 100.0% | ACTION REQUIRED — Unrotated symmetric CMEKs increase ciphertext exposure volume. |
| 5. Network Edge TLS 1.3 (X25519MLKEM768 Hybrid Readiness) | 50.0% | 100.0% | MODERATE — Legacy TLS 1.0/1.2 SSL policies allow classical SNDL session capture. |
| 6. BYOK / HYOK Supply Chain (Cloud KMS ImportJob Wrapping) | 50.0% | 100.0% | MODERATE — Classical RSA-OAEP wrapping exposes imported key material in transit. |
| 7. Application & API Gateway Crypto Agility (Tink & 16KB+ JWT) | 45.0% | 100.0% | HIGH PRIORITY — Direct AsymmetricDecrypt calls and 8KB proxy header ceilings. |

## 3. Physical Quantum Fall-Order Prioritization (Why Elliptic Curves Fall Before RSA-2048)

A widespread misconception in enterprise security teams is that 256-bit Elliptic Curve Cryptography (ECDSA P-256, ECDH X25519, Ed25519) is more resistant to quantum computers than RSA-2048 because ECC is stronger against classical computers. In quantum physics, the exact opposite is true: Shor's algorithm solves the Elliptic Curve Discrete Logarithm Problem (ECDLP) with nearly half the logical qubits required to factor a 2048-bit RSA modulus.

- Elliptic Curve Discrete Logarithm Vulnerability (Roetteler et al., 2017): Breaking a 256-bit elliptic curve (ECDSA P-256 / Ed25519 / X25519) requires Q-logical = 9n + 2*ceil(log2(n)) + 10 = 2,330 logical qubits and ~1.26 x 10^11 Toffoli gates. Under a planar surface code at code distance d = 27 (physical gate error rate 10^-3), this translates to ~3.40M to ~13.4M physical qubits (depending on magic-state distillation factory concurrency) and an ~8-to-9.5 hour runtime. Therefore, ECDSA P-256 and X25519 will be broken by smaller, earlier quantum processors than RSA-2048.
- Integer Factorization Vulnerability (Gidney & Ekera, 2021): Factoring an n = 2048-bit RSA modulus via windowed modular exponentiation requires Q-logical = 2n + 2 = 4,098 logical qubits and ~2.7 x 10^10 Toffoli gates (~5.97M to ~20.0M physical qubits at surface-code distance d = 27, executing in ~8.0 hours). While RSA-2048 requires ~1.76x more logical qubits than ECDSA P-256, it remains critically exposed to Harvest-Now, Decrypt-Later (HNDL) archival decryption.
- Module-Lattice & Symmetric Quantum Resilience (Albrecht Core-SVP & Grassl Grover): NIST FIPS 203 (ML-KEM-768 / KEM-XWING) and FIPS 204 (ML-DSA-65) rely on Module-LWE / Module-SIS lattices with BKZ block sizes beta >= 590–625, requiring > 2^156 to 2^167 quantum sieve operations. Symmetric AES-256-GCM under Grover's quadratic speedup (Grassl et al., 2016) requires ~2,953 logical qubits executing ~2^128 sequential oracle iterations—physically infeasible within cosmological timescales.

| Quantum Fall Order | Cryptographic Primitive Class | Logical Qubits (Shor / Grover) | Physical Qubits (Surface Code d=27-31) | Security Remediation Priority & Target Replacement |
| --- | --- | --- | --- | --- |
| 1st to Fall (Earliest CRQC Break) | ECDSA P-256 / Ed25519 / ECDH P-256 | 2,330 Logical Qubits | ~3.40M – 13.4M Physical Qubits | P0 Immediate — Migrate to Cloud HSM PQ-SIGN-ML-DSA-65 (FIPS 204) & X25519MLKEM768 |
| 2nd to Fall (Critical HNDL Exposure) | RSA-2048 (OAEP Decrypt / PSS Sign) | 4,098 Logical Qubits | ~5.97M – 20.0M Physical Qubits | P1 Urgent — Migrate to Cloud HSM KEM-XWING / ML-KEM-768 (FIPS 203) & Google Tink SDK |
| 3rd to Fall (High HNDL Exposure) | RSA-3072 / RSA-4096 (BYOK & Root PKI) | 6,146 – 8,194 Logical Qubits | ~15.0M – 52.0M Physical Qubits | P2 Planned — Migrate CAS Root/Subordinate CAs & KMS ImportJobs to ML-DSA / SLH-DSA |
| Quantum-Safe Target Baseline | AES-256-GCM / ML-KEM-768 / ML-DSA-65 | Core-SVP >= 166b / Grover > 2^128 | Computationally Infeasible | Target State — Enforce <= 90-day symmetric rotation & FIPS 140-3 Level 3 Cloud HSM |

## 4. Financial Risk Quantification: Mosca's Theorem (X + Y > Z) & Monte Carlo Q-VaR (95%)

To enable Security Leadership, Risk Committees, and CFOs to prioritize capital allocation, the Agentic PQC Readiness Engine pairs Dr. Michele Mosca's inequality (X + Y > Z) with a 10,000-iteration Monte Carlo Quantum Value-at-Risk (Q-VaR 95%) simulation in USD:

- Mosca's Theorem (X + Y > Z) Operationalized: When the required confidentiality shelf-life of regulated data (X years) plus the engineering time required to refactor and migrate cryptographic infrastructure (Y years) exceeds the time remaining until a Cryptographically Relevant Quantum Computer arrives (Z years), the organization is in active HNDL breach status today.
- Benchmark Financial Exposure (Unmitigated vs. Mitigated Q-VaR 95%): Across the reference enterprise benchmark, unmitigated 95th-percentile Quantum Value-at-Risk reaches US$ 10.32 Million (driven by regulatory fines under GDPR/LGPD/HIPAA/PCI-DSS, per-record notification costs, and sovereign IP loss). Completing the recommended Google Cloud PQC architecture migration reduces residual Q-VaR (95%) to US$ 0.15 Million—a 98.5% net financial risk reduction.

| Regulated Industry Vertical | Confidentiality Horizon (X) & Migration Time (Y) | Mosca Sum (X + Y) vs. CRQC Window (Z=9 yrs) | Q-VaR Sector Multiplier | Primary Financial & Regulatory Exposure Drivers |
| --- | --- | --- | --- | --- |
| Banking & Financial Services (BFSI) | X = 15 yrs | Y = 3.5 yrs | 18.5 yrs > 9 yrs (OVERDUE: -9.5 yrs) | 1.35x Multiplier | ISO 20022 wire settlement, PCI-DSS v4.0.1, EU DORA, BACEN BCB 85/4893, long-term credit archives. |
| Healthcare, Biopharma & Genomics | X = 35 yrs | Y = 5.0 yrs | 40.0 yrs > 9 yrs (OVERDUE: -31.0 yrs) | 1.50x Multiplier | Non-revocable human genomic sequences, permanent EHR/PHI records, HIPAA, FDA SaMD cybersecurity. |
| Public Sector, Defense & National Infra | X = 30 yrs | Y = 4.5 yrs | 34.5 yrs > 9 yrs (OVERDUE: -25.5 yrs) | 1.60x Multiplier | Sovereign citizen registries, classified CUI, White House EO 14412, OMB M-26-15, NSA CNSA 2.0. |
| Telecommunications, 5G Core & Cloud | X = 12 yrs | Y = 3.0 yrs | 15.0 yrs > 9 yrs (OVERDUE: -6.0 yrs) | 1.30x Multiplier | 3GPP SA3 5G SUCI subscriber identity privacy, eSIM root PKI, carrier IPsec/MACsec trunks. |
| Energy, Utilities & Industrial OT | X = 20 yrs | Y = 6.0 yrs | 26.0 yrs > 9 yrs (OVERDUE: -17.0 yrs) | 1.40x Multiplier | Substation SCADA/PLC long-lived firmware roots, NERC CIP, IEC 62443 critical infrastructure. |

## 5. Recommended Target Security Architecture on Google Cloud (5-Pillar Product BOM)

To remediate discovered vulnerabilities without disrupting production SLAs, Google Cloud PSO recommends a defense-in-depth Target Security Architecture built on five native Google Cloud security capabilities:

| Pillar # | Google Cloud Security Product Pillar | Target PQC Primitives & Capabilities | Identified Cryptographic Gap Resolved & Business Value |
| --- | --- | --- | --- |
| Pillar 1 | Cloud HSM (FIPS 140-3 Level 3) & Cloud KMS PQC | PQ-SIGN-ML-DSA-65 (FIPS 204), KEM-XWING & ML-KEM-768 (FIPS 203), SLH-DSA (FIPS 205), HPKE BYOK Import. | Eliminates Shor vulnerability on asymmetric signing/encryption keys and secures BYOK key import chains inside hardware roots of trust. |
| Pillar 2 | Global External Application Load Balancing (L7), Cloud Armor & CAS | Hybrid TLS 1.3 Key Exchange (X25519MLKEM768) + Dual-Root CAS PKI (ML-DSA-65 / SLH-DSA). | Neutralizes passive Store-Now, Decrypt-Later (SNDL) packet capture at the internet edge and modernizes internal mTLS PKI. |
| Pillar 3 | Google Tink SDK & Apigee / Envoy Gateway Modernization | Hybrid Envelope Encryption (KEM-XWING KEK + AES-256-GCM DEK) + 16KB–32KB HTTP Header Buffers. | Abstracts KEM Encapsulate/Decapsulate API breaking changes from application code and prevents HTTP 431 errors on 3,309B ML-DSA JWTs. |
| Pillar 4 | VPC Service Controls (VPC-SC) & Private Service Connect (PSC) | Context-aware zero-trust service perimeters around BigQuery, Cloud Storage, Cloud SQL & Cloud KMS. | Prevents bulk Harvest-Now, Decrypt-Later (HNDL) ciphertext exfiltration even if an application credential is compromised. |
| Pillar 5 | Binary Authorization, Artifact Registry & SCC Enterprise | Post-quantum container attestation (PQ-SIGN-ML-DSA-65) + continuous cryptographic drift monitoring. | Secures the CI/CD software supply chain against forged signatures and enforces continuous compliance with NIST IR 8547. |

## 6. Domain-by-Domain Prescriptive Security Recommendations (Domains 1 to 7)

- Domain 1 (Governance & CycloneDX v1.6 CBOM): Establish a formal Post-Quantum Migration Office chartered by Security Leadership; integrate automated OWASP CycloneDX v1.6 CBOM generation into quarterly GRC reviews and mandate PQC readiness attestations in third-party vendor procurement contracts.
- Domain 2 (Data Confidentiality Shelf-Life & HNDL Containment): Immediately enclose all Tier-0 data repositories with confidentiality shelf-life X >= 10 years (BigQuery datasets, GCS archival buckets, Cloud SQL instances) inside VPC Service Controls (VPC-SC) perimeters and re-wrap archival DEKs under hybrid KEM-XWING KEKs.
- Domain 3 (KMS, Cloud HSM & BYOK Supply Chain): Upgrade all production asymmetric keys from SOFTWARE protection level to FIPS 140-3 Level 3 Cloud HSM; enforce automated <= 90-day rotation (7,776,000s) on all AES-256 symmetric CMEKs; and replace classical RSA-OAEP BYOK ImportJobs with quantum-safe HPKE wrapping.
- Domain 4 (Application Cryptographic Agility & Database Schemas): Refactor direct Cloud KMS AsymmetricDecrypt() API calls to Google Tink SDK envelope encryption; audit relational/NoSQL database schemas (Cloud SQL, Spanner, AlloyDB) to expand fixed-width signature/key columns (e.g., VARBINARY(256) -> BLOB / BYTEA) before cutover.
- Domain 5 (Identity, OIDC/SAML & API Gateway Buffers): Increase HTTP request header limits (max-request-headers-kb) from 4KB/8KB to 16KB–32KB across Envoy proxies, NGINX ingresses, and Apigee API Gateways to accommodate 3,309-byte ML-DSA-65 signatures (~4.4 KB Base64URL JWTs), or adopt opaque Phantom Tokens at the edge.
- Domain 6 (Edge TLS 1.3 X25519MLKEM768 & CAS PKI): Enforce minTlsVersion = TLS-1-3 and the RESTRICTED cipher profile across all Google Cloud HTTPS Load Balancers; tune TCP initial congestion windows (initcwnd) for 1,120-byte hybrid key shares; and deploy parallel cross-signed ML-DSA-65 subordinate CAs in Certificate Authority Service (CAS).
- Domain 7 (CI/CD Supply Chain & Binary Authorization): Migrate container image and CI/CD artifact signing attestors in Binary Authorization from ECDSA P-256 / RSA-PSS to Cloud HSM PQ-SIGN-ML-DSA-65, and adopt stateless hash-based SLH-DSA (FIPS 205) for long-lived firmware roots.

## 7. Preventive Governance: Declarative GCP Organization Policy Guardrails

Remediation without preventive governance leads to cryptographic regression as engineering teams provision new cloud resources. Google Cloud PSO recommends enforcing three declarative GCP Organization Policy guardrails upon completing Phase 3 pilot validation:

1. Enforce Hardware Root of Trust (constraints/cloudkms.allowedProtectionLevels): Configure the Organization Policy constraint on production folders to permit only HSM and EXTERNAL protection levels, blocking creation of software-backed asymmetric keys.
2. Block New Classical Asymmetric Key Provisioning (Custom Org Policy Constraint): Deploy a Custom Organization Policy constraint on googleapis.com/CryptoKey resources evaluating resource.versionTemplate.algorithm to deny creation of new RSA-SIGN-*, RSA-DECRYPT-*, and EC-SIGN-* algorithms in migrated production projects without an approved exception label.
3. Enforce Minimum TLS 1.3 & Restricted Cipher Profiles (Custom Compute SSL Policy Constraint): Enforce custom constraints on compute.googleapis.com/SslPolicy resources requiring minTlsVersion == TLS-1-3 and profile == RESTRICTED across all external load balancers.

## 8. Phased Multi-Horizon Security Modernization Roadmap (2026–2035)

The table below sequences the recommended security engineering workstreams across three operational horizons—from the initial 6-week PSO assessment through full classical algorithm disallowance under NIST IR 8547 and EO 14412:

| Migration Horizon & Timeline | Strategic Security Objective | Core Engineering & Governance Deliverables | Target Maturity & Q-VaR Reduction |
| --- | --- | --- | --- |
| Horizon 1: Days 1–45<br>(6-Week PSO Assessment & Pilot) | Baseline Discovery, Calibration, Edge Containment & Non-Prod HSM Pilot | Complete 7-Domain Discovery Questionnaire, CycloneDX v1.6 CBOM, Q-VaR (95%) model, VPC-SC HNDL containment, and Week 5 Non-Prod Cloud HSM PQC Key Pilot. | Maturity: 45% -> 70%<br>Q-VaR Reduction: -35% (Containment) |
| Horizon 2: Months 3–12<br>(Hybrid Dual-Stack Production Rollout) | Production Edge TLS 1.3 (X25519MLKEM768), Tink SDK KEM & Dual-Key JWKS | Upgrade L7 Load Balancers to TLS 1.3 X25519MLKEM768; tune Envoy/Apigee to 16KB–32KB; refactor Tier-0 apps to Google Tink KEM-XWING; rotate P0 ECDSA/RSA keys in Cloud HSM. | Maturity: 70% -> 92%<br>Q-VaR Reduction: -90% (Tier-0 PQC) |
| Horizon 3: Months 12–36+<br>(Full NIST IR 8547 2030/2035 Compliance) | Full Classical Asymmetric Deprecation, PQC Root PKI & Preventive Org Policies | Complete CAS ML-DSA-65 / SLH-DSA PKI cutover; enforce preventive GCP Organization Policies blocking RSA/ECC; disable all legacy classical key versions ahead of 2030 mandate. | Maturity: 92% -> 100%<br>Q-VaR Reduction: -98.5% (Quantum-Safe) |

## 9. Reference Golden Sample: Live GCP Telemetry Assessment & CBOM Report (Org 31564119954)

## 1. Executive Summary (BLUF) & Validated Scorecard

Authenticity Attestation: LIVE-GCP-TELEMETRY-VERIFIED | Quantum Engine: 2.0.0-GidneyEkera-Roetteler-CoreSVP-Validated.

| Executive KPI / Posture Metric | Validated Value | Target Benchmark | Consultative Assessment |
| --- | --- | --- | --- |
| Weighted PQC Maturity Score | 70.0% | 100.0% | MODERATE — Immediate action required on asymmetric keys |
| Asymmetric Migration Score (Shor Immunity) | 50.0% (2/4 keys) | 100.0% | CRITICAL — ECDSA P-256 & RSA-2048 exposed to Shor/HNDL |
| Symmetric Data-at-Rest (Grover Resilience) | 100.0% (6/6 keys) | 100.0% | COMPLIANT — AES-256 provides 128-bit post-quantum security |
| Symmetric Rotation Hygiene (<= 90 Days) | 66.7% (4/6 keys) | 100.0% | ACTION REQUIRED — 2 AES-256 keys lack 90-day rotation |
| SSL/TLS Edge Readiness (X25519MLKEM768) | 50.0% | 100.0% | ACTION REQUIRED — Upgrade TLS 1.0/1.2 policies to TLS 1.3 |
| Monte Carlo Q-VaR (95% Financial Exposure) | US$ 10.32M -> US$ 0.15M | < US$ 0.25M | 98.5% Risk Reduction upon PQC Remediation |

## 2. Quantum Physics Cryptanalysis & Fall-Order Ranking

| Fall Order | Asset Name (Project / KeyRing) | Algorithm | Logical / Physical Qubits | Estimated Break Time & Risk |
| --- | --- | --- | --- | --- |
| 1st to Fall | jwt-signing-ecdsa-key (auth-kr) | EC-SIGN-P256-SHA256 | 2,330 Logical / ~13.4M Physical | ~9.5 Hours on CRQC — P0 Immediate |
| 2nd to Fall | legacy-payment-rsa-key (payments-kr) | RSA-DECRYPT-OAEP-2048-SHA256 | 4,098 Logical / ~20.0M Physical | ~8.0 Hours on CRQC — P1 Active HNDL |
| Quantum-Safe | pqc-hybrid-kem-key (payments-kr) | KEM-XWING (X25519 + ML-KEM-768) | Core-SVP 167-Bit Lattice | Quantum-Safe (NIST FIPS 203 Hybrid) |
| Quantum-Safe | pqc-mldsa-signing-key (auth-kr) | PQ-SIGN-ML-DSA-65 | Core-SVP 166-Bit Lattice | Quantum-Safe (NIST FIPS 204 Level 3) |

## 3. Consultative 5-Step Remediation Runbooks (100% of Vulnerable Keys)

### 3.1 Runbook 1 — jwt-signing-ecdsa-key (EC-SIGN-P256-SHA256 -> PQ-SIGN-ML-DSA-65)

1. Step 1 — Provision PQC Key in Cloud HSM: gcloud kms keys create jwt-signing-ecdsa-key-pqc --keyring=auth-kr --location=global --purpose=asymmetric-signing --default-algorithm=pq-sign-ml-dsa-65 --protection-level=hsm --project=<TARGET-PROJECT-ID>
2. Step 2 — Replicate Least-Privilege IAM Binding: gcloud kms keys add-iam-policy-binding jwt-signing-ecdsa-key-pqc --keyring=auth-kr --location=global --member="serviceAccount:Workload-SA@<TARGET-PROJECT-ID>.iam.gserviceaccount.com" --role="roles/cloudkms.signerVerifier"
3. Step 3 — Gateway & JWT Header Adaptation: Increase max-request-headers-kb to 16KB-32KB in Envoy/Cloud Armor/NGINX to accommodate 3,309-byte ML-DSA-65 signatures.
4. Step 4 — Dual-Signing Canary Cutover: Publish both ECDSA P-256 and ML-DSA-65 public keys in JWKS endpoint during canary rollout.
5. Step 5 — Post-Change Verification & Legacy Disablement: Run gcloud kms keys versions list --key=jwt-signing-ecdsa-key-pqc --keyring=auth-kr --location=global and disable legacy version via gcloud kms keys versions disable 1 --key=jwt-signing-ecdsa-key --keyring=auth-kr --location=global.

### 3.2 Runbook 2 — legacy-payment-rsa-key (RSA-2048 -> KEM-XWING / ML-KEM-768)

1. Step 1 — Provision Hybrid PQC KEM Key in Cloud HSM: gcloud kms keys create legacy-payment-rsa-key-pqc --keyring=payments-kr --location=us-central1 --purpose=key-encapsulation --default-algorithm=kem-xwing --protection-level=hsm --project=<TARGET-PROJECT-ID>
2. Step 2 — Replicate Least-Privilege IAM Binding: Grant roles/cloudkms.cryptoOperator to the payment workload Service Account.
3. Step 3 — Refactor AsymmetricDecrypt to KEM Decapsulate / Google Tink: Replace raw RSA decryption calls with Cloud KMS Decapsulate() or Google Tink AEAD envelope encryption.
4. Step 4 — Historical Data Re-Encryption (HNDL Mitigation): Re-wrap stored payment archives encrypted under RSA-2048 using AES-256-GCM DEKs protected by KEM-XWING.
5. Step 5 — Post-Change Verification & Legacy Disablement: Verify ENABLED state via gcloud kms keys versions list and disable the classical RSA-2048 version.
