# Agentic PQC Security Recommendations Book
**Google Cloud Consulting — Security Architecture, Auditable Risk Scorecard, 3-Wave Roadmap & Golden Sample Report**

> **Google Drive Official Deliverable:** [Agentic PQC Security Recommendations Book](https://docs.google.com/document/d/1D-uN1-0OiTgp9x03F9RWrtDHNmZFRaJ-5dg8UWnuc0I/edit)

> **Executive Summary:** This Agentic PQC Security Recommendations Book turns the evidence collected by the Agentic PQC Gemini AI agents from read-only Google Cloud control-plane telemetry, together with 7-domain stakeholder calibration, into an actionable security leadership blueprint. Designed as a reusable customer engagement deliverable, it unifies an auditable posture scorecard (every KPI with numerator, denominator and definition), literature-based quantum resource estimates with citations and caveats (explaining why 256-bit Elliptic Curve cryptography needs fewer logical qubits than RSA-2048), an optional business-impact view sized only with the customer's own data-value and breach-cost inputs, a 5-pillar Google Cloud Security Architecture Bill of Materials (BOM), and a phased 2026–2035 migration roadmap aligned with NIST FIPS 203/204/205, NIST IR 8547, and EO 14412.

---

## 1. Security Executive Context & Customer Environment Parameterization

Adversaries are actively executing Harvest-Now, Decrypt-Later (HNDL) and Store-Now, Decrypt-Later (SNDL) collection against encrypted enterprise traffic, database backups, and identity tokens today. Once Cryptographically Relevant Quantum Computers (CRQCs) reach the scale of published Shor constructions requiring roughly 2,330 to 4,098 logical qubits (newer constructions trade qubits for runtime), classical asymmetric primitives (RSA, Diffie-Hellman, ECDH, ECDSA, Ed25519) will be retroactively compromised. This Security Recommendations Book establishes the customer's verified cryptographic baseline and target Google Cloud security architecture.

Consultative Security Advisory Framing (Non-Audit Positioning): Google Cloud Consulting (PSO) provides this document as a Consultative Post-Quantum Security Readiness Assessment, Posture Verification, and Target Architecture Blueprint. It does not constitute a statutory, regulatory, or compliance audit.

| Security Engagement Parameter | Template Configuration Token | Expected Format / Target Scope | Customer Environment Value (Populate per Engagement) |
| --- | --- | --- | --- |
| Customer Legal Entity Name | <CUSTOMER-LEGAL-NAME> | Full legal name of the organization | [ Leave Blank — Populate in Customer Environment ] |
| Primary Regulated Industry Sector | <INDUSTRY-SECTOR> | BFSI | Healthcare & Genomics | Public Sector & Defense | Telecom & 5G | Energy & OT | [ Leave Blank — Populate in Customer Environment ] |
| Assessed GCP Organization Scope | <CUSTOMER-ORG-ID> | organizations/<12-DIGIT-ORG-ID> | [ Leave Blank — Populate in Customer Environment ] |
| Agentic PQC Host Project & Engine | <CUSTOMER-HOST-PROJECT> | Cloud Run Host Project (Vertex AI Agent Engine optional) | [ Leave Blank — Populate in Customer Environment ] |
| Calibrated Mosca Horizons (X, Y, Z) | <MOSCA-HORIZONS> | Shelf-Life X (yrs) + Migration Y (yrs) vs. CRQC Z (yrs) | [ Leave Blank — Populate from Discovery Questionnaire ] |
| Security Leadership Sponsor | <SECURITY-SPONSOR> | VP of Information Security / Head of Cloud Security / GRC Lead | [ Leave Blank — Populate in Customer Environment ] |

## 2. Validated 7-KPI Organization Cryptographic Security Scorecard

In every assessment, the Gemini quantum-risk agent calls the compute_pqc_scorecard tool, which computes the posture KPIs with reproducible, auditable arithmetic over the read-only inventory (Cloud KMS/HSM keys, plus optional Compute SSL/TLS proxy and BYOK ImportJob KPIs); every KPI carries its value, numerator, denominator and definition, and Gemini explains what the numbers mean. Row 7 (application & API gateway crypto agility) is assessed by the agents and consultants from evidence and interviews rather than computed by the tool. The table below presents an illustrative reference scorecard alongside target security SLAs:

| Security Control Domain (NIST FIPS 203/204/205 & IR 8547) | Benchmark Score | Target Security SLA | Security Posture Verdict & Primary Exposure Vector |
| --- | --- | --- | --- |
| 1. Weighted Overall Agentic PQC Security Maturity | 70.0% | 100.0% | MODERATE — Immediate remediation required on asymmetric signing & KEM keys. |
| 2. Asymmetric Cryptography (Shor Immunity: RSA/ECC -> PQC) | 50.0% | 100.0% | CRITICAL — Classical ECDSA P-256 and RSA-2048 keys exposed to Shor & HNDL. |
| 3. Symmetric Data-at-Rest (AES-256 Grover Resilience) | 100.0% | 100.0% | COMPLIANT — AES-256-GCM provides 128-bit effective post-quantum security. |
| 4. Symmetric Key Rotation Hygiene (<= 90-Day Cryptoperiod) | 66.7% | 100.0% | ACTION REQUIRED — Unrotated symmetric CMEKs increase ciphertext exposure volume. |
| 5. Network Edge Minimum TLS 1.3 (Removes Pre-1.3 Classical Handshakes) | 50.0% | 100.0% | MODERATE — Legacy TLS 1.0/1.2 SSL policies allow classical SNDL session capture. |
| 6. BYOK / HYOK Supply Chain (Cloud KMS ImportJob Wrapping) | 50.0% | 100.0% | MODERATE — Classical RSA-OAEP wrapping exposes imported key material in transit. |
| 7. Application & API Gateway Crypto Agility (Tink & 16KB+ JWT) | 45.0% | 100.0% | HIGH PRIORITY — Direct AsymmetricDecrypt calls and 8KB proxy header ceilings. |

## 3. Quantum Resource Estimates & Prioritization (Elliptic Curves vs. RSA-2048)

A widespread misconception in enterprise security teams is that 256-bit Elliptic Curve Cryptography (ECDSA P-256, ECDH X25519, Ed25519) is more resistant to quantum computers than RSA-2048 because ECC is stronger against classical computers. In the constructions cited below, the opposite holds for logical qubits: Shor's algorithm solves the Elliptic Curve Discrete Logarithm Problem (ECDLP) for a 256-bit curve with 2,330 logical qubits versus 4,098 to factor a 2048-bit RSA modulus. Logical-qubit counts depend on the circuit construction, and which algorithm will be broken first remains uncertain.

- Elliptic Curve Discrete Logarithm Vulnerability (Roetteler et al., 2017): Breaking a 256-bit elliptic curve (ECDSA P-256) requires at most Q-logical = 9n + 2*ceil(log2(n)) + 10 = 2,330 logical qubits and at most 448n^3*log2(n) + 4090n^3 (~1.29 x 10^11) Toffoli gates; the same formula approximates ~2,321 logical qubits for the 255-bit curve behind Ed25519 / X25519. Webber et al. (2022) estimated ~13 million physical qubits to break 256-bit ECC within one day (~317 million within one hour), assuming a surface code with a 10^-3 physical gate error rate. Statements about which algorithm will be broken first are uncertain: physical-qubit and runtime estimates depend on hardware error rates and architecture and have fallen sharply over time.
- Integer Factorization Vulnerability (Häner et al., 2017; Gidney & Ekerå, 2021; Gidney, 2025): Factoring an n = 2048-bit RSA modulus requires Q-logical = 2n + 2 = 4,098 logical qubits in the construction of Häner, Roetteler & Svore (2017). Using a different construction (logical-qubit counts trade off against gate count and runtime), Gidney & Ekerå (2021) estimated ~2.7 x 10^9 Toffoli gates, ~20 million noisy physical qubits and ~8 hours; Gidney (2025) lowered this to fewer than 1 million noisy qubits in under one week (both at a 10^-3 physical gate error rate). While RSA-2048 requires ~1.76x more logical qubits than ECDSA P-256 in the cited 2017 constructions, it remains critically exposed to Harvest-Now, Decrypt-Later (HNDL) archival decryption.
- Module-Lattice & Symmetric Quantum Resilience (Albrecht Core-SVP & Grassl Grover): NIST FIPS 203 (ML-KEM-768 / KEM-XWING) and FIPS 204 (ML-DSA-65) rely on Module-LWE / Module-SIS lattices with BKZ block sizes beta >= 590–625, requiring > 2^156 to 2^167 quantum sieve operations per published lattice-estimator (core-SVP) analyses. Symmetric AES-256-GCM keeps ~128-bit effective security, since Grover's quadratic speedup roughly halves key-search security bits: Grassl et al. (2016) estimate ~2^128 sequential oracle iterations—physically infeasible within cosmological timescales.

| Quantum Exposure Class | Cryptographic Primitive Class | Logical Qubits (Shor / Grover) | Physical Qubits (Published Estimates) | Security Remediation Priority & Target Replacement |
| --- | --- | --- | --- | --- |
| Shor-Vulnerable (Fewest Cited Logical Qubits) | ECDSA P-256 / Ed25519 / ECDH P-256 | 2,330 Logical Qubits | ~13M, ~1 day (Webber et al. 2022) | P0 Immediate — Migrate to Cloud HSM PQ-SIGN-ML-DSA-65 (FIPS 204) & X25519MLKEM768 |
| Shor-Vulnerable (Critical HNDL Exposure) | RSA-2048 (OAEP Decrypt / PSS Sign) | 4,098 Logical Qubits | ~20M (Gidney & Ekerå 2021); < 1M (Gidney 2025) | P1 Urgent — Migrate to Cloud HSM KEM-XWING / ML-KEM-768 (FIPS 203) & Google Tink SDK |
| Shor-Vulnerable (High HNDL Exposure) | RSA-3072 / RSA-4096 (BYOK & Root PKI) | 6,146 – 8,194 Logical Qubits | Higher than RSA-2048 (no estimate cited) | P2 Planned — Migrate CAS Root/Subordinate CAs to ML-DSA / SLH-DSA & KMS ImportJobs to PQ HPKE wrapping |
| Quantum-Safe Target Baseline | AES-256-GCM / ML-KEM-768 / ML-DSA-65 | Core-SVP >= 166b (lattice estimator) / Grover > 2^128 | Computationally Infeasible | Target State — Enforce <= 90-day symmetric rotation & FIPS 140-3 Level 3 Cloud HSM |

## 4. Risk Timing & Business Impact: Mosca's Theorem (X + Y > Z) & Optional Q-VaR

To help Security Leadership, Risk Committees, and CFOs prioritize capital allocation, the Gemini quantum-risk agent evaluates Dr. Michele Mosca's inequality (X + Y > Z) with the values stakeholders provide; any value not provided falls back to a clearly labeled sector baseline reported as "not calibrated", and the table below shows those default sector baselines, which remain assumptions until validated with stakeholders. Translating the risk into money is optional and uses only the customer's own inputs:

- Mosca's Theorem (X + Y > Z) Operationalized: When the required confidentiality shelf-life of regulated data (X years) plus the engineering time required to refactor and migrate cryptographic infrastructure (Y years) exceeds the time remaining until a Cryptographically Relevant Quantum Computer arrives (Z years), the organization is in active HNDL breach status today.
- Business Impact (Optional, Customer-Provided Inputs): Q-VaR is a way to translate encryption risk into money using the customer's own data-value and breach-cost inputs. It is optional, performed with the consultants (FAIR-style: loss-event frequency x loss magnitude, expected loss and loss-exceedance) from inputs such as data volumes and classification, incident/breach cost history, cyber-insurance limits or BIA, and applicable fines (e.g., LGPD/GDPR), and presented as ranges with visible assumptions. The agent never invents dollar figures; financial exposure is only quantified when the customer provides those inputs.

| Regulated Industry Vertical | Confidentiality Horizon (X) & Migration Time (Y) | Mosca Sum (X + Y) vs. CRQC Horizon (Z) | Calibration Status | Primary Financial & Regulatory Exposure Drivers |
| --- | --- | --- | --- | --- |
| Banking & Financial Services (BFSI) | X = 15 yrs | Y = 3.0 yrs | 18.0 yrs > Z = 8.5 yrs (OVERDUE: -9.5 yrs) | Assumption (not calibrated) | ISO 20022 wire settlement, PCI-DSS v4.0.1, EU DORA, BACEN BCB 85/4893, long-term credit archives. |
| Healthcare, Biopharma & Genomics | X = 35 yrs | Y = 5.0 yrs | 40.0 yrs > Z = 8.5 yrs (OVERDUE: -31.5 yrs) | Assumption (not calibrated) | Non-revocable human genomic sequences, permanent EHR/PHI records, HIPAA, FDA SaMD cybersecurity. |
| Public Sector, Defense & National Infra | X = 30 yrs | Y = 4.0 yrs | 34.0 yrs > Z = 7.5 yrs (OVERDUE: -26.5 yrs) | Assumption (not calibrated) | Sovereign citizen registries, classified CUI, White House EO 14412, OMB M-26-15, NSA CNSA 2.0. |
| Telecommunications, 5G Core & Cloud | X = 10 yrs | Y = 3.0 yrs | 13.0 yrs > Z = 8.5 yrs (OVERDUE: -4.5 yrs) | Assumption (not calibrated) | 3GPP SA3 5G SUCI subscriber identity privacy, eSIM root PKI, carrier IPsec/MACsec trunks. |
| Energy, Utilities & Industrial OT | X = 12 yrs | Y = 7.0 yrs | 19.0 yrs > Z = 8.5 yrs (OVERDUE: -10.5 yrs) | Assumption (not calibrated) | Substation SCADA/PLC long-lived firmware roots, NERC CIP, IEC 62443 critical infrastructure. |

## 5. Recommended Target Security Architecture on Google Cloud (5-Pillar Product BOM)

To remediate discovered vulnerabilities without disrupting production SLAs, Google Cloud PSO recommends a defense-in-depth Target Security Architecture built on five native Google Cloud security capabilities:

| Pillar # | Google Cloud Security Product Pillar | Target PQC Primitives & Capabilities | Identified Cryptographic Gap Resolved & Business Value |
| --- | --- | --- | --- |
| Pillar 1 | Cloud HSM (FIPS 140-3 Level 3) & Cloud KMS PQC | PQ-SIGN-ML-DSA-65 (FIPS 204), KEM-XWING & ML-KEM-768 (FIPS 203), SLH-DSA (FIPS 205), HPKE BYOK Import. | Eliminates Shor vulnerability on asymmetric signing/encryption keys and secures BYOK key import chains inside hardware roots of trust. |
| Pillar 2 | Global External Application Load Balancing (L7), Cloud Armor & CAS | Hybrid TLS 1.3 Key Exchange (X25519MLKEM768 via SSL policy post-quantum key exchange = ENABLED) + Dual-Root CAS PKI (ML-DSA-65 / SLH-DSA). | Protects client-to-load-balancer sessions of TLS 1.3 clients that support X25519MLKEM768 against passive Store-Now, Decrypt-Later (SNDL) capture and modernizes internal mTLS PKI. |
| Pillar 3 | Google Tink SDK & Apigee / Envoy Gateway Modernization | Hybrid Envelope Encryption (KEM-XWING KEK + AES-256-GCM DEK) + 16KB–32KB HTTP Header Buffers. | Abstracts KEM Encapsulate/Decapsulate API breaking changes from application code and prevents HTTP 431 errors on 3,309B ML-DSA JWTs. |
| Pillar 4 | VPC Service Controls (VPC-SC) & Private Service Connect (PSC) | Context-aware zero-trust service perimeters around BigQuery, Cloud Storage, Cloud SQL & Cloud KMS. | Prevents bulk Harvest-Now, Decrypt-Later (HNDL) ciphertext exfiltration even if an application credential is compromised. |
| Pillar 5 | Binary Authorization, Artifact Registry & SCC Enterprise | Post-quantum container attestation (PQ-SIGN-ML-DSA-65) + continuous cryptographic drift monitoring. | Secures the CI/CD software supply chain against forged signatures and enforces continuous compliance with NIST IR 8547. |

## 6. Domain-by-Domain Prescriptive Security Recommendations (Domains 1 to 7)

- Domain 1 (Governance & CycloneDX v1.6 CBOM): Establish a formal Post-Quantum Migration Office chartered by Security Leadership; integrate automated OWASP CycloneDX v1.6 CBOM generation into quarterly GRC reviews and mandate PQC readiness attestations in third-party vendor procurement contracts.
- Domain 2 (Data Confidentiality Shelf-Life & HNDL Containment): Immediately enclose all Tier-0 data repositories with confidentiality shelf-life X >= 10 years (BigQuery datasets, GCS archival buckets, Cloud SQL instances) inside VPC Service Controls (VPC-SC) perimeters and re-wrap archival DEKs under hybrid KEM-XWING KEKs.
- Domain 3 (KMS, Cloud HSM & BYOK Supply Chain): Upgrade all production asymmetric keys from SOFTWARE protection level to FIPS 140-3 Level 3 Cloud HSM; enforce automated <= 90-day rotation (7,776,000s) on all AES-256 symmetric CMEKs; and replace classical RSA-OAEP BYOK ImportJobs with quantum-safe HPKE wrapping.
- Domain 4 (Application Cryptographic Agility & Database Schemas): Refactor direct Cloud KMS AsymmetricDecrypt() API calls to Google Tink SDK envelope encryption; audit relational/NoSQL database schemas (Cloud SQL, Spanner, AlloyDB) to expand fixed-width signature/key columns (e.g., VARBINARY(256) -> BLOB / BYTEA) before cutover.
- Domain 5 (Identity, OIDC/SAML & API Gateway Buffers): Increase HTTP request header limits (max-request-headers-kb) from 4KB/8KB to 16KB–32KB across Envoy proxies, NGINX ingresses, and Apigee API Gateways to accommodate 3,309-byte ML-DSA-65 signatures (~4.4 KB Base64URL JWTs), or adopt opaque Phantom Tokens at the edge.
- Domain 6 (Edge TLS 1.3 X25519MLKEM768 & CAS PKI): Set post-quantum key exchange to ENABLED on the SSL policies of all Google Cloud HTTPS/SSL load balancer target proxies (hybrid X25519MLKEM768 for TLS 1.3 clients; verify with a read-only gcloud compute ssl-policies describe) and treat any policy set to DEFERRED as an explicit harvest-now-decrypt-later exposure; require TLS 1.3 (MODERN/RESTRICTED/CUSTOM profile) where clients allow, which removes classical-only handshakes from older clients; tune TCP initial congestion windows (initcwnd) and MTU for the 1,216-byte client / 1,120-byte server hybrid key shares on self-managed proxies, backends and on-prem middleboxes (not on Google-managed load balancer frontends); and deploy parallel cross-signed ML-DSA-65 subordinate CAs in Certificate Authority Service (CAS).
- Domain 7 (CI/CD Supply Chain & Binary Authorization): Migrate container image and CI/CD artifact signing attestors in Binary Authorization from ECDSA P-256 / RSA-PSS to Cloud HSM PQ-SIGN-ML-DSA-65, and adopt stateless hash-based SLH-DSA (FIPS 205) for long-lived firmware roots.

## 7. Preventive Governance Advisory: Declarative GCP Organization Policy Reference Templates

Remediation without preventive governance leads to cryptographic regression as engineering teams provision new cloud resources. Google Cloud PSO delivers three declarative GCP Organization Policy reference templates (for the Customer's governance team to evaluate and enforce during future PQC adoption waves):

1. Enforce Hardware Root of Trust (constraints/cloudkms.allowedProtectionLevels): Configure the Organization Policy constraint on production folders to permit only HSM and EXTERNAL protection levels, blocking creation of software-backed asymmetric keys.
2. Block New Classical Asymmetric Key Provisioning (Custom Org Policy Constraint): Deploy a Custom Organization Policy constraint on googleapis.com/CryptoKey resources evaluating resource.versionTemplate.algorithm to deny creation of new RSA-SIGN-*, RSA-DECRYPT-*, and EC-SIGN-* algorithms in migrated production projects without an approved exception label.
3. Enforce TLS 1.3 & Post-Quantum Key Exchange (Custom Compute SSL Policy Constraint): Enforce custom constraints on compute.googleapis.com/SslPolicy resources across external load balancers requiring minTlsVersion == TLS_1_3 and postQuantumKeyExchange != DEFERRED (or == ENABLED); verify that the postQuantumKeyExchange field is supported in custom constraints before rollout. Requiring profile == RESTRICTED is optional hardening.

## 8. Phased Multi-Horizon PQC Adoption Roadmap (2026–2035)

The table below sequences the recommended PQC adoption workstreams across three operational horizons—starting with the 6-week PSO Cryptographic Security Posture Review, Inventory & Area Readiness Assessment, followed by Customer-led hybrid adoption and full classical algorithm disallowance under NIST IR 8547 and EO 14412:

| Migration Horizon & Timeline | Strategic Security Objective | Core Posture Review & Customer-Led Adoption Milestones | Target Maturity & Exposure Outcome |
| --- | --- | --- | --- |
| Horizon 1: Weeks 1–6<br>(6-Week PSO Posture Review & Readiness Assessment) | Automated Inventory (CBOM), 7-Domain Area Readiness Interviews & Cryptographic Security Posture Review | Complete 100% read-only 4-Vector GCP Inventory & CycloneDX v1.6 CBOM (Weeks 1–2), 7-Domain Area Readiness Questionnaire & Stakeholder Interviews + Mosca/Risk Scorecard (Weeks 3–4), and Cryptographic Key Security Posture Review + Advisory Recommendations Book & Adoption Roadmap (Weeks 5–6). | Complete CBOM, Area Readiness Baseline & Prioritized PQC Adoption Plan |
| Horizon 2: Months 3–12<br>(Customer-Led Hybrid PQC Rollout) | Edge TLS 1.3 (X25519MLKEM768), Tink SDK Crypto-Agility & High-Priority Key Adoption | Customer engineering teams apply advisory guidelines to enable hybrid PQC on L7 Load Balancer SSL policies (`postQuantumKeyExchange = ENABLED`), expand Envoy/Apigee header buffers (16KB–32KB), adopt Google Tink KEM-XWING in Tier-0 apps, and transition P0 classical keys in Cloud HSM. | Maturity: 45% -> 85%<br>Exposure: Tier-0 HNDL paths remediated by Customer |
| Horizon 3: Months 12–36+<br>(Full NIST IR 8547 2030/2035 Compliance) | Full Classical Asymmetric Deprecation, PQC Root PKI & Preventive Org Policies | Customer completes CAS ML-DSA-65 / SLH-DSA PKI hierarchy transition, enforces preventive GCP Organization Policies blocking legacy RSA/ECC, and retires classical key versions ahead of the 2030 mandate. | Maturity: 85% -> 100%<br>Exposure: classical asymmetric keys retired |

## 9. Reference Golden Sample: Live GCP Telemetry Assessment & CBOM Report (Org 31564119954)

## 1. Executive Summary (BLUF) & Validated Scorecard

Sample Notice: Illustrative sample output, shown only to explain the report format; real reports are written by the Gemini agents solely from the evidence collected in the customer's environment, with every KPI shown as numerator/denominator and every key-to-workload link tagged STRONG, MEDIUM, WEAK or consumer not identified.

| Executive KPI / Posture Metric | Validated Value | Target Benchmark | Consultative Assessment |
| --- | --- | --- | --- |
| Active Keys on Quantum-Safe Algorithms | 80.0% (8/10 keys) | 100.0% | MODERATE — Immediate action required on asymmetric keys |
| Asymmetric Migration Score (Shor Immunity) | 50.0% (2/4 keys) | 100.0% | CRITICAL — ECDSA P-256 & RSA-2048 exposed to Shor/HNDL |
| Symmetric Data-at-Rest (Grover Resilience) | 100.0% (6/6 keys) | 100.0% | COMPLIANT — AES-256 provides 128-bit post-quantum security |
| Symmetric Rotation Hygiene (<= 90 Days) | 66.7% (4/6 keys) | 100.0% | ACTION REQUIRED — 2 AES-256 keys lack 90-day rotation |
| HTTPS Proxies Requiring TLS 1.3 | Not quantified in sample | 100.0% | ACTION REQUIRED — Upgrade TLS 1.0/1.2 policies to TLS 1.3 |
| Business Impact (Optional) | Not computed by the agent | Customer inputs required | Sized with the customer's data-value & breach-cost inputs, as ranges |

## 2. Quantum Resource Estimates & Risk Prioritization

| Quantum Status | Asset Name (Project / KeyRing) | Algorithm | Quantum Profile (Tool Estimates) | Priority & Rationale |
| --- | --- | --- | --- | --- |
| Shor-Vulnerable | jwt-signing-ecdsa-key (auth-kr) | EC-SIGN-P256-SHA256 | 2,330 Logical (Roetteler et al. 2017) | P1 Urgent — forgery risk only once a CRQC exists; long-lived trust anchors need lead time |
| Shor-Vulnerable | legacy-payment-rsa-key (payments-kr) | RSA-DECRYPT-OAEP-2048-SHA256 | 4,098 Logical / ~20M, ~8 h (2021); < 1M, < 1 week (2025) | P0 Immediate — HNDL: data recorded today can be decrypted later (long-lived data assumed) |
| Quantum-Safe | pqc-hybrid-kem-key (payments-kr) | KEM-XWING (X25519 + ML-KEM-768) | NIST PQC Category 3 | Quantum-Safe (NIST FIPS 203 Hybrid) |
| Quantum-Safe | pqc-mldsa-signing-key (auth-kr) | PQ-SIGN-ML-DSA-65 | NIST PQC Category 3 | Quantum-Safe (NIST FIPS 204 Level 3) |

## 3. Advisory Per-Key Reference Guidelines from the Actual Inventory (For Future Customer-Led Adoption)

> **Advisory Scope Notice:** Google Cloud Consulting (PSO) does not execute key creation, IAM changes, or cutovers in the Customer's environment. The reference steps below are generated from the read-only inventory as **consultative advisory guidelines** for the Customer's engineering teams to review and execute under their own change-management governance.

### 3.1 Advisory Reference 1 — jwt-signing-ecdsa-key (EC-SIGN-P256-SHA256 -> PQ-SIGN-ML-DSA-65)

1. Reference Step 1 — Target PQC Key Specification in Cloud HSM: `gcloud kms keys create jwt-signing-ecdsa-key-pqc --keyring=auth-kr --location=global --purpose=asymmetric-signing --default-algorithm=pq-sign-ml-dsa-65 --protection-level=hsm --project=<TARGET-PROJECT-ID>`
2. Reference Step 2 — Least-Privilege IAM Binding Alignment: `gcloud kms keys add-iam-policy-binding jwt-signing-ecdsa-key-pqc --keyring=auth-kr --location=global --member="serviceAccount:Workload-SA@<TARGET-PROJECT-ID>.iam.gserviceaccount.com" --role="roles/cloudkms.signerVerifier"` (consumer not identified in this sample: bind only a service account confirmed at STRONG or MEDIUM evidence)
3. Reference Step 3 — Gateway & JWT Header Sizing Prerequisite: If the consumer is confirmed to issue JWTs (today WEAK evidence: key name only), increase `max-request-headers-kb` to 16KB-32KB in Envoy/Cloud Armor/NGINX to accommodate 3,309-byte ML-DSA-65 signatures before any future key transition.
4. Reference Step 4 — Dual-Signing Canary Strategy: Publish both ECDSA P-256 and ML-DSA-65 public keys in the JWKS endpoint during future canary validation by the Customer's team.
5. Reference Step 5 — Verification & Rollback Reference: Verify key state via `gcloud kms keys versions list --key=jwt-signing-ecdsa-key-pqc --keyring=auth-kr --location=global` before retiring the legacy version under Customer CAB governance.

### 3.2 Advisory Reference 2 — legacy-payment-rsa-key (RSA-2048 -> KEM-XWING / ML-KEM-768)

1. Reference Step 1 — Target Hybrid PQC KEM Key Specification in Cloud HSM: `gcloud kms keys create legacy-payment-rsa-key-pqc --keyring=payments-kr --location=us-central1 --purpose=key-encapsulation --default-algorithm=kem-xwing --protection-level=hsm --project=<TARGET-PROJECT-ID>`
2. Reference Step 2 — Least-Privilege IAM Binding Alignment: Grant `roles/cloudkms.cryptoOperator` only to the consuming service account once confirmed at STRONG or MEDIUM evidence (the payment-workload link in this sample is WEAK: naming only).
3. Reference Step 3 — Application API Readiness (`AsymmetricDecrypt` -> KEM `Decapsulate` / Google Tink): Plan application refactoring from raw RSA decryption calls to Cloud KMS `Decapsulate()` or Google Tink AEAD envelope encryption.
4. Reference Step 4 — Historical Data Re-Wrapping Advisory (HNDL Mitigation): Plan re-wrapping of long-lived archives encrypted under RSA-2048 using AES-256-GCM DEKs protected by `KEM-XWING`.
5. Reference Step 5 — Verification & Rollback Reference: Verify `ENABLED` state via `gcloud kms keys versions list` and retain rollback procedures under Customer CAB governance.
