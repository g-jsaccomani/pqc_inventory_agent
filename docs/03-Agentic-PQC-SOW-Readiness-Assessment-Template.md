# Agentic PQC SOW Readiness Assessment Template
**Google Cloud Consulting — 6-Week Statement of Work (SOW), RACI Governance & T-Shirt Sizing Guide**

> **Google Drive Official Deliverable:** [Agentic PQC SOW Readiness Assessment Template](https://docs.google.com/document/d/1B2PlRFyDlkUDKrb224OHUBGjtnnTPs7uWMMZjy9eWZE/edit)

> **Executive Summary:** This Statement of Work (SOW) template defines the contractual scope, 6-week Work Breakdown Structure (WBS), deliverables, acceptance criteria, RACI matrix, and governance model for a Google Cloud Consulting — Professional Services Organization (PSO) Post-Quantum Cryptography (PQC) Readiness Assessment and Migration Advisory engagement. By pairing senior PSO Security Architects with the Agentic PQC Readiness & CBOM Engine, Google Cloud compresses cryptographic discovery and mathematical risk modeling into Weeks 1–3, dedicating Weeks 4–6 to high-value architecture workshops, application refactoring, non-production Cloud HSM cutover validation, and preventive GCP Organization Policy guardrails.

---

## 1. Engagement Identification & Customer Environment Parameterization

This Statement of Work ("SOW") is entered into between Google Cloud Consulting — Professional Services Organization ("Google Cloud PSO") and Customer (<CUSTOMER-LEGAL-NAME>) to execute a 6-week Consultative Post-Quantum Cryptography (PQC) Readiness Assessment and Migration Advisory across the Customer's designated Google Cloud estate. Populate the engagement parameters below prior to contract execution:

| Contractual / Technical Parameter | Placeholder / Config Token | Expected Value / Selection Options | Customer Contracted Value (Populate at SOW Signing) |
| --- | --- | --- | --- |
| Customer Legal Entity Name | <CUSTOMER-LEGAL-NAME> | Full legal entity name of the contracting organization | [ Leave Blank — Populate for Customer ] |
| Primary Regulated Industry Vertical | <SECTOR-CODE> | BFSI-BANKING | HEALTHCARE-GENOMICS | PUBLIC-SECTOR-DEFENSE | TELECOM-5G-CLOUD | ENERGY-OT-INDUSTRIAL | [ Leave Blank — Populate for Customer ] |
| In-Scope GCP Organization ID(s) | <CUSTOMER-ORG-ID> | organizations/<12-DIGIT-ORG-ID> (plus designated folder/project scopes) | [ Leave Blank — Populate for Customer ] |
| Engagement Sizing Tier & Duration | <SIZING-TIER> | Standard Enterprise Tier — 6 Calendar Weeks (30 Business Days) | 6 Calendar Weeks (Weeks 1 to 6) |
| Selected Agent Deployment Topology | <DEPLOYMENT-TOPOLOGY> | Topology A (Customer Cloud Run + VPC-SC) | Topology B (Cross-Org SA Impersonation) | Topology C (Workstation) | [ Leave Blank — Populate for Customer ] |
| Customer Host Project & Agent Endpoint | <CUSTOMER-HOST-PROJECT-ID> | Host Project ID / Cloud Run URL / Vertex AI Agent Engine URI | [ Leave Blank — Populate in Customer Environment ] |
| Customer Executive Sponsor & CISO POC | <CUSTOMER-SPONSOR-NAME> | Name, Title, Email of CISO / VP of Security / Head of Cloud Platform | [ Leave Blank — Populate for Customer ] |

## 2. Strategic Objectives, Regulatory Drivers & Consultative Positioning

Customer has engaged Google Cloud PSO to establish an empirical, cryptographically verified baseline of its Google Cloud estate and engineer a phased migration roadmap toward Post-Quantum Cryptography (PQC). This engagement directly addresses the technical, operational, and financial imperatives introduced by:

- NIST Post-Quantum Cryptography Standards: Federal Information Processing Standards FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism: ML-KEM-512/768/1024 and hybrid X-Wing), FIPS 204 (Module-Lattice-Based Digital Signature Standard: ML-DSA-44/65/87), and FIPS 205 (Stateless Hash-Based Digital Signature Standard: SLH-DSA).
- Global Deprecation Mandates & Executive Directives: NIST IR 8547 (Final, October 2026) establishing the mandatory 2030 deprecation and 2035 disallowance of classical RSA-2048/3072/4096, ECDSA, and ECDH (P-256/P-384/P-521); White House Executive Order 14412 & OMB Memoranda M-23-02 / M-26-15 requiring automated Cryptographic Bills of Materials (CBOM); NSA CNSA 2.0; UK NCSC (2028/2031/2035 milestones); and sector frameworks (PCI-DSS v4.0.1, DORA, BACEN BCB 85/4893, HIPAA).
- Harvest-Now, Decrypt-Later (HNDL) & Breaking-Change Mitigation: Neutralizing passive adversary interception of long-lived ciphertexts where Mosca's Theorem (X + Y > Z) is violated, while engineering safe application transitions across KEM API shifts (Decrypt -> Encapsulate/Decapsulate) and signature payload bloat (64B ECDSA -> 3,309B ML-DSA-65).
- Consultative Engineering Advisory (Non-Audit Positioning): Google Cloud PSO performs a deep Consultative PQC Readiness Assessment, Control-Plane Posture Verification, and Engineering Migration Advisory. Google Cloud PSO does not act as a statutory, regulatory, or financial auditor, nor does this engagement constitute a formal compliance certification or legal opinion.

## 3. Detailed 6-Week Work Breakdown Structure (WBS) & Execution Plan

The engagement is structured across four logical delivery phases executed over six (6) consecutive calendar weeks. By leveraging the Agentic PQC Readiness & CBOM Engine (detailed in Agentic PQC Technical Architecture and Consultant Guide), automated telemetry collection and mathematical modeling are completed rapidly in Weeks 1–3, enabling deep architectural and hands-on engineering workshops in Weeks 4–6:

| Week & Phase | Primary Focus Area | Key PSO & Agentic Activities | Weekly Outputs & Exit Criteria |
| --- | --- | --- | --- |
| Week 1 (Phase 1A) | Mobilization, IAM Onboarding & 7-Domain Calibration | Deliver Executive Kickoff (Agentic PQC README); configure least-privilege read-only IAM or deploy Agentic PQC Engine (Agentic PQC Technical Architecture and Consultant Guide); conduct 7-Domain Stakeholder Discovery Workshops (Agentic PQC Discovery Questionnaire); execute calibrate-assessment-context. | Validated GCP read-only telemetry access; scored 7-Domain Maturity Rubric (Levels 1-5); locked Sector Calibration Profile in calibration-history.jsonl. |
| Week 2 (Phase 1B & 2A) | Automated 4-Vector GCP Discovery & Blast-Radius Correlation | Execute discover-gcp-kms-inventory and compute-quantum-risk-posture across Cloud KMS/HSM, Cloud Asset Inventory (4-Vector workload correlation across GKE, Cloud SQL, BigQuery, GCS, Compute), Compute SSL/TLS policies, CAS PKI, and BYOK ImportJobs; resolve -tp tenant sandboxes. | 100% in-scope GCP cryptographic inventory correlated to downstream workloads; baseline OWASP CycloneDX v1.6 CBOM JSON generated. |
| Week 3 (Phase 2B) | Quantum Physics Modeling, Mosca (X+Y>Z) & Monte Carlo Q-VaR | Run Shor (Gidney & Ekera 2021), Roetteler ECDLP (2017), Grover, and Core-SVP circuit modeling; evaluate Mosca's Theorem (X + Y > Z) per business unit; execute 10,000-iteration Monte Carlo Q-VaR (95%) financial simulation in USD; hold Mid-Engagement Risk Review with CISO. | Validated Quantum Vulnerability Heatmap, Mosca HNDL Overdue Matrix, and calibrated Q-VaR (95%) financial exposure model signed off. |
| Week 4 (Phase 3A) | Edge TLS 1.3 (X25519MLKEM768), CAS PKI & Network Perimeter Design | Conduct architecture workshops with Network, SRE, and PKI teams; design hybrid TLS 1.3 (X25519MLKEM768) policies on Cloud Load Balancing (L7) & Service Mesh; evaluate 1,120B KEM TCP initcwnd impact; design CAS PQC dual-root PKI and VPC-SC HNDL exfiltration perimeters. | Target-State Edge TLS 1.3 & CAS PKI Architecture Blueprint; VPC Service Controls (VPC-SC) HNDL containment design. |
| Week 5 (Phase 3B) | Application Crypto Agility, Tink SDK Refactoring & Non-Prod HSM Pilot | Conduct developer & IAM workshops on KEM refactoring (AsymmetricDecrypt -> Google Tink SDK KEM-XWING / ML-KEM-768 + AES-256-GCM DEK), JWT header bloat mitigation (3,309B ML-DSA-65 on Envoy/Apigee 16KB-32KB buffers), Binary Authorization signing, and execute a guided 5-step Cloud HSM PQC key rotation pilot in non-production. | Validated Non-Production Cloud HSM PQC Key Cutover Pilot; completed Technical Engineering Playbook with 5-step per-key runbooks. |
| Week 6 (Phase 4) | Preventive Org Policy Guardrails, Multi-Year Roadmap & Board Closeout | Deliver preventive GCP Organization Policy YAML constraints (enforcing HSM protection levels and blocking legacy RSA/ECC creation post-cutover); finalize Agentic PQC Security Recommendations Book and 2026-2035 Migration Roadmap; conduct Executive Board & CISO Closeout Presentation. | Complete 6-Deliverable Handover Package accepted; formal Deliverable Acceptance Form signed. |

### 3.1 Week 1 (Phase 1A): Mobilization, IAM Onboarding & 7-Domain Sector Calibration

- Executive & Technical Kickoff: Deliver the formal engagement kickoff presentation (aligned with Agentic PQC README) to align executive sponsors, security architects, PKI owners, and platform leads on the 6-week schedule, milestones, and governance cadence.
- Non-Intrusive Read-Only IAM & Runtime Onboarding: Provision the four least-privilege read-only GCP IAM roles (roles/cloudasset.viewer, roles/cloudkms.viewer, roles/privateca.auditor, and roles/compute.viewer) at the target GCP Organization scope (organizations/<CUSTOMER-ORG-ID>) and deploy or connect the Agentic PQC Readiness Engine using the selected deployment topology (Topology A, B, or C per Agentic PQC Technical Architecture and Consultant Guide).
- 7-Domain Stakeholder Discovery & Posture Verification Workshops: Facilitate structured interviews across all seven weighted domains of the Agentic PQC Discovery Questionnaire: (1) Data Confidentiality Shelf-Life (X) & HNDL Exposure, (2) KMS/HSM/BYOK & Root PKI, (3) Edge L7 Load Balancers & TLS/mTLS Service Mesh, (4) Application Cryptographic Agility & Tink SDKs, (5) Identity/IAM & JWT/OIDC Header Sizing, (6) CI/CD Supply Chain & Binary Authorization, and (7) Third-Party SaaS & Inter-Cloud Interconnects.
- Agent Context & Sector Calibration: Score the 35-question maturity rubric (Levels 1.0 to 5.0) and execute calibrate-assessment-context to persist the Customer's industry sector profile, Mosca X and Y horizons, and compensating controls into calibration-history.jsonl.
- Week 1 Exit Criteria: Read-only GCP telemetry access verified; 7-Domain Discovery Questionnaire completed and scored; Customer Sector Calibration Profile locked.

### 3.2 Week 2 (Phase 1B & Phase 2A): Automated 4-Vector GCP Discovery & Blast-Radius Correlation

- Vector 1 — Cloud KMS, Cloud HSM & EKM Inventory: Execute discover-gcp-kms-inventory across all in-scope GCP folders and projects to enumerate every KeyRing, CryptoKey, primary CryptoKeyVersion, algorithm family, protection level (SOFTWARE, HSM, EXTERNAL), rotation schedule, and ImportJob wrapping method.
- Vector 2 — Cloud Asset Inventory 4-Vector Workload Blast-Radius Correlation: Correlate every discovered KMS key against downstream GCP resources across (a) Direct CMEK infrastructure bindings, (b) GKE cluster boot-disk and application-layer Secrets encryption, (c) Cloud SQL, AlloyDB, Spanner, BigQuery, and Cloud Storage data stores, and (d) Pub/Sub, Secret Manager, and Artifact Registry pipelines.
- Vector 3 & Vector 4 — Edge SSL/TLS Policies, CAS PKI & Tenant Sandbox Resolution: Inspect Compute Engine SSL/TLS policies (minimum TLS versions and cipher profiles), Certificate Authority Service (CAS) root/subordinate CA algorithms, and automatically resolve Google-managed tenant projects (-tp suffix) to parent projects.
- Baseline CycloneDX v1.6 CBOM Generation: Execute generate-cyclonedx-cbom to compile the machine-readable OWASP CycloneDX v1.6 JSON Cryptographic Bill of Materials mapped to official NIST Object Identifiers (OIDs).
- Week 2 Exit Criteria: 100% of in-scope GCP cryptographic assets inventoried, correlated to downstream application workloads, classified by project tier (PROD / NON-PROD / SANDBOX), and exported to CycloneDX v1.6 CBOM.

### 3.3 Week 3 (Phase 2B): Quantum Physics Modeling, Mosca (X+Y>Z) & Monte Carlo Q-VaR Quantification

- Surface-Code Quantum Circuit Modeling: Execute calculate-quantum-circuit-metrics using peer-reviewed cryptanalytic models—Gidney & Ekera (2021) for RSA factoring (4,098 logical qubits / ~5.97M physical qubits for RSA-2048), Roetteler et al. (2017) for Elliptic Curve Discrete Logarithms (2,330 logical qubits / ~3.40M physical qubits for ECDSA/ECDH P-256), Albrecht Core-SVP for lattice primitives, and Grassl et al. (2016) for Grover symmetric search.
- Mosca's Theorem (X + Y > Z) HNDL Horizon Analysis: Combine the Customer's calibrated confidentiality shelf-life (X) and migration duration (Y) against empirical CRQC arrival horizons (Z) to pinpoint every business domain and dataset currently in active Harvest-Now, Decrypt-Later (HNDL) violation.
- 10,000-Iteration Monte Carlo Quantum Value-at-Risk (Q-VaR 95%) Simulation: Execute simulate-monte-carlo-qvar incorporating the Customer's sector regulatory multiplier, data volume, and breach cost baselines to quantify the 95th-percentile financial exposure in USD.
- Mid-Engagement CISO & Risk Committee Checkpoint: Present the validated Quantum Vulnerability Heatmap, Mosca HNDL Overdue Matrix, and Q-VaR (95%) financial model to the CISO and Enterprise Risk Management (ERM) stakeholders to prioritize Weeks 4–5 engineering focus.
- Week 3 Exit Criteria: Quantum Vulnerability Heatmap, Mosca HNDL Overdue Matrix, and Monte Carlo Q-VaR (95%) financial model formally reviewed and signed off by Security Leadership.

### 3.4 Week 4 (Phase 3A): Edge TLS 1.3 (X25519MLKEM768), CAS PKI & Network Perimeter Workshops

- Hybrid Post-Quantum TLS 1.3 Edge Architecture: Lead technical design workshops with Network and SRE teams to configure hybrid post-quantum key exchange (X25519MLKEM768) on Google Cloud Global External Application Load Balancers (L7), Cloud Armor, and GKE Service Mesh (Istio/Envoy).
- Network MTU & TCP Initial Congestion Window (initcwnd) Engineering: Analyze the wire-format impact of 1,120-byte X25519MLKEM768 client/server key shares and 3,309-byte ML-DSA-65 certificate signatures across middleboxes, deep-packet inspection (DPI) firewalls, and TCP initcwnd budgets.
- Certificate Authority Service (CAS) Dual-Root / Cross-Signed PKI Blueprint: Design the phased migration from classical RSA/ECDSA internal CAs to FIPS 204 (ML-DSA-65) and FIPS 205 (SLH-DSA) hierarchies with automated short-lived certificate issuance via cert-manager.
- VPC Service Controls (VPC-SC) HNDL Exfiltration Containment: Architect zero-trust VPC-SC service perimeters, Private Service Connect (PSC) endpoints, and ingress/egress rules around high-value data repositories (BigQuery, GCS, Cloud SQL) to block bulk ciphertext exfiltration.
- Week 4 Exit Criteria: Target-State Edge TLS 1.3 (X25519MLKEM768), CAS PQC PKI, and VPC-SC HNDL Containment Architecture Blueprint completed.

### 3.5 Week 5 (Phase 3B): Application Crypto Agility, Tink SDK Refactoring & Non-Prod Cloud HSM Pilot

- KEM API Contract Refactoring Workshop (Decrypt -> Encapsulate/Decapsulate + HPKE): Guide Application Architects through refactoring direct Cloud KMS AsymmetricDecrypt calls into RFC 9180 Hybrid Public Key Encryption (HPKE) and Google Tink SDK hybrid envelope encryption using KEM-XWING / ML-KEM-768 Key-Encryption Keys (KEKs) and AES-256-GCM Data-Encryption Keys (DEKs).
- Identity, OIDC/SAML & JWT Header Bloat Mitigation Workshop: Evaluate the 51x signature expansion from ECDSA P-256 (64 bytes) to ML-DSA-65 (3,309 bytes / ~4.4 KB in Base64URL JWTs); specify HTTP header buffer upgrades (16KB–32KB) for Envoy, NGINX, and Apigee API Gateways alongside Phantom Token / Reference Token architectural patterns.
- CI/CD Software Supply Chain & Binary Authorization Signing: Design post-quantum artifact and container image signing pipelines using Cloud KMS PQ-SIGN-ML-DSA-65 keys integrated with Binary Authorization on GKE and Cloud Run.
- Guided Non-Production Cloud HSM PQC Cutover Lab: Execute a live, non-disruptive 5-step PQC key rotation pilot in the Customer's designated non-production GCP project—provisioning FIPS 140-3 Level 3 Cloud HSM keys (pq-sign-ml-dsa-65 and kem-xwing), replicating IAM bindings, validating dual-stack signing/encapsulation, and compiling per-key runbooks.
- Week 5 Exit Criteria: Non-Production Cloud HSM PQC Key Cutover Pilot successfully validated; Technical Engineering Playbook with 100% per-key 5-step runbooks generated.

### 3.6 Week 6 (Phase 4): Preventive Org Policy Guardrails, Multi-Year Roadmap & Executive Board Closeout

- Preventive GCP Organization Policy Guardrail Engineering: Deliver and validate declarative GCP Organization Policy YAML constraints—including constraints/cloudkms.allowedProtectionLevels (enforcing HSM protection levels) and custom constraints prohibiting new classical RSA-SIGN-*, RSA-DECRYPT-*, and EC-SIGN-* key creation in migrated production folders.
- Agentic PQC Security Recommendations Book & Multi-Year Roadmap (2026–2035): Finalize the phased migration roadmap (Phase 1 Immediate 0–6 Months, Phase 2 Near-Term 6–18 Months, Phase 3 Long-Term 18–36+ Months toward 2030 NIST deprecation) and the Google Cloud Security Architecture Bill of Materials (BOM).
- Executive Board & CISO Closeout Presentation: Deliver the formal closeout readout to the CISO, CIO, CFO, and Architecture Review Board, walking through the validated maturity score, Q-VaR reduction trajectory, and operational handover.
- Final 6-Deliverable Handover & Engagement Sign-Off: Transfer all six contractual deliverables into the Customer's designated repository and execute the formal Deliverable Acceptance Sign-Off.
- Week 6 Exit Criteria: All six contractual deliverables (D-01 through D-06) delivered and formally accepted; Executive Board Closeout completed.

## 4. Contractual Deliverables & Acceptance Criteria Matrix

Google Cloud PSO will deliver six (6) formal engagement artifacts. All deliverables are produced in fluent English and grounded in the Customer's live GCP telemetry and calibrated stakeholder workshops:

| ID | Deliverable Name | Delivery Week & Target Audience | Core Contents & Objective Acceptance Criteria |
| --- | --- | --- | --- |
| D-01 | Calibrated 7-Domain Discovery & Maturity Baseline | Week 1 — CISO, GRC, Enterprise Security Architects | Completed 35-question Agentic PQC Discovery Questionnaire scorecard (Levels 1.0–5.0 across 7 domains), sector calibration ledger (calibration-history.jsonl), and validated Mosca X and Y parameters. |
| D-02 | OWASP CycloneDX v1.6 CBOM & 4-Vector Inventory | Week 2 — GRC, SecOps, KMS & PKI Owners | Machine-readable CycloneDX v1.6 JSON CBOM plus human-readable inventory covering 100% of in-scope GCP KMS/HSM keys, TLS policies, CAS CAs, and 4-Vector workload dependencies with NIST OIDs. |
| D-03 | Executive Board PQC Readiness & Q-VaR Report | Week 3 / Week 6 — CEO, CFO, CISO, Board of Directors | C-Level BLUF, Validated PQC Maturity Score (0-100%), surface-code qubit metrics, Mosca HNDL Overdue Matrix, 10k Monte Carlo Q-VaR (95%) in USD, and Google Cloud Security Architecture BOM. |
| D-04 | Edge TLS 1.3 (X25519MLKEM768) & CAS PKI Blueprint | Week 4 — Network, SRE, Load Balancer & PKI Owners | Target-state architecture for L7 Load Balancer & Service Mesh hybrid TLS 1.3 (X25519MLKEM768), TCP initcwnd tuning, CAS dual-root ML-DSA-65/SLH-DSA hierarchy, and VPC-SC HNDL perimeters. |
| D-05 | Technical Engineering Playbook & 5-Step HSM Runbooks | Week 5 — Cloud Engineers, IAM Leads, App Developers | Individual 5-step Cloud HSM rotation runbooks for 100% of vulnerable keys, IAM replication scripts, Google Tink SDK KEM/HPKE refactoring templates, Envoy/Apigee 16KB-32KB JWT configs, and non-prod pilot logs. |
| D-06 | Preventive GCP Org Policy Bundle & CISO Roadmap Book | Week 6 — Cloud Governance, CISO & Security Leadership | Declarative GCP Organization Policy YAML constraints blocking legacy RSA/ECC creation and enforcing Cloud HSM, paired with the Agentic PQC Security Recommendations Book and 2026–2035 Migration Roadmap. |

## 5. Engagement Team Structure, Resource Allocation & RACI Matrix

Successful completion within the 6-week timeline relies on a dedicated Google Cloud PSO delivery pod working alongside Customer subject matter experts (SMEs). The tables below define the PSO specialist roles, weekly effort allocation, and the Responsibility Assignment Matrix (R = Responsible, A = Accountable, C = Consulted, I = Informed):

| Role Title | Organization | Primary Responsibilities Across the 6-Week Engagement | Estimated Allocation |
| --- | --- | --- | --- |
| Principal PQC Security Architect (Lead) | Google Cloud PSO | Leads kickoff, 7-domain calibration, quantum cryptanalysis/Q-VaR modeling, Edge TLS/PKI architecture workshops, CISO roadmap, and Board readout. | Weeks 1–6 (Full Engagement Lead) |
| Cloud Infrastructure, KMS & App Crypto Specialist | Google Cloud PSO | Executes Agentic PQC Engine deployment, 4-Vector CBOM discovery, Tink SDK/JWT refactoring workshops, Week 5 Cloud HSM pilot, and Org Policy YAML engineering. | Weeks 1–6 (Hands-On Engineering) |
| Engagement Manager / Project Director | Google Cloud PSO | Manages 6-week WBS governance, weekly steering syncs, stakeholder scheduling, risk tracking, and formal Deliverable Acceptance sign-offs. | Weeks 1–6 (Governance & PMO) |
| Executive Sponsor / CISO & Risk Lead | Customer | Approves engagement scope, validates Mosca confidentiality horizons (X) and Q-VaR risk appetite, chairs Week 3/Week 6 readouts, and signs Deliverable Acceptance. | Weeks 1, 3, 6 (Executive Checkpoints) |
| Cloud Platform, KMS/PKI, Network & App SMEs | Customer | Provisions read-only IAM roles (Days 1–3), participates in Week 1 calibration and Weeks 4–5 workshops, and co-executes the Week 5 non-prod Cloud HSM pilot. | 2–4 Hours / Week (Workshops & Lab) |

### 5.1 Workstream Responsibility Assignment Matrix (RACI)

| Engagement Workstream / Weekly Milestone | Google PSO Lead Architect | Google PSO KMS & App Specialist | Customer CISO / Exec Sponsor | Customer Cloud / IAM / PKI SMEs |
| --- | --- | --- | --- | --- |
| Week 1: Kickoff, Read-Only IAM Provisioning & Agent Deployment | R | C | A | R |
| Week 1: 7-Domain Stakeholder Discovery & Mosca (X, Y) Calibration | R | C | A | R |
| Week 2: Automated 4-Vector GCP Discovery & CycloneDX v1.6 CBOM | A | R | I | C |
| Week 3: Quantum Circuit Modeling & Monte Carlo Q-VaR (95%) Simulation | R | R | A | C |
| Week 4: Edge TLS 1.3 (X25519MLKEM768), CAS PKI & VPC-SC Design | R | C | I | R |
| Week 5: Tink SDK KEM/JWT Refactoring & Non-Prod Cloud HSM Pilot | C | R | I | R |
| Week 6: Preventive GCP Org Policies & Executive Board Closeout | R | C | A | C |

## 6. Out-of-Scope Boundaries & Engagement Assumptions

To maintain strict scope control and ensure on-time delivery within the 6-week schedule, the following activities are explicitly excluded from this Statement of Work unless added via a mutually executed Project Change Request (PCR):

- No Statutory or Regulatory Auditing: Google Cloud PSO does not perform formal statutory, regulatory, PCI-DSS QSA, ISO 27001, SOC 2, or financial audits. All deliverables represent consultative engineering assessments and posture verifications.
- Zero Plaintext Data or Private Key Access: The Agentic PQC Readiness Engine inspects GCP control-plane configuration metadata only. Google Cloud PSO will never access, decrypt, export, or inspect Customer plaintext payloads, database records, or raw cryptographic key material.
- No Direct Production Cutover or Production Code Modification by PSO: Google Cloud PSO provides prescriptive 5-step CLI/Terraform runbooks, refactoring blueprints, and guided validation in a designated non-production project during Week 5. Execution of changes in production environments remains the sole responsibility of Customer under Customer's Change Advisory Board (CAB) governance.
- No Source Code Decompilation of Third-Party Commercial Off-The-Shelf (COTS) Binaries: Application cryptographic agility assessments cover Customer-owned workloads, configurations, and documented API integrations, excluding reverse engineering of proprietary third-party binaries.

## 7. Customer Responsibilities, SLA Prerequisites & Governance Cadence

1. IAM & Environment Onboarding (SLA — Within 3 Business Days of Kickoff): Customer will provision the four read-only GCP IAM roles (roles/cloudasset.viewer, roles/cloudkms.viewer, roles/privateca.auditor, roles/compute.viewer) at the in-scope Organization level (organizations/<CUSTOMER-ORG-ID>) as specified in Agentic PQC Technical Architecture and Consultant Guide. Delays in IAM provisioning beyond Day 3 may result in a day-for-day extension of the 6-week schedule.
2. Stakeholder Workshop Participation: Customer will ensure timely attendance of Cloud Security Architects, KMS/PKI Owners, Network/SRE Leads, Identity Architects, and Application Leads during the Week 1 Calibration Workshops and Weeks 4–5 Architecture & Refactoring Workshops.
3. Non-Production Pilot Sandbox (By End of Week 3): Customer will designate one non-production GCP project with Cloud KMS API enabled to host the guided Week 5 Cloud HSM PQC key creation and dual-stack verification lab.
4. Weekly Steering Cadence & Deliverable Acceptance Window (5 Business Days): Google Cloud PSO and Customer Project Managers will conduct a 30-minute Weekly Status & Risk Sync every Friday. Upon submission of each formal deliverable (D-01 through D-06), Customer will review and provide written acceptance or consolidated feedback within five (5) business days, after which the deliverable is deemed accepted.

## 8. Statement of Work Execution & Authorized Sign-Off Block

By signing below, the authorized representatives of Customer (<CUSTOMER-LEGAL-NAME>) and Google Cloud Consulting (PSO) agree to the scope, 6-week schedule, deliverables, assumptions, and governance terms set forth in this Statement of Work:

| Signatory Party | Authorized Representative Name & Title | Signature | Execution Date |
| --- | --- | --- | --- |
| Customer (<CUSTOMER-LEGAL-NAME>) | [ Leave Blank — Populate Name & Title ] | [ Authorized Electronic or Physical Signature ] | [ YYYY-MM-DD ] |
| Google Cloud Consulting (PSO) | [ Leave Blank — Populate Name & Title ] | [ Authorized Electronic or Physical Signature ] | [ YYYY-MM-DD ] |

## 11. Appendix: Commercial Delivery Model, T-Shirt Sizing Tiers & Staffing Allocation

## 1. End-to-End 4-Stage Delivery Flow

1. Stage 1 — Mobilization, Read-Only IAM Setup & 7-Domain Scope Calibration (Weeks 1–2): Configure read-only IAM permissions (Agentic PQC Technical Architecture and Consultant Guide) and execute Agentic PQC Discovery Questionnaire to calibrate industry data shelf-life (X), migration velocity (Y), and CRQC horizon (Z).
2. Stage 2 — Automated 4-Vector Telemetry Scan, CBOM & Quantum Risk Modeling (Weeks 2–3): Execute parallel discovery across Cloud KMS, CAI 4-Vector workload bindings, Compute SSL Policies, Certificate Authority Service, and BYOK ImportJobs, generating the OWASP CycloneDX v1.6 CBOM and Monte Carlo Q-VaR (95%) model.
3. Stage 3 — Edge TLS 1.3 Architecture, Tink SDK Crypto Agility & Non-Prod HSM Pilot (Weeks 4–5): Design hybrid post-quantum TLS 1.3 (X25519MLKEM768) and CAS PQC PKI hierarchies, conduct application refactoring workshops (Google Tink SDK & 16KB–32KB JWT buffers), and execute the guided 5-step Cloud HSM PQC cutover pilot.
4. Stage 4 — Preventive GCP Org Policy Guardrails, Security Recommendations Book & Closeout (Week 6): Deliver preventive GCP Organization Policy YAML constraints blocking legacy RSA/ECC creation, finalize the Agentic PQC Security Recommendations Book and 2026–2035 Migration Roadmap, and conduct the Executive Board Closeout.

## 2. Engagement T-Shirt Sizing Matrix (Small / Medium / Large)

| Sizing Tier | Customer Footprint | Manual Effort (Legacy) | Agent-Accelerated Effort | Recommended PSO Staffing |
| --- | --- | --- | --- | --- |
| Small (Fast-Track / Single Domain) | 1-15 GCP Projects | <50 KMS Keys | 6–8 Weeks (240–320 Hours) | 2–3 Weeks (88–120 Hours) | 1 PSO Security Consultant + 1 Security CE (Part-Time) |
| Medium (Standard Enterprise — Baseline SOW) | 15-100 GCP Projects | 50-300 KMS Keys | 12–16 Weeks (480–640 Hours) | 6 Weeks (224 Hours: 100h PSO Consultant, 80h Security CE, 44h GSD Architect) | 1 PSO Security Consultant (100h) + 1 Security CE (80h) + 1 GSD Architect (44h) |
| Large (Global / Multi-Org Regulated) | 100-1,000+ GCP Projects | 300+ Keys & PKI | 20–24 Weeks (800–960 Hours) | 8–10 Weeks (320–400 Hours) | 2 PSO Security Consultants + 1 Security CE + 1 GSD Lead Architect |

## 3. RACI Governance Matrix

| Workstream / Activity | Google PSO Architect | Google TAM / CE | Customer CISO / GRC | Customer AppSec / SRE |
| --- | --- | --- | --- | --- |
| Read-Only IAM & Scope Onboarding | Consulted (C) | Informed (I) | Approver (A) | Responsible (R) |
| 7-Domain Discovery & Self-Calibration | Responsible (R) | Consulted (C) | Consulted (C) | Consulted (C) |
| Agentic PQC Scan & CycloneDX v1.6 CBOM | Responsible (R) | Consulted (C) | Informed (I) | Consulted (C) |
| Monte Carlo Q-VaR & Executive Board Readout | Responsible (R) | Accountable (A) | Approver (A) | Informed (I) |
| 5-Step HSM Key Cutover & Tink Refactoring | Consulted (C) | Informed (I) | Informed (I) | Responsible (R) |
