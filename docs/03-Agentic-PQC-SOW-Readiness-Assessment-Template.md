# Agentic PQC SOW Readiness Assessment Template
**Google Cloud Consulting — 6-Week Statement of Work (SOW), RACI Governance & T-Shirt Sizing Guide**

> **Google Drive Official Deliverable:** [Agentic PQC SOW Readiness Assessment Template](https://docs.google.com/document/d/1B2PlRFyDlkUDKrb224OHUBGjtnnTPs7uWMMZjy9eWZE/edit)

> **Executive Summary:** This Statement of Work (SOW) template defines the contractual scope, 6-week Work Breakdown Structure (WBS), deliverables, acceptance criteria, RACI matrix, and governance model for a Google Cloud Consulting — Professional Services Organization (PSO) **Post-Quantum Cryptography (PQC) Cryptographic Security Posture Review, Automated Inventory & Organizational Readiness Assessment** engagement. By pairing senior PSO Security Architects with the 100% read-only Agentic PQC Readiness & CBOM Engine, Google Cloud completes automated cryptographic discovery and CycloneDX v1.6 CBOM generation in Weeks 1–2, conducts structured 7-Domain Readiness Questionnaires, cross-functional area interviews, and Mosca ($X+Y>Z$) risk analysis in Weeks 3–4, and dedicates Weeks 5–6 to a comprehensive Cryptographic Key Security Posture Review, advisory architecture/governance guidelines, and the multi-year PQC Adoption Roadmap (strictly consultative and read-only — zero hands-on implementation or key modification in Customer environments).

---

## 1. Engagement Identification & Customer Environment Parameterization

This Statement of Work ("SOW") is entered into between Google Cloud Consulting — Professional Services Organization ("Google Cloud PSO") and Customer (<CUSTOMER-LEGAL-NAME>) to execute a 6-week Consultative Cryptographic Security Posture Review, Automated Inventory, and Organizational PQC Readiness Assessment across the Customer's designated Google Cloud estate. Populate the engagement parameters below prior to contract execution:

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

Customer has engaged Google Cloud PSO to establish an empirical, cryptographically verified inventory of its Google Cloud estate, assess organizational readiness across business and technical areas, review key security posture, and deliver an advisory PQC adoption roadmap. This engagement directly addresses the technical, operational, and governance imperatives introduced by:

- NIST Post-Quantum Cryptography Standards: Federal Information Processing Standards FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism: ML-KEM-512/768/1024 and hybrid X-Wing), FIPS 204 (Module-Lattice-Based Digital Signature Standard: ML-DSA-44/65/87), and FIPS 205 (Stateless Hash-Based Digital Signature Standard: SLH-DSA).
- Global Deprecation Mandates & Executive Directives: NIST IR 8547 (Final, October 2026) establishing the mandatory 2030 deprecation and 2035 disallowance of classical RSA-2048/3072/4096, ECDSA, and ECDH (P-256/P-384/P-521); White House Executive Order 14412 & OMB Memoranda M-23-02 / M-26-15 requiring automated Cryptographic Bills of Materials (CBOM); NSA CNSA 2.0; UK NCSC (2028/2031/2035 milestones); and sector frameworks (PCI-DSS v4.0.1, DORA, BACEN BCB 85/4893, HIPAA).
- Harvest-Now, Decrypt-Later (HNDL) & Key Posture Assessment: Identifying passive adversary interception exposure on long-lived ciphertexts where Mosca's Theorem (X + Y > Z) is violated, while evaluating key security posture (rotation hygiene, protection levels, IAM access, and workload blast radius) and area readiness for future PQC adoption.
- Read-Only Discovery & Consultative Posture Advisory (Zero Implementation / Non-Audit Positioning): Google Cloud PSO performs a 100% read-only Cryptographic Inventory, 7-Domain Area Readiness Assessment, Control-Plane Security Posture Review, and PQC Adoption Advisory. Google Cloud PSO does not perform hands-on implementation, key upgrades, or workload changes, nor does it act as a statutory, regulatory, or financial auditor.

## 3. Detailed 6-Week Work Breakdown Structure (WBS) & Execution Plan

The engagement is structured across three 2-week workstreams executed over six (6) consecutive calendar weeks: **Weeks 1–2 (Automated Cryptographic Inventory & CBOM)**, **Weeks 3–4 (7-Domain Readiness Questionnaire, Area Interviews & Risk/Mosca Analysis)**, and **Weeks 5–6 (Cryptographic Security Posture Review, Advisory Guidelines & Executive Adoption Roadmap)**:

| Week & Phase | Primary Focus Area | Key PSO & Agentic Activities | Weekly Outputs & Exit Criteria |
| --- | --- | --- | --- |
| Week 1 (Phase 1A) | Mobilization, Kickoff & Read-Only IAM Onboarding | Deliver Executive Kickoff (Agentic PQC README); align stakeholder interview calendar across the 7 areas; configure least-privilege read-only IAM roles and connect the Agentic PQC Engine (Agentic PQC Technical Architecture and Consultant Guide). | Kickoff completed; stakeholder interview schedule locked; validated 100% read-only GCP telemetry access. |
| Week 2 (Phase 1B) | Agent-Assisted 4-Vector GCP Inventory & CycloneDX v1.6 CBOM | Run the discovery and correlation agents across Cloud KMS/HSM, Cloud Asset Inventory (4-Vector workload correlation with STRONG / MEDIUM / WEAK evidence across GKE, Cloud SQL, BigQuery, GCS, Compute), Compute SSL/TLS policies (`postQuantumKeyExchange`), CAS PKI, and BYOK ImportJobs. | 100% in-scope GCP cryptographic inventory; workload correlations recorded with evidence levels (STRONG / MEDIUM / WEAK) or as consumer not identified; baseline OWASP CycloneDX v1.6 CBOM JSON generated. |
| Week 3 (Phase 2A) | 7-Domain Readiness Questionnaire & Area Interviews | Distribute the Agentic PQC Discovery Questionnaire and conduct structured readiness interviews across all 7 areas (Governance/GRC, Data Owners, KMS/PKI, Application Teams, IAM/Gateway, Network/Edge, and CI/CD DevSecOps); execute calibrate-assessment-context. | Completed 35-question 7-Domain Area Readiness Rubric (Levels 1.0–5.0); locked Sector Calibration Profile (Mosca X, Y, Z and gateway parameters) in pqc_calibration_events. |
| Week 4 (Phase 2B) | Quantum Risk Scorecard, Mosca (X+Y>Z), Prioritization & Business Impact | Compute the auditable PQC posture scorecard (numerators and denominators); profile keys against literature-based quantum resource estimates with citations; evaluate Mosca's Theorem (X + Y > Z) per business unit; rank priorities with evidence; optionally size business impact using Customer inputs; hold Mid-Engagement CISO Review. | Validated PQC Posture Scorecard, Quantum Vulnerability Heatmap, Mosca HNDL Overdue Matrix, and evidence-backed risk ranking signed off; optional business-impact ranges documented with Customer inputs. |
| Week 5 (Phase 3A) | Cryptographic Key Security Posture Review & Advisory Guidelines | Conduct a comprehensive security posture review of all discovered keys, SSL/TLS policies, CAS CAs, and application dependencies (evaluating key rotation hygiene, SOFTWARE vs. HSM protection levels, IAM over-permissioning, edge TLS `DEFERRED` exposure, and app/gateway sizing constraints) and compile advisory reference guidelines. | Completed Cryptographic Security Posture Review & Advisory Reference Playbook (tailored advisory guidelines for future Customer-led implementation across KMS/HSM, Edge TLS, and Tink crypto-agility). |
| Week 6 (Phase 3B) | Governance Recommendations, PQC Adoption Roadmap & Board Closeout | Deliver advisory GCP Organization Policy reference templates (to prevent legacy RSA/ECC regression); finalize the Agentic PQC Security Recommendations Book and multi-year PQC Adoption Roadmap (2026–2035); conduct Executive Board & CISO Closeout Presentation. | Complete 6-Deliverable Handover Package accepted; formal Deliverable Acceptance Form signed. |

### 3.1 Week 1 (Phase 1A): Mobilization, Kickoff & Read-Only IAM Onboarding

- Executive & Technical Kickoff: Deliver the formal engagement kickoff presentation (aligned with Agentic PQC README) to align executive sponsors, security architects, PKI owners, and area leads on the 6-week posture review schedule, interview cadence, and deliverables.
- Non-Intrusive Read-Only IAM & Runtime Onboarding: Provision the least-privilege read-only GCP IAM roles (roles/cloudasset.viewer, roles/cloudkms.viewer, roles/resourcemanager.organizationViewer, roles/privateca.auditor, and roles/compute.viewer) at the target GCP Organization scope (organizations/<CUSTOMER-ORG-ID>), and connect the Agentic PQC Readiness Engine using the selected deployment topology (Topology A, B, or C per Agentic PQC Technical Architecture and Consultant Guide).
- Area Interview Scheduling & Questionnaire Distribution: Distribute the Agentic PQC Discovery Questionnaire to the 7 organizational and technical areas in preparation for the Weeks 3–4 readiness interviews.
- Week 1 Exit Criteria: Read-only GCP telemetry access verified; kickoff completed; area stakeholder interview calendar confirmed.

### 3.2 Week 2 (Phase 1B): Agent-Assisted 4-Vector GCP Inventory & Blast-Radius Correlation (CBOM)

- Vector 1 — Cloud KMS, Cloud HSM & EKM Inventory: Execute collect-kms-inventory and collect-kms-import-jobs across all in-scope GCP folders and projects to enumerate every KeyRing, CryptoKey, primary CryptoKeyVersion, algorithm family, protection level (SOFTWARE, HSM, EXTERNAL), rotation schedule, and ImportJob wrapping method.
- Vector 2 — Cloud Asset Inventory 4-Vector Workload Blast-Radius Correlation: Correlate every discovered KMS key against downstream GCP resources across (a) Direct CMEK infrastructure bindings, (b) GKE cluster boot-disk and application-layer Secrets encryption, (c) Cloud SQL, AlloyDB, Spanner, BigQuery, and Cloud Storage data stores, and (d) Pub/Sub, Secret Manager, and Artifact Registry pipelines. Each link carries exactly one evidence level—STRONG (Cloud Asset Inventory shows the exact key reference), MEDIUM (cryptographic IAM role on the key plus a read-only describe confirming the workload's service account), or WEAK (naming or label similarity only, never presented as fact)—and keys without an identified consumer are listed as consumer not identified.
- Vector 3 & Vector 4 — Edge SSL/TLS Policies (`postQuantumKeyExchange`), CAS PKI & Certificates: Inspect Compute Engine SSL/TLS policies (minimum TLS versions, cipher profiles, and `postQuantumKeyExchange` modes: ENABLED, DEFAULT, or DEFERRED), target HTTPS/SSL proxies, Certificate Authority Service (CAS) root/subordinate CA algorithms, and Certificate Manager certificates.
- Baseline CycloneDX v1.6 CBOM Generation: Execute export-cyclonedx-cbom to compile the machine-readable OWASP CycloneDX v1.6 JSON Cryptographic Bill of Materials mapped to official NIST Object Identifiers (OIDs), including application dependencies only from validated correlations, each with its evidence level.
- Week 2 Exit Criteria: 100% of in-scope GCP cryptographic assets inventoried, each key linked to its consuming workloads with an evidence level (STRONG / MEDIUM / WEAK) or listed as consumer not identified, and exported to CycloneDX v1.6 CBOM.

### 3.3 Week 3 (Phase 2A): 7-Domain Area Readiness Questionnaire & Stakeholder Interviews

- 7-Domain Stakeholder Readiness Interviews: Facilitate structured discovery and readiness interviews across all seven weighted domains of the Agentic PQC Discovery Questionnaire: (1) Strategic Governance, CBOM Maturity & Regulatory Posture, (2) Data Confidentiality Shelf-Life (X) & HNDL Exposure, (3) KMS/HSM/BYOK & Root PKI Posture, (4) Application Cryptographic Agility & SDK Dependencies, (5) Identity/IAM & JWT/OIDC Header Sizing, (6) Edge L7 Load Balancers, Service Mesh & Network Readiness, and (7) CI/CD Supply Chain & Governance Readiness.
- Area Maturity Scoring & Gap Identification: Score the 35-question maturity rubric (Levels 1.0 to 5.0) across each organizational area, documenting operational bottlenecks, skill gaps, third-party dependencies, and change-management constraints.
- Agent Context & Sector Calibration: Execute calibrate-assessment-context to persist the Customer's industry sector profile, stakeholder-validated Mosca X and Y horizons, and gateway header limits into pqc_calibration_events.
- Week 3 Exit Criteria: 7-Domain Discovery Questionnaire and stakeholder interviews completed across all in-scope areas; maturity scores (Levels 1.0–5.0) documented; Customer Sector Calibration Profile locked.

### 3.4 Week 4 (Phase 2B): Quantum Risk Scorecard, Mosca (X+Y>Z), Prioritization & Business Impact

- Literature-Based Quantum Resource Estimates: Execute run-quantum-cryptanalysis-simulation to profile every active Cloud KMS key against published quantum resource estimates, always reported with citations and caveats—e.g., RSA-2048: 4,098 logical qubits (2n+2; Häner, Roetteler & Svore 2017), with physical estimates of ~20 million noisy qubits (Gidney & Ekerå 2021) and fewer than 1 million (Gidney 2025); ECDSA/ECDH P-256: 2,330 logical qubits (Roetteler et al. 2017); symmetric keys: Grover's quadratic speedup.
- Mosca's Theorem (X + Y > Z) HNDL Horizon Analysis: Combine the Customer's calibrated confidentiality shelf-life (X) and migration duration (Y) from the Week 3 area interviews against the assumed CRQC arrival horizon (Z; stakeholder-provided or sector baseline) to pinpoint every business domain and dataset currently in active Harvest-Now, Decrypt-Later (HNDL) violation.
- Optional Business-Impact Sizing Workshop (Customer Inputs): Facilitate a working session with the Customer's CISO, DPO, and Finance stakeholders to size business impact using the Customer's own data volumes and classification, incident and breach-cost history, cyber-insurance limits or Business Impact Analysis (BIA), and applicable fines (e.g., LGPD/GDPR), presented as ranges with visible assumptions. The agents never invent dollar figures; financial exposure is only quantified when the Customer provides those inputs.
- Mid-Engagement CISO & Risk Committee Checkpoint: Present the validated PQC Posture Scorecard, Area Readiness Maturity Scores, Mosca HNDL Overdue Matrix, and evidence-backed risk ranking to the CISO and Enterprise Risk Management (ERM) stakeholders.
- Week 4 Exit Criteria: PQC Posture Scorecard (every KPI with value, numerator, denominator, and definition), Area Readiness Matrix, Mosca HNDL Overdue Matrix, and evidence-backed risk ranking formally reviewed by Security Leadership.

### 3.5 Week 5 (Phase 3A): Cryptographic Key Security Posture Review & Advisory Guidelines

- Cloud KMS, HSM & BYOK Key Security Posture Review: Perform a detailed security posture review of every discovered key and keyring—evaluating algorithm compliance (classical RSA/ECC vs. AES-256 vs. NIST FIPS 203/204/205 PQC), protection level posture (`SOFTWARE` vs. `HSM` / `EXTERNAL`), symmetric key rotation hygiene (<= 90-day policy adherence), IAM binding least-privilege hygiene, and BYOK ImportJob wrapping methods (`RSA_OAEP` vs. quantum-safe `HPKE`).
- Edge TLS 1.3 (`postQuantumKeyExchange`), CAS PKI & Network Posture Review: Evaluate external and internal HTTPS/SSL load balancer policies (identifying policies with `postQuantumKeyExchange = DEFERRED` or pre-TLS 1.3 minimum versions), CAS CA hierarchy algorithms, and VPC Service Controls (VPC-SC) perimeter posture around high-value data repositories.
- Application, IAM & API Gateway Readiness Review: Synthesize findings from the Week 2 inventory and Week 3 application/IAM interviews to document where direct `AsymmetricDecrypt` API calls, database column widths, or 4KB–8KB API gateway HTTP header limits will require future adaptation for PQC ciphertexts (1,120B) and signatures (3,309B ML-DSA-65).
- Advisory Reference Playbook Compilation (No Hands-On Execution by Google): Compile the **Advisory Technical Reference Playbook**, providing consultative reference guidelines, architecture patterns, and per-key reference runbooks grounded in the Customer's actual inventory so the Customer's own engineering teams have a clear technical reference when they execute future PQC migrations.
- Week 5 Exit Criteria: Cryptographic Key Security Posture Review completed across all 4 vectors; Advisory Technical Reference Playbook delivered.

### 3.6 Week 6 (Phase 3B): Governance Recommendations, PQC Adoption Roadmap & Executive Board Closeout

- Preventive Governance Posture & Reference Templates: Deliver advisory GCP Organization Policy YAML reference templates—including `constraints/cloudkms.allowedProtectionLevels` (for HSM enforcement) and custom constraint templates to prevent new classical RSA/ECC key creation or `DEFERRED` SSL policies once the Customer's teams complete future migrations.
- Agentic PQC Security Recommendations Book & Multi-Year Adoption Roadmap (2026–2035): Finalize the comprehensive **Agentic PQC Security Recommendations Book**, consolidating the inventory (CBOM), 7-Domain Area Readiness Assessment, Cryptographic Key Security Posture Review, target Google Cloud Security Architecture Bill of Materials (BOM), and the phased multi-year PQC Adoption Roadmap.
- Executive Board & CISO Closeout Presentation: Deliver the formal closeout readout to the CISO, CIO, CFO, and Architecture Review Board, walking through the cryptographic inventory, area readiness maturity scores, key security posture findings, and prioritized PQC adoption roadmap.
- Final 6-Deliverable Handover & Engagement Sign-Off: Transfer all six contractual deliverables into the Customer's designated repository and execute the formal Deliverable Acceptance Sign-Off.
- Week 6 Exit Criteria: All six contractual deliverables (D-01 through D-06) delivered and formally accepted; Executive Board Closeout completed.

## 4. Contractual Deliverables & Acceptance Criteria Matrix

Google Cloud PSO will deliver six (6) formal consultative assessment artifacts grounded in the Customer's live read-only GCP telemetry and stakeholder readiness interviews:

| ID | Deliverable Name | Delivery Week & Target Audience | Core Contents & Objective Acceptance Criteria |
| --- | --- | --- | --- |
| D-01 | OWASP CycloneDX v1.6 CBOM & 4-Vector Cryptographic Inventory | Week 2 — GRC, SecOps, KMS & PKI Owners | Machine-readable CycloneDX v1.6 JSON CBOM plus human-readable inventory covering 100% of in-scope GCP KMS/HSM keys, TLS policies (`postQuantumKeyExchange`), CAS CAs, BYOK import jobs, and 4-Vector workload dependencies (each with its evidence level: STRONG / MEDIUM / WEAK), with NIST OIDs. |
| D-02 | Calibrated 7-Domain Area Readiness Assessment & Maturity Baseline | Week 3 — CISO, GRC, Area Leads & Enterprise Architects | Completed 35-question Agentic PQC Discovery Questionnaire scorecard (Levels 1.0–5.0 across 7 areas), area readiness gap analysis, sector calibration ledger (`pqc_calibration_events`), and validated Mosca X and Y parameters. |
| D-03 | Executive Posture Scorecard & Quantum Risk Assessment Report | Week 4 — CEO, CFO, CISO, Board of Directors | C-Level BLUF, Auditable PQC Posture Scorecard (every KPI with numerator and denominator), top risks tied to workload correlations with evidence levels, literature-based quantum resource estimates with citations, Mosca HNDL Overdue Matrix, and optional business-impact ranges sized only from Customer-provided inputs. |
| D-04 | Edge TLS, CAS PKI & Network Security Posture Review (Advisory) | Week 5 — Network, SRE, Load Balancer & PKI Owners | Security posture review of L7 Load Balancer SSL policies (`postQuantumKeyExchange` status and TLS versions), CAS PKI hierarchies, and data perimeters, paired with advisory target-state architecture recommendations. |
| D-05 | Cloud KMS/HSM Key Security Posture Review & Advisory Reference Playbook | Week 5 — Cloud Engineers, IAM Leads, App Architects | Deep security posture review of all discovered KMS/HSM keys (algorithms, SOFTWARE vs. HSM protection levels, 90-day rotation hygiene, IAM bindings, and app/gateway readiness constraints) plus advisory per-key reference guidelines for future Customer-led adoption. |
| D-06 | Agentic PQC Security Recommendations Book & Multi-Year Adoption Roadmap | Week 6 — Cloud Governance, CISO & Security Leadership | Comprehensive Cryptographic Posture & Security Recommendations Book, advisory GCP Organization Policy reference templates, and the phased 2026–2035 PQC Adoption Roadmap presented at the Executive Board Closeout. |

## 5. Engagement Team Structure, Resource Allocation & RACI Matrix

Successful completion within the 6-week timeline relies on a dedicated Google Cloud PSO delivery pod working alongside Customer subject matter experts (SMEs). The tables below define the PSO specialist roles, weekly effort allocation, and the Responsibility Assignment Matrix (R = Responsible, A = Accountable, C = Consulted, I = Informed):

| Role Title | Organization | Primary Responsibilities Across the 6-Week Engagement | Estimated Allocation |
| --- | --- | --- | --- |
| Principal PQC Security Architect (Lead) | Google Cloud PSO | Leads kickoff, 7-domain area readiness interviews, quantum risk prioritization and optional business-impact sizing workshop, cryptographic posture review, and Executive Board readout. | Weeks 1–6 (Full Engagement Lead) |
| Cloud Infrastructure, KMS & Crypto Posture Specialist | Google Cloud PSO | Executes read-only Agentic PQC Engine onboarding, 4-Vector CBOM discovery, KMS/TLS/PKI security posture review, and advisory reference playbook compilation. | Weeks 1–6 (Discovery & Posture Analysis) |
| Engagement Manager / Project Director | Google Cloud PSO | Manages 6-week WBS governance, weekly steering syncs, stakeholder interview scheduling across areas, and formal Deliverable Acceptance sign-offs. | Weeks 1–6 (Governance & PMO) |
| Executive Sponsor / CISO & Risk Lead | Customer | Approves engagement scope, validates Mosca confidentiality horizons (X) and risk appetite, provides business-impact inputs if impact sizing is requested, chairs Week 4/Week 6 readouts, and signs Deliverable Acceptance. | Weeks 1, 4, 6 (Executive Checkpoints) |
| Cloud Platform, KMS/PKI, Network, IAM & App Area SMEs | Customer | Provisions read-only IAM roles (Days 1–3), completes the 7-Domain Readiness Questionnaire, participates in Weeks 3–4 area interviews, and reviews Week 5 posture findings. | 2–4 Hours / Week (Interviews & Reviews) |

### 5.1 Workstream Responsibility Assignment Matrix (RACI)

| Engagement Workstream / Weekly Milestone | Google PSO Lead Architect | Google PSO Crypto Posture Specialist | Customer CISO / Exec Sponsor | Customer Area SMEs (KMS, Net, App, GRC) |
| --- | --- | --- | --- | --- |
| Week 1: Kickoff, Read-Only IAM Provisioning & Agent Onboarding | R | C | A | R |
| Week 2: Agent-Assisted 4-Vector GCP Inventory & CycloneDX v1.6 CBOM | A | R | I | C |
| Week 3: 7-Domain Readiness Questionnaire & Stakeholder Area Interviews | R | C | A | R |
| Week 4: Quantum Risk Scorecard, Mosca Analysis & Business Impact Sizing | R | R | A | C |
| Week 5: Cryptographic Key Security Posture Review & Advisory Guidelines | R | R | I | C |
| Week 6: Security Posture Recommendations Book, Adoption Roadmap & Readout | R | C | A | I |

## 6. Out-of-Scope Boundaries & Engagement Assumptions

To maintain strict scope control and ensure on-time delivery within the 6-week schedule, the following activities are explicitly excluded from this Statement of Work unless added via a mutually executed Project Change Request (PCR):

- No Implementation, Key Upgrade, Key Rotation, or Pilot Execution by Google Cloud PSO: This engagement is strictly a **100% read-only cryptographic inventory, area readiness assessment, and cryptographic security posture review**. Google Cloud PSO will **not** create, upgrade, rotate, or modify cryptographic keys, SSL/TLS policies, Certificate Authorities, Organization Policies, or application code in any Customer environment (neither production nor non-production). All architecture blueprints, policy templates, and per-key runbooks are delivered strictly as **consultative advisory reference materials** for future evaluation and execution by the Customer's own teams.
- No Statutory or Regulatory Auditing: Google Cloud PSO does not perform formal statutory, regulatory, PCI-DSS QSA, ISO 27001, SOC 2, or financial audits. All deliverables represent consultative security posture assessments and readiness advisories.
- Zero Plaintext Data or Private Key Access: The Agentic PQC Readiness Engine inspects GCP control-plane configuration metadata only. Google Cloud PSO will never access, decrypt, export, or inspect Customer plaintext payloads, database records, or raw cryptographic key material.
- No Source Code Decompilation of Third-Party Commercial Off-The-Shelf (COTS) Binaries: Application cryptographic readiness assessments cover Customer-owned cloud configurations, interview responses, and documented API integrations, excluding reverse engineering of proprietary third-party binaries.

## 7. Customer Responsibilities, SLA Prerequisites & Governance Cadence

1. IAM & Environment Onboarding (SLA — Within 3 Business Days of Kickoff): Customer will provision the five read-only GCP IAM roles (roles/cloudasset.viewer, roles/cloudkms.viewer, roles/resourcemanager.organizationViewer, roles/privateca.auditor, roles/compute.viewer) at the in-scope Organization level (organizations/<CUSTOMER-ORG-ID>), plus viewer roles on the in-scope workload services (e.g., roles/run.viewer, roles/container.viewer) for read-only evidence verification, as specified in Agentic PQC Technical Architecture and Consultant Guide. Delays in IAM provisioning beyond Day 3 may result in a day-for-day extension of the 6-week schedule.
2. Stakeholder Area Interview & Questionnaire Participation: Customer will ensure timely participation of representatives from the 7 in-scope areas (Governance/GRC, Data Owners, Cloud KMS/PKI Leads, Application Architects, IAM/API Gateway Leads, Network/SRE Leads, and CI/CD DevSecOps) to complete the Agentic PQC Discovery Questionnaire and attend the Weeks 3–4 readiness interviews. If the optional Week 4 business-impact sizing is requested, Customer's CISO, DPO, and Finance stakeholders will provide its inputs (data volumes and classification, incident and breach-cost history, cyber-insurance limits or BIA, and applicable fines such as LGPD/GDPR).
3. Weekly Steering Cadence & Deliverable Acceptance Window (5 Business Days): Google Cloud PSO and Customer Project Managers will conduct a 30-minute Weekly Status & Risk Sync every Friday. Upon submission of each formal deliverable (D-01 through D-06), Customer will review and provide written acceptance or consolidated feedback within five (5) business days, after which the deliverable is deemed accepted.

## 8. Statement of Work Execution & Authorized Sign-Off Block

By signing below, the authorized representatives of Customer (<CUSTOMER-LEGAL-NAME>) and Google Cloud Consulting (PSO) agree to the scope, 6-week schedule, deliverables, assumptions, and governance terms set forth in this Statement of Work:

| Signatory Party | Authorized Representative Name & Title | Signature | Execution Date |
| --- | --- | --- | --- |
| Customer (<CUSTOMER-LEGAL-NAME>) | [ Leave Blank — Populate Name & Title ] | [ Authorized Electronic or Physical Signature ] | [ YYYY-MM-DD ] |
| Google Cloud Consulting (PSO) | [ Leave Blank — Populate Name & Title ] | [ Authorized Electronic or Physical Signature ] | [ YYYY-MM-DD ] |

## 11. Appendix: Commercial Delivery Model, T-Shirt Sizing Tiers & Staffing Allocation

## 1. End-to-End 3-Stage Delivery Flow (6 Weeks)

1. Stage 1 — Mobilization, Read-Only IAM Setup & 4-Vector Cryptographic Inventory / CBOM (Weeks 1–2): Configure 100% read-only IAM permissions (Agentic PQC Technical Architecture and Consultant Guide) and execute parallel discovery across Cloud KMS, CAI 4-Vector workload bindings, Compute SSL Policies (`postQuantumKeyExchange`), Certificate Authority Service, and BYOK ImportJobs, generating the baseline OWASP CycloneDX v1.6 CBOM.
2. Stage 2 — 7-Domain Area Readiness Questionnaire, Stakeholder Interviews & Quantum Risk / Mosca Modeling (Weeks 3–4): Conduct structured readiness interviews across all 7 business and technical areas using the Agentic PQC Discovery Questionnaire, calibrate industry data shelf-life (X), migration velocity (Y), and CRQC horizon (Z), and compute the auditable PQC Posture Scorecard and Mosca HNDL exposure analysis.
3. Stage 3 — Cryptographic Key Security Posture Review, Advisory Recommendations & Adoption Roadmap (Weeks 5–6): Perform a comprehensive security posture review of all discovered keys, TLS policies, PKI hierarchies, and area readiness gaps; deliver advisory reference guidelines and Organization Policy templates (for future Customer-led implementation); finalize the Agentic PQC Security Recommendations Book and 2026–2035 PQC Adoption Roadmap; and conduct the Executive Board Closeout.

## 2. Engagement T-Shirt Sizing Matrix (Small / Medium / Large)

| Sizing Tier | Customer Footprint | Manual Effort (Legacy) | Agent-Accelerated Effort | Recommended PSO Staffing |
| --- | --- | --- | --- | --- |
| Small (Fast-Track / Single Domain) | 1-15 GCP Projects | <50 KMS Keys | 6–8 Weeks (240–320 Hours) | 2–3 Weeks (88–120 Hours) | 1 PSO Security Consultant + 1 Security CE (Part-Time) |
| Medium (Standard Enterprise — Baseline SOW) | 15-100 GCP Projects | 50-300 KMS Keys | 12–16 Weeks (480–640 Hours) | 6 Weeks (224 Hours: 100h PSO Consultant, 80h Security CE, 44h GSD Architect) | 1 PSO Security Consultant (100h) + 1 Security CE (80h) + 1 GSD Architect (44h) |
| Large (Global / Multi-Org Regulated) | 100-1,000+ GCP Projects | 300+ Keys & PKI | 20–24 Weeks (800–960 Hours) | 8–10 Weeks (320–400 Hours) | 2 PSO Security Consultants + 1 Security CE + 1 GSD Lead Architect |

## 3. RACI Governance Matrix

| Workstream / Activity | Google PSO Architect | Google TAM / CE | Customer CISO / GRC | Customer Area SMEs |
| --- | --- | --- | --- | --- |
| Read-Only IAM & Scope Onboarding | Consulted (C) | Informed (I) | Approver (A) | Responsible (R) |
| Agentic PQC Scan & CycloneDX v1.6 CBOM | Responsible (R) | Consulted (C) | Informed (I) | Consulted (C) |
| 7-Domain Readiness Questionnaire & Area Interviews | Responsible (R) | Consulted (C) | Consulted (C) | Responsible (R) |
| Posture Scorecard, Business Impact & Executive Readout | Responsible (R) | Accountable (A) | Approver (A) | Informed (I) |
| Cryptographic Posture Review & Advisory Adoption Roadmap | Responsible (R) | Consulted (C) | Approver (A) | Consulted (C) |
