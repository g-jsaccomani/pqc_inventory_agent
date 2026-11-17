# Agentic PQC Executive Presentation Deck (12-Slide Plain-Language Guide)
**Google Cloud Consulting — Automated Cryptographic Inventory, Area Readiness & Security Posture Review**

> **Google Drive Official Deliverable (Google Slides):** [Agentic PQC Executive Presentation Deck](https://docs.google.com/presentation/d/1G2SdUg5x_hypeZC6yRTABlV-Ju02e6rC8sHzdwYfyOo/edit)

---

## Slide 1 — Cover
- **Title:** Agentic PQC: Cryptographic Posture & Readiness
- **Subtitle:** 6-Week Inventory, Area Readiness & Security Posture Review

---

## Slide 2 — Agentic PQC in Plain Language
- **What is the Problem? (Digital Locks vs. Quantum):** Every company uses "digital locks" (encryption) to protect data and payments. Future quantum computers will break today's standard locks — and hackers are already stealing encrypted data today to unlock it later.
- **What is Post-Quantum Cryptography (PQC)?** The new generation of "quantum-proof" digital locks approved by global regulators (NIST). You do **NOT** need a quantum computer — they run on normal cloud systems today.
- **What is Agentic PQC?** Gemini AI agents perform a **100% read-only cryptographic inventory**, map which applications depend on each key with evidence, and pair with structured area readiness interviews to deliver a complete **Cryptographic Security Posture Review & PQC Adoption Roadmap**.

---

## Slide 3 — What We Will Cover Today (Simple 8-Point Executive Guide)
1. **Why Act Now?** ("Steal Today, Unlock Tomorrow")
2. **How Our AI Agents Work** (100% Read-Only Inventory)
3. **What We Inventory Across Your Cloud** (4 Key Areas)
4. **Area Readiness Questionnaire & Stakeholder Interviews**
5. **Translating Cryptographic Posture into Business Impact**
6. **Advisory Posture Review & PQC Adoption Guidelines**
7. **Our 6-Week Posture Review Program (Step-by-Step)**
8. **Why Google Cloud & What Your Team Receives**

---

## Slide 4 — Agentic PQC at a Glance
- **Who Needs This?** Banks, healthcare, government, telecom, retail, and any company whose data must stay private for 5+ years.
- **The Threat ("Steal Today, Open Later"):** Hackers do not need a quantum computer today. They are copying encrypted data now and saving it until quantum computers can unlock it. Regulators require PQC readiness by 2030, but finding thousands of keys and interviewing every area manually takes months.
- **Our Solution (Agentic PQC):**
  - Instead of months of manual spreadsheets, our Google Cloud AI agents (powered by Gemini) inventory your cloud cryptographic settings in minutes.
  - It is **100% read-only & non-intrusive** — like checking the brand label on a padlock from the outside without ever touching your keys, modifying systems, or accessing customer data.
  - Combines automated inventory (CBOM) with **7-Domain Area Readiness Interviews** to deliver a complete key security posture review and advisory adoption roadmap.
- **Business Value:**
  - Replaces 4+ weeks of manual spreadsheet discovery with an automated read-only inventory.
  - Evaluates the PQC readiness of every business and technical area via structured questionnaires and interviews.
  - Gives leadership an auditable posture scorecard and business impact sized with your own data.
  - Identifies key hygiene gaps (rotation, SOFTWARE vs. HSM protection, legacy RSA/ECC) and application readiness constraints.
  - Delivers advisory architecture and governance guidelines so your teams can plan and execute future PQC adoption safely.

---

## Slide 5 — What the AI Agents Inventory in Your Cloud
| Area | Focus | What the AI Agents Do in Plain English |
| :--- | :--- | :--- |
| **1. Stored Data Locks** | Cloud Keys & Vaults | Inventories all digital keys protecting your databases and files to review key posture (RSA/ECC vs. quantum-safe, rotation, HSM vs. software). |
| **2. Business Impact Map** | Connected Apps & Databases | Maps which business applications and databases depend on each key, with evidence, so teams know the exact blast radius. |
| **3. Internet Traffic Locks** | Websites & Network Edge | Reviews load balancer SSL/TLS policies (`postQuantumKeyExchange` status and TLS versions) to detect HNDL exposure at the edge. |
| **4. Imported External Keys** | On-Premises to Cloud Keys | Reviews BYOK import jobs from external HSMs into Google Cloud to assess key-wrapping posture. |

---

## Slide 6 — How We Prioritize Key Posture Findings (No Guesswork)
1. **Legacy RSA Locks (Traditional Encryption & Signatures):** Standard RSA locks used across websites and apps will be cracked by quantum computers and must be inventoried for pre-2030 transition.
2. **Elliptic Curve — ECC (Likely Among the First to Fall):** Smaller elliptic-curve keys require fewer quantum resources to break than RSA. **High Priority** — posture exposure ranked per key with evidence.
3. **Database Encryption — AES-256 (Already Safe!):** Standard AES-256 file and database encryption is **already resistant** to quantum computers! We verify rotation hygiene (90-day policy) and separate what is already safe from what requires future migration.
4. **Target Approved Locks (Official NIST PQC Standards):** Evaluates readiness to adopt NIST standards (`ML-KEM-768`, `KEM-XWING` & `ML-DSA-65`) available in Google Cloud KMS today.
5. **Business Impact (Sized with Your Own Data):** Translates posture findings into impact ranges from your data value, breach costs and fines, with visible assumptions — the agent never invents dollar figures.

---

## Slide 7 — Illustrative Example: Cryptographic Posture Scorecard
*Badge: SAMPLE READ-ONLY CLOUD SCAN*

| Security Area Checked | Score / Result | Posture Finding & Advisory Recommendation |
| :--- | :---: | :--- |
| **Overall Quantum Readiness** | **70.0% (MODERATE)** | 52 digital keys and 22 cloud systems inventoried automatically in minutes. |
| **Digital Signatures & Keys** | **50.0%** | Half of asymmetric keys still use classical RSA/ECC — prioritized in the adoption roadmap. |
| **Database & File Encryption** | **100%** | 100% Quantum-Safe (AES-256)! Posture review flags keys missing 90-day rotation schedules. |
| **Website & Internet Traffic** | **50.0%** | Identifies SSL policies with `DEFERRED` PQC key exchange or pre-TLS 1.3 settings for remediation planning. |
| **Business Impact Sizing** | **Your Data** | Uses only your data-value and breach-cost inputs from area interviews, shown as ranges. |

---

## Slide 8 — Cryptographic Posture Review & Advisory Adoption Guidelines
### Left Column: Key Security Posture & Governance Review
1. **Algorithm & Protection Posture:** Audits every key's algorithm family (classical vs. PQC) and protection level (`SOFTWARE` vs. `HSM` / `EXTERNAL`).
2. **Access & Rotation Hygiene:** Reviews IAM bindings per key, missing 90-day rotation schedules, and workload dependency evidence (`STRONG` / `MEDIUM` / `WEAK`).
3. **Advisory Reference Playbooks:** Provides tailored reference guidelines for your engineering teams (Google executes zero changes in your environment).

### Right Column: Area Readiness & Architectural Advisory
- **Application Readiness (Google Tink Advisory):** Assesses application dependencies through interviews and advises how dev teams can adopt crypto-agile patterns.
- **Network & Gateway Sizing Assessment:** Identifies where larger PQC signatures and key shares require gateway buffer or TLS 1.3 policy planning.
- **Preventive Governance Templates:** Delivers reference GCP Organization Policy templates so your team can prevent legacy key regression.

---

## Slide 9 — How We Work Together: 6-Week Posture Review Program
- **Weeks 1–2 (Automated Inventory & CBOM Discovery):** We onboard read-only access, run the automated cryptographic scan across Cloud KMS, TLS, CAS, and workloads, and build your CycloneDX v1.6 CBOM. *Key deliverables: read-only cloud scan, key-to-workload mapping, baseline CycloneDX v1.6 CBOM.*
- **Weeks 3–4 (Area Readiness Interviews & Risk Analysis):** We apply the 7-Domain Readiness Questionnaire, interview your technical and business areas, evaluate Mosca ($X+Y>Z$) urgency, and size business impact. *Key deliverables: 7-domain area interviews, readiness maturity scores, Mosca HNDL analysis, prioritized risk scorecard.*
- **Weeks 5–6 (Security Posture Review & Executive Roadmap):** We complete the cryptographic key security posture review, deliver advisory PQC architecture and governance guidelines, and present the multi-year adoption roadmap to leadership. *Key deliverables: cryptographic posture review, advisory reference guides, Executive Recommendations Book, PQC adoption roadmap.*

---

## Slide 10 — Why Google Cloud & Agentic PQC?
- **Subtitle:** Combining Gemini AI Agents with Google Cloud Security Posture Advisors
- **Business Impact & Time Saved:**
  - **Replaces Months of Spreadsheets:** Turns a slow, manual inventory and interview cycle into a fast, structured 6-week posture review.
  - **Time to First Inventory:** 120-160 hrs ➔ < 5 mins — 85% less manual effort for your security and engineering teams.
  - **100% Non-Intrusive & Read-Only:** Zero changes to your keys or production workloads — full visibility with zero operational risk.
- **3 Reasons Customers Choose Google Cloud:**
  1. **Automated Multi-Vector Discovery:** Instant visibility across Cloud KMS, HSM, SSL/TLS policies (`postQuantumKeyExchange`), certificates, and workload bindings.
  2. **Structured 7-Domain Area Readiness Assessment:** Aligns Security, PKI, Network, Application, IAM, CI/CD, and GRC/Risk teams around a single readiness baseline.
  3. **6-Week Expert Posture Review & Adoption Blueprint:** Our Consultants (224h across 6 weeks) deliver an auditable posture scorecard, advisory reference guides, and a board-ready PQC adoption roadmap.

---

## Slide 11 — What You Receive in 6 Weeks
*The Agentic PQC: Cryptographic Posture & Readiness platform is deployed on Cloud Run (Vertex AI Agent Engine optional), supporting 4 executive and technical deliverable packages:*

**4 Key Deliverables for Leadership & Engineering:**
1. **01. Executive Posture Scorecard & Board Report** *(Risk, Mosca & Business Impact)*
2. **02. 7-Domain Area Readiness Assessment** *(Questionnaire & Stakeholder Interviews)*
3. **03. Complete Cryptographic Inventory** *(Compliance-Ready CycloneDX v1.6 CBOM)*
4. **04. Advisory Architecture Guidelines & PQC Adoption Roadmap** *(Customer-Led Implementation Blueprint)*
- **Why Customers Trust Our Approach:**
  - **100% Real Cloud Data (Zero Guesswork):** Every number comes from your Google Cloud metadata or your own interview inputs — never AI guesswork.
  - **100% Read-Only & Advisory:** We inspect configuration metadata and interview your teams — we never touch secret keys, private data, or live workloads.
  - **Tailored to Your Industry:** Sector baselines for Banking, Healthcare, Government, Telecom, Energy, and Retail.

## Slide 12 — Commercial Proposal & Engagement Investment
- **Header:** `COMMERCIAL PROPOSAL & ENGAGEMENT INVESTMENT`
- **Title:** 6-Week Cryptographic Security Posture Review & Readiness
- **Subtitle:** Fixed-scope Google Cloud Consulting (GCC) engagement combining automated read-only inventory, area interviews, and posture review:
- **Commercial Investment & Engagement Parameters:**
  - **R$ 248,000** — Consolidated Investment (Fixed-Scope Fee, Taxes Excl.)
  - **6 Weeks** — Fixed Delivery Timeline (Inventory, Interviews & Posture)
  - **Up to 50 Projects** — Bounded Assessment Scope (1 Org, up to 300 Keys, 7 Areas)
  - **Lean GCC Squad** — Expert Security Delivery (Consultant + Engineer)
- **Included Scope, Governance & Key Premises:**
  - **Complete 6-Deliverable Package:** CycloneDX v1.6 CBOM, 7-Domain Area Readiness, Key Posture Review & PQC Adoption Roadmap.
  - **Read-Only & Zero Data Exposure:** Strictly 100% read-only GCP metadata and interviews — zero changes to keys or workloads.
  - **Key Execution Premises:** Read-only IAM ready by Day 3; Customer ensures area SME participation in Weeks 3–4 interviews.

---

## Slide 13 — Engagement Execution Path: Next Steps
- **STEP 1 (01) — Commercial Approval:** Review and approve the commercial proposal, engagement parameters, and 6-week posture review scope. *Key Actions: Confirm assessment scope & areas, Validate 6-week delivery model, Approve commercial proposal, Confirm executive sponsorship.*
- **STEP 2 (02) — SOW Preparation & Signature:** Finalize the Statement of Work (SOW) and complete legal and procurement review for formal execution. *Key Actions: Finalize Statement of Work (SOW), Complete legal & procurement review, Execute SOW & Order Form, Align governance checkpoints.*
- **STEP 3 (03) — Timeline Alignment & Kickoff:** Align target project start dates, provision 100% read-only cloud access, schedule area interviews, and launch Week 1. *Key Actions: Align target kickoff & milestones, Provision required setup for project, Conduct Week 1 kickoff session.*

---

## Slide 14 — Closing
- **Thank You** — Google Cloud Consulting

