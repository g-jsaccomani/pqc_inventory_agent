# Agentic PQC: Plain-Language Guide & Master README
**Google Cloud Consulting — Simple Introduction, 8-File Guide, 60-Second Pitch & FAQ**

> **Google Drive Official Deliverable:** [Agentic PQC: Plain-Language Guide & Master README](https://docs.google.com/document/d/1HS0yym4MJoigjpzaN7dtBMi4P6S63Cri_U_Cgp4cRy0/edit)

> **Executive Summary:** Welcome to the Agentic PQC kit! You do not need to be a cryptography or quantum physics expert to understand or pitch this solution. In simple terms: future quantum computers will break the digital locks (encryption) that companies use today to protect bank transfers, medical records, and cloud systems. Worse, hackers are already stealing encrypted data today to unlock it in a few years. Agentic PQC combines a Google Cloud AI agent (Gemini specialist agents that read the customer's cloud configuration 100% read-only, discover every cryptographic key, and evaluate key security posture with evidence) with a **6-week Google Cloud Consulting Cryptographic Security Posture Review & Readiness Assessment** covering automated inventory (CBOM), structured readiness questionnaires and interviews across the customer's teams, and an advisory roadmap for PQC adoption (without executing key upgrades or touching customer workloads).

---

## 1. Agentic PQC Explained in 2 Minutes (For Non-Specialists)

If you are new to Post-Quantum Cryptography (PQC), here is the entire story in five simple points:

- **The Everyday Analogy (Reviewing Your Digital Locks):** Every day, companies use digital locks (called RSA and ECC encryption) to protect websites, mobile apps, databases, and digital signatures. Those locks work today because normal computers would take thousands of years to guess the combination. However, future quantum computers will be able to crack those combinations in a few hours.
- **Why Is This Urgent Today? ("Steal the Safe Today, Open It Tomorrow"):** A common question is: *"If powerful quantum computers are still a few years away, why care now?"* Because hackers are already intercepting and copying encrypted data today and storing it in giant hard drives. As soon as a quantum computer comes online, they will unlock everything they stole years earlier. Security experts call this **Harvest Now, Decrypt Later (HNDL)**. If a company's data must stay secret for 5 to 10+ years (financial records, health data, government secrets, personal IDs), it is already at risk today.
- **What is PQC (Post-Quantum Cryptography)?** PQC is simply the new generation of "quantum-proof" digital locks approved by the US National Institute of Standards and Technology (NIST). **Important myth-buster:** A company does **NOT** need to buy a quantum computer to use PQC! These new locks are normal software updates that run on today's servers and cloud systems — they just use new mathematical puzzles that neither normal computers nor quantum computers can break.
- **Why Do Companies Struggle with PQC Readiness?** A medium or large company has thousands of digital keys, certificates, databases, and applications spread across the cloud, owned by different teams. Finding all of them manually with spreadsheets and evaluating each area's readiness takes months. Worse, if teams attempt to swap keys without a complete inventory and posture review, systems can break because post-quantum signatures and key shares are physically larger.
- **What is Agentic PQC?** Agentic PQC is Google Cloud's intelligent discovery and posture review accelerator. Instead of spending months on manual spreadsheets, our AI agent (built with Gemini and Google ADK) collects the cryptographic inventory of the customer's Google Cloud environment in seconds, and Gemini specialist agents correlate keys to applications, evaluate key security posture, prioritize risks, and generate advisory recommendations — always citing the evidence. It is **100% read-only** — like looking at the brand label on the outside of a padlock without ever touching the key or seeing what is inside the safe. Paired with our 7-Domain Readiness Questionnaire and stakeholder interviews, it gives our Google Cloud Consultants a complete, evidence-backed posture review and advisory roadmap in 6 weeks (while leaving all future key upgrades and implementation under the customer's own execution).

## 2. Quick Dictionary: 5 Terms You Will Hear (Translated into Plain English)

Whenever someone mentions a technical acronym in a meeting, use this simple cheat sheet:

| Term / Acronym | What It Means in Plain English | Why It Matters to the Customer |
| --- | --- | --- |
| PQC (Post-Quantum Cryptography) | New "quantum-proof" digital locks approved by global regulators (NIST) that run on normal computers today. | Replaces old digital locks (RSA and ECC) that quantum computers will break. Mandatory by 2030-2035. |
| HNDL (Harvest Now, Decrypt Later) | "Steal the locked safe today, open it tomorrow." Hackers copy encrypted traffic now to unlock it when quantum computers arrive. | Means companies cannot wait until 2030 to protect sensitive data that must stay confidential for 5+ years. |
| CBOM (Cryptographic Bill of Materials) | A complete nutrition label / inventory list of every digital lock, key, and certificate used across the company. | Regulators and auditors require companies to have an up-to-date inventory of all their encryption keys. |
| Q-VaR (Quantum Value-at-Risk) | A way to translate encryption risk into money using the customer's own data-value and breach-cost inputs. | Optional. The agent never invents dollar figures; financial exposure is only quantified when the customer provides those inputs. |
| Mosca's Rule (X + Y > Z) | A simple deadline check: (Years data must stay secret) + (Years needed to migrate) vs. (Years until quantum arrives). | If keeping data secret (e.g., 7 yrs) + migrating (2 yrs) = 9 yrs, and quantum arrives in 5 yrs, you are already 4 years late! |

## 3. Which File Should I Open? (Guide to the 8 Consolidated Deliverables)

All documentation is synchronized between the Google Drive folder and the `docs/` directory in this Git repository:

| # | Deliverable Name | Git Markdown Mirror (`docs/`) | Google Drive Link | Who Should Use It & When |
| --- | --- | --- | --- | --- |
| 1 | Agentic PQC README | [docs/01-Agentic-PQC-README.md](docs/01-Agentic-PQC-README.md) | [Google Doc](https://docs.google.com/document/d/1HS0yym4MJoigjpzaN7dtBMi4P6S63Cri_U_Cgp4cRy0/edit) | Everyone: Plain-language guide, 60-second pitch, top 5 FAQ, and 6-week posture review overview. |
| 2 | Agentic PQC Executive Presentation Deck | [docs/02-Agentic-PQC-Executive-Presentation-Deck.md](docs/02-Agentic-PQC-Executive-Presentation-Deck.md) | [Google Slides](https://docs.google.com/presentation/d/1G2SdUg5x_hypeZC6yRTABlV-Ju02e6rC8sHzdwYfyOo/edit) | Sales, Customer Engineers & Executives: 12-slide presentation on Inventory, Area Readiness & Posture Review. |
| 3 | Agentic PQC SOW Readiness Assessment Template | [docs/03-Agentic-PQC-SOW-Readiness-Assessment-Template.md](docs/03-Agentic-PQC-SOW-Readiness-Assessment-Template.md) | [Google Doc](https://docs.google.com/document/d/1B2PlRFyDlkUDKrb224OHUBGjtnnTPs7uWMMZjy9eWZE/edit) | Engagement Managers & Legal: Complete 6-Week Posture Review SOW, WBS, RACI, Deliverables & Sizing. |
| 4 | Agentic PQC Services Estimation Sheet | [docs/04-Agentic-PQC-Services-Estimation-Sheet.md](docs/04-Agentic-PQC-Services-Estimation-Sheet.md) | [Google Sheet](https://docs.google.com/spreadsheets/d/1Pw_60p_6gmgEF6xJKSscP06-65snXOUpiFeLKgawp7k/edit?usp=sharing&resourcekey=0-M5HkFkS46UNpvYwvSbbcAA#gid=845702646) | PSO Estimators: Official 224-hour Security estimate (100h Consultant, 80h SCE, 44h GSD). |
| 5 | Agentic PQC Security Recommendations Book | [docs/05-Agentic-PQC-Security-Recommendations-Book.md](docs/05-Agentic-PQC-Security-Recommendations-Book.md) | [Google Doc](https://docs.google.com/document/d/1D-uN1-0OiTgp9x03F9RWrtDHNmZFRaJ-5dg8UWnuc0I/edit) | Heads of Security & Architects: 8-section Cryptographic Posture & Advisory Recommendations Book. |
| 6 | Agentic PQC Technical Architecture and Consultant Guide | [docs/06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md](docs/06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md) | [Google Doc](https://docs.google.com/document/d/1YZOE7t4veH1S_xIrMMKRTsp8DG36_bWebB0f8_dDwwI/edit) | Technical Consultants & Engineers: System Architecture + L400 TDD + Consultant How-To Guide. |
| 7 | Agentic PQC Discovery Questionnaire | [docs/07-Agentic-PQC-Discovery-Questionnaire.md](docs/07-Agentic-PQC-Discovery-Questionnaire.md) | [Google Doc](https://docs.google.com/document/d/1iaw9_AviJ6APW5gZwHMjgecJwycrPoNc-Izs3_SvEIM/edit) | Customer SMEs: Standalone 7-domain area readiness & discovery questionnaire for stakeholder interviews. |
| 8 | OnePage : Agentic PQC | [docs/08-Agentic-PQC-One-Pager.md](docs/08-Agentic-PQC-One-Pager.md) | [Google Slides](https://docs.google.com/presentation/d/1PdwQw-gLSQ8pc_kQlRQDKKQYGuu3djES43ACXS0Rol8/edit) | Sales & Account Teams: 1-page visual executive summary of the 6-week (224-hour) posture review offering. |

## 4. The 60-Second Elevator Pitch & Top 5 Customer Questions (FAQ)

### 4.1 How to Pitch Agentic PQC in 60 Seconds

"Today, attackers are already copying encrypted corporate data and storing it until quantum computers can break standard RSA and ECC encryption — a threat called Harvest Now, Decrypt Later. Because of this, global regulators require organizations to inventory their cryptographic keys and assess their PQC readiness ahead of 2030 mandates. Normally, discovering thousands of keys and interviewing every team across the cloud takes months of manual spreadsheets. With Google Cloud's Agentic PQC, our 100% read-only AI agent inventories your Google Cloud cryptographic estate in minutes, maps every vulnerable key to the applications that depend on it with evidence, and pairs with our 6-week Google Cloud Consulting engagement to conduct area readiness interviews, review your cryptographic security posture, and deliver an actionable PQC adoption roadmap — with zero disruption to your environments."

### 4.2 Top 5 Questions Customers Ask — And How to Answer Simply

| Customer Question | Simple, Clear Answer |
| --- | --- |
| 1. "Quantum computers aren't ready yet. Why can't we wait until 2029?" | Because of "Steal Today, Unlock Tomorrow" (HNDL). If your data needs to stay private for 5 to 10 years, hackers are already recording encrypted traffic today to unlock it later. Starting with a 6-week inventory and cryptographic posture review now gives your teams a clear roadmap before regulatory deadlines hit. |
| 2. "Do we need to buy a quantum computer to use Post-Quantum Cryptography?" | No! Not at all. Quantum-proof locks (PQC) run on normal computers and standard Google Cloud services today. They simply use stronger math that quantum computers cannot break. |
| 3. "Does your AI Agent see our secret keys, passwords, or private customer data?" | Never. The agent is 100% read-only and only looks at configuration labels (metadata) — like checking the brand and model stamped on the outside of a padlock without ever touching the key or opening the safe. |
| 4. "Will Google Cloud modify or upgrade our encryption keys during this 6-week engagement?" | No. This engagement is strictly a **read-only inventory, area readiness assessment, and cryptographic security posture review**. We do not modify or upgrade keys, policies, or code in your environments. We deliver the complete inventory (CBOM), area readiness assessment, posture findings, and advisory reference guides so your own teams can implement future changes safely under your change-management process. |
| 5. "Is this a regulatory audit that will give us a pass/fail compliance grade?" | No. Google Cloud Consulting works as your trusted security advisor, not a regulatory auditor. We give you full visibility into your cryptographic posture, area readiness gaps, and advisory architecture recommendations so your team is 100% prepared. |

## 5. How the 6-Week Consulting Engagement Works (Step-by-Step)

When a customer signs the 6-week Cryptographic Security Posture Review & Readiness Assessment (224 consulting hours in the Agentic PQC Services Estimation Sheet), here is the week-by-week journey (100% read-only discovery and advisory — zero implementation or key modification):

1. **Week 1 — Mobilization & Read-Only Onboarding:** We hold the kickoff meeting, align with the customer's business and technical areas, and connect our 100% read-only AI Agent to the customer's Google Cloud environment.
2. **Week 2 — Automated Cloud Cryptographic Inventory & CBOM:** We run the automated scan across Cloud KMS/HSM keys, SSL/TLS policies (`postQuantumKeyExchange`), Certificate Authority Service, BYOK import jobs, and workload correlations, producing the baseline **CycloneDX v1.6 CBOM**.
3. **Week 3 — 7-Domain Readiness Questionnaire & Area Interviews:** We apply the Discovery Questionnaire (File #7) and conduct structured readiness interviews across 7 organizational and technical areas (Security/PKI, Network, Application Architecture, IAM, CI/CD, Data Governance, and GRC/Legal) to assess maturity and calibrate data confidentiality shelf-life ($X$) and migration horizon ($Y$).
4. **Week 4 — Quantum Risk Modeling, Mosca Analysis & Business Impact:** We evaluate Mosca's Rule ($X + Y > Z$) per business domain, compute the auditable PQC Posture Scorecard, rank exposures with evidence, and optionally size business impact using the customer's own data-value and breach-cost inputs.
5. **Week 5 — Cryptographic Security Posture Review & Advisory Guidelines:** We conduct a deep security posture review of the discovered keys (rotation hygiene, SOFTWARE vs. HSM protection levels, algorithm exposure, edge TLS posture, and application/gateway readiness gaps) and prepare advisory reference guidelines for future customer-led PQC adoption.
6. **Week 6 — Security Posture Recommendations Book & Executive Adoption Roadmap:** We deliver the Agentic PQC Security Recommendations Book (File #5), preventive governance reference templates, and present the multi-year PQC Adoption Roadmap to executive leadership.

## 6. Copy-Paste Prompts for Live Demos

If you are showing the Agentic PQC web interface (authenticated via Cloud IAP Google Sign-In with isolated per-user sessions across NorthAm, EMEA, India, APAC, and LATAM) or Gemini chat live to a customer, simply copy and paste any of these 3 plain-language prompts:

- **Prompt 1 — Full Cryptographic Inventory & Posture Assessment:** `Run a complete Post-Quantum Cryptography (PQC) readiness and security posture assessment across our Google Cloud organization. Show me our posture scorecard, which encryption keys and SSL policies are exposed first and why (with evidence), which applications depend on them, and an advisory PQC adoption plan.`
- **Prompt 2 — Calibrate with Area Interview Findings (e.g., Banking):** `Calibrate our assessment for a Retail & Investment Bank where financial records must remain confidential for 10 years and regulatory deadlines require PQC adoption within 24 months. Recalculate our Mosca urgency and top posture priorities.`
- **Prompt 3 — Generate Advisory Reference Guides for Engineering Teams:** `Using our actual Cloud KMS and TLS inventory, generate advisory posture recommendations and reference migration guidelines for each vulnerable signing and encryption key so our engineering teams can plan future adoption.`
