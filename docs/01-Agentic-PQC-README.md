# Agentic PQC: Plain-Language Guide & Master README
**Google Cloud Consulting — Simple Introduction, 8-File Guide, 60-Second Pitch & FAQ**

> **Google Drive Official Deliverable:** [Agentic PQC: Plain-Language Guide & Master README](https://docs.google.com/document/d/1HS0yym4MJoigjpzaN7dtBMi4P6S63Cri_U_Cgp4cRy0/edit)

> **Executive Summary:** Welcome to the Agentic PQC kit! You do not need to be a cryptography or quantum physics expert to understand or pitch this solution. In simple terms: future quantum computers will break the digital locks (encryption) that companies use today to protect bank transfers, medical records, and cloud systems. Worse, hackers are already stealing encrypted data today to unlock it in a few years. Agentic PQC combines a Google Cloud AI agent (Gemini specialist agents that read the customer's cloud configuration, find every vulnerable digital lock and explain each risk with evidence) with a 6-week Google Cloud Consulting engagement to help the customer upgrade safely without downtime.

---

## 1. Agentic PQC Explained in 2 Minutes (For Non-Specialists)

If you are new to Post-Quantum Cryptography (PQC), here is the entire story in five simple points:

- **The Everyday Analogy (Upgrading Digital Locks):** Every day, companies use digital locks (called RSA and ECC encryption) to protect websites, mobile apps, databases, and digital signatures. Those locks work today because normal computers would take thousands of years to guess the combination. However, future quantum computers will be able to crack those combinations in a few hours.
- **Why Is This Urgent Today? ("Steal the Safe Today, Open It Tomorrow"):** A common question is: *"If powerful quantum computers are still a few years away, why care now?"* Because hackers are already intercepting and copying encrypted data today and storing it in giant hard drives. As soon as a quantum computer comes online, they will unlock everything they stole years earlier. Security experts call this **Harvest Now, Decrypt Later (HNDL)**. If a company's data must stay secret for 5 to 10+ years (financial records, health data, government secrets, personal IDs), it is already at risk today.
- **What is PQC (Post-Quantum Cryptography)?** PQC is simply the new generation of "quantum-proof" digital locks approved by the US National Institute of Standards and Technology (NIST). **Important myth-buster:** A company does **NOT** need to buy a quantum computer to use PQC! These new locks are normal software updates that run on today's servers and cloud systems — they just use new mathematical puzzles that neither normal computers nor quantum computers can break.
- **Why Do Companies Struggle to Upgrade?** A medium or large company has thousands of digital keys, certificates, databases, and applications spread across the cloud. Finding all of them manually with spreadsheets and interviews takes months. Worse, if an engineer swaps an old key for a new quantum-proof key without checking connected apps, systems can crash because the new keys are physically larger.
- **What is Agentic PQC?** Agentic PQC is Google Cloud's intelligent accelerator. Instead of spending months on manual spreadsheets, our AI agent (built with Gemini and Google ADK) collects the cryptographic inventory of the customer's Google Cloud environment in seconds, and Gemini specialist agents then correlate keys to applications, prioritize risks and draft the migration plan, always citing the evidence. It is **100% read-only** — like looking at the brand label on the outside of a padlock without ever touching the key or seeing what is inside the safe. It maps every lock and gives our Google Cloud Consultants a complete, evidence-backed blueprint to guide the customer through a safe 6-week modernization.

## 2. Quick Dictionary: 5 Terms You Will Hear (Translated into Plain English)

Whenever someone mentions a technical acronym in a meeting, use this simple cheat sheet:

| Term / Acronym | What It Means in Plain English | Why It Matters to the Customer |
| --- | --- | --- |
| PQC (Post-Quantum Cryptography) | New "quantum-proof" digital locks approved by global regulators (NIST) that run on normal computers today. | Replaces old digital locks (RSA and ECC) that quantum computers will break. Mandatory by 2030-2035. |
| HNDL (Harvest Now, Decrypt Later) | "Steal the locked safe today, open it tomorrow." Hackers copy encrypted traffic now to unlock it when quantum computers arrive. | Means companies cannot wait until 2030 to protect sensitive data that must stay confidential for 5+ years. |
| CBOM (Cryptographic Bill of Materials) | A complete nutrition label / inventory list of every digital lock, key, and certificate used across the company. | Regulators and auditors require companies to have an up-to-date inventory of all their encryption keys. |
| Q-VaR (Quantum Value-at-Risk) | A way to translate encryption risk into money using the customer's own data-value and breach-cost inputs. | Optional. The agent never invents dollar figures; financial exposure is only quantified when the customer provides those inputs. |
| Mosca's Rule (X + Y > Z) | A simple deadline check: (Years data must stay secret) + (Years needed to upgrade) vs. (Years until quantum arrives). | If keeping data secret (e.g., 7 yrs) + upgrading (2 yrs) = 9 yrs, and quantum arrives in 5 yrs, you are already 4 years late! |

## 3. Which File Should I Open? (Guide to the 8 Consolidated Deliverables)

All documentation is synchronized between the Google Drive folder and the `docs/` directory in this Git repository:

| # | Deliverable Name | Git Markdown Mirror (`docs/`) | Google Drive Link | Who Should Use It & When |
| --- | --- | --- | --- | --- |
| 1 | Agentic PQC README | [docs/01-Agentic-PQC-README.md](docs/01-Agentic-PQC-README.md) | [Google Doc](https://docs.google.com/document/d/1HS0yym4MJoigjpzaN7dtBMi4P6S63Cri_U_Cgp4cRy0/edit) | Everyone: Plain-language guide, 60-second pitch, top 5 FAQ, and 6-week overview. |
| 2 | Agentic PQC Executive Presentation Deck | [docs/02-Agentic-PQC-Executive-Presentation-Deck.md](docs/02-Agentic-PQC-Executive-Presentation-Deck.md) | [Google Slides](https://docs.google.com/presentation/d/1G2SdUg5x_hypeZC6yRTABlV-Ju02e6rC8sHzdwYfyOo/edit) | Sales, Customer Engineers & Executives: 12-slide plain-language customer presentation. |
| 3 | Agentic PQC SOW Readiness Assessment Template | [docs/03-Agentic-PQC-SOW-Readiness-Assessment-Template.md](docs/03-Agentic-PQC-SOW-Readiness-Assessment-Template.md) | [Google Doc](https://docs.google.com/document/d/1B2PlRFyDlkUDKrb224OHUBGjtnnTPs7uWMMZjy9eWZE/edit) | Engagement Managers & Legal: Complete 6-Week SOW, WBS, RACI, Deliverables & T-Shirt Sizing. |
| 4 | Agentic PQC Services Estimation Sheet | [docs/04-Agentic-PQC-Services-Estimation-Sheet.md](docs/04-Agentic-PQC-Services-Estimation-Sheet.md) | [Google Sheet](https://docs.google.com/spreadsheets/d/1Pw_60p_6gmgEF6xJKSscP06-65snXOUpiFeLKgawp7k/edit?usp=sharing&resourcekey=0-M5HkFkS46UNpvYwvSbbcAA#gid=845702646) | PSO Estimators: Official 224-hour Security estimate (100h Consultant, 80h SCE, 44h GSD). |
| 5 | Agentic PQC Security Recommendations Book | [docs/05-Agentic-PQC-Security-Recommendations-Book.md](docs/05-Agentic-PQC-Security-Recommendations-Book.md) | [Google Doc](https://docs.google.com/document/d/1D-uN1-0OiTgp9x03F9RWrtDHNmZFRaJ-5dg8UWnuc0I/edit) | Heads of Security & Architects: 8-section security architecture book + Golden Sample report. |
| 6 | Agentic PQC Technical Architecture and Consultant Guide | [docs/06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md](docs/06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md) | [Google Doc](https://docs.google.com/document/d/1YZOE7t4veH1S_xIrMMKRTsp8DG36_bWebB0f8_dDwwI/edit) | Technical Consultants & Engineers: System Architecture + L400 TDD + Consultant How-To Guide. |
| 7 | Agentic PQC Discovery Questionnaire | [docs/07-Agentic-PQC-Discovery-Questionnaire.md](docs/07-Agentic-PQC-Discovery-Questionnaire.md) | [Google Doc](https://docs.google.com/document/d/1iaw9_AviJ6APW5gZwHMjgecJwycrPoNc-Izs3_SvEIM/edit) | Customer SMEs: Standalone 7-domain discovery questionnaire to send before Kickoff. |
| 8 | OnePage : Agentic PQC | [docs/08-Agentic-PQC-One-Pager.md](docs/08-Agentic-PQC-One-Pager.md) | [Google Slides](https://docs.google.com/presentation/d/1PdwQw-gLSQ8pc_kQlRQDKKQYGuu3djES43ACXS0Rol8/edit) | Sales & Account Teams: 1-page visual executive summary of the 6-week (224-hour) offering. |

## 4. The 60-Second Elevator Pitch & Top 5 Customer Questions (FAQ)

### 4.1 How to Pitch Agentic PQC in 60 Seconds

"Today, attackers are already copying encrypted corporate data and storing it until quantum computers can break standard RSA and ECC encryption — a threat called Harvest Now, Decrypt Later. Because of this, global regulators require organizations to inventory and upgrade their digital locks by 2030. Normally, finding thousands of keys across the cloud takes months of manual spreadsheets. With Google Cloud's Agentic PQC, our read-only AI agent reads your Google Cloud configuration in seconds, and Gemini specialist agents map every vulnerable key to the applications that use it, explain the evidence behind each risk, and give our Google Cloud Consulting team everything needed to guide your safe, zero-downtime upgrade in just 6 weeks."

### 4.2 Top 5 Questions Customers Ask — And How to Answer Simply

| Customer Question | Simple, Clear Answer |
| --- | --- |
| 1. "Quantum computers aren't ready yet. Why can't we wait until 2029?" | Because of "Steal Today, Unlock Tomorrow" (HNDL). If your data needs to stay private for 5 to 10 years, hackers are already recording encrypted traffic today to unlock it later. Plus, upgrading across hundreds of apps takes years of careful testing — starting with a 6-week assessment now prevents a costly emergency later. |
| 2. "Do we need to buy a quantum computer to use Post-Quantum Cryptography?" | No! Not at all. Quantum-proof locks (PQC) run on normal computers and standard Google Cloud services today. They simply use stronger math that quantum computers cannot break. |
| 3. "Does your AI Agent see our secret keys, passwords, or private customer data?" | Never. The agent is 100% read-only and only looks at configuration labels (metadata) — like checking the brand and model stamped on the outside of a padlock without ever touching the key or opening the safe. |
| 4. "Can't we just turn on the new keys ourselves in 5 minutes?" | Creating a new key takes seconds, but plugging it into live applications without preparation can break systems. Quantum-proof signatures are up to 50x larger than old ones, which can cause web gateways to block traffic. Our 6-week engagement ensures your apps and networks are tuned and tested safely first. |
| 5. "Is this a regulatory audit that will give us a pass/fail compliance grade?" | No. Google Cloud Consulting works as your trusted advisor and engineering partner, not a regulatory auditor. We give you visibility, hands-on architecture designs, and tested upgrade guides so your team is 100% ready when auditors arrive. |

## 5. How the 6-Week Consulting Engagement Works (Step-by-Step)

When a customer signs the 6-week engagement (224 consulting hours in the Agentic PQC Services Estimation Sheet), here is the simple week-by-week journey:

1. **Week 1 — Kickoff & Fast Setup:** We hold the kickoff meeting, review the Discovery Questionnaire (File #7), and connect our read-only AI Agent to the customer's Google Cloud environment.
2. **Week 2 — Automated Cloud Inventory:** We run the automated scan across their cloud keys, databases, network load balancers, and certificates, producing their complete digital lock inventory (CBOM).
3. **Week 3 — Prioritization & Business Impact:** The agents rank which systems are most urgent, with the evidence for each, and we translate the risk into business impact using the customer's own data-value and breach-cost inputs.
4. **Week 4 — Protecting Internet Traffic & Architecture Design:** We design the upgrade blueprint and show how to turn on quantum-safe internet traffic protection on Google Cloud Load Balancers.
5. **Week 5 — Safe Testing & Application Tuning:** We guide the customer through a safe test upgrade in a non-production environment and help developers tune their apps and gateways.
6. **Week 6 — Automatic Guardrails & Executive Presentation:** We turn on cloud rules that prevent anyone from creating old vulnerable keys again, and present the Agentic PQC Security Recommendations Book (File #5) and multi-year roadmap to leadership.

## 6. Copy-Paste Prompts for Live Demos

If you are showing the Agentic PQC web interface (authenticated via Cloud IAP Google Sign-In with isolated per-user sessions across NorthAm, EMEA, India, APAC, and LATAM) or Gemini chat live to a customer, simply copy and paste any of these 3 plain-language prompts:

- **Prompt 1 — Full Executive & Technical Assessment:** `Run a complete Post-Quantum Cryptography (PQC) readiness assessment across our Google Cloud organization. Show me our readiness scorecard, which encryption keys are at risk first and why (with evidence), which applications depend on them, and a step-by-step upgrade plan.`
- **Prompt 2 — Calibrate for a Specific Industry (e.g., Banking):** `Calibrate our assessment for a Retail & Investment Bank where financial records must remain confidential for 10 years and regulatory deadlines require migration within 24 months. Recalculate our risk and top priorities.`
- **Prompt 3 — Generate Safe Upgrade Instructions for Engineers:** `Using our actual Cloud KMS inventory, write a zero-downtime migration runbook for each vulnerable signing and encryption key, including how to test safely, how to roll back, and how to prevent application outages.`
