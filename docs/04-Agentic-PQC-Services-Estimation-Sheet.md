# Agentic PQC Services Estimation Sheet (Security Tab — 224 Hours)
**Google Cloud Consulting — 6-Week Work Breakdown Structure & Role Hours Estimate**

> **Google Drive Official Deliverable (Google Sheets):** [Agentic PQC Services Estimation Sheet](https://docs.google.com/spreadsheets/d/1Pw_60p_6gmgEF6xJKSscP06-65snXOUpiFeLKgawp7k/edit?usp=sharing&resourcekey=0-M5HkFkS46UNpvYwvSbbcAA#gid=845702646)

## Summary by Role Category
- **Consultant Total:** `100 hours` (`92h` Consultant Security + `8h` Consultant AppMod)
- **SCE (Customer Engineer / Specialist) Total:** `80 hours` (`72h` SCE Security + `8h` SCE Network)
- **GSD (Global Security Delivery) Total:** `44 hours` (`44h` GSD Architect)
- **Grand Total (6-Week Engagement):** **`224 hours`**

## Populated Security Tab Activities (Rows 152–161)

| Row | Selected | Phase | Activity | Complexity | Quantity | Unit | Hours | Total | Consultant AppMod | Consultant Security | SCE Network | SCE Security | GSD Architect |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 153 | TRUE | Phase 1A: Mobilization, Kickoff & Read-Only IAM Onboarding | Aligns on Agentic PQC methodology, 6-week WBS timeline, RACI governance, and validates non-intrusive read-only GCP IAM roles for automated discovery. | Low | 1 | Phase | 12 | 12 | 0 | 4 | 0 | 4 | 4 |
| 154 | TRUE | Phase 1A: 7-Domain Stakeholder Discovery & Sector Calibration | Conducts structured discovery interviews across 7 cryptographic domains and calibrates data confidentiality shelf-life (X) and regulatory regime parameters. | High | 1 | Phase | 24 | 24 | 0 | 12 | 0 | 8 | 4 |
| 155 | TRUE | Phase 1B & 2A: Agent-Assisted 4-Vector GCP Discovery & CycloneDX v1.6 CBOM | Runs automated collectors for KMS, TLS, BYOK and certificates (VPN and vectors 3-4 via agent read-only gcloud lookups and consultant review) and compiles the CycloneDX v1.6 CBOM. | Medium | 1 | Phase | 24 | 24 | 0 | 8 | 0 | 8 | 8 |
| 156 | TRUE | Phase 2B: Quantum Circuit Cryptanalysis, Mosca (X+Y>Z) & Business Impact Sizing | Profiles discovered primitives against published quantum resource estimates (with citations), evaluates Mosca Urgency (X+Y>Z), ranks priorities with evidence, and sizes business impact using the customer's own inputs. | High | 1 | Phase | 24 | 24 | 0 | 12 | 0 | 8 | 4 |
| 157 | TRUE | Phase 3A: Edge TLS 1.3 (X25519MLKEM768), CAS PQC PKI & VPC-SC HNDL Containment Design | Designs target hybrid PQC ingress architecture, internal ML-DSA PKI hierarchies in CAS, and VPC Service Controls perimeters for HNDL exfiltration mitigation. | High | 1 | Phase | 32 | 32 | 0 | 12 | 8 | 8 | 4 |
| 158 | TRUE | Phase 3B: Application Crypto Agility (Google Tink SDK KEM) & JWT/Gateway Buffer Refactoring | Designs crypto-agile application patterns using Google Tink SDK keysets and remediates MTU/header buffer constraints for expanded PQC ciphertexts and signatures. | High | 1 | Phase | 32 | 32 | 8 | 12 | 0 | 8 | 4 |
| 159 | TRUE | Phase 3B: Guided Non-Production Cloud HSM PQC Key Cutover Pilot & Per-Key Runbooks | Executes a guided non-production pilot of zero-downtime dual-signing/hybrid KEM rotation in Cloud KMS/HSM and delivers per-key runbooks written by the remediation agent from the customer's actual inventory. | High | 1 | Phase | 32 | 32 | 0 | 12 | 0 | 12 | 8 |
| 160 | TRUE | Phase 4: Preventive GCP Organization Policy Guardrails & CI/CD Binary Authorization PQC | Designs preventive GCP Organization Policies to block new quantum-vulnerable keys and integrates ML-DSA/SLH-DSA attestation into Cloud Build and Binary Authorization. | Medium | 1 | Phase | 20 | 20 | 0 | 8 | 0 | 8 | 4 |
| 161 | TRUE | Phase 4: Agentic PQC Security Recommendations Book, Multi-Year Roadmap & Executive Board Closeout | Delivers the comprehensive Agentic PQC Security Recommendations Book, 3-Wave Migration Roadmap (2026-2030), and conducts the Executive Board & Technical Readout. | Medium | 1 | Phase | 24 | 24 | 0 | 12 | 0 | 8 | 4 |
| 152 (Subtotal) | TRUE | Security & Trust - Agentic PQC Readiness (6 Weeks) | Total 6-Week Agentic PQC Engagement Scope | Total | 9 | Activities | 224 | 224 | 8 | 92 | 8 | 72 | 44 |
