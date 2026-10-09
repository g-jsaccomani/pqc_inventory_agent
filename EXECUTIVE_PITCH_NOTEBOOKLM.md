# Google Cloud Post-Quantum Cryptography (PQC) Readiness & Migration Agent
## Executive Product Dossier, Architecture & Sales Deck Source (for NotebookLM & Gemini)

---

## 1. Executive Summary & Value Proposition (The "Why Now")

### The Existential Threat: "Harvest Now, Decrypt Later" (HNDL) & CNSA 2.0 Deadlines
Adversaries and nation-state actors are actively intercepting and storing encrypted enterprise traffic, backups, and intellectual property today with the certainty that **Cryptographically Relevant Quantum Computers (CRQCs)** will break classical asymmetric cryptography (**RSA-2048, RSA-3072, RSA-4096, ECDSA P-256, P-384, Ed25519, and X25519**) via **Shor's Algorithm**.

Enterprise CISOs, CIOs, and Cloud Architects face three immediate pressures:
1. **Mosca's Theorem ($X + Y > Z$):** If **Data Shelf-Life ($X$)** + **Migration Engineering Time ($Y$)** exceeds the **Time to Quantum Threat ($Z$)**, the organization's most sensitive data is **already compromised today** via Harvest Now, Decrypt Later (HNDL).
2. **Regulatory & Compliance Mandates:**
   - **NIST FIPS 203 (`ML-KEM`), FIPS 204 (`ML-DSA`), and FIPS 205 (`SLH-DSA`)** are finalized and active.
   - **NSA CNSA 2.0** mandates PQC transition milestones starting **2025–2030**.
   - **OMB M-23-02**, **PCI-DSS 4.0**, **DORA**, and **BACEN / Financial Regulators** require continuous cryptographic inventories (**CBOM — Cryptographic Bill of Materials**) and crypto-agility roadmaps.
3. **The Visibility & Compatibility Blind Spot:**
   - Security teams do not know **where** classical cryptography is hidden across hundreds of GCP projects (KMS keys, CMEK-attached databases/buckets, TLS 1.2/1.3 load balancers, SSL policies, mTLS certificates, KMS ImportJobs, and container signing keys).
   - Even when they find a vulnerable RSA/ECC key, they cannot simply rotate it to `ML-KEM` or `ML-DSA` without **breaking production applications**, because PQC keys have 20x–40x larger key/signature sizes (`ML-DSA-65` = 3,309-byte signatures) and use **KEM encapsulation (`Encapsulate`/`Decapsulate`)** instead of classical RSA `Encrypt`/`Decrypt`.

---

## 2. Our Solution: The Google Cloud PQC Readiness & Migration Agent

Built on **Gemini 3.1 (`gemini-3.1-pro-preview-customtools`)**, **Google Agent Development Kit (ADK)**, and **Vertex AI Agent Engine**, the **PQC Readiness & Migration Agent** is an autonomous, non-intrusive Cloud Security & Architecture Agent that transforms a multi-month manual cryptographic discovery engagement into a **7-second automated Organization-wide assessment, risk quantification, refactoring blueprint, and Google Cloud Security Architecture BOM**.

### Core Differentiators (Why Customers & Google Cloud Teams Love It)
- **100% Live & Non-Destructive (Zero Agent Installation):** Scans the entire Google Cloud Organization (`organizations/<ORG_ID>`) using native **Cloud KMS** and **Cloud Asset Inventory (CAI)** APIs in under **7 seconds** via high-concurrency parallel discovery (`ThreadPoolExecutor`).
- **End-to-End 4-Layer Cryptographic Visibility:**
  1. **Layer 1 — Data-at-Rest (Cloud KMS & CMEK):** Evaluates every key ring, crypto key, protection level (`SOFTWARE`, `HSM`, `EXTERNAL`), and rotation schedule against NIST FIPS 203/204/205 and Grover's / Shor's algorithms.
  2. **Layer 2 — Live Workload & Application Blast-Radius (4-Vector CAI Discovery):** Automatically maps every KMS key to the exact live workloads using it (BigQuery tables, GCS buckets, Compute disks, GKE clusters, Cloud SQL, Secret Manager, Pub/Sub, Spanner, Artifact Registry, Vertex AI).
  3. **Layer 3 — Data-in-Transit (TLS/SSL, Certificates & mTLS):** Inspects `Compute SslPolicy`, `Compute SslCertificate`, `Certificate Manager`, and Load Balancers to identify missing hybrid Post-Quantum key exchange (**`X25519MLKEM768`**, IETF TLS 1.3 draft) and vulnerable RSA/ECDSA leaf/CA certificates.
  4. **Layer 4 — BYOK / HYOK Supply Chain (`KMS ImportJobs`):** Detects external key material wrapped with classical `RSA_OAEP_3072_SHA1` / `RSA_OAEP_4096_SHA256` during key import into Cloud KMS.
- **Application Compatibility & Code Refactoring Engine:** Prevents production outages by generating side-by-side "Before vs. After" **Google Tink SDK**, **Cloud KMS API (`Decapsulate`)**, and **Envoy / Istio / Cloud Load Balancing `X25519MLKEM768`** refactoring blueprints.
- **Compliance-Ready OWASP CycloneDX v1.6 CBOM Exporter:** Generates machine-readable `application/vnd.cyclonedx+json` Cryptographic Bills of Materials (`cryptoProperties`) with NIST OIDs and PQC readiness ratings.
- **Programmatic Google Cloud Security Product Upsell & BOM Engine:** Automatically translates every technical cryptographic gap into a prescriptive **Google Cloud Security Architecture & Product Bill of Materials (BOM)** (`Cloud HSM`, `Google Tink SDK`, `VPC Service Controls + Private Service Connect`, `Global Load Balancing L7 + Certificate Authority Service`, and `Binary Authorization`).

---

## 3. Technical Architecture & Gemini 3.1 Innovation

### Powered by Google's Latest Agentic Stack
- **Brain / Model:** `gemini-3.1-pro-preview-customtools` deployed on the `global` Vertex AI endpoint with **`thinking_level: "MEDIUM"`** and extended context/output capacity (`1,048,576` config / `65,536` max output tokens) to synthesize massive multi-project cryptographic reports without truncation.
- **Orchestration & Runtime:**
  - **Google Agent Development Kit (ADK)** (`google-adk`) with custom Python tools (`tools/gcp_inventory.py`).
  - **Dual Deployment:**
    - **Cloud Run Web UI & SSE API:** `https://pqc-inventory-agent-110254026096.us-central1.run.app/dev-ui/?app=pqc_agent`
    - **Vertex AI Agent Engine (Reasoning Engine) for Gemini Enterprise:** `projects/110254026096/locations/us-central1/reasoningEngines/519268830350934016`
- **5 Specialized Agentic Tools:**
  1. `scan_gcp_crypto_inventory`: High-speed parallel KMS + Cloud Asset Inventory scanner across all active projects in a GCP Organization.
  2. `assess_pqc_readiness`: Evaluates assets against Shor's and Grover's algorithms, computes the **PQC Readiness Score (`0–100%`)**, and runs **Mosca's Theorem ($X + Y > Z$)** HNDL breach timeline math.
  3. `generate_pqc_migration_plan`: Produces prioritized migration runbooks (`gcloud kms keys create`, envelope encryption patterns, preventative GCP Organization Policies, and the **Google Cloud Security Architecture & Product BOM**).
  4. `export_cyclonedx_cbom`: Exports an official **OWASP CycloneDX v1.6 CBOM** JSON artifact for GRC and regulatory submission.
  5. `generate_application_pqc_refactoring_guide`: Generates copy-pasteable Python/Go/Java (`Google Tink` + `Cloud KMS`) and Envoy/GKE code refactoring templates.

---

## 4. The 7 Enterprise Capabilities in Detail

1. **4-Vector Live Application-to-Key Discovery (`_discover_live_workloads_via_cai`):**
   - Queries Cloud Asset Inventory across 4 vectors (CMEK `kmsKeyName`, full-text resource references, IAM `roles/cloudkms.cryptoKeyEncrypterDecrypter` service account bindings, and project-adjacent workloads) to eliminate "unknown consumer" blind spots before key rotation.
2. **Deep Data-in-Transit TLS 1.3 (`X25519MLKEM768`) & PKI Classification:**
   - Identifies whether `Compute SslPolicy` resources enforce `TLS_1_3` with `MODERN`/`RESTRICTED` profiles capable of **Hybrid Post-Quantum Key Exchange (`X25519MLKEM768`)**, and flags classical RSA/ECDSA X.509 certificates.
3. **Mosca's Theorem ($X + Y > Z$) Risk Quantification Engine:**
   - Calculates whether `shelf_life_years (X) + migration_time_years (Y) > crqc_horizon_years (Z, default 2030)` for every asset class (e.g., 10-year financial/healthcare retention + 2-year migration = 12 years > 4 years remaining $\rightarrow$ **ACTIVE HNDL BREACH WINDOW**).
4. **OWASP CycloneDX v1.6 CBOM Exporter (`export_cyclonedx_cbom`):**
   - Produces standardized `crypto-asset` components with `algorithmProperties`, `oid`, `nistQuantumSecurityLevel` (`0` to `5`), and `cryptoRef` dependencies.
5. **Interactive Application Code & Gateway Refactoring Generator:**
   - Solves the API paradigm shift (`AsymmetricDecrypt` $\rightarrow$ `Decapsulate` + `Google Tink` AEAD envelope encryption; `ECDSA` 64-byte signature $\rightarrow$ `ML-DSA-65` 3,309-byte signature).
6. **Preventive Governance & GCP Organization Policy Guardrails:**
   - Generates ready-to-apply `gcloud org-policies set-policy` YAML manifests (`constraints/cloudkms.allowedProtectionLevels`, `constraints/gcp.restrictTLSVersion`, `constraints/compute.ManagedSslCertificateDomains`, and custom KMS algorithm constraints) to stop teams from creating new legacy RSA/ECC keys.
7. **High-Concurrency Parallel Scanner (`ThreadPoolExecutor`):**
   - Scans 8+ projects and 50+ cryptographic assets across an entire GCP Organization in **~6.7 seconds** (down from ~18.5 seconds sequential).

---

## 5. Commercial Impact: Programmatic Google Cloud Security Product Upsell Engine

Every executive report generated by the PQC Agent includes a mandatory **Section 8: Recommended Google Cloud Security Architecture & Product BOM**, turning every PQC readiness assessment into an actionable Google Cloud security architecture expansion:

| Identified Cryptographic / Architectural Gap | Recommended Google Cloud Product(s) | Business & Technical Value |
| :--- | :--- | :--- |
| **1. Vulnerable Asymmetric Keys (`RSA-*`, `EC_SIGN_*`)** | **Cloud HSM** (FIPS 140-3 Level 3) & **Cloud KMS Software PQC** (`ML-KEM`, `KEM_XWING`, `ML-DSA`) | Hardware-protected FIPS 140-3 Level 3 root of trust for AES-256 KEKs + NIST-standardized PQC keys (`KEM_XWING`, `ML-DSA-65`) in Cloud KMS. |
| **2. Application Breaking Changes (`KEM` vs. `Encrypt`, Payload Bloat)** | **Google Tink SDK** (Cryptographic Agility & Envelope Encryption) | Abstracts cryptographic primitives so developers don't call raw `Decapsulate()` directly; solves the 64KB KMS payload limit via local AES-256-GCM DEKs wrapped by KMS KEKs. |
| **3. Harvest Now, Decrypt Later (HNDL) Exposure on High-Shelf-Life Data** | **VPC Service Controls (VPC-SC)** & **Private Service Connect (PSC)** | Establishes zero-trust data exfiltration perimeters and private backbone connectivity to block bulk ciphertext interception while PQC migration is underway. |
| **4. Vulnerable TLS/SSL Policies (`TLS_1_0`–`TLS_1_2`) & Classical X.509 PKI** | **Google Cloud Global Load Balancing (L7)** & **Certificate Authority Service (CAS)** | Immediate edge termination of Hybrid PQC TLS 1.3 (`X25519MLKEM768`) + automated short-lived mTLS and internal PKI lifecycle management via CAS. |
| **5. Classical Code & Container Signing (`RSA_SIGN_*`, `EC_SIGN_*`)** | **Binary Authorization** + **Cloud KMS `PQ_SIGN_ML_DSA_65`** | Enforces quantum-resistant software supply chain attestations at GKE and Cloud Run admission control, preventing forged container deployments. |

---

## 6. Proven Live Results (Argolis Organization `31564119954` Benchmark)

In live production testing across Organization `jsaccomani.altostrat.com` (`31564119954`):
- **Execution Time:** `6.71 seconds` across 8 active projects (`pqc-inventory-agent-cd06`, `cymbal-banking-pqc`, `cymbal-health-records`, `gcp-Zero-trust-demo`, `my-logging-project-404114`, etc.).
- **Assets Discovered:** **52 cryptographic assets** across all 4 layers:
  - **20 Cloud KMS Keys** (including vulnerable `RSA-2048/3072/4096` and `ECDSA P-256/P-384`, quantum-safe `AES-256` CMEKs, and already-migrated `KEM_XWING` and `PQ_SIGN_ML_DSA_65` keys).
  - **28 Data-in-Transit TLS/SSL & Certificate Assets** (Load Balancers, `SslPolicy`, `SslCertificate`, `Certificate Manager`).
  - **4 KMS ImportJobs** (BYOK/HYOK supply chain wrapping jobs).
  - **22 Live Applications/Workloads Mapped** via 4-Vector Cloud Asset Inventory discovery.
- **PQC Readiness Score:** **`38.5%` (`MODERATE - Hybrid / Partial Readiness`)** with concrete phased remediation to reach **100% Quantum Readiness**.

---

## 7. Suggested 12-Slide Executive Deck Structure (for NotebookLM / Google Slides)

- **Slide 1 — Title Slide:** *Securing the Post-Quantum Future on Google Cloud: Autonomous PQC Readiness, Migration & Architecture Agent (Powered by Gemini 3.1 & ADK)*.
- **Slide 2 — The Executive Problem:** *Harvest Now, Decrypt Later (HNDL) & Mosca's Theorem ($X + Y > Z$) — Why 2030 is Already Too Late for 10-Year Data*.
- **Slide 3 — The Enterprise Blind Spot:** *Why CISOs Can't Just "Flip a Switch" to Post-Quantum Cryptography (Discovery Gaps + Application Breaking Changes)*.
- **Slide 4 — Introducing the PQC Readiness Agent:** *From Months of Manual Spreadsheets to a 7-Second Autonomous Organization-Wide Assessment*.
- **Slide 5 — 4-Layer Cryptographic Discovery Engine:** *Data-at-Rest (KMS/CMEK), Live Workload Blast-Radius (4-Vector CAI), Data-in-Transit (`X25519MLKEM768` TLS 1.3), and BYOK Supply Chain (`ImportJobs`)*.
- **Slide 6 — Powered by Gemini 3.1 & Google ADK:** *Why `gemini-3.1-pro-preview-customtools` (`MEDIUM` thinking, global endpoint, 5 deterministic tools) Changes the Game*.
- **Slide 7 — Preventing Production Outages:** *Automated Code & Gateway Refactoring (`Google Tink SDK`, Envelope Encryption, `Decapsulate`, and `ML-DSA-65` Signature Sizing)*.
- **Slide 8 — Continuous Governance & Compliance:** *One-Click OWASP CycloneDX v1.6 CBOM Export & Preventive GCP Organization Policies*.
- **Slide 9 — Strategic Architecture & Google Cloud Product BOM:** *Turning Cryptographic Gaps into Cloud Security Modernization (`Cloud HSM`, `Tink`, `VPC-SC`, `Global L7 LB + CAS`, `Binary Authorization`)*.
- **Slide 10 — Live Benchmark Proof (Demo Results):** *52 Assets & 22 Workloads Mapped in 6.71 Seconds Across 8 GCP Projects*.
- **Slide 11 — 3-Phase Customer Engagement Roadmap:** *Phase 1: 7-Second Discovery & CBOM $\rightarrow$ Phase 2: Hybrid PQC (`X-Wing` & `X25519MLKEM768`) + VPC-SC $\rightarrow$ Phase 3: Full NIST FIPS 203/204 Enforcement*.
- **Slide 12 — Call to Action & Live Demo:** *Run the Agent Today via Cloud Run Web UI or Gemini Enterprise (Vertex AI Agent Engine)*.

---

## 8. Etapa 1 — Motor de Inteligência & Criptoanálise Quântica (`run_quantum_cryptanalysis_simulation`)

O agente conta agora com o motor determinístico [`tools/quantum_engine.py`](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/pqc_inventory_agent/tools/quantum_engine.py) (`run_quantum_cryptanalysis_simulation`), fundamentado na literatura científica de computação quântica tolerante a falhas (*Google Quantum AI Surface Code / Willow*, *Gidney & Ekerå 2021*, *Roetteler et al. 2017* e *Albrecht Lattice Estimator*):

1. **Estimativa Física e Lógica de Circuitos Quânticos por Ativo:**
   - **`ECDSA P-256` / `Ed25519`:** `2.330` Qubits Lógicos | $1,26 \times 10^{11}$ portas Toffoli | Distância de Código de Superfície $d = 27$ | **~13,4 milhões de Qubits Físicos Supercondutores** (`9,5 horas` de execução).
   - **`ECDSA P-384`:** `3.484` Qubits Lógicos | $4,19 \times 10^{11}$ portas Toffoli | $d = 29$ | **~18,2 milhões de Qubits Físicos** (`26,0 horas`).
   - **`RSA-2048`:** `4.098` Qubits Lógicos | $2,70 \times 10^9$ portas Toffoli | $d = 27$ | **~20,0 milhões de Qubits Físicos** (`8,0 horas`).
   - **`RSA-3072` / `RSA-4096`:** `6.146` a `8.194` Qubits Lógicos | **34,5M a 52,0M Qubits Físicos**.
   - **Descoberta Contra-Intuitiva para o CISO (Ordem de Queda Quântica):** As chaves **`ECDSA P-256` e `P-384` exigem até 43% menos Qubits Lógicos do que `RSA-2048`** sob o algoritmo de Shor para logaritmo discreto em curvas elípticas, sendo **quebradas PRIMEIRO** pelos primeiros processadores quânticos tolerantes a falhas (FTQC).
2. **Prova de Dureza Exponencial Core-SVP em Reticulados (NIST FIPS 203 / 204):**
   - `KEM_XWING` / `ML-KEM-768` (`Module-LWE dim=768, q=3329`): **167 bits de segurança quântica Core-SVP** ($> 2^{167}$ operações de crivo quântico BKZ — termodinamicamente impossível).
   - `PQ_SIGN_ML_DSA_65` (`Module-LWE/SIS dim=1536`): **174 bits de segurança quântica Core-SVP** ($> 2^{174}$ operações).
   - `ML-KEM-1024` / `ML-DSA-87` (CNSA 2.0): **226 a 232 bits de segurança quântica Core-SVP**.
3. **Simulação Estocástica de Monte Carlo (10.000 Cenários, 2026–2035) & `Q-VaR 95%`:**
   - Modela a curva de probabilidade anual de quebra (`2026–2035`) e calcula o **Quantum Value-at-Risk (`Q-VaR 95%`)** financeiro antes e após a adoção do **Google Cloud Product BOM** (redução de **98,5%** da exposição financeira).

### Prompt Pronto para o Gemini Enterprise (Relatório 6 — Inteligência & Física Quântica)
> *"Atue como Principal Quantum Security Scientist do Google Cloud. Execute a ferramenta `run_quantum_cryptanalysis_simulation` na organização `organizations/31564119954` e gere o **Relatório 6: Inteligência & Criptoanálise Quântica Preditiva (Qubits Lógicos/Físicos, Core-SVP & Monte Carlo Q-VaR)**. Apresente: (1) A prova matemática (Gidney-Ekerå vs. Roetteler) de por que as chaves ECDSA P-256 e P-384 da organização cairão ANTES das chaves RSA-2048; (2) A tabela de Estimativa de Recursos de Circuitos Quânticos (Qubits Lógicos, Portas Toffoli, Distância de Código de Superfície d, Qubits Físicos Supercondutores e Horas de Decriptação) para as chaves vulneráveis; (3) A prova de imunidade Core-SVP para KEM_XWING e ML-DSA-65; e (4) A curva de Monte Carlo (10.000 iterações, 2026-2035) com o Quantum Value-at-Risk (Q-VaR 95%) antes e depois do Google Cloud Product BOM."*

---

## 9. Etapa 2 — Guia Consultivo Passo a Passo, Validação Determinística & Exportação Executiva/Técnica (`export_pqc_assessment_reports`)

O agente opera com **validação determinística de escopo e métricas** e geração automatizada de **entregáveis separados para a Diretoria (Executivo) e para a Engenharia (Técnico)**:

1. **Redirecionamento Automático de Tenant Runtime & Selo de Autenticidade (`data_validation_manifest`):**
   - Intercepta automaticamente IDs efêmeros de execução do Vertex AI Agent Engine (`project-cb232322-...`, `*-tp`) e redireciona para a Organização real do cliente (`organizations/31564119954` — `jsaccomani.altostrat.com`), garantindo leitura de telemetria real (`LIVE_GCP_TELEMETRY_VERIFIED`) e bloqueando cálculos manuais incorretos no LLM via `validated_executive_scorecard`.
2. **Guia Consultivo de Execução Passo a Passo no Ambiente do Cliente:**
   - **5 Workstreams Operacionais por Camada** (`customer_environment_execution_guide`): Governança Preventiva (Dia 0–15) $\rightarrow$ Rede TLS 1.3 `X25519MLKEM768` & Buffers HTTP `32KB` (Dia 15–30) $\rightarrow$ Migração HNDL `KEM_XWING` + `HPKE` (Dia 30–60) $\rightarrow$ Migração de Assinaturas `PQ_SIGN_ML_DSA_65` (Dia 45–75) $\rightarrow$ Modernização BYOK & Descomissionamento Seguro (Dia 75–90).
   - **Runbooks de 5 Passos por Chave (`consultative_execution_guide`)**: Avaliação do estado atual, impacto arquitetural, pré-requisitos de banco/gateway, criação em Cloud HSM (`--protection-level=hsm`), binding IAM (`gcloud kms keys add-iam-policy-binding`), refatoração de código em modo *dual-read/dual-verify* e comando de validação pós-mudança.
3. **Pacote de Exportação em 4 Entregáveis (`export_pqc_assessment_reports` & `python main.py export`):**
   - **`01_PQC_Executive_Board_Report` (`.md` e `.html` pronto para PDF)**: Exclusivo para CISO, CIO, CFO e Board.
   - **`02_PQC_Technical_Engineering_Playbook` (`.md` e `.html` pronto para PDF)**: Guia mão na massa para Arquitetos, SRE, DevSecOps e Desenvolvedores.
   - **`03_PQC_CycloneDX_v1.6_CBOM.json`**: Inventário oficial OWASP CycloneDX v1.6.
   - **`04_PQC_Consolidated_Full_Assessment` (`.md` e `.html` pronto para PDF)**: Relatório Master unificado, com upload automático para o **Cloud Storage (`gs://...`)**.

### Prompt Pronto para o Gemini Enterprise (Exportação Executiva + Técnica)
> *"Execute a ferramenta `export_pqc_assessment_reports` para a organização `organizations/31564119954`. Exporte o pacote completo separando o **Relatório Executivo para o Board/CISO** e o **Playbook Técnico Passo a Passo de Engenharia**, faça o upload para o Cloud Storage e me apresente os links de download junto com o resumo executivo e técnico validado."*


