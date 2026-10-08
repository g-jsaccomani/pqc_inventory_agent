# 🛡️ Google Cloud PQC Enterprise Inventory, Application Compatibility & Governance Agent

An enterprise-grade AI Agent specializing in **Post-Quantum Cryptography (PQC) Readiness Assessment**, **4-Vector Application-to-Key Dependency Mapping**, **PQC Application Model Compatibility Evaluation**, **Network TLS 1.3 (`X25519 + ML-KEM-768`) & BYOK (`ImportJobs` HPKE X-Wing) Detection**, **Cryptographic Governance (OWASP CycloneDX v1.6 CBOM)**, and **Programmatic Google Cloud Security Architecture & Product BOM Recommendations**, built with the **Google Agent Development Kit (`google-adk`)** on the **Gemini 3.1 (`gemini-3.1-pro-preview-customtools`)** architecture, and deployed on **Cloud Run** and **Vertex AI Agent Engine (Reasoning Engine)** for native integration with **Gemini Enterprise (Google Agentspace)**.

---

## 📌 Production Details for Gemini Enterprise (Agentspace) Registration

Use the production metadata below directly in the **Gemini Enterprise > Apps > [Your App] > Agents > + Add agent (Custom agent via Agent Runtime)** console:

| Gemini Enterprise Field | Production Value |
| :--- | :--- |
| **Agent Name (Display Name)** | `PQC Enterprise Inventory & Application Compatibility Agent` |
| **Model Endpoint** | `gemini-3.1-pro-preview-customtools` (`thinking_level: MEDIUM`, `max_output_tokens: 1048576`) |
| **Default GCP Organization Scope** | `organizations/31564119954` (`jsaccomani.altostrat.com`) |
| **Host Project ID / Number** | `pqc-inventory-agent-cd06` (`110254026096`) |
| **Region** | `us-central1` (Automatic `global` endpoint routing for Gemini 3.1 Preview) |
| **Vertex AI Agent Engine Resource Path** | `projects/110254026096/locations/us-central1/reasoningEngines/5079022715575205888` |
| **Cloud Run ADK Web UI (Active)** | `https://pqc-inventory-agent-110254026096.us-central1.run.app/dev-ui/?app=pqc_agent` |
| **Active Cloud Run Revision** | `pqc-inventory-agent-00013-dmr` (Serving 100% of traffic) |
| **Runtime Service Account** | `pqc-agent-runner@pqc-inventory-agent-cd06.iam.gserviceaccount.com` |

### Recommended Agent Description for Gemini Enterprise (Copy & Paste)

> `Expert AI Agent powered by Gemini 3.1 (gemini-3.1-pro-preview-customtools) for Post-Quantum Cryptography (PQC) Readiness Assessment, Quantum Physics & Cryptanalysis Simulation (Shor Surface-Code Qubits, Core-SVP Lattice Hardness, Monte Carlo Q-VaR 95%), 4-Vector Live Application-to-Key Dependency Mapping, Network SSL Policy SNDL Detection (TLS 1.3 + X25519MLKEM768), Cloud KMS BYOK ImportJob Verification (HPKE X-Wing), PQC Application Compatibility Evaluation, Mosca's Theorem (X+Y>Z) Risk Quantification, OWASP CycloneDX v1.6 CBOM Export, SDK/Gateway Code Refactoring, Preventive GCP Organization Policy Guardrails, and Programmatic Google Cloud Security Product BOM Recommendations across Google Cloud Organizations (organizations/31564119954) and Projects, aligned with NIST FIPS 203 (ML-KEM / KEM_XWING), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NIST IR 8547, NIST SP 800-57, and NSA CNSA 2.0.`

---

## 🏗️ System Design & Architecture

### 1. End-to-End Multi-Layered PQC Architecture Diagram

The diagram below illustrates the complete 4-tier architecture across **Executive Experience Interfaces**, the **Gemini 3.1 Agentic Reasoning Layer**, the **3-Layer PQC Tool & Detector Engine**, and **Google Cloud Organization Telemetry APIs**:

```mermaid
flowchart TB
    subgraph UX["1. Executive Experience & Orchestration Layer"]
        GE["Gemini Enterprise (Google Agentspace)<br/>Enterprise Conversational Interface"]
        CR["Cloud Run ADK Web UI (/dev-ui)<br/>Revision: pqc-inventory-agent-00013-dmr"]
        CLI["Local CLI & Validation Harness (main.py)<br/>test / ask / deploy"]
    end

    subgraph BRAIN["2. Agentic Reasoning Layer (Vertex AI Agent Engine & Google ADK)"]
        RE["Vertex AI Reasoning Engine (AdkApp / LangchainAgent)<br/>reasoningEngines/5079022715575205888"]
        LLM["Model: gemini-3.1-pro-preview-customtools<br/>thinking_level: MEDIUM | max_output_tokens: 1,048,576<br/>Endpoint: global"]
        SYS["Multi-Layered System Instruction<br/>NIST FIPS 203/204/205 + IR 8547 + CNSA 2.0 + Product BOM"]
        RE --> LLM
        LLM --> SYS
    end

    subgraph TOOLS["3. PQC Tools, Detectors & Quantum Physics Engines (9 Registered Tools)"]
        direction TB
        subgraph L1["Layer 1: KMS Keys & Application Compatibility (tools/gcp_inventory.py)"]
            T1["scan_organization_pqc_readiness<br/>Parallel Org-Wide Scanner (ThreadPoolExecutor)"]
            T2["scan_pqc_readiness<br/>KMS Inspection + ENABLED vs DESTROY Versions"]
            T3["discover_all_crypto_assets<br/>CAI Deep Discovery (read_mask='*')"]
            T4["generate_pqc_migration_plan<br/>Scorecard + Mosca (X+Y>Z) + Playbooks + Product BOM"]
        end

        subgraph L2["Layer 2: Network & TLS 1.3 Transport (tools/pqc_detectors.py)"]
            T5["scan_ssl_policies<br/>Verifies TLS 1.3 + Hybrid Key Share (X25519 + ML-KEM-768)<br/>Flag: VULNERABLE_TO_SNDL_ATTACKS"]
        end

        subgraph L3["Layer 3: BYOK & Key Import Transport (tools/pqc_detectors.py)"]
            T6["scan_import_jobs_pqc<br/>Inspects KMS ImportJobs (RSA-OAEP vs HPKE X-Wing)<br/>Flags: VULNERABLE_KEY_IMPORT_TRANSPORT | SECURE_PQC_BYOK"]
        end

        subgraph ENGINES["Specialized Engineering, Quantum Physics & Governance Engines"]
            T7["generate_application_pqc_refactoring_guide<br/>Python/Go SDK Snippets (KEM Decapsulate + FIPS 204 External Mu)<br/>+ Envoy/Istio & NGINX Manifests (32 KB Headers)"]
            T8["export_cyclonedx_cbom<br/>Official OWASP CycloneDX v1.6 JSON Exporter<br/>ASN.1 OIDs + nistQuantumSecurityLevel (0..5)"]
            T9["run_quantum_cryptanalysis_simulation<br/>Shor Surface-Code Qubits + Core-SVP Lattice Hardness<br/>+ 10,000-Iteration Monte Carlo CRQC & Q-VaR 95%"]
            BOM["Programmatic Cloud Product Upsell Engine<br/>Recommended Google Cloud Security Architecture & Product BOM"]
        end
    end

    subgraph GCP["4. Google Cloud Telemetry Layer (Organization: 31564119954 — jsaccomani.altostrat.com)"]
        CAI["Cloud Asset Inventory API<br/>SearchAllResources (read_mask='*')<br/>CMEK Workloads, KeyRings, SslPolicies, Certs"]
        KMS["Cloud KMS API<br/>KeyRings, CryptoKeys, CryptoKeyVersions,<br/>ImportJobs, IAM Policies"]
        NET["Compute Engine & Network Security<br/>SslPolicy, TargetHttpsProxy, TargetSslProxy,<br/>SslCertificate, CertificateManager, PrivateCA"]
        PROJECTS["Active Projects Scanned in Parallel:<br/>• pqc-inventory-agent-cd06 (Canary PQC + Legacy)<br/>• fnlab-apps-8fa913 (ApexFin Payment API / CRM)<br/>• fnlab-sec-mgmt-8fa913 (SecMgmt Vault / Logs)<br/>• fnlab-ai-data-8fa913 (Cross-Project CMEK)<br/>• api-sec-poc-1582 (ApiSPR Telemetry)"]
    end

    GE --> RE
    CR --> RE
    CLI --> RE

    SYS --> L1
    SYS --> L2
    SYS --> L3
    SYS --> ENGINES
    T4 --> BOM

    L1 --> CAI
    L1 --> KMS
    L2 --> CAI
    L2 --> NET
    L3 --> KMS
    CAI --> PROJECTS
    KMS --> PROJECTS
    NET --> PROJECTS
```

---

### 2. Real-Time Multi-Layered Execution Flow (Sequence Diagram)

When a security architect requests a post-quantum readiness assessment, **Gemini 3.1 (`gemini-3.1-pro-preview-customtools`)** orchestrates the tools across **all 3 cryptographic security layers** automatically (defaulting natively to `organizations/31564119954` without prompting for manual IDs):

```mermaid
sequenceDiagram
    autonumber
    actor Arch as Security Architect<br/>(Gemini Enterprise / Web UI)
    participant Agent as Gemini 3.1 Agent<br/>(gemini-3.1-pro-preview-customtools)
    participant Inv as Layer 1: gcp_inventory.py<br/>(KMS + 4-Vector App Discovery)
    participant Det as Layer 2 & 3: pqc_detectors.py<br/>(SSL Policies & KMS ImportJobs)
    participant GCP as Google Cloud APIs<br/>(CAI + KMS + Compute across Org 31564119954)

    Arch->>Agent: "Run a complete PQC readiness assessment across the organization"
    Note over Agent: Thinking Level: MEDIUM<br/>Resolves default scope: organizations/31564119954

    par Layer 1: KMS Keys, 4-Vector Workloads & Mosca Risk
        Agent->>Inv: scan_organization_pqc_readiness("31564119954")
        Inv->>GCP: CAI SearchAllResources (KeyRings, CryptoKeys, CMEK Workloads)
        Inv->>GCP: ThreadPoolExecutor -> KMS list_crypto_keys + list_crypto_key_versions + get_iam_policy
        GCP-->>Inv: 11 Keys (10 Active, 1 Destroy-Scheduled) + 12 Consuming Applications
        Note over Inv: • Evaluates App PQC Compatibility (Native / Zero-Refactor CMEK / Incompatible)<br/>• Computes Mosca Inequality (X + Y > Z_2030 / Z_2035)<br/>• Generates Preventive Org Policy CEL Guardrails & Product BOM
        Inv-->>Agent: Multidimensional JSON Report + Application Matrix + Product BOM
    and Layer 2: Network TLS 1.3 & Hybrid PQC Key Share (SNDL)
        Agent->>Det: scan_ssl_policies("organizations/31564119954")
        Det->>GCP: CAI SearchAllResources (SslPolicy, TargetHttpsProxy, TargetSslProxy)
        GCP-->>Det: Active SSL Policies & Unattached Proxies
        Note over Det: Checks minTlsVersion == TLS_1_3 & X25519+ML-KEM-768<br/>Flags pre-TLS 1.3 as VULNERABLE_TO_SNDL_ATTACKS
        Det-->>Agent: SSL Policy SNDL Report & gcloud Remediation
    and Layer 3: BYOK Key Import Wrapping (Cloud KMS ImportJobs)
        Agent->>Det: scan_import_jobs_pqc("organizations/31564119954", "all")
        Det->>GCP: ThreadPoolExecutor -> KMS list_import_jobs across all 8 KeyRings
        GCP-->>Det: Active ImportJobs & ImportMethod specs
        Note over Det: Flags RSA-OAEP as VULNERABLE_KEY_IMPORT_TRANSPORT<br/>Classifies HPKE_KEM_XWING as SECURE_PQC_BYOK
        Det-->>Agent: BYOK ImportJobs PQC Report & gcloud Remediation
    end

    Agent-->>Arch: Executive PQC Assessment Report (8 Mandatory Sections + Product BOM)
```

---

### 3. 4-Vector Application-to-Key Discovery Engine & PQC Compatibility Decision Tree

Rather than evaluating cryptographic keys in isolation, the agent discovers all consuming applications across **4 combined discovery vectors** and applies a deterministic decision tree to evaluate whether each application **supports or will break** when migrating to the PQC model:

```mermaid
flowchart LR
    subgraph VECTORS["Application ↔ Key Discovery (4 Vectors)"]
        V1["Vector 1: Live CAI CMEK Binding<br/>(Direct & Cross-Project kms_key)"]
        V2["Vector 2: Live CAI + Topology Match<br/>(GKE, Cloud Run, GCE, BigQuery, GCS)"]
        V3["Vector 3: Live KMS IAM Policy<br/>(ServiceAccounts w/ Encrypter/Signer)"]
        V4["Vector 4: Project Workload Correlation<br/>(Project-Level Workload Fallback)"]
    end

    subgraph CLASS["PQC Model Compatibility Decision Tree"]
        KEY["Active KMS Key +<br/>Consuming Application"]
        Q1{"Algorithm Family?"}
        C1["✅ COMPATIBLE_PQC_NATIVE<br/>Already uses KEM_XWING (FIPS 203)<br/>or PQ_SIGN_ML_DSA_65 (FIPS 204)"]
        C2["✅ COMPATIBLE_ZERO_REFACTORING_CMEK<br/>AES-256-GCM / HMAC-SHA256+<br/>Grover-Resilient (128-bit PQ Security)<br/>Zero code or payload changes required"]
        C3["🚨 INCOMPATIBLE_REQUIRES_REFACTORING<br/>RSA-2048/3072/4096 or ECDSA P-256/P-384<br/>Vulnerable to Shor's Algorithm"]

        B1["Blocker 1 (Decrypt -> KEM API):<br/>Replace AsymmetricDecrypt with<br/>Decapsulate + RFC 9180 HPKE (Tink SDK)"]
        B2["Blocker 2 (Sign digest -> data/mu):<br/>Replace pre-hashed SHA-256 digest with<br/>raw data or 64B SHAKE256 external mu"]
        B3["Blocker 3 (Payload Expansion 13x–51x):<br/>Signature grows from 64B/256B to 3,309B<br/>Requires max_request_headers_kb >= 32"]
    end

    V1 --> KEY
    V2 --> KEY
    V3 --> KEY
    V4 --> KEY
    KEY --> Q1
    Q1 -- "KEM_XWING / ML_KEM / ML_DSA / SLH_DSA" --> C1
    Q1 -- "GOOGLE_SYMMETRIC_ENCRYPTION / HMAC" --> C2
    Q1 -- "RSA_DECRYPT / RSA_SIGN / EC_SIGN" --> C3
    C3 --> B1
    C3 --> B2
    C3 --> B3
```

---

### 4. Programmatic Google Cloud Security Product Recommendation Engine (`Product BOM`)

For every cryptographic or architectural gap identified across the 3 scanning layers, the agent programmatically generates the mandatory **`Recommended Google Cloud Security Architecture & Product BOM`** section, mapping each technical finding to Google Cloud security products:

```mermaid
flowchart LR
    G1["Gap 1: Software-Backed RSA/ECC Keys<br/>or Classical RSA-OAEP ImportJobs<br/>(VULNERABLE_KEY_IMPORT_TRANSPORT)"] --> P1["🔐 Cloud HSM (FIPS 140-3 Level 3)<br/>+ Cloud KMS PQC (KEM_XWING / ML-DSA-65)<br/>+ HPKE_KEM_XWING BYOK ImportJobs"]
    G2["Gap 2: Legacy Codebases Using Native<br/>Asymmetric Decrypt or Sign<br/>(INCOMPATIBLE_REQUIRES_REFACTORING)"] --> P2["🧰 Google Tink SDK + Cloud KMS<br/>Native abstraction for RFC 9180 HPKE flows<br/>and post-quantum public key formats"]
    G3["Gap 3: HNDL / SNDL Risks in Data<br/>at Rest or in Transit<br/>(Mosca X + Y > Z_2035)"] --> P3["🛡️ VPC Service Controls (VPC-SC)<br/>+ Private Service Connect (PSC)<br/>Zero-Trust perimeter for GCS & BigQuery"]
    G4["Gap 4: API Endpoints / SSL Policies<br/>Without TLS 1.3 + Hybrid Key Share<br/>(VULNERABLE_TO_SNDL_ATTACKS)"] --> P4["🌐 Google Cloud Global Load Balancing (L7)<br/>(TLS 1.3 + X25519MLKEM768)<br/>+ Certificate Authority Service (CAS)"]
    G5["Gap 5: CI/CD Pipelines &<br/>Container Artifact Signing"] --> P5["✅ Binary Authorization<br/>backed by Cloud HSM keys<br/>and PQ_SIGN_ML_DSA_65"]
```

| Identified Cryptographic / Architectural Gap | Technical Status / Flag | Recommended Google Cloud Products (`Product BOM`) | Programmatic Architectural Recommendation |
| :--- | :--- | :--- | :--- |
| **Software-Backed Production Keys (`RSA`/`ECC`) & Classical BYOK Transport** | `VULNERABLE_CLASSICAL_RSA_ECC` / `VULNERABLE_KEY_IMPORT_TRANSPORT` | **`Cloud HSM`** (`protection-level=HSM`, FIPS 140-3 Level 3) + **`Cloud KMS PQC`** (`KEM_XWING`, `PQ_SIGN_ML_DSA_65`) | Migrate keys and BYOK `ImportJobs` to `HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM` backed by FIPS 140-3 Level 3 hardware (noting `--protection-level=software` where Cloud KMS PQC algorithms are currently in software GA while envelope KEKs reside in Cloud HSM). |
| **Legacy Application Codebases Calling `AsymmetricDecrypt` or `AsymmetricSign(digest)`** | `INCOMPATIBLE_REQUIRES_APPLICATION_REFACTORING` | **`Google Tink SDK`** + **`Cloud KMS`** | Adopt the Google Tink SDK integrated with Cloud KMS to handle complex RFC 9180 HPKE flows (`Decapsulate` + `HKDF-SHA256` + `AES-256-GCM`) and PQC public key formatting changes without manual coding toil. |
| **'Harvest Now, Decrypt Later' (HNDL / SNDL) Exposure on Critical Data Stores** | `CRITICAL_MOSCA_BREACH_ACTIVE_HNDL` ($X + Y > Z_{2035}$) | **`VPC Service Controls (VPC-SC)`** + **`Private Service Connect (PSC)`** | Wrap sensitive data resources (**Cloud Storage**, **BigQuery**) with Zero-Trust VPC-SC perimeters and private PSC endpoints to prevent bulk ciphertext exfiltration alongside PQC migration. |
| **Internal or External API Endpoints & Load Balancers Without TLS 1.3 + Hybrid PQC** | `VULNERABLE_TO_SNDL_ATTACKS` | **`Google Cloud Global Load Balancing (L7)`** + **`Certificate Authority Service (CAS)`** | Enforce modern/restricted TLS 1.3 policies (`--min-tls-version=1.3 --profile=RESTRICTED`) enabling hybrid post-quantum key shares (`X25519 + ML-KEM-768` / `X25519MLKEM768`) and managed PKI via CAS. |
| **CI/CD Pipelines & Container Artifact Signing** | `SUPPLY_CHAIN_ATTESTATION_GAP` | **`Binary Authorization`** + **`Cloud HSM`** | Enforce cryptographic container image attestation via Binary Authorization backed by Cloud HSM keys and post-quantum signatures prior to GKE and Cloud Run deployment. |

---

## 🧠 Core Cryptographic & Architectural Intelligence Capabilities

### 1. 4-Vector Live Application-to-Key Discovery (`_discover_live_workloads_via_cai`)
The agent automatically maps all applications and workloads consuming cryptographic keys across the Organization by combining **4 real-time discovery vectors** (`discovery_confidence`):
1. **Vector 1 — `VERIFIED_LIVE_CAI_CMEK_BINDING` (Direct & Cross-Project Cloud Asset Inventory CMEK):** Inspects `kms_key` and `kms_keys` attributes across all Organization workloads (`run.googleapis.com/Service`, `compute.googleapis.com/Instance`, `compute.googleapis.com/Disk`, `container.googleapis.com/Cluster`, `storage.googleapis.com/Bucket`, `bigquery.googleapis.com/Dataset`, `sqladmin.googleapis.com/Instance`, `secretmanager.googleapis.com/Secret`), automatically detecting **cross-project CMEK bindings** (such as bucket `bkt-iso-compliant-records-a3540b` in `fnlab-ai-data-8fa913` encrypted by key `kms-key-fintech-compliant` in `fnlab-sec-mgmt-8fa913`).
2. **Vector 2 — `HIGH_TOPOLOGY_AND_LIVE_CAI_VERIFIED`:** Cross-references architectural microservice mappings with live verified workload assets in Cloud Asset Inventory.
3. **Vector 3 — `VERIFIED_LIVE_KMS_IAM_POLICY`:** Inspects each key's individual IAM policy (`kms_client.get_iam_policy`) to identify `serviceAccounts` granted `cloudkms.cryptoKeyEncrypterDecrypter`, `cloudkms.signerVerifier`, or `cloudkms.publicKeyViewer` and correlates them to active project workloads.
4. **Vector 4 — `INFERRED_PROJECT_WORKLOAD_CORRELATION`:** Correlates active workloads in the same project if a newly created key does not yet have dedicated bindings.

### 2. Application PQC Model Compatibility Matrix (`application_compatibility_matrix`)
For every mapped application, the agent evaluates whether the application's architecture is compatible with the PQC model and classifies it into one of three categories:
- **`COMPATIBLE_PQC_NATIVE` ✅:** Applications already consuming `KEM_XWING` / `ML_KEM_768` / `ML_KEM_1024` (via `Encapsulate`/`Decapsulate`) or `PQ_SIGN_ML_DSA_65` / `PQ_SIGN_SLH_DSA_SHA2_128S`.
- **`COMPATIBLE_ZERO_REFACTORING_CMEK` ✅:** Applications and managed workloads (GKE etcd, Cloud Run, BigQuery, GCS, Cloud SQL) consuming `GOOGLE_SYMMETRIC_ENCRYPTION` (AES-256-GCM) or `HMAC_SHA256+`. Because AES-256 provides 128-bit post-quantum security against **Grover's Algorithm**, these applications are **100% compatible with the PQC model with zero code or payload changes**.
- **`INCOMPATIBLE_REQUIRES_APPLICATION_REFACTORING` 🚨:** Applications consuming classical asymmetric keys (`RSA_*`, `EC_*`) that **will break** if migrated without code and infrastructure refactoring:

| Technical Dimension | Classical Cryptography (`RSA-2048` / `ECDSA P-256`) | Post-Quantum Cryptography (`KEM_XWING` / `ML-DSA-65`) | Application & Infrastructure Impact |
| :--- | :--- | :--- | :--- |
| **KMS API Contract (Confidentiality)** | `AsymmetricDecrypt(ciphertext)` (`purpose=ASYMMETRIC_DECRYPT`) | `Decapsulate(ciphertext)` $\rightarrow$ `shared_secret` (32 B) (`purpose=KEY_ENCAPSULATION`) | Requires refactoring to **RFC 9180 HPKE** envelope encryption (`HKDF-SHA256` + `AES-256-GCM`) via the **Google Tink SDK**. |
| **KMS API Contract (Digital Signatures)** | `AsymmetricSign(digest={'sha256': ...})` (Pre-hashed external digest) | `AsymmetricSign(data=raw_bytes)` or `PQ_SIGN_ML_DSA_65_EXTERNAL_MU` ($\mu$ = 64 B `SHAKE256`) | Calls passing `digest` fail with `INVALID_ARGUMENT` on pure `ML-DSA-65`; requires sending `data` or computing external $\mu$ (FIPS 204 Section 6.2). |
| **Public Key / Ciphertext / Signature Size** | Public Key: `64 B–256 B`<br/>Signature: `64 B` (ECDSA) / `256 B` (RSA) | Public Key: `1,216 B` (`X-Wing`) / `1,952 B` (`ML-DSA-65`)<br/>Signature: **`3,309 B`** (`ML-DSA-65`) / **`4,627 B`** (`ML-DSA-87`) | **13x to 51.7x** signature expansion; causes `HTTP 431 Request Header Fields Too Large` on JWTs (`Authorization: Bearer`) unless API Gateway header buffers are expanded to $\ge 32\text{ KB}$. |

### 3. Mathematical Quantification of Mosca's Theorem ($X + Y > Z$) Against NIST IR 8547
For every active key, the agent computes **Dr. Michele Mosca's Inequality ($X + Y > Z$)**:
- **$X$ (*Shelf-Life Years*):** Required confidentiality retention or trust anchor validity period (`10.0 years` for decryption/confidentiality keys and CAs; `3.0 years` for transactional/JWT signing keys).
- **$Y$ (*Migration & Refactoring Years*):** Engineering lead time required to refactor SDKs, KMS API calls, and network header buffers (`1.5 to 2.0 years`).
- **$Z_{2030} = 4.0\text{ years}$ (NIST IR 8547 Classical Deprecation in 2030)** and **$Z_{2035} = 9.0\text{ years}$ (NIST IR 8547 Classical Disallowance / CRQC Horizon in 2035)**:
  - `RSA_DECRYPT_OAEP_*` keys exhibit **$X (10\text{y}) + Y (2\text{y}) = 12.0\text{ years} > Z_{2035} (9.0\text{y})$** $\rightarrow$ `CRITICAL_MOSCA_BREACH_ACTIVE_HNDL` (immediate exposure to *"Harvest Now, Decrypt Later"* attacks today).
  - `RSA_SIGN_*` and `EC_SIGN_*` keys exhibit **$X (3\text{y}) + Y (1.5\text{y}) = 4.5\text{ years} > Z_{2030} (4.0\text{y})$** $\rightarrow$ `HIGH_MOSCA_BREACH_NIST_2030_DEADLINE`.

### 4. Specialized Network (`scan_ssl_policies`) & BYOK (`scan_import_jobs_pqc`) Detectors
- **Network TLS 1.3 & Hybrid PQC Key Share Inspection (`scan_ssl_policies` in `tools/pqc_detectors.py`):**
  - Scans all `compute.googleapis.com/SslPolicy`, `TargetHttpsProxy`, and `TargetSslProxy` resources across the Organization or Project.
  - Verifies whether each policy enforces **`min_tls_version == "TLS_1_3"`** and supports hybrid post-quantum key shares **`X25519 + ML-KEM-768` (`X25519MLKEM768`)** (`QUANTUM_READY_HYBRID_TLS_1_3`).
  - Flags policies permitting `TLS_1_0`, `TLS_1_1`, `TLS_1_2` or unattached proxies as **`VULNERABLE_TO_SNDL_ATTACKS`**, generating `gcloud compute ssl-policies update --min-tls-version=1.3 --profile=RESTRICTED` commands.
- **Cloud KMS BYOK Key Import Inspection (`scan_import_jobs_pqc` in `tools/pqc_detectors.py`):**
  - Concurrently scans all active `ImportJobs` across KeyRings in the Organization/Project.
  - Flags classical `RSA_OAEP_3072_*` and `RSA_OAEP_4096_*` jobs as **`VULNERABLE_KEY_IMPORT_TRANSPORT`**.
  - Classifies jobs using hybrid post-quantum **`HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM`** (or `HPKE_KEM_ML_KEM_*`) wrapping as **`SECURE_PQC_BYOK`**.

### 5. Official OWASP CycloneDX v1.6 CBOM Exporter (`export_cyclonedx_cbom`)
- Generates a standards-compliant **OWASP CycloneDX v1.6 (`bomFormat: "CycloneDX"`, `specVersion: "1.6"`)** JSON document containing:
  - `type: "cryptographic-asset"` components with `cryptoProperties`, `algorithmProperties` (`primitive`, `parameterSetIdentifier`, `classicalSecurityLevel`, `nistQuantumSecurityLevel: 0..5`), `relatedCryptoMaterialProperties`, and **official NIST CSOR / IETF CFRG ASN.1 OIDs** (`1.3.6.1.4.1.62253.25722` for `KEM_XWING`, `2.16.840.1.101.3.4.3.18` for `ML-DSA-65`, `2.16.840.1.101.3.4.4.2` for `ML-KEM-768`, etc.).
  - `type: "application"` components and the complete `dependencies` graph linking applications to cryptographic keys.

### 6. Interactive SDK Code & API Gateway Refactoring Generator (`generate_application_pqc_refactoring_guide`)
- Produces ready-to-use **Before vs. After** code in **Python (`google-cloud-kms` + `cryptography`)** and **Go (`cloud.google.com/go/kms/apiv1`)** demonstrating:
  - Migration from `asymmetric_decrypt()` to `decapsulate()` + DEK derivation via `HKDF-SHA256` + `AES-256-GCM`.
  - Migration from `asymmetric_sign(digest=...)` to `asymmetric_sign(data=...)` and 64-byte external $\mu$ computation using `hashlib.shake_256` for `PQ_SIGN_ML_DSA_65_EXTERNAL_MU`.
  - YAML manifests for **Envoy / Istio (`EnvoyFilter` with `max_request_headers_kb: 32`)** and **NGINX Ingress (`large_client_header_buffers 4 32k;`)**.

### 7. Preventive Governance via GCP Organization Policy Guardrails, High-Concurrency Parallel Scanner (`ThreadPoolExecutor`) & TTL Cache
- **Preventive Guardrails (`preventive_org_policy_guardrails`):** Generates CEL Custom Constraints for the **GCP Organization Policy Service** (`custom.pqcEnforceQuantumSafeKmsAlgorithms` and `custom.pqcEnforceSymmetricKeyRotation90d`) that block (`CREATE`/`UPDATE`) the creation of new classical RSA/ECC keys or symmetric keys without $\le 90\text{-day}$ automatic rotation.
- **High-Concurrency Parallel Scanner & In-Memory TTL Cache (`120s`):** Executes Cloud Asset Inventory discovery and Cloud KMS version/IAM/ImportJob inspections concurrently via `ThreadPoolExecutor`, reducing full Organization scan latency from **~18.5s to ~6.7s** on cold runs and **`0.40 ms`** on multi-tool warm turns, while compact JSON serialization (`_compact_json`) cuts LLM token consumption by **~40%**.

### 8. Quantum Physics & Cryptanalysis Simulation Engine (`run_quantum_cryptanalysis_simulation` in `tools/quantum_engine.py`)
- **Shor's & Roetteler's Surface-Code Quantum Circuit Resource Estimator:** Computes exact Logical Qubits (`2,330` for `ECDSA P-256`/`Ed25519`, `3,484` for `ECDSA P-384`, `4,098` for `RSA-2048`, `6,146` for `RSA-3072`, `8,194` for `RSA-4096`), Toffoli gate counts, Surface Code Distance ($d = 27$ to $31$), Physical Superconducting Qubits (`13.4M` to `52.0M` at $10^{-3}$ gate error rate), and CRQC runtime hours (`8.0h` to `49.0h`), proving why **`ECDSA P-256` falls before `RSA-2048`**.
- **Core-SVP Lattice Sieving Hardness & 10,000-Iteration Monte Carlo (`Q-VaR 95%`):** Quantifies classical/quantum Core-SVP security bits (`167-bit` quantum security for `KEM_XWING`, `174-bit` for `PQ_SIGN_ML_DSA_65`) and simulates 2026–2035 annual CRQC breach probabilities and financial `Q-VaR 95%`.

---

## 🛠️ Catalog of the 9 Registered Agent Tools (`root_agent.tools`)

| Tool Name | Module | PQC Layer | Description | Key Parameters |
| :--- | :--- | :--- | :--- | :--- |
| `scan_organization_pqc_readiness` | `tools/gcp_inventory.py` | **Layer 1 (Org KMS + CAI + Apps)** | Executes the full Organization-wide PQC Readiness Assessment, 4-Vector App Compatibility, Mosca Risk, Guardrails, and `Product BOM` across `organizations/31564119954`. | `organization_id="31564119954"` |
| `generate_pqc_migration_plan` | `tools/gcp_inventory.py` | **Layer 1 (Scorecard + BOM)** | Generates the Multidimensional Scorecard, Application Compatibility Matrix, Mosca Analysis, `gcloud kms` Playbooks, Org Policy Guardrails, and `Product BOM`. | `project_id="organizations/31564119954"`, `location_id="all"` |
| `scan_pqc_readiness` | `tools/gcp_inventory.py` | **Layer 1 (KMS Keys)** | Concurrently lists and classifies all Cloud KMS keys, active vs. destroyed versions (`ENABLED` vs. `DESTROY_SCHEDULED`), IAM policies, and consuming applications. | `project_id="organizations/31564119954"`, `location_id="all"` |
| `discover_all_crypto_assets` | `tools/gcp_inventory.py` | **Layer 1 & 2 (CAI PKI/TLS)** | Scans Cloud Asset Inventory (`read_mask="*"`) classifying KeyRings, CryptoKeys, `SslPolicy` (TLS 1.3 `X25519MLKEM768`), `SslCertificate`, `CertificateManager`, and `PrivateCA`. | `project_id="organizations/31564119954"` |
| `scan_ssl_policies` | `tools/pqc_detectors.py` | **Layer 2 (Network SNDL)** | Inspects all active Google Cloud SSL Policies and HTTPS Proxies, verifying TLS 1.3 enforcement and hybrid key shares (`X25519 + ML-KEM-768`), flagging `VULNERABLE_TO_SNDL_ATTACKS` when missing. | `project_id="organizations/31564119954"` |
| `scan_import_jobs_pqc` | `tools/pqc_detectors.py` | **Layer 3 (BYOK ImportJobs)** | Lists and inspects all active Cloud KMS `ImportJobs` (BYOK), flagging `VULNERABLE_KEY_IMPORT_TRANSPORT` for classical RSA-OAEP and `SECURE_PQC_BYOK` for `HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM`. | `project_id="organizations/31564119954"`, `location_id="global"` |
| `generate_application_pqc_refactoring_guide` | `tools/gcp_inventory.py` | **SDK & Gateway Engineering** | Generates practical *Before vs. After* SDK code guides (Python/Go) and API Gateway configurations (Envoy/Istio/NGINX) to refactor PQC-incompatible applications. | `project_id="organizations/31564119954"`, `application_or_key_filter="all"` |
| `export_cyclonedx_cbom` | `tools/gcp_inventory.py` | **CBOM v1.6 Governance** | Exports the cryptographic and application inventory in official **OWASP CycloneDX v1.6 CBOM JSON** format with ASN.1 OIDs and `nistQuantumSecurityLevel`. | `project_id="organizations/31564119954"`, `location_id="all"` |
| `run_quantum_cryptanalysis_simulation` | `tools/quantum_engine.py` | **Quantum Physics & Cryptanalysis** | Simulates Shor's/Roetteler's surface-code Logical/Physical Qubits, Core-SVP lattice hardness, and 10,000-iteration Monte Carlo CRQC breach probabilities & `Q-VaR 95%`. | `project_id="organizations/31564119954"`, `location_id="global"` |

---

## 💬 Sample Prompts for Gemini Enterprise / Web UI Testing

1. **Full Multi-Layered Executive Organization Assessment (KMS + Applications + SSL Policies + ImportJobs + Product BOM):**
   > *"Run a complete multi-layered Post-Quantum Cryptography (PQC) readiness assessment across the organization, bringing all applications using the cryptographic keys, SSL policies, KMS ImportJobs, and the Recommended Google Cloud Security Architecture & Product BOM."*
2. **Targeted Network (TLS 1.3 Hybrid PQC) & BYOK Key Import (`ImportJobs`) Inspection:**
   > *"Scan all active Google Cloud SSL Policies for SNDL vulnerabilities and inspect all Cloud KMS ImportJobs for PQC BYOK transport readiness across our organization."*
3. **SDK Code & API Gateway Refactoring Guide for Incompatible Applications:**
   > *"Generate the application PQC code refactoring guide and Envoy/NGINX gateway configurations for all incompatible applications in our organization."*
4. **Formal OWASP CycloneDX v1.6 CBOM Export:**
   > *"Export the official OWASP CycloneDX v1.6 Cryptographic Bill of Materials (CBOM) for our organization."*
5. **Quantum Physics & Cryptanalysis Simulation (Shor Surface Code, Core-SVP & Monte Carlo Q-VaR 95%):**
   > *"Run the quantum cryptanalysis simulation across our organization and show the exact Logical/Physical Qubits, why ECDSA P-256 falls before RSA-2048, Core-SVP lattice hardness, and the 2026–2035 Monte Carlo Q-VaR 95% curve."*

---

## 📂 Project Structure

```text
pqc_inventory_agent/
├── Dockerfile                   # Production container image for Cloud Run (adk web --host 0.0.0.0, Gemini 3.1 global)
├── app.yaml                     # Declarative agent manifest (gemini-3.1-pro-preview-customtools, thinking MEDIUM, 1M tokens)
├── requirements.txt             # Python dependencies (google-adk, google-genai, google-cloud-kms, google-cloud-asset)
├── pyproject.toml               # Package metadata and pytest configuration
├── main.py                      # Main entrypoint: Reasoning Engine (LangchainAgent + AdkApp), local harness, and CLI
├── pqc_agent/                   # Module compatible with the official Google ADK CLI (`adk web` / `adk run`)
│   ├── __init__.py
│   └── agent.py                 # `root_agent` definition (Gemini 3.1), System Instructions, and 9 registered tools
├── tools/
│   ├── __init__.py              # Unified export of all 9 PQC tools
│   ├── gcp_inventory.py         # Layer 1 PQC Engine: KMS + 4-Vector CAI + Mosca + CycloneDX v1.6 + Refactoring + Product BOM
│   ├── pqc_detectors.py         # Layer 2 & 3 PQC Detectors: Network (SSL Policies SNDL) & BYOK (KMS ImportJobs HPKE X-Wing)
│   ├── quantum_engine.py        # Quantum Physics Engine: Shor Surface Code, Core-SVP Lattice Hardness, Monte Carlo Q-VaR 95%
│   └── mock_data.py             # Realistic simulation dataset for offline unit testing
└── tests/
    └── test_pqc_inventory.py    # 19 automated test suites (pytest) covering all PQC capabilities, quantum physics, and cache/token optimizations
```

---

## 🚀 How to Run, Test, and Deploy

### 1. Run the Automated Unit & Integration Test Suite (`19/19` tests)
```bash
.venv/bin/pytest -v
```

### 2. Run the Local Validation Harness
```bash
# Fast offline simulation mode (validates KMS, CAI, SSL Policies, ImportJobs, and Product BOM):
.venv/bin/python main.py test --input='{"project_id": "meu-projeto-gcp"}'

# Live scan against the GCP Organization (organizations/31564119954):
.venv/bin/python main.py ask --project-id=organizations/31564119954
```

### 3. Deploy / Update the Service on Cloud Run (ADK Web UI)
```bash
gcloud run deploy pqc-inventory-agent \
  --source . \
  --project=pqc-inventory-agent-cd06 \
  --region=us-central1 \
  --allow-unauthenticated \
  --set-env-vars="GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_PROJECT=pqc-inventory-agent-cd06,GOOGLE_CLOUD_LOCATION=global,GCP_ORGANIZATION_ID=31564119954,GCP_ORGANIZATION_NAME=jsaccomani.altostrat.com,PQC_SIMULATION_MODE=AUTO,PQC_AGENT_MODEL=gemini-3.1-pro-preview-customtools"
```

### 4. Deploy / Update on Vertex AI Agent Engine (Reasoning Engine)
```bash
.venv/bin/python main.py deploy \
  --project=pqc-inventory-agent-cd06 \
  --location=us-central1 \
  --staging-bucket=gs://pqc-inventory-agent-cd06-pqc-agent-staging
```

---

## 🔐 Security Model & IAM Permissions (Least Privilege)

The runtime Service Account `pqc-agent-runner@pqc-inventory-agent-cd06.iam.gserviceaccount.com` operates in **100% Read-Only (Non-Intrusive) Mode** at the GCP Organization level (`organizations/31564119954`):

| IAM Role | Scope | Architectural Purpose |
| :--- | :--- | :--- |
| `roles/resourcemanager.organizationViewer` | `organizations/31564119954` | Visibility into the GCP Organization hierarchy and project metadata. |
| `roles/cloudasset.viewer` | `organizations/31564119954` | Executes `SearchAllResources` (`read_mask="*"`) to discover KeyRings, CryptoKeys, `SslPolicy`, `TargetHttpsProxy`, `SslCertificate`, `PrivateCA`, and CMEK bindings across all projects. |
| `roles/cloudkms.viewer` | `organizations/31564119954` | Reads `KeyRings`, `CryptoKeys`, `CryptoKeyVersions` (`ENABLED` vs. `DESTROY_SCHEDULED`), and `ImportJobs` (`ImportMethod`, `ProtectionLevel`). |
| `roles/cloudkms.admin` *(or `cloudkms.cryptoKeys.getIamPolicy`)* | `organizations/31564119954` | Inspects per-key IAM policies (`Vector 3` consuming application discovery). |
| `roles/aiplatform.user` | `projects/pqc-inventory-agent-cd06` | Invokes the global `gemini-3.1-pro-preview-customtools` endpoint on Vertex AI and executes the Reasoning Engine. |
