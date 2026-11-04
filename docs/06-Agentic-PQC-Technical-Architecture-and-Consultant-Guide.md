# Agentic PQC Technical Architecture and Consultant Guide
**Google Cloud Consulting — L300/L400 System Architecture, Technical Design Document (TDD) & Deployment How-To**

> **Google Drive Official Deliverable:** [Agentic PQC Technical Architecture and Consultant Guide](https://docs.google.com/document/d/1YZOE7t4veH1S_xIrMMKRTsp8DG36_bWebB0f8_dDwwI/edit)

> **Executive Summary:** This L300/L400 System Architecture Specification defines the enterprise reference architecture for the Agentic Post-Quantum Cryptography (PQC) Readiness & CBOM Engine. Designed as a modular, template-driven specification for deployment in any contracted customer Google Cloud environment, it details the 5-plane neuro-symbolic AI architecture (combining Gemini 3.1 Pro / 2.5 Pro cognitive orchestration on Google ADK with deterministic quantum physics, 4-vector Cloud Asset Inventory introspection, and closed-loop historical self-calibration), enterprise VPC-SC deployment patterns, and STRIDE zero-trust security boundaries. This L400 Technical Design Document (TDD) specifies the low-level software engineering, mathematical equations, API introspection schemas, and self-calibrating memory structures of the Agentic PQC Readiness & CBOM Engine. Designed as a reusable Google Cloud Consulting (PSO) technical blueprint, it connects the macro topology in Agentic PQC Technical Architecture and Consultant Guide, the stakeholder calibration parameters from Agentic PQC Discovery Questionnaire, and the deployment workflows in Agentic PQC Technical Architecture and Consultant Guide.

---

## Part I — System Architecture Specification (5-Plane Neuro-Symbolic Topology & VPC-SC)

## 1. Architectural Vision, Design Tenets & Customer Environment Template Manifest

Analyzing an enterprise's Post-Quantum Cryptography (PQC) posture requires simultaneous mastery of cloud control-plane telemetry, quantum circuit physics, application wire-protocol constraints, and financial risk modeling. A purely generative LLM approach fails in this domain due to arithmetic hallucinations and non-deterministic scoring, whereas a purely static scanner fails to synthesize cross-layer application blast radius and consultative migration architecture. The Agentic PQC Readiness & CBOM Engine solves this via a Neuro-Symbolic Multi-Plane Architecture:

- Tenet 1 — Neuro-Symbolic Separation of Concerns (Cognitive Orchestration vs. Deterministic Math/Physics): The Large Language Model (Gemini 3.1 Pro / 2.5 Pro orchestrated via Google ADK) handles natural-language intent routing, stakeholder calibration synthesis, and consultative report structuring, while 100% of GCP API discovery, Shor/Roetteler/Grover/Core-SVP qubit equations, 10,000-run Monte Carlo Q-VaR simulations, and KPI percentage calculations execute inside deterministic, auditable Python engines.
- Tenet 2 — 100% Agentless, Zero-Plaintext Control-Plane Introspection: The system operates exclusively via read-only Google Cloud control-plane APIs. It never installs host agents, never inspects data-plane network packets, never reads Secret Manager payloads, and never accesses private cryptographic key material.
- Tenet 3 — Closed-Loop Self-Calibrating Intelligence: Stakeholder context captured via Agentic PQC Discovery Questionnaire and interactive consultant feedback (Agentic PQC Technical Architecture and Consultant Guide) are persisted in a longitudinal calibration ledger (tools/calibration-engine.py), allowing the agent to automatically learn from its history and refine Mosca (X + Y > Z) and Q-VaR parameters across runs.
- Tenet 4 — Portable Customer-Environment Template Design: Every runtime URI, project identifier, storage bucket, and IAM principal is parameterized via environment variables so the architecture can be deployed identically in a customer's single-tenant production enclave, a central governance hub, or a consultant's workstation.

### 1.1 Customer Environment Parameterization Table (Engagement Template)

To instantiate this architecture in a customer's contracted Google Cloud environment, replace the template placeholders below with the customer's provisioned resource identifiers (detailed step-by-step in Agentic PQC Technical Architecture and Consultant Guide):

| Architectural Component | Template Placeholder Variable | Standard GCP Resource URI Pattern | Contracted Customer Environment Value |
| --- | --- | --- | --- |
| Target Assessment Scope (Org / Folder) | <CUSTOMER-ORG-ID> | organizations/<ORG-ID> or folders/<FOLDER-ID> | [ Populate in Customer Environment ] |
| Agent Host GCP Project | <AGENT-HOST-PROJECT-ID> | projects/<HOST-PROJECT-ID> | [ Populate in Customer Environment ] |
| Vertex AI Agent Engine Runtime | <REASONING-ENGINE-URI> | projects/<PROJECT-NUM>/locations/<REGION>/reasoningEngines/<ID> | [ Populate in Customer Environment ] |
| Cloud Run Web UI & SSE API Gateway | <CLOUD-RUN-ENDPOINT-URL> | https://<SERVICE>-<PROJECT-NUM>.<REGION>.run.app | [ Populate in Customer Environment ] |
| Dedicated Read-Only Scanner SA | <SCANNER-SERVICE-ACCOUNT> | pqc-scanner-sa@<HOST-PROJECT-ID>.iam.gserviceaccount.com | [ Populate in Customer Environment ] |
| Persistent Calibration & CBOM Vault | <CALIBRATION-GCS-BUCKET> | gs://<HOST-PROJECT-ID>-pqc-artifacts/calibration-history.jsonl | [ Populate in Customer Environment ] |

## 2. Five-Plane System Architecture & End-to-End Data Flow (C4 Container & Component View)

The platform is architected across five decoupled horizontal planes that process telemetry from raw GCP control-plane APIs into board-ready financial risk models and engineering runbooks in ~6.7 seconds:

1. Plane 1 — Multi-Channel Presentation, Streaming & API Gateway Layer (main.py): Asynchronous FastAPI server exposing (a) an interactive Consultative Web UI with real-time Server-Sent Events (SSE) tool-execution tracing (/api/chat/stream), (b) REST batch assessment and multi-persona export endpoints (/api/assess, /api/export), (c) native Google ADK Developer UI (/dev-ui), (d) conversational integration with Gemini Enterprise via Vertex AI Agent Engine, and (e) a headless CLI exporter for CI/CD governance pipelines.
2. Plane 2 — Cognitive Agent Orchestration & Guardrail Plane (pqc-agent/agent.py): Powered by Google ADK (Agent Development Kit) and Vertex AI Gemini 3.1 Pro / 2.5 Pro (configured with temperature=0.1 and thinking-level=MEDIUM). Enforces strict anti-hallucination system instructions: mandatory multi-tool correlation, automatic tenant-sandbox (*-tp) scope redirection, verbatim locking of backend-computed scorecard percentages, and a standardized 6-section consultative deliverable layout.
3. Plane 3 — Deterministic Cryptographic, Quantum Physics & Self-Calibrating Tool Plane (tools/): Comprises five specialized deterministic sub-engines invoked autonomously by the ADK agent: (3A) High-Concurrency GCP Inventory & 4-Vector Blast-Radius Engine (tools/gcp-inventory.py), (3B) Network Edge TLS 1.3 & BYOK Supply-Chain Detector Engine (tools/pqc-detectors.py), (3C) Surface-Code Quantum Physics & 10,000-Run Monte Carlo Q-VaR Engine (tools/quantum-engine.py), (3D) Historical Self-Calibration & Sector Memory Engine (tools/calibration-engine.py), and (3E) Multi-Persona Report & CycloneDX v1.6 CBOM Exporter (tools/report-exporter.py).
4. Plane 4 — Target Google Cloud Control-Plane Telemetry Plane: Asynchronous, rate-limited, 16-worker ThreadPoolExecutor introspection across Cloud Resource Manager v3, Cloud KMS & Cloud HSM v1, Cloud Asset Inventory v1 (searchAllResources & searchAllIamPolicies), Compute Engine SSL Policies (global & regional), Certificate Authority Service (CAS) v1, GKE Cluster encryption metadata, and KMS ImportJobs.
5. Plane 5 — Persistent Calibration Ledger & Deliverable Storage Plane: Stores longitudinal calibration events (calibration-history.jsonl), timestamped OWASP CycloneDX v1.6 CBOM JSON artifacts, and print-to-PDF HTML/Markdown Executive & Engineering reports in local storage or customer-managed Cloud Storage (gs://<CALIBRATION-GCS-BUCKET>).

### 2.1 Sub-Engine Component Matrix & Cross-Document Traceability

| Architectural Plane & Sub-Engine | Implementation Module | Key Capabilities & Algorithms | Connected Accelerator Document |
| --- | --- | --- | --- |
| Plane 1: Presentation & SSE Gateway | main.py / FastAPI / ADK Web | Async SSE streaming, REST export endpoints, session state management, health probes. | Agentic PQC Technical Architecture and Consultant Guide |
| Plane 2: Cognitive ADK Orchestrator | pqc-agent/agent.py | Gemini 3.1 Pro / 2.5 Pro reasoning, 12-tool routing, zero-hallucination scorecard locking. | Agentic PQC Technical Architecture and Consultant Guide |
| Plane 3A: 4-Vector Telemetry Engine | tools/gcp-inventory.py | 16-worker ThreadPoolExecutor org scan, KMS/HSM/CAS inventory, 4-vector app blast-radius. | Agentic PQC Technical Architecture and Consultant Guide |
| Plane 3B: Edge TLS & BYOK Detectors | tools/pqc-detectors.py | Compute SslPolicy (X25519MLKEM768) detector, ImportJob wrapping audit, Tink & OrgPolicy YAML. | Agentic PQC Security Recommendations Book |
| Plane 3C: Quantum Physics & Q-VaR | tools/quantum-engine.py | Gidney-Ekera Shor, Roetteler ECDLP, Grassl Grover, Core-SVP, 10k Monte Carlo Q-VaR (95%). | Agentic PQC Security Recommendations Book |
| Plane 3D: Self-Calibrating Memory | tools/calibration-engine.py | Sector baselines (BFSI, Healthcare, Public Sector, Telecom, OT), Mosca (X+Y>Z) ledger. | Agentic PQC Discovery Questionnaire |
| Plane 3E: Multi-Persona Exporter | tools/report-exporter.py | Generates Executive Board Report, Engineering Playbook, and OWASP CycloneDX v1.6 CBOM. | Agentic PQC Security Recommendations Book |

## 3. Enterprise Reference Deployment Topologies (Customer vs. Consultant Environments)

Depending on the customer's regulatory posture, data residency rules, and engagement phase, the architecture supports three validated deployment topologies (with step-by-step commands provided in Agentic PQC Technical Architecture and Consultant Guide):

| Deployment Topology | Runtime Hosting Location | Authentication & IAM Model | Network & Data Isolation Boundary | Recommended Engagement Scenario |
| --- | --- | --- | --- | --- |
| Topology A: Customer-Hosted Single-Tenant Enclave<br>(Production Recommended) | Customer's Security Operations GCP Project (Cloud Run + Vertex AI Agent Engine) | Dedicated Customer Service Account (pqc-scanner-sa) with read-only Org Viewer roles; zero external access. | Internal Load Balancer + Identity-Aware Proxy (IAP) enclosed in a VPC Service Controls (VPC-SC) perimeter. | Regulated BFSI, Healthcare, Defense, and Large Enterprise engagements requiring continuous posture monitoring. |
| Topology B: Hub-and-Spoke Cross-Organization Assessment | Central Governance Hub Project scanning multiple subsidiary Organizations/Folders | Keyless Cross-Project Service Account Impersonation (roles/iam.serviceAccountTokenCreator); short-lived 1h OAuth2 tokens. | Encrypted TLS 1.3 control-plane API calls over Google's production backbone; zero static JSON keys. | Conglomerates, M&A due diligence, or multi-org enterprises managed by a central CISO office. |
| Topology C: Ephemeral Consultant Workstation / Cloud Shell | Consultant Laptop, Cloud Shell, or PSO Lab Project | Google Cloud SDK Application Default Credentials (ADC) with --impersonate-service-account against customer SA. | Ephemeral session execution; CBOM and reports generated directly into customer's authorized workspace. | Fast-Track (1-week) discovery assessments, PoCs, and live executive workshops. |

## 4. Closed-Loop Self-Calibration & Continuous Historical Learning Architecture

A core architectural differentiator of this AI system is its ability to self-calibrate its analytical models by learning from stakeholder discovery inputs and historical consultant feedback:

1. Phase 1 — Structured Context Ingestion: During stakeholder interviews (guided by Agentic PQC Discovery Questionnaire), the consultant executes Calibration Prompts (cataloged in Agentic PQC Technical Architecture and Consultant Guide). The ADK agent invokes calibrate-assessment-context(), validating and writing the organization's sector profile, confidentiality horizon (X), refactoring velocity (Y), CRQC threat window (Z), API gateway header limits, and project criticality overrides into calibration-history.jsonl.
2. Phase 2 — Automatic Pre-Execution Memory Retrieval: Whenever a user asks the agent to assess an organization, evaluate quantum risk, or generate migration runbooks, the agent first invokes get-historical-calibration-profile(scope). This loads the cumulative historical calibration state into the active execution context without requiring the user to repeat prior constraints.
3. Phase 3 — Dynamic Recalibration of Mosca Horizons & Q-VaR Multipliers: The retrieved calibration parameters dynamically adjust the Mosca safety margin (M = Z - (X + Y)), re-weight the 10,000-iteration Monte Carlo Q-VaR financial exposure by the sector multiplier, flag HTTP header overflow risks if gateway limits are <16KB, and prioritize Tier-0 business projects first in the 30-60-90 day execution plan.

## 5. Security Architecture, Zero-Trust Threat Model (STRIDE) & Least-Privilege IAM

### 5.1 Least-Privilege Read-Only IAM Permission Matrix

| Predefined GCP Role | Granular API Permissions Utilized | Architectural Purpose | Explicitly Excluded High-Risk Permissions |
| --- | --- | --- | --- |
| roles/cloudasset.viewer | cloudasset.assets.searchAllResources, cloudasset.assets.searchAllIamPolicies | 4-Vector workload blast-radius mapping & folder/project discovery. | No write, delete, or policy modification permissions. |
| roles/cloudkms.viewer | cloudkms.keyRings.list, cloudkms.cryptoKeys.list, cloudkms.cryptoKeyVersions.list, cloudkms.importJobs.list | Inspects key algorithms, HSM protection levels, rotation periods, and BYOK wrapping. | Excludes cloudkms.cryptoKeyVersions.useToDecrypt and useToSign (zero key usage). |
| roles/privateca.auditor | privateca.caPools.list, privateca.certificateAuthorities.list | Audits Root and Subordinate CA key specifications in Certificate Authority Service. | Excludes privateca.certificates.create and CA private key access. |
| roles/compute.viewer | compute.sslPolicies.list, compute.regionSslPolicies.list, compute.targetHttpsProxies.list | Detects TLS 1.0/1.2 SNDL exposure vs. TLS 1.3 X25519MLKEM768 readiness. | Excludes compute.instances.* mutation or network packet capture. |

### 5.2 AI Safety, Anti-Hallucination & STRIDE Threat Mitigation Controls

- Mitigating LLM Arithmetic & Scoring Hallucinations (Integrity): The LLM is prohibited from computing maturity percentages. All 7 KPI percentages are deterministically calculated in Python (-compute-metrics-for-keys) and locked inside validated-executive-scorecard.
- Cryptographic Provenance Attestation (Non-Repudiation): Every tool response embeds a data-validation-manifest with an explicit authenticity flag (LIVE-GCP-TELEMETRY-VERIFIED vs. SIMULATED-BENCHMARK-DATASET) and timestamp.
- Tenant Sandbox Isolation (Confidentiality): Runtime scope resolution blocks accidental scanning of internal Vertex AI *-tp tenant projects and enforces strict customer scope boundaries.
- Prompt Injection & Tool-Argument Sanitization (Tampering): All scope identifiers and calibration parameters are regex-sanitized and type-checked before invoking Google Cloud client libraries or shell runbook generators.

## 6. Non-Functional Requirements: Scalability, Resilience, Observability & FinOps

- High-Concurrency Throughput & Latency SLAs: Utilizes a 16-worker ThreadPoolExecutor to scan 8–15 projects in ~6.7 seconds, scaling linearly to 100–500+ projects in <45 seconds via paginated Cloud Asset Inventory bulk queries.
- Graceful Degradation & Rate-Limit Resilience: Implements per-project exception isolation (if Cloud KMS or CAS API is disabled in a sandbox project, the worker records a clean status without aborting the organization scan) and exponential backoff on HTTP 429/503 responses.
- Vertex AI Token FinOps & Context Efficiency: Tool outputs are serialized as compact JSON (separators=(',', ':')) and paired with temperature=0.1 and thinking-level=MEDIUM, minimizing token consumption while maximizing analytical precision.

## Part II — L400 Technical Design Document (12 ADK Tools, Quantum Physics Engine & CBOM)

## 1. Engineering Context, Breaking Changes & Deployment Configuration Template

Migrating enterprise cloud infrastructure to Post-Quantum Cryptography (PQC) under NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NIST IR 8547 (Final, Oct 2026), White House EO 14412, and NSA CNSA 2.0 is not a drop-in key rotation. It introduces fundamental mathematical, wire-format, and API breaking changes that require deterministic automated analysis:

- Harvest Now, Decrypt Later (HNDL) & Store Now, Decrypt Later (SNDL): Adversaries intercept encrypted TLS sessions, database backups, and archival ciphertexts today to decrypt them retroactively once Cryptographically Relevant Quantum Computers (CRQCs) reach the ~2,330 to ~4,098 logical qubit threshold required by Shor's algorithm.
- Wire-Format & Artifact Size Expansion (20x to 51x Bloat): Classical ECDSA P-256 signatures occupy 64 bytes (and RSA-2048 occupies 256 bytes), whereas NIST FIPS 204 ML-DSA-65 signatures require 3,309 bytes (~4.4 KB in Base64URL JWTs) and public keys require 1,952 bytes. This breaks reverse proxies, NGINX/Envoy ingresses, Apigee API Gateways, and browser cookies configured with 4KB/8KB HTTP header limits, as well as fixed-width database columns (e.g., VARBINARY(256)).
- Cryptographic API Contract Shift (Decrypt -> KEM Encapsulate/Decapsulate): Post-quantum key establishment (ML-KEM / X-Wing) eliminates direct asymmetric decryption (AsymmetricDecrypt). Applications must be refactored to execute client-side Key Encapsulation (Encapsulate) paired with Cloud KMS Decapsulate() and RFC 9180 Hybrid Public Key Encryption (HPKE) or Google Tink SDK envelope encryption.
- Digital Signature Pre-Hashing Shift (Digest -> Raw Data / External-Mu): Classical Cloud KMS AsymmetricSign accepts pre-computed SHA-256/384 digests, whereas ML-DSA (FIPS 204) requires signing the raw message payload (data field) or computing a 64-byte external-mu hash over the public key TR and message.

### 1.1 Customer Deployment Configuration Manifest (Template Specification)

When deploying the agent in a contracted customer environment or PSO project (following Agentic PQC Technical Architecture and Consultant Guide), populate the environment identifiers below. Fields are intentionally left blank in this master template so each engagement records its isolated runtime endpoints:

| Configuration Parameter | Environment Variable / Config Key | Expected Format / URI Pattern | Customer Environment Value (Populate at Deployment) |
| --- | --- | --- | --- |
| Target GCP Organization Scope | PQC-TARGET-ORG-ID | organizations/<CUSTOMER-ORG-ID> | [ Leave Blank — Populate in Customer Environment ] |
| Agent Host GCP Project ID | GOOGLE-CLOUD-PROJECT | <CUSTOMER-HOST-PROJECT-ID> | [ Leave Blank — Populate in Customer Environment ] |
| Vertex AI Agent Engine URI | VERTEX-AI-REASONING-ENGINE-URI | projects/<PROJECT-NUMBER>/locations/<REGION>/reasoningEngines/<ENGINE-ID> | [ Leave Blank — Populate in Customer Environment ] |
| Cloud Run Interactive Web UI URL | CLOUD-RUN-SERVICE-URL | https://<SERVICE-NAME>-<PROJECT-NUMBER>.<REGION>.run.app | [ Leave Blank — Populate in Customer Environment ] |
| Scanner Service Account Identity | SCANNER-SERVICE-ACCOUNT | <SA-NAME>@<HOST-PROJECT-ID>.iam.gserviceaccount.com | [ Leave Blank — Populate in Customer Environment ] |
| Calibration & CBOM Storage Path | PQC-CALIBRATION-STORE-PATH | gs://<CUSTOMER-BUCKET>/calibration-history.jsonl | [ Leave Blank — Populate in Customer Environment ] |

## 2. Low-Level Software Package Architecture & ADK Tool Contracts

The codebase is organized into a modular neuro-symbolic Python architecture where the Google ADK LlmAgent (pqc-agent/agent.py) delegates 100% of telemetry introspection, quantum circuit math, financial simulation, and historical calibration to 12 deterministic Python tools across 5 specialized modules:

| Module File | Registered ADK Tool Function | Input Arguments | Deterministic Output Contract |
| --- | --- | --- | --- |
| pqc-agent/agent.py | create-pqc-agent / root-agent | model-name, GenerateContentConfig (temp=0.1, thinking=MEDIUM) | Orchestrates 12 tools; enforces zero-hallucination scorecard rules and 6-part PSO report structure. |
| tools/gcp-inventory.py | scan-organization-pqc-readiness | organization-id: str | Parallel 16-worker org scan returning validated-executive-scorecard, 4-vector blast-radius, and per-key playbooks. |
| tools/gcp-inventory.py | scan-pqc-readiness | project-id: str | Single-project KMS/HSM inventory, CMEK bindings, and deterministic maturity metrics. |
| tools/gcp-inventory.py | discover-all-crypto-assets | scope: str | Full enumeration of KMS keys, Certificate Authority Service (CAS) CAs, and workload bindings. |
| tools/gcp-inventory.py | generate-pqc-migration-plan | scope: str | Phased 30-60-90 day migration plan, 5-step Cloud HSM runbooks, and symmetric 90-day rotation commands. |
| tools/gcp-inventory.py | generate-application-pqc-refactoring-guide | scope: str | Side-by-side Python/Go SDK code diffs (AsymmetricDecrypt -> KEM Decapsulate + HPKE) and Envoy/NGINX configs. |
| tools/gcp-inventory.py | export-cyclonedx-cbom | scope: str | OWASP CycloneDX v1.6 JSON CBOM with NIST OIDs, cryptoProperties, and quantum readiness statuses. |
| tools/pqc-detectors.py | scan-ssl-policies | scope: str | Audits Compute Engine SslPolicies for TLS 1.3 + RESTRICTED profile (X25519MLKEM768 hybrid KEM readiness). |
| tools/pqc-detectors.py | scan-import-jobs-pqc | scope: str | Audits Cloud KMS ImportJobs for classical RSA-OAEP wrapping vs. quantum-safe HPKE X-Wing transport. |
| tools/quantum-engine.py | run-quantum-cryptanalysis-simulation | scope: str | Computes Gidney-Ekera/Roetteler qubits, Core-SVP bits, fall-order ranking, and 10k Monte Carlo Q-VaR (95%). |
| tools/calibration-engine.py | calibrate-assessment-context | scope, industry-sector, X, Y, Z, gateway-header-limit-kb, notes | Persists stakeholder discovery overrides into calibration-history.jsonl and recalculates Mosca margins. |
| tools/calibration-engine.py | get-historical-calibration-profile | scope: str | Loads cumulative learned calibration parameters and sector multipliers before assessment execution. |
| tools/report-exporter.py | export-pqc-assessment-reports | scope: str, output-dir: str | Exports Executive Board Report (.md/.html), Engineering Playbook (.md/.html), and CycloneDX v1.6 CBOM (.json). |

## 3. Deep Specification of the 4-Layer Telemetry & 4-Vector Blast-Radius Engine

### 3.1 Intelligent Runtime Scope Resolution & Tenant Sandbox Interception (-resolve-scope)

When executed inside managed Vertex AI Agent Engine containers, the runtime environment injects internal Google-managed tenant project identifiers (matching project-*-tp). The -resolve-scope(raw-scope) function intercepts these ephemeral identifiers, validates whether a customer Organization ID or Project ID was explicitly supplied, and automatically resolves active child projects via Cloud Resource Manager API v3 (projects.search) with concurrent worker pooling.

### 3.2 Layer 1 — Cloud KMS, Cloud HSM & Cloud EKM Control-Plane Introspection

- API Traversal Pattern: Iterates concurrently across projects/*/locations/*/keyRings/*/cryptoKeys and inspects primaryVersion and enabled CryptoKeyVersions via cloudkms.googleapis.com/v1.
- Extracted Metadata Attributes: Captures purpose (ENCRYPT-DECRYPT, ASYMMETRIC-SIGN, ASYMMETRIC-DECRYPT, MAC, KEY-ENCAPSULATION), protectionLevel (SOFTWARE, HSM, EXTERNAL, EXTERNAL-VPC), algorithm (e.g., RSA-SIGN-PSS-2048-SHA256, EC-SIGN-P256-SHA256, GOOGLE-SYMMETRIC-ENCRYPTION, PQ-SIGN-ML-DSA-65, KEM-XWING), rotationPeriod, and nextRotationTime.
- Zero-Key-Material Guarantee: The scanner never invokes AsymmetricDecrypt, AsymmetricSign, Decapsulate, or Secret Manager accessSecretVersion. Only control-plane configuration descriptors are read.

### 3.3 Layer 2 — The 4-Vector Application Blast-Radius Correlation Algorithm

To determine which applications break when a classical KMS key is migrated to PQC, tools/gcp-inventory.py executes a 4-Vector correlation graph across Cloud Asset Inventory (cloudasset.googleapis.com/v1):

1. Vector 1 — Direct CMEK Resource Binding (searchAllResources kmsKeyName): Identifies all BigQuery datasets/tables, Cloud Storage buckets, GKE clusters (etcd encryption), Compute Engine persistent disks, Cloud SQL instances, Spanner databases, and Pub/Sub topics encrypted via Customer-Managed Encryption Keys. Since CMEK uses AES-256-GCM under the hood, these workloads are flagged as COMPATIBLE-ZERO-REFACTORING-CMEK (requiring only <= 90-day key rotation hygiene).
2. Vector 2 — Full-Text Workload Configuration Correlation: Queries CAI resource metadata, Cloud Run service environment variables, GKE ConfigMaps/Ingress annotations, and API Gateway descriptors referencing the KMS key URI.
3. Vector 3 — IAM Policy Principal & Service Account Graph (searchAllIamPolicies): Traces every workload Service Account bound to roles/cloudkms.cryptoKeyEncrypterDecrypter, roles/cloudkms.signerVerifier, or roles/cloudkms.cryptoOperator on the target key, mapping the key directly to the microservice identity invoking it.
4. Vector 4 — Project-Adjacent & PKI Certificate Authority Mapping: Correlates Certificate Authority Service (privateca.googleapis.com/v1) CA pools and subordinate CAs backed by Cloud KMS/HSM keys to downstream mTLS and ingress consumers.

### 3.4 Layer 3 & 4 — Network Edge SslPolicy (X25519MLKEM768) & BYOK ImportJob Detectors

- Network Edge TLS 1.3 Hybrid PQC Detector (scan-ssl-policies): Queries compute.sslPolicies.list and regionSslPolicies.list. Policies with minTlsVersion < TLS-1-3 or permissive profiles (COMPATIBLE / MODERN) are flagged as VULNERABLE-TO-SNDL-ATTACKS because they permit classical ECDHE/RSA handshakes without hybrid post-quantum key exchange. Policies enforcing TLS-1-3 with RESTRICTED profile negotiate IETF hybrid X25519MLKEM768.
- BYOK Key Supply-Chain Detector (scan-import-jobs-pqc): Queries projects.locations.keyRings.importJobs.list. ImportJobs using RSA-OAEP-3072-SHA256 or RSA-OAEP-4096-SHA256 wrapping are flagged as VULNERABLE-KEY-IMPORT-TRANSPORT, prescribing migration to HPKE-KEM-XWING / ML-KEM wrapping.

## 4. Mathematical Specification of the Quantum Physics & Stochastic Q-VaR Engine

The quantum simulation engine (tools/quantum-engine.py) avoids arbitrary qualitative risk labels by implementing peer-reviewed surface-code quantum circuit equations assuming superconducting planar surface codes at physical gate error rate p = 10^-3 (aligned with Google Quantum AI Willow error-correction scaling):

| Cryptographic Primitive | Quantum Attack Circuit & Reference | Logical Qubits (Q-L) | Surface Code Distance (d) & Physical Qubits (Q-P) | CRQC Runtime / Core-SVP Security Verdict |
| --- | --- | --- | --- | --- |
| ECDSA P-256 / Ed25519 | Shor ECDLP Windowed Point Addition (Roetteler et al., 2017) | 2,330 Logical Qubits | d = 27 | ~13.4 Million Physical Qubits | ~9.5 Hours | RANK 1 — FALLS FIRST ON EARLY FTQC |
| ECDSA P-384 | Shor ECDLP 384-Bit Modular Arithmetic (Roetteler / Haner 2020) | 3,484 Logical Qubits | d = 29 | ~18.2 Million Physical Qubits | ~26.0 Hours | RANK 2 — FALLS BEFORE RSA-2048 |
| RSA-2048 | Shor Windowed Modular Exponentiation (Gidney & Ekera, 2021) | 4,098 Logical Qubits (2n+2) | d = 27 | ~20.0 Million Physical Qubits | ~8.0 Hours | RANK 3 — CRITICAL HNDL TARGET |
| RSA-3072 / RSA-4096 | Shor Lattice Surgery Factorization (Gidney & Ekera, 2021) | 6,146 to 8,194 Logical Qubits | d = 29-31 | ~34.5M to 52.0M Physical Qubits | 21.5h - 49.0h | RANK 4-5 — HIGH HNDL TARGET |
| KEM-XWING / ML-KEM-768 | Quantum BKZ Lattice Sieving (Albrecht Core-SVP / FIPS 203) | Infeasible (Module-LWE dim=768) | N/A — > 2^167 Quantum Gate Operations | 167-Bit Post-Quantum Core-SVP (QUANTUM-SAFE) |
| PQ-SIGN-ML-DSA-65 | Quantum BKZ Lattice Sieving (Module-SIS / FIPS 204 Level 3) | Infeasible (Module-SIS) | N/A — > 2^166 Quantum Gate Operations | 166-Bit Post-Quantum Core-SVP (QUANTUM-SAFE) |
| AES-256-GCM / HMAC-SHA256 | Grover Amplitude Amplification (Grassl et al. / NIST MAXDEPTH) | 2,953 Logical Qubits | Requires 1.51e43 Serial Toffoli Gates (> 2^96 MAXDEPTH) | 128-Bit Effective PQ Security (QUANTUM-SAFE) |

### 4.1 Counter-Intuitive Proof: Why ECDSA P-256 & P-384 Fall Before RSA-2048

Classical security intuition assumes ECDSA P-256 (128-bit classical security) is stronger than RSA-2048 (112-bit classical security). However, under Shor's algorithm on a fault-tolerant quantum computer, the required number of logical qubits scales linearly with key bit-length n: Q-logical(RSA) = 2n + 2 = 4,098 for n=2048 (Gidney & Ekera, 2021), whereas Q-logical(ECDLP) = 9n + 2*ceil(log2(n)) + 10 = 2,330 for n=256 (Roetteler et al., 2017). Because a quantum computer reaches 2,330 logical qubits years before it reaches 4,098 logical qubits, ECDSA P-256 and P-384 keys are always prioritized as Rank 1 and Rank 2 in the agent's remediation fall-order table.

### 4.2 10,000-Iteration Monte Carlo CRQC & Financial Q-VaR (95%) Formulation

1. Stochastic CRQC Arrival Distribution (Z-sim): Samples 10,000 trajectories of fault-tolerant logical qubit scaling from a log-normal distribution calibrated to published hardware roadmaps (mean Z = 8.5 years, adjustable via tools/calibration-engine.py).
2. Mosca Inequality Evaluation per Iteration (X + Y > Z-sim): For each vulnerable asset i with confidentiality shelf-life X-i and refactoring lead time Y-i (calibrated via Agentic PQC Discovery Questionnaire), evaluates whether X-i + Y-i > Z-sim (HNDL breach for decryption/TLS assets) or Y-i > Z-sim (active forgery breach for signing/PKI assets).
3. 95th-Percentile Quantum Value-at-Risk (Q-VaR 95%): Aggregates simulated breach losses across all 10,000 runs (weighted by sector multiplier and per-record regulatory penalty) and extracts the 95th percentile in USD (unmitigated vs. residual post-PQC adoption).

## 5. Adaptive Self-Calibration & Historical Learning Engine Design (tools/calibration-engine.py)

To ensure the agent adapts dynamically to each customer's industry vertical, regulatory regime, and architectural nuances without manual code edits, tools/calibration-engine.py implements a persistent closed-loop calibration architecture:

- Longitudinal Calibration Ledger (calibration-history.jsonl): Every execution of calibrate-assessment-context() appends a timestamped JSON record containing scope, industry-sector, mosca-parameters (X, Y, Z, safety margin Z - (X+Y)), gateway-header-limit-kb, qvar-sector-multiplier, compensating-controls-note, and project-tier-overrides.
- Pre-Configured Industry Vertical Profiles: Built-in mathematical baselines for BFSI-BANKING (X=15y, Y=3y, mult=1.35x), HEALTHCARE-GENOMICS (X=35y, Y=5y, mult=1.50x), PUBLIC-SECTOR-DEFENSE (X=30y, Y=4y, Z=7.5y, mult=1.60x), TELECOM-5G-CLOUD (X=10y, Y=3y, mult=1.25x), and ENERGY-OT-INDUSTRIAL (X=12y, Y=7y, mult=1.30x).
- Automatic Pre-Scan Context Injection: Before executing scan-organization-pqc-readiness or run-quantum-cryptanalysis-simulation, the agent calls get-historical-calibration-profile(scope), retrieving the latest learned parameters and historical audit trail so responses automatically self-calibrate across turns and sessions.

## 6. Deterministic Scorecard Equations, CycloneDX v1.6 Schema & Refactoring Blueprints

### 6.1 Separation of Asymmetric and Symmetric Denominators (Zero-Hallucination Guardrail)

To prevent LLMs from conflating symmetric AES-256 keys with asymmetric RSA/ECC keys, -compute-metrics-for-keys() pre-computes 7 locked KPIs in validated-executive-scorecard: (1) Asymmetric PQC Migration Score = Approved-PQC-Asymmetric-Keys / Total-Active-Asymmetric-Keys; (2) Symmetric Grover Resilience Score = AES256-And-SHA256-Keys / Total-Active-Symmetric-Keys; (3) Symmetric Rotation Hygiene Score = Symmetric-Keys-With-Rotation-<=90d / Total-Active-Symmetric-Keys; (4) Application PQC Compatibility Score; (5) Network TLS 1.3 Hybrid Readiness Score; (6) BYOK Import Transport Score; and (7) Weighted Overall PQC Maturity Index.

### 6.2 Application SDK & Gateway Refactoring Specifications

| Breaking Change Vector | Legacy Classical Pattern | Target Post-Quantum Pattern (Google Cloud) | Required Infrastructure / Schema Pre-Requisite |
| --- | --- | --- | --- |
| Asymmetric Encryption / Wrapping | Cloud KMS AsymmetricDecrypt(ciphertext) with RSA-DECRYPT-OAEP-2048-SHA256 (256B ciphertext) | Client-side KEM Encapsulate() + Cloud KMS Decapsulate() with KEM-XWING (1,120B ciphertext) or Google Tink HPKE | Widen database ciphertext columns from VARBINARY(256) to VARBINARY(2048) before key cutover. |
| Digital Signatures & JWT Tokens | Cloud KMS AsymmetricSign(digest) with EC-SIGN-P256-SHA256 (64B signature) | Cloud KMS AsymmetricSign(data) with PQ-SIGN-ML-DSA-65 (3,309B signature / ~4.4KB Base64URL JWT) | Increase Envoy max-request-headers-kb and NGINX large-client-header-buffers to 16KB-32KB. |
| External Ingress TLS Handshake | Compute SslPolicy TLS-1-0 / TLS-1-2 MODERN profile (ECDHE-RSA) | Compute SslPolicy minTlsVersion=TLS-1-3 + profile=RESTRICTED (X25519MLKEM768 hybrid KEM) | Verify middlebox/firewall DPI MTU handling for 1,120B hybrid key-share ClientHello frames. |
| Preventive Governance Guardrails | Unrestricted KMS algorithm creation across GCP projects | Custom Org Policies: custom.pqcEnforceQuantumSafeKmsAlgorithms & custom.pqcEnforceSymmetricKeyRotation90d | Deploy via gcloud org-policies set-policy at Folder/Org scope after canary validation. |

## Part III — Consultant & Engineer Deployment How-To Guide & Calibration Library

## 1. Operational Workflow & Cross-Document Integration

To execute a consistent, high-margin PQC Readiness Assessment, the practitioner follows a 4-step closed-loop operational workflow that connects all documents in the Technical and Executive folders:

1. Step 1 — Deploy & Authenticate (Sections 2 & 3 below): Deploy the agent either in the Consultant's workstation/Cloud Shell (Topology C) or inside the Customer's contracted GCP environment (Topology A/B, as architected in Agentic PQC Technical Architecture and Consultant Guide) and bind the 4 read-only IAM roles.
2. Step 2 — Calibrate with Stakeholder Discovery Context (Section 4 below): Conduct the 7-domain interview using Agentic PQC Discovery Questionnaire and run the Calibration Prompts below. The agent invokes calibrate-assessment-context() (specified in Agentic PQC Technical Architecture and Consultant Guide) to persist sector parameters (X, Y, Z, gateway limits, and project overrides) into its historical ledger.
3. Step 3 — Execute Self-Calibrated Multi-Layer Scan (Section 5 below): Run the full assessment prompt. The agent automatically retrieves its learned history via get-historical-calibration-profile(), scans all 4 GCP telemetry layers, runs the 10,000-iteration Monte Carlo Q-VaR simulation, and synthesizes the 6-part consultative report.
4. Step 4 — Export Multi-Persona Deliverables & Execute Runbooks (Section 6 below): Export the Executive Board Report (aligned with Agentic PQC Security Recommendations Book), the Technical Engineering Playbook (5-step Cloud HSM runbooks), and the OWASP CycloneDX v1.6 CBOM (.json).

### 1.1 Template Execution Channels Summary

| Execution Channel | Template Endpoint / Command Pattern | Primary Operator & Use Case |
| --- | --- | --- |
| Google ADK Developer Web UI (Local / Cloud Shell) | adk web (http://localhost:8000 -> select pqc-inventory-agent) | Consultant / Engineer live tool tracing, interactive calibration, and debugging. |
| FastAPI Consultative Web UI & SSE Server | https://<CLOUD-RUN-SERVICE>-<PROJECT-NUM>.<REGION>.run.app | Customer workshops, live streaming executive demos, and 1-click report downloads. |
| Vertex AI Agent Engine (Gemini Enterprise) | projects/<PROJECT-NUM>/locations/<REGION>/reasoningEngines/<ENGINE-ID> | Managed enterprise conversational access inside customer's Gemini Enterprise portal. |
| Headless CLI Multi-Persona Exporter | python3 main.py --scope organizations/<CUSTOMER-ORG-ID> --export-dir ./exports | Automated batch generation of Markdown, print-to-PDF HTML, and CycloneDX v1.6 CBOM. |

## 2. Part 1 — How-To: Deploying in the Consultant / Engineer Environment

Use this workflow when running the agent from a PSO Consultant laptop, Google Cloud Shell, or an isolated PSO Sandbox project to assess a customer organization via keyless Service Account impersonation:

1. Step 2.1 — Install Toolchain & Python Virtual Environment: Ensure Python 3.11+ and Google Cloud SDK (gcloud) are installed. Clone the accelerator repository and install locked dependencies: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
2. Step 2.2 — Authenticate via Keyless Application Default Credentials (ADC): Never download static Service Account JSON keys. Authenticate with your corporate identity and impersonate the customer's read-only scanner Service Account: gcloud auth application-default login --impersonate-service-account=pqc-scanner-sa@<CUSTOMER-HOST-PROJECT-ID>.iam.gserviceaccount.com
3. Step 2.3 — Configure the Local Environment Template (.env): Create a .env file in the project root with the customer's target scope: GOOGLE-GENAI-USE-VERTEXAI=TRUE, GOOGLE-CLOUD-PROJECT=<CONSULTANT-OR-HOST-PROJECT-ID>, GOOGLE-CLOUD-LOCATION=global, PQC-AGENT-MODEL=gemini-3.1-pro-preview-customtools, PQC-TARGET-ORG-ID=organizations/<CUSTOMER-ORG-ID>, and PQC-CALIBRATION-STORE-PATH=./exports/calibration-history.jsonl.
4. Step 2.4 — Launch Interactive ADK Web UI or FastAPI Server: Run adk web --port 8000 (for the native ADK trace inspector) OR uvicorn main:app --host 0.0.0.0 --port 8080 (for the Google Cloud Consulting styled Web UI with SSE streaming and deliverable export buttons).

## 3. Part 2 — How-To: Deploying in the Customer's Contracted GCP Environment

Use this workflow when deploying the agent as a permanent or engagement-long single-tenant service inside the customer's own Google Cloud Organization (Topology A in Agentic PQC Technical Architecture and Consultant Guide):

1. Step 3.1 — Enable Required Control-Plane APIs in the Customer Host Project: Run gcloud services enable aiplatform.googleapis.com run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com cloudasset.googleapis.com cloudkms.googleapis.com privateca.googleapis.com compute.googleapis.com cloudresourcemanager.googleapis.com --project=<CUSTOMER-HOST-PROJECT-ID>
2. Step 3.2 — Create the Dedicated Read-Only Scanner Service Account: Run gcloud iam service-accounts create pqc-scanner-sa --display-name="PQC Readiness Assessment Scanner SA" --project=<CUSTOMER-HOST-PROJECT-ID>
3. Step 3.3 — Bind Least-Privilege Read-Only Roles at the Customer Organization Scope: Grant the 4 metadata-only viewer roles across organizations/<CUSTOMER-ORG-ID> (for ROLE in roles/cloudasset.viewer roles/cloudkms.viewer roles/privateca.auditor roles/compute.viewer; do gcloud organizations add-iam-policy-binding <CUSTOMER-ORG-ID> --member="serviceAccount:pqc-scanner-sa@<CUSTOMER-HOST-PROJECT-ID>.iam.gserviceaccount.com" --role="$ROLE"; done) and grant roles/aiplatform.user on <CUSTOMER-HOST-PROJECT-ID> so the Service Account can invoke Vertex AI Gemini.
4. Step 3.4 — Deploy to Customer Google Cloud Run (Zero-Trust Internal + IAP): Run gcloud run deploy pqc-inventory-agent --source=. --region=<REGION> --project=<CUSTOMER-HOST-PROJECT-ID> --service-account=pqc-scanner-sa@<CUSTOMER-HOST-PROJECT-ID>.iam.gserviceaccount.com --no-allow-unauthenticated --ingress=internal-and-cloud-load-balancing --set-env-vars="GOOGLE-GENAI-USE-VERTEXAI=TRUE,GOOGLE-CLOUD-PROJECT=<CUSTOMER-HOST-PROJECT-ID>,GOOGLE-CLOUD-LOCATION=global,PQC-TARGET-ORG-ID=organizations/<CUSTOMER-ORG-ID>"
5. Step 3.5 — Deploy to Vertex AI Agent Engine (Reasoning Engine / Gemini Enterprise): Run adk deploy agent-engine --project=<CUSTOMER-HOST-PROJECT-ID> --region=<REGION> --staging-bucket=gs://<CUSTOMER-STAGING-BUCKET> pqc-agent. Record the output resource URI (projects/<PROJECT-NUM>/locations/<REGION>/reasoningEngines/<ENGINE-ID>) in the Customer Configuration Manifest of Agentic PQC Technical Architecture and Consultant Guide and Agentic PQC Technical Architecture and Consultant Guide.

## 4. Part 3 — Calibration Prompts Library (Sector, Mosca X+Y>Z & Constraint Tuning)

Before running the final executive readout, use the copy-pasteable Calibration Prompts below to feed the answers collected from Agentic PQC Discovery Questionnaire into the agent. Each prompt triggers calibrate-assessment-context() so the agent stores and learns the customer's exact context:

| Calibration Scenario | Target Discovery Domains | Copy-Paste Calibration Prompt for ADK Web UI / Gemini Enterprise |
| --- | --- | --- |
| 1. Industry Sector & Mosca (X, Y, Z) Baseline Calibration | Domains 1, 2 & 7<br>(Sector, Shelf-Life X, Velocity Y) | Calibrate the PQC assessment context for scope organizations/<CUSTOMER-ORG-ID> with industry-sector='<BFSI-BANKING | HEALTHCARE-GENOMICS | PUBLIC-SECTOR-DEFENSE | TELECOM-5G-CLOUD | ENERGY-OT-INDUSTRIAL>', confidentiality-years-x=<X-YEARS>, migration-years-y=<Y-YEARS>, and crqc-horizon-years-z=<Z-YEARS>. Persist this baseline in the historical calibration ledger and display the resulting Mosca safety margin (Z - (X+Y)) and active regulatory frameworks. |
| 2. API Gateway HTTP Header & JWT Buffer Calibration | Domains 4 & 5<br>(JWT Signing & Proxy Limits) | Update the calibration profile for organizations/<CUSTOMER-ORG-ID>: our API Gateways and Envoy/NGINX proxies currently enforce gateway-header-limit-kb=<4 | 8 | 16 | 32>. Evaluate whether 3,309-byte ML-DSA-65 JWT signatures (~4.4 KB Base64URL) will trigger HTTP 431 Request Header Fields Too Large errors and calibrate all engineering runbooks accordingly. |
| 3. Project-Tier Criticality & Crown-Jewel Override Calibration | Domains 2 & 3<br>(Business Unit Prioritization) | Calibrate project-tier-overrides for organizations/<CUSTOMER-ORG-ID>: classify projects [<TIER-0-PROJECT-IDS>] as Tier-0 Crown-Jewel workloads with X=<25> years confidentiality requirement, and projects [<SANDBOX-PROJECT-IDS>] as Tier-3 non-production sandboxes. Ensure all subsequent Q-VaR simulations and 30-60-90 day workstreams prioritize Tier-0 keys first. |
| 4. Compensating Controls & BYOK/VPC-SC Calibration | Domains 2, 3 & 6<br>(VPC-SC, HSM & Exceptions) | Record compensating-controls-note for organizations/<CUSTOMER-ORG-ID>: '<e.g., BigQuery datasets in project X are enclosed in a VPC-SC perimeter; legacy RSA key Y is scheduled for decommissioning in 30 days>'. Recalibrate our historical posture profile and adjust remediation urgency. |
| 5. Inspect Learned Historical Calibration Ledger | All Domains<br>(Governance & Drift Verification) | Retrieve the active historical calibration profile for organizations/<CUSTOMER-ORG-ID> using get-historical-calibration-profile. Summarize all learned parameters, historical calibration events, active Mosca (X+Y vs Z) verdicts, and sector Q-VaR multipliers currently governing the agent. |
| 6. Full Self-Calibrated Assessment & Deliverable Export | All 4 Telemetry Layers + Learned Calibration | Run a complete, self-calibrated Post-Quantum Cryptography (PQC) Readiness Assessment and Step-by-Step Execution Guide for organizations/<CUSTOMER-ORG-ID>. First load our learned historical calibration profile, then correlate scan-organization-pqc-readiness, scan-ssl-policies, scan-import-jobs-pqc, and run-quantum-cryptanalysis-simulation, and export all Executive, Engineering, and CycloneDX v1.6 CBOM deliverables. |

## 5. Part 4 — How Automated Self-Calibration & Continuous Historical Learning Work

The Agentic PQC Readiness & CBOM Engine is engineered so that its responses automatically self-calibrate over time by learning from its interaction history (implemented in tools/calibration-engine.py and enforced by SYSTEM-INSTRUCTION in pqc-agent/agent.py):

- 1. Persistent Longitudinal Memory (calibration-history.jsonl): Every time a consultant or customer engineer provides organizational context, answers a discovery question, or overrides a parameter (such as adjusting X from 10 to 25 years for biometric data or noting an 8KB Apigee header limit), the agent invokes calibrate-assessment-context() to append a structured JSON event to the calibration ledger.
- 2. Automatic Pre-Scan Recall (Zero Re-Prompting Required): Under Mandatory Rule #2 of the agent's system instruction, before generating any readiness assessment or quantum risk simulation, the agent automatically calls get-historical-calibration-profile(scope). It reads the cumulative calibration history for that organization, extracts the most recent sector multipliers, Mosca (X, Y, Z) horizons, gateway constraints, and compensating controls, and applies them automatically.
- 3. Progressive Refinement Across Engagement Phases: In Week 1 (Mobilization), the agent starts with the industry vertical baseline (e.g., BFSI-BANKING: X=15y, Y=3y). In Week 2 (Deep Discovery), as application and PKI owners refine gateway limits and project tiers via Calibration Prompts 2–4, the agent's risk rankings, Q-VaR figures, and refactoring runbooks automatically adapt to reflect the newly learned architectural reality.
- 4. Multi-Customer Isolation & Ledger Reset: Each calibration entry is keyed by scope (organizations/<CUSTOMER-ORG-ID>). When starting an engagement for a new customer, specifying the new Organization ID or pointing PQC-CALIBRATION-STORE-PATH to a dedicated customer bucket guarantees 100% tenant isolation.

## 6. Part 5 — Operational Troubleshooting & Post-Execution Verification Checklist

| Symptom / Error Code | Root Cause Analysis | Prescriptive Resolution Command / Action |
| --- | --- | --- |
| HTTP 403 PERMISSION-DENIED on Cloud KMS or CAI | Scanner Service Account lacks organization-level viewer bindings or impersonation permission. | Verify roles/cloudasset.viewer and roles/cloudkms.viewer on organizations/<CUSTOMER-ORG-ID> and roles/iam.serviceAccountTokenCreator for impersonation. |
| Agent attempts to scan project-*-tp sandbox | Vertex AI Agent Engine injects its internal runtime tenant project ID by default. | Resolved automatically by -resolve-scope() in tools/gcp-inventory.py; always pass organizations/<CUSTOMER-ORG-ID> explicitly in prompts. |
| HTTP 429 RESOURCE-EXHAUSTED on Vertex AI | Concurrent tool payloads or regional Gemini quota saturation. | Set GOOGLE-CLOUD-LOCATION=global when using gemini-3.1-pro-preview-customtools or switch PQC-AGENT-MODEL to gemini-2.5-pro. |
| VPC Service Controls (VPC-SC) Violation | Customer perimeter blocks ingress from external workstation or Cloud Run service. | Deploy the agent inside the customer's VPC-SC perimeter (Topology A) or add an ingress policy allowing pqc-scanner-sa. |
