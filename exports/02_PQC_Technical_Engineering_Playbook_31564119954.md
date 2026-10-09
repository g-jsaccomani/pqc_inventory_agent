# GOOGLE CLOUD CONSULTING — TECHNICAL ENGINEERING PLAYBOOK
## Post-Quantum Cryptography (PQC) Step-by-Step Environment Execution & Refactoring Guide
*(Audience: Security Architects, Cloud Platform Engineers, SRE, DevSecOps & Application Developers)*

| Technical Metadata | Validated Value |
| :--- | :--- |
| **Evaluated GCP Scope** | `organizations/31564119954` (Location Scope: `all`) |
| **Telemetry Authenticity** | `LIVE_GCP_TELEMETRY_VERIFIED` (`2.0.0-GidneyEkera-Roetteler-CoreSVP-Validated`) |
| **Total Active KMS Keys & Workloads** | `17` Active KMS Keys / `21` Consuming Workloads |
| **Vulnerable Keys Requiring Runbooks** | `3` Asymmetric Classical Keys (`RSA` / `ECDSA`) + `0` Symmetric Rotation Updates |

---

## 1. Quantum Physics Cryptanalysis & Priority Fall-Order Matrix
**Engineering Rationale (Gidney-Ekerå 2021, Roetteler et al. 2017 & Lattice Core-SVP):** Shor's algorithm scales as $O(n^3)$ for integer factorization (RSA) and $O(n)$ in key bit-length for elliptic curve discrete logarithms (ECDSA/Ed25519). Consequently, `ECDSA P-256` (`2,330` logical qubits) and `ECDSA P-384` (`3,484` logical qubits) require fewer fault-tolerant qubits than `RSA-2048` (`4,098` logical qubits) and must be remediated first alongside HNDL decryption keys.

### 1.1. Vulnerable Classical Keys Ranked by Quantum Fall-Order
| Project & KMS Key | Algorithm & Fall Rank | Logical / Physical Qubits | Toffoli Gates & Surface Code | Target PQC & Lattice Hardness |
| :--- | :--- | :--- | :--- | :--- |
| `pqc-inventory-agent-cd06/kr-pqc-enterprise-prod/legacy-ecdsa-p256-sign (global)` | `EC_SIGN_P256_SHA256` (Rank #1) | `2330` logical / `13400000` physical | `1.26e11` gates (`d=27`, `9.5h`) | `PQ_SIGN_ML_DSA_65 (or PQ_SIGN_ML_DSA_87 for CNSA 2.0)` (`174-bit` Core-SVP) |
| `fnlab-apps-8fa913/kr-iso-legacy-apps/jwt-signing-rsa2048 (us-central1)` | `RSA_SIGN_PSS_2048_SHA256` (Rank #3) | `4098` logical / `20000000` physical | `2.70e9` gates (`d=27`, `8.0h`) | `PQ_SIGN_ML_DSA_65 (or PQ_SIGN_ML_DSA_87 for CNSA 2.0)` (`174-bit` Core-SVP) |
| `pqc-inventory-agent-cd06/kr-pqc-enterprise-prod/legacy-rsa-oaep-decrypt (global)` | `RSA_DECRYPT_OAEP_2048_SHA256` (Rank #3) | `4098` logical / `20000000` physical | `2.70e9` gates (`d=27`, `8.0h`) | `KEM_XWING (or ML_KEM_1024 for CNSA 2.0)` (`167-bit` Core-SVP) |

---

## 2. Per-Application PQC Compatibility & API/Payload Impact Matrix
| Consuming Application & Workload | Service Account & Key | Algorithm (Current ➡️ Target) | API Contract Migration | Payload & Gateway Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Hardened GKE Cluster — etcd Application-Layer Secrets Encryption** (`api-sec-poc-1582` — Google Kubernetes Engine (GKE Cluster)) | `gke-node-sa@api-sec-poc-1582.iam.gserviceaccount.com`<br/>Key: `hsm-keyring/etcd-encryption-key (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **GKE Security Telemetry Warehouse** (`api-sec-poc-1582` — BigQuery Dataset) | `sa-orchestrator@api-sec-poc-1582.iam.gserviceaccount.com`<br/>Key: `hsm-keyring/etcd-encryption-key (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **Cloud Security Agentic Web UI & Collector** (`api-sec-poc-1582` — Cloud Run Service & Artifact Registry) | `apispr-prereq-cloudrun-sa@api-sec-poc-1582.iam.gserviceaccount.com`<br/>Key: `hsm-keyring/registry-encryption-key (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **ApiSPR Telemetry & WAAP Analytics Pipeline** (`api-sec-poc-1582` — BigQuery Analytics Datasets (apispr_inventory, apispr_waap, raw_telemetry_lake)) | `sa-orchestrator@api-sec-poc-1582.iam.gserviceaccount.com`<br/>Key: `hsm-keyring/registry-encryption-key (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **ApexFin Payment API Microservice** (`fnlab-apps-8fa913` — Compute Engine VM Microservice (OAuth 2.0 / OIDC JWT Issuer)) | `sa-api-payment-svc@fnlab-apps-8fa913.iam.gserviceaccount.com`<br/>Key: `kr-iso-legacy-apps/jwt-signing-rsa2048 (us-central1)` | `RSA_SIGN_PSS_2048_SHA256` ➡️ `PQ_SIGN_ML_DSA_65 (or PQ_SIGN_ML_DSA_87 for CNSA 2.0)` | `BREAKING CHANGE: kms.AsymmetricSign(digest={'sha256': ...}) -> kms.AsymmetricSign(data=raw_bytes) [or SHAKE256 external_mu]` | BREAKING PROTOCOL & PAYLOAD IMPACT: Migrating from RSA_SIGN_PSS_2048_SHA256 (256-byte signature) to NIST FIPS 204 PQ_SIGN_ML_DSA_65 (3,309-byte signature, 1,952-byte public key) increases signature payload size by 12.9x and changes the Cloud KMS signing input contract. |
| **ApexFin Legacy CRM & Sync Agent** (`fnlab-apps-8fa913` — Compute Engine Legacy Application (JWT Verifier & API Consumer)) | `sa-legacy-sync-agent@fnlab-apps-8fa913.iam.gserviceaccount.com`<br/>Key: `kr-iso-legacy-apps/jwt-signing-rsa2048 (us-central1)` | `RSA_SIGN_PSS_2048_SHA256` ➡️ `PQ_SIGN_ML_DSA_65 (or PQ_SIGN_ML_DSA_87 for CNSA 2.0)` | `BREAKING CHANGE: kms.AsymmetricSign(digest={'sha256': ...}) -> kms.AsymmetricSign(data=raw_bytes) [or SHAKE256 external_mu]` | BREAKING PROTOCOL & PAYLOAD IMPACT: Migrating from RSA_SIGN_PSS_2048_SHA256 (256-byte signature) to NIST FIPS 204 PQ_SIGN_ML_DSA_65 (3,309-byte signature, 1,952-byte public key) increases signature payload size by 12.9x and changes the Cloud KMS signing input contract. |
| **ApexFin Legacy CRM Storage & Disk Layer** (`fnlab-apps-8fa913` — Cloud Storage Bucket & Compute Engine Persistent Disk (vm-legacy-crm)) | `sa-legacy-sync-agent@fnlab-apps-8fa913.iam.gserviceaccount.com`<br/>Key: `kr-iso-legacy-apps/kms-key-legacy-insecure (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **ApexFin Core Application Data Service** (`fnlab-apps-8fa913` — Cloud Storage Bucket & Payment Microservice (vm-payment-api)) | `sa-api-payment-svc@fnlab-apps-8fa913.iam.gserviceaccount.com`<br/>Key: `poc-keyring-apps/poc-key-app-data (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **ApexFin Archival & Disaster Recovery Backup Service** (`fnlab-apps-8fa913` — Cloud Storage Archival Buckets (bkt-fnlab-app-backups-e375a6, poc-bucket-backup-apps-8fa913)) | `sa-backend-deployer@fnlab-apps-8fa913.iam.gserviceaccount.com`<br/>Key: `poc-keyring-apps/poc-key-backup-long (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **ApexFin Session & Token Cache Service** (`fnlab-apps-8fa913` — Compute Engine Token Store Workload) | `poc-sa-reader@fnlab-apps-8fa913.iam.gserviceaccount.com`<br/>Key: `poc-keyring-apps/poc-key-tokens-stale (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **bkt-iso-compliant-records-a3540b (Live CMEK Resource in 791284238373)** (`fnlab-sec-mgmt-8fa913` — storage.googleapis.com/Bucket (Direct CMEK Binding)) | `gcp-cmek-service-agent@791284238373.iam.gserviceaccount.com`<br/>Key: `kr-iso-compliance-mgmt/kms-key-fintech-compliant (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **Enterprise SIEM Log Ingestion Forwarder** (`fnlab-sec-mgmt-8fa913` — Log Sink & Security Telemetry Pipeline) | `sa-siem-forwarder@fnlab-sec-mgmt-8fa913.iam.gserviceaccount.com`<br/>Key: `kr-iso-compliance-mgmt/kms-key-fintech-compliant (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **Central Security Analytics & Bastion Host** (`fnlab-sec-mgmt-8fa913` — BigQuery Dataset & Compute Engine Bastion (vm-mgmt-bastion)) | `1002674382623-compute@developer.gserviceaccount.com`<br/>Key: `kr-security-mgmt/key-root-database-encryption (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **AISPR Security Posture Collector** (`fnlab-sec-mgmt-8fa913` — Automated Security Posture Service) | `sa-aispr-auditor@fnlab-sec-mgmt-8fa913.iam.gserviceaccount.com`<br/>Key: `poc-keyring-sec/poc-key-audit-software (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **SecMgmt Security Event Warehouse** (`fnlab-sec-mgmt-8fa913` — Cloud Storage Bucket & BigQuery Activity Tables) | `sa-iso-compliant-auditor@fnlab-sec-mgmt-8fa913.iam.gserviceaccount.com`<br/>Key: `poc-keyring-sec/poc-key-database-hsm (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **SecMgmt Payment Vault Storage** (`fnlab-sec-mgmt-8fa913` — Cloud Storage HSM-Protected Bucket) | `sa-iso-compliant-auditor@fnlab-sec-mgmt-8fa913.iam.gserviceaccount.com`<br/>Key: `poc-keyring-sec/poc-key-payments-hsm (us-central1)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **Vertex AI Agent Engine Staging & Artifact Store** (`pqc-inventory-agent-cd06` — Cloud Storage Bucket & Vertex AI Reasoning Engine) | `110254026096-compute@developer.gserviceaccount.com`<br/>Key: `kr-pqc-enterprise-prod/cmek-aes256-datalake (global)` | `GOOGLE_SYMMETRIC_ENCRYPTION` ➡️ `GOOGLE_SYMMETRIC_ENCRYPTION` | `NONE (Transparent AES-256-GCM CMEK / KMS Encrypt-Decrypt API)` | 100% PQC-Compatible: AES-256 / SHA-256+ maintains 128 bits of effective post-quantum security against Grover's Algorithm. Managed GCP services (BigQuery, Cloud Storage, GKE etcd, Compute Engine, Cloud Run) handle CMEK wrapping transparently with zero payload expansion or code changes. |
| **Legacy Webhook & Artifact Attestation Signer** (`pqc-inventory-agent-cd06` — Cloud Run Microservice (Webhook & CI/CD Attestation Module)) | `110254026096-compute@developer.gserviceaccount.com`<br/>Key: `kr-pqc-enterprise-prod/legacy-ecdsa-p256-sign (global)` | `EC_SIGN_P256_SHA256` ➡️ `PQ_SIGN_ML_DSA_65 (or PQ_SIGN_ML_DSA_87 for CNSA 2.0)` | `BREAKING CHANGE: kms.AsymmetricSign(digest={'sha256': ...}) -> kms.AsymmetricSign(data=raw_bytes) [or SHAKE256 external_mu]` | BREAKING PROTOCOL & PAYLOAD IMPACT: Migrating from EC_SIGN_P256_SHA256 (64-byte signature) to NIST FIPS 204 PQ_SIGN_ML_DSA_65 (3,309-byte signature, 1,952-byte public key) increases signature payload size by 51.7x and changes the Cloud KMS signing input contract. |
| **Legacy Partner Payload & DEK Unwrapper Service** (`pqc-inventory-agent-cd06` — Cloud Run Microservice (Partner Envelope Decryption Module)) | `110254026096-compute@developer.gserviceaccount.com`<br/>Key: `kr-pqc-enterprise-prod/legacy-rsa-oaep-decrypt (global)` | `RSA_DECRYPT_OAEP_2048_SHA256` ➡️ `KEM_XWING (or ML_KEM_1024 for CNSA 2.0)` | `BREAKING CHANGE: kms.AsymmetricDecrypt(ciphertext) -> kms.Decapsulate(ciphertext) + HKDF-SHA256 + AES-256-GCM` | HIGH ARCHITECTURAL IMPACT: Classical RSA-OAEP encrypts arbitrary small payloads or DEKs directly (256-byte ciphertext for RSA-2048). NIST FIPS 203 PQC algorithms (KEM_XWING / ML_KEM_1024) are Key Encapsulation Mechanisms (KEM), NOT public-key encryption ciphers. Ciphertext expands from 256 bytes to 1,120 bytes (KEM_XWING) or 1,568 bytes (ML_KEM_1024), and the API returns a 32-byte shared_secret instead of decrypted plaintext. |
| **PQC Zero-Trust Key Encapsulation Gateway** (`pqc-inventory-agent-cd06` — Cloud Run Microservice & Vertex AI Agent Engine) | `110254026096-compute@developer.gserviceaccount.com`<br/>Key: `kr-pqc-enterprise-prod/pqc-kem-xwing-hybrid (global)` | `KEM_XWING` ➡️ `KEM_XWING` | `NONE (Already using NIST PQC Cloud KMS API)` | Application is already engineered for PQC artifact sizes (1,120–1,568B KEM ciphertexts or 3,309–7,856B PQC signatures) and PQC KMS APIs. |
| **PQC Artifact & CBOM Attestation Service** (`pqc-inventory-agent-cd06` — Cloud Run Microservice & Vertex AI Agent Engine) | `110254026096-compute@developer.gserviceaccount.com`<br/>Key: `kr-pqc-enterprise-prod/pqc-sign-mldsa65 (global)` | `PQ_SIGN_ML_DSA_65` ➡️ `PQ_SIGN_ML_DSA_65` | `NONE (Already using NIST PQC Cloud KMS API)` | Application is already engineered for PQC artifact sizes (1,120–1,568B KEM ciphertexts or 3,309–7,856B PQC signatures) and PQC KMS APIs. |

---

## 3. Step-by-Step Environment Execution Workstreams (By Architectural Layer)
### Fase 1 (Dia 0–15): Governança Preventiva e Higiene de Rotação Simétrica (Zero Downtime)
- **Engineering Objective:** Bloquear a criação de novas chaves clássicas RSA/ECC na Organização e aplicar rotação automática <= 90 dias em todas as chaves CMEK AES-256 sem impacto nas aplicações.
  - 1. Aplicar as Custom Constraints de Organization Policy (`custom.pqcEnforceQuantumSafeKmsAlgorithms` e `custom.pqcEnforceSymmetricKeyRotation90d`) na Organização `31564119954` em modo dry-run/enforced.
  - 2. Executar os 0 comandos `gcloud kms keys update --rotation-period=90d` listados em `symmetric_rotation_playbooks`.
  - 3. Validar que 100% das chaves simétricas exibem `COMPLIANT_ROTATION_90D` e que tentativas de criar chaves `RSA_*` ou `EC_*` são bloqueadas pela política organizacional.

### Fase 2 (Dia 15–30): Blindagem de Perímetro de Rede e TLS 1.3 Hybrid PQC (X25519MLKEM768)
- **Engineering Objective:** Eliminar a captura passiva de pacotes (HNDL em trânsito) nos Cloud Load Balancers e expandir buffers HTTP antes da migração de assinaturas PQC.
  - 1. Criar ou atualizar políticas `compute.sslPolicies` com `--min-tls-version=1.3 --profile=RESTRICTED` em todos os projetos com ingress externo/interno para habilitar a troca de chaves híbrida `X25519MLKEM768`.
  - 2. Associar a SSL Policy a todos os `target-https-proxies` e `target-ssl-proxies` (`gcloud compute target-https-proxies update <PROXY> --ssl-policy=<POLICY>`).
  - 3. Ajustar `max_request_headers_kb: 32` no Envoy/Istio e `large_client_header_buffers 4 32k` no NGINX/Apigee para suportar tokens JWT/cabeçalhos assinados com `ML-DSA-65` (~4.4 KB Base64URL).

### Fase 3 (Dia 30–60): Mitigação Crítica de HNDL em Chaves de Decriptação (RSA-OAEP -> KEM_XWING / ML-KEM-1024)
- **Engineering Objective:** Substituir chaves `ASYMMETRIC_DECRYPT` vulneráveis ao Algoritmo de Shor por mecanismos de encapsulamento pós-quânticos em Cloud HSM (`--protection-level=hsm`).
  - 1. Expandir colunas de banco de dados/metadados que armazenam DEKs encapsuladas de 256 bytes para >= 1.568 bytes (`VARBINARY(2048)`).
  - 2. Provisionar as chaves substitutas `KEM_XWING` (ou `ML_KEM_1024` para CNSA 2.0) com `--purpose=key-encapsulation --protection-level=hsm` e conceder `roles/cloudkms.cryptoKeyDecapsulator` às Service Accounts consumidoras.
  - 3. Refatorar os microsserviços consumidores de `kms.AsymmetricDecrypt` para `kms.Decapsulate` + `HKDF-SHA256` + `AES-256-GCM` (RFC 9180 HPKE / Google Tink SDK) e desativar as versões RSA legadas após re-encapsulamento.

### Fase 4 (Dia 60–90): Migração de Assinaturas Digitais, Tokens JWT e PKI (RSA/ECDSA -> ML-DSA-65 / ML-DSA-87)
- **Engineering Objective:** Eliminar o risco de falsificação quântica de identidade, tokens OAuth/JWT e webhooks com NIST FIPS 204 (`PQ_SIGN_ML_DSA_65`).
  - 1. Provisionar as chaves `PQ_SIGN_ML_DSA_65` (ou `PQ_SIGN_ML_DSA_87`) em Cloud HSM (`--protection-level=hsm`) e vincular `roles/cloudkms.signerVerifier` às Service Accounts emissoras.
  - 2. Refatorar as chamadas de assinatura no código de `AsymmetricSign(digest={'sha256': ...})` para `AsymmetricSign(data=raw_bytes)` (ou calcular `mu` de 64 bytes via SHAKE256 em modo `_EXTERNAL_MU`).
  - 3. Atualizar os verificadores consumidores (OpenSSL 3.5+ / BoringSSL / Tink) com a nova chave pública ML-DSA-65 (1.952 bytes) e desativar as versões RSA/ECDSA antigas.

### Fase 5 (Contínuo): BYOK/EKM Pós-Quântico, Descomissionamento Seguro e Atestação CBOM CycloneDX 1.6
- **Engineering Objective:** Garantir que chaves importadas (BYOK) utilizem wrapping compatível com PQC e auditar o estado final do ambiente.
  - 1. Substituir `ImportJobs` legados por `--import-method=rsa-oaep-3072-sha256-aes-256` ou `rsa-oaep-4096-sha256-aes-256`.
  - 2. Executar os comandos `post_migration_disable_legacy_command` e `post_change_validation_command` para confirmar que nenhuma versão clássica `RSA_*` ou `EC_*` permanece `ENABLED`.
  - 3. Exportar o inventário final `CycloneDX v1.6 CBOM` para registro de conformidade NIST IR 8547 e NSA CNSA 2.0.

---

## 4. Asset-by-Asset 5-Step Execution Runbooks (`gcloud kms`, IAM & Verification)
### 4.1. Asymmetric Classical Key Migration Runbooks (100% of Vulnerable Keys)
#### 4.1.1. Key `fnlab-apps-8fa913/kr-iso-legacy-apps/jwt-signing-rsa2048 (us-central1)` (`RSA_SIGN_PSS_2048_SHA256`) ➡️ `PQ_SIGN_ML_DSA_65 (or PQ_SIGN_ML_DSA_87 for CNSA 2.0)`
- **Consuming Applications:** `ApexFin Payment API Microservice, ApexFin Legacy CRM & Sync Agent`
- **Current State Evaluation:** Key 'fnlab-apps-8fa913/kr-iso-legacy-apps/jwt-signing-rsa2048' (us-central1) currently uses classical algorithm 'RSA_SIGN_PSS_2048_SHA256' with protection_level='SOFTWARE' and is consumed by 2 workload(s): ApexFin Payment API Microservice, ApexFin Legacy CRM & Sync Agent. Mosca status: HIGH_MOSCA_BREACH_NIST_2030_DEADLINE (X+Y = 4.5 years).
- **Architectural Impact Assessment:** BREAKING PROTOCOL & PAYLOAD IMPACT: Migrating from RSA_SIGN_PSS_2048_SHA256 (256-byte signature) to NIST FIPS 204 PQ_SIGN_ML_DSA_65 (3,309-byte signature, 1,952-byte public key) increases signature payload size by 12.9x and changes the Cloud KMS signing input contract.
- **⚠️ TECHNICAL NOTE (JWT/Token Header Buffer Expansion): Increase HTTP header buffer limits (to 16KB in API Gateways/Envoy, or 32KB max_request_headers_kb) because ML-DSA-65 signatures expand Base64URL JWT tokens by ~4.4KB.**
- **5-Step Prescriptive Execution Plan:**
  - Step 1 (Pre-Flight & Gateway Header Buffer Expansion): Before switching signing keys for `ApexFin Payment API Microservice, ApexFin Legacy CRM & Sync Agent`, increase HTTP header buffer limits (`max_request_headers_kb: 32` in Envoy/Istio, `large_client_header_buffers 4 32k` in NGINX/Apigee) to prevent HTTP 431 errors when signatures expand from 64–256 bytes to 3,309 bytes (~4.4 KB Base64URL).
  - Step 2 (Provision PQC Signing Key in Cloud HSM): Execute `gcloud kms keys create jwt-signing-rsa2048-pqc-mldsa65 --project=fnlab-apps-8fa913 --location=us-central1 --keyring=kr-iso-legacy-apps --purpose=asymmetric-signing --default-algorithm=pq-sign-ml-dsa-65 --protection-level=hsm` (or `gcloud kms keys create jwt-signing-rsa2048-pqc-mldsa87 --project=fnlab-apps-8fa913 --location=us-central1 --keyring=kr-iso-legacy-apps --purpose=asymmetric-signing --default-algorithm=pq-sign-ml-dsa-87 --protection-level=hsm` for CNSA 2.0 Category 5).
  - Step 3 (Grant Least-Privilege IAM Signer/Verifier Role): Execute `gcloud kms keys add-iam-policy-binding jwt-signing-rsa2048-pqc-mldsa65 --keyring=kr-iso-legacy-apps --location=us-central1 --project=fnlab-apps-8fa913 --member='serviceAccount:sa-api-payment-svc@fnlab-apps-8fa913.iam.gserviceaccount.com' --role='roles/cloudkms.signerVerifier'` for service account `sa-api-payment-svc@fnlab-apps-8fa913.iam.gserviceaccount.com`.
  - Step 4 (Refactor KMS Signing API Contract & Verifier SDKs): Update `ApexFin Payment API Microservice, ApexFin Legacy CRM & Sync Agent` from `kms_client.asymmetric_sign(digest={'sha256': ...})` to `kms_client.asymmetric_sign(data=raw_message_bytes)` (or 64-byte SHAKE256 `mu` with `_EXTERNAL_MU`) and distribute the new 1,952-byte ML-DSA-65 public key to downstream verifiers.
  - Step 5 (Decommission Legacy Signing Key Version & Validate): Once all active tokens/artifacts issued by `jwt-signing-rsa2048` expire, execute `gcloud kms keys versions disable 1 --key=jwt-signing-rsa2048 --keyring=kr-iso-legacy-apps --location=us-central1 --project=fnlab-apps-8fa913` and validate with `gcloud kms keys describe jwt-signing-rsa2048-pqc-mldsa65 --keyring=kr-iso-legacy-apps --location=us-central1 --project=fnlab-apps-8fa913 --format='yaml(name,purpose,versionTemplate,primary)' && gcloud kms keys versions list --key=jwt-signing-rsa2048 --keyring=kr-iso-legacy-apps --location=us-central1 --project=fnlab-apps-8fa913`.
```bash
# Step 2a: Provision Recommended NIST PQC Key in Cloud HSM (FIPS 140-3 Level 3)
gcloud kms keys create jwt-signing-rsa2048-pqc-mldsa65 --project=fnlab-apps-8fa913 --location=us-central1 --keyring=kr-iso-legacy-apps --purpose=asymmetric-signing --default-algorithm=pq-sign-ml-dsa-65 --protection-level=hsm

# Step 2b: Alternative NSA CNSA 2.0 Category 5 Key Command
gcloud kms keys create jwt-signing-rsa2048-pqc-mldsa87 --project=fnlab-apps-8fa913 --location=us-central1 --keyring=kr-iso-legacy-apps --purpose=asymmetric-signing --default-algorithm=pq-sign-ml-dsa-87 --protection-level=hsm

# Step 3: Bind Least-Privilege IAM Role to Consuming Workload Service Account
gcloud kms keys add-iam-policy-binding jwt-signing-rsa2048-pqc-mldsa65 --keyring=kr-iso-legacy-apps --location=us-central1 --project=fnlab-apps-8fa913 --member='serviceAccount:sa-api-payment-svc@fnlab-apps-8fa913.iam.gserviceaccount.com' --role='roles/cloudkms.signerVerifier'

# Step 5a: Disable Legacy Classical Key Version Post-Cutover
gcloud kms keys versions disable 1 --key=jwt-signing-rsa2048 --keyring=kr-iso-legacy-apps --location=us-central1 --project=fnlab-apps-8fa913

# Step 5b: Post-Change Verification Command
gcloud kms keys describe jwt-signing-rsa2048-pqc-mldsa65 --keyring=kr-iso-legacy-apps --location=us-central1 --project=fnlab-apps-8fa913 --format='yaml(name,purpose,versionTemplate,primary)' && gcloud kms keys versions list --key=jwt-signing-rsa2048 --keyring=kr-iso-legacy-apps --location=us-central1 --project=fnlab-apps-8fa913
```

#### 4.1.2. Key `pqc-inventory-agent-cd06/kr-pqc-enterprise-prod/legacy-ecdsa-p256-sign (global)` (`EC_SIGN_P256_SHA256`) ➡️ `PQ_SIGN_ML_DSA_65 (or PQ_SIGN_ML_DSA_87 for CNSA 2.0)`
- **Consuming Applications:** `Legacy Webhook & Artifact Attestation Signer`
- **Current State Evaluation:** Key 'pqc-inventory-agent-cd06/kr-pqc-enterprise-prod/legacy-ecdsa-p256-sign' (global) currently uses classical algorithm 'EC_SIGN_P256_SHA256' with protection_level='SOFTWARE' and is consumed by 1 workload(s): Legacy Webhook & Artifact Attestation Signer. Mosca status: HIGH_MOSCA_BREACH_NIST_2030_DEADLINE (X+Y = 4.5 years).
- **Architectural Impact Assessment:** BREAKING PROTOCOL & PAYLOAD IMPACT: Migrating from EC_SIGN_P256_SHA256 (64-byte signature) to NIST FIPS 204 PQ_SIGN_ML_DSA_65 (3,309-byte signature, 1,952-byte public key) increases signature payload size by 51.7x and changes the Cloud KMS signing input contract.
- **5-Step Prescriptive Execution Plan:**
  - Step 1 (Pre-Flight & Gateway Header Buffer Expansion): Before switching signing keys for `Legacy Webhook & Artifact Attestation Signer`, increase HTTP header buffer limits (`max_request_headers_kb: 32` in Envoy/Istio, `large_client_header_buffers 4 32k` in NGINX/Apigee) to prevent HTTP 431 errors when signatures expand from 64–256 bytes to 3,309 bytes (~4.4 KB Base64URL).
  - Step 2 (Provision PQC Signing Key in Cloud HSM): Execute `gcloud kms keys create legacy-ecdsa-p256-sign-pqc-mldsa65 --project=pqc-inventory-agent-cd06 --location=global --keyring=kr-pqc-enterprise-prod --purpose=asymmetric-signing --default-algorithm=pq-sign-ml-dsa-65 --protection-level=hsm` (or `gcloud kms keys create legacy-ecdsa-p256-sign-pqc-mldsa87 --project=pqc-inventory-agent-cd06 --location=global --keyring=kr-pqc-enterprise-prod --purpose=asymmetric-signing --default-algorithm=pq-sign-ml-dsa-87 --protection-level=hsm` for CNSA 2.0 Category 5).
  - Step 3 (Grant Least-Privilege IAM Signer/Verifier Role): Execute `gcloud kms keys add-iam-policy-binding legacy-ecdsa-p256-sign-pqc-mldsa65 --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06 --member='serviceAccount:110254026096-compute@developer.gserviceaccount.com' --role='roles/cloudkms.signerVerifier'` for service account `110254026096-compute@developer.gserviceaccount.com`.
  - Step 4 (Refactor KMS Signing API Contract & Verifier SDKs): Update `Legacy Webhook & Artifact Attestation Signer` from `kms_client.asymmetric_sign(digest={'sha256': ...})` to `kms_client.asymmetric_sign(data=raw_message_bytes)` (or 64-byte SHAKE256 `mu` with `_EXTERNAL_MU`) and distribute the new 1,952-byte ML-DSA-65 public key to downstream verifiers.
  - Step 5 (Decommission Legacy Signing Key Version & Validate): Once all active tokens/artifacts issued by `legacy-ecdsa-p256-sign` expire, execute `gcloud kms keys versions disable 1 --key=legacy-ecdsa-p256-sign --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06` and validate with `gcloud kms keys describe legacy-ecdsa-p256-sign-pqc-mldsa65 --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06 --format='yaml(name,purpose,versionTemplate,primary)' && gcloud kms keys versions list --key=legacy-ecdsa-p256-sign --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06`.
```bash
# Step 2a: Provision Recommended NIST PQC Key in Cloud HSM (FIPS 140-3 Level 3)
gcloud kms keys create legacy-ecdsa-p256-sign-pqc-mldsa65 --project=pqc-inventory-agent-cd06 --location=global --keyring=kr-pqc-enterprise-prod --purpose=asymmetric-signing --default-algorithm=pq-sign-ml-dsa-65 --protection-level=hsm

# Step 2b: Alternative NSA CNSA 2.0 Category 5 Key Command
gcloud kms keys create legacy-ecdsa-p256-sign-pqc-mldsa87 --project=pqc-inventory-agent-cd06 --location=global --keyring=kr-pqc-enterprise-prod --purpose=asymmetric-signing --default-algorithm=pq-sign-ml-dsa-87 --protection-level=hsm

# Step 3: Bind Least-Privilege IAM Role to Consuming Workload Service Account
gcloud kms keys add-iam-policy-binding legacy-ecdsa-p256-sign-pqc-mldsa65 --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06 --member='serviceAccount:110254026096-compute@developer.gserviceaccount.com' --role='roles/cloudkms.signerVerifier'

# Step 5a: Disable Legacy Classical Key Version Post-Cutover
gcloud kms keys versions disable 1 --key=legacy-ecdsa-p256-sign --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06

# Step 5b: Post-Change Verification Command
gcloud kms keys describe legacy-ecdsa-p256-sign-pqc-mldsa65 --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06 --format='yaml(name,purpose,versionTemplate,primary)' && gcloud kms keys versions list --key=legacy-ecdsa-p256-sign --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06
```

#### 4.1.3. Key `pqc-inventory-agent-cd06/kr-pqc-enterprise-prod/legacy-rsa-oaep-decrypt (global)` (`RSA_DECRYPT_OAEP_2048_SHA256`) ➡️ `KEM_XWING (or ML_KEM_1024 for CNSA 2.0)`
- **Consuming Applications:** `Legacy Partner Payload & DEK Unwrapper Service`
- **Current State Evaluation:** Key 'pqc-inventory-agent-cd06/kr-pqc-enterprise-prod/legacy-rsa-oaep-decrypt' (global) currently uses classical algorithm 'RSA_DECRYPT_OAEP_2048_SHA256' with protection_level='SOFTWARE' and is consumed by 1 workload(s): Legacy Partner Payload & DEK Unwrapper Service. Mosca status: CRITICAL_MOSCA_BREACH_ACTIVE_HNDL (X+Y = 12.0 years).
- **Architectural Impact Assessment:** HIGH ARCHITECTURAL IMPACT: Classical RSA-OAEP encrypts arbitrary small payloads or DEKs directly (256-byte ciphertext for RSA-2048). NIST FIPS 203 PQC algorithms (KEM_XWING / ML_KEM_1024) are Key Encapsulation Mechanisms (KEM), NOT public-key encryption ciphers. Ciphertext expands from 256 bytes to 1,120 bytes (KEM_XWING) or 1,568 bytes (ML_KEM_1024), and the API returns a 32-byte shared_secret instead of decrypted plaintext.
- **5-Step Prescriptive Execution Plan:**
  - Step 1 (Pre-Flight & Database Schema Preparation): Verify regional Cloud HSM quota in 'global' for project 'pqc-inventory-agent-cd06' and expand wrapped DEK columns in consuming storage/databases from 256 bytes (RSA-2048) to >= 1,568 bytes (VARBINARY(2048)) to accommodate KEM_XWING (1,120 B) or ML_KEM_1024 (1,568 B) ciphertexts.
  - Step 2 (Provision PQC KEM Key in Cloud HSM): Execute `gcloud kms keys create legacy-rsa-oaep-decrypt-pqc-xwing --project=pqc-inventory-agent-cd06 --location=global --keyring=kr-pqc-enterprise-prod --purpose=key-encapsulation --default-algorithm=kem-xwing --protection-level=hsm` (or `gcloud kms keys create legacy-rsa-oaep-decrypt-pqc-mlkem1024 --project=pqc-inventory-agent-cd06 --location=global --keyring=kr-pqc-enterprise-prod --purpose=key-encapsulation --default-algorithm=ml-kem-1024 --protection-level=hsm` for pure CNSA 2.0 Category 5).
  - Step 3 (Grant Least-Privilege IAM Decapsulation Role): Execute `gcloud kms keys add-iam-policy-binding legacy-rsa-oaep-decrypt-pqc-xwing --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06 --member='serviceAccount:110254026096-compute@developer.gserviceaccount.com' --role='roles/cloudkms.cryptoKeyDecapsulator'` so workload `Legacy Partner Payload & DEK Unwrapper Service` can invoke `kms.Decapsulate`.
  - Step 4 (Refactor Consuming Application to RFC 9180 HPKE / Envelope Encryption): Update `Legacy Partner Payload & DEK Unwrapper Service` from `kms_client.asymmetric_decrypt()` to `kms_client.decapsulate()` + `HKDF-SHA256` (32-byte shared_secret -> 256-bit DEK) + `AES-256-GCM` in dual-read mode until existing RSA-OAEP ciphertexts are re-wrapped.
  - Step 5 (Decommission Legacy RSA Key Version & Validate): Execute `gcloud kms keys versions disable 1 --key=legacy-rsa-oaep-decrypt --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06` and verify posture via `gcloud kms keys describe legacy-rsa-oaep-decrypt-pqc-xwing --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06 --format='yaml(name,purpose,versionTemplate,primary)' && gcloud kms keys versions list --key=legacy-rsa-oaep-decrypt --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06`.
```bash
# Step 2a: Provision Recommended NIST PQC Key in Cloud HSM (FIPS 140-3 Level 3)
gcloud kms keys create legacy-rsa-oaep-decrypt-pqc-xwing --project=pqc-inventory-agent-cd06 --location=global --keyring=kr-pqc-enterprise-prod --purpose=key-encapsulation --default-algorithm=kem-xwing --protection-level=hsm

# Step 2b: Alternative NSA CNSA 2.0 Category 5 Key Command
gcloud kms keys create legacy-rsa-oaep-decrypt-pqc-mlkem1024 --project=pqc-inventory-agent-cd06 --location=global --keyring=kr-pqc-enterprise-prod --purpose=key-encapsulation --default-algorithm=ml-kem-1024 --protection-level=hsm

# Step 3: Bind Least-Privilege IAM Role to Consuming Workload Service Account
gcloud kms keys add-iam-policy-binding legacy-rsa-oaep-decrypt-pqc-xwing --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06 --member='serviceAccount:110254026096-compute@developer.gserviceaccount.com' --role='roles/cloudkms.cryptoKeyDecapsulator'

# Step 5a: Disable Legacy Classical Key Version Post-Cutover
gcloud kms keys versions disable 1 --key=legacy-rsa-oaep-decrypt --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06

# Step 5b: Post-Change Verification Command
gcloud kms keys describe legacy-rsa-oaep-decrypt-pqc-xwing --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06 --format='yaml(name,purpose,versionTemplate,primary)' && gcloud kms keys versions list --key=legacy-rsa-oaep-decrypt --keyring=kr-pqc-enterprise-prod --location=global --project=pqc-inventory-agent-cd06
```

### 4.2. Symmetric CMEK Rotation Hygiene Runbooks (`<= 90 Days` — Zero Downtime)
- **All active symmetric `GOOGLE_SYMMETRIC_ENCRYPTION` (AES-256) keys are already compliant with `<= 90 days` (`7776000s`) automatic rotation.**

### 4.3. Network SSL/TLS Policies (`X25519MLKEM768`) & BYOK `ImportJobs` Runbooks
| Asset Type & Name | Project / Scope | Current Config | PQC Status | Remediation / Baseline Command |
| :--- | :--- | :--- | :--- | :--- |
| Baseline SSL Policy (Recommended) | `organizations/31564119954` | `Default L7 Policy` | `CREATE_RESTRICTED_TLS_1_3` | `` |
| Baseline BYOK ImportJob | `organizations/31564119954` | `None Configured` | `READY_FOR_HSM_BYOK` | `` |

---

## 5. Application Code Refactoring Blueprints (`Python`, `Go`, `Tink HPKE` & `Envoy 32KB`)
### 5.1. Blueprint for `None` (`RSA_SIGN_PSS_2048_SHA256` ➡️ `PQ_SIGN_ML_DSA_65 (FIPS 204 Category 3) or PQ_SIGN_ML_DSA_87 (CNSA 2.0 Category 5)`)
- **Pattern:** `None`
- **Affected Workloads:** ``

#### Envoy / Istio Gateway & NGINX Header Buffer Expansion (`32KB` for `ML-DSA-65` JWS/JWT)
```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: pqc-mldsa-header-buffer-expansion
spec:
  configPatches:
  - applyTo: NETWORK_FILTER
    patch:
      operation: MERGE
      value:
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          max_request_headers_kb: 32
```
```nginx

```

### 5.1. Blueprint for `None` (`EC_SIGN_P256_SHA256` ➡️ `PQ_SIGN_ML_DSA_65 (FIPS 204 Category 3) or PQ_SIGN_ML_DSA_87 (CNSA 2.0 Category 5)`)
- **Pattern:** `None`
- **Affected Workloads:** ``

#### Envoy / Istio Gateway & NGINX Header Buffer Expansion (`32KB` for `ML-DSA-65` JWS/JWT)
```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: pqc-mldsa-header-buffer-expansion
spec:
  configPatches:
  - applyTo: NETWORK_FILTER
    patch:
      operation: MERGE
      value:
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          max_request_headers_kb: 32
```
```nginx

```

### 5.1. Blueprint for `None` (`RSA_DECRYPT_OAEP_2048_SHA256` ➡️ `KEM_XWING (Hybrid X25519 + ML-KEM-768, FIPS 203) or ML_KEM_1024 (CNSA 2.0)`)
- **Pattern:** `None`
- **Affected Workloads:** ``

#### Python — Target Cloud KMS `Decapsulate` + `HKDF-SHA256` + `AES-256-GCM` (RFC 9180 HPKE)
```python
import os
from google.cloud import kms_v1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

kms_client = kms_v1.KeyManagementServiceClient()
pqc_key_version_name = "projects/pqc-inventory-agent-cd06/locations/global/keyRings/kr-pqc-enterprise-prod/cryptoKeys/legacy-rsa-oaep-decrypt-pqc-xwing/cryptoKeyVersions/1"

# STEP 1: Decapsulate the 1,120-byte KEM_XWING (or 1,568-byte ML_KEM_1024) ciphertext via Cloud KMS
decap_response = kms_client.decapsulate(
    request={"name": pqc_key_version_name, "ciphertext": kem_ciphertext}
)
shared_secret = decap_response.shared_secret  # 32-byte post-quantum shared secret

# STEP 2: Derive 256-bit Data Encryption Key (DEK) via HKDF-SHA256 (RFC 9180 HPKE context)
dek = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=hkdf_salt,
    info=b"gcp-kms-pqc-kem-xwing-aes256gcm-v1",
).derive(shared_secret)

# STEP 3: Decrypt the envelope payload locally with AES-256-GCM (Grover-resilient)
plaintext = AESGCM(dek).decrypt(nonce=aes_nonce, data=aes_ciphertext, associated_data=aad)
```

---

## 6. Preventive GCP Organization Policy Guardrails & Post-Change Verification Checklist
### 6.1. Custom Constraint 1 — Block Creation of Classical RSA/ECDSA Keys
```yaml
name: organizations/31564119954/customConstraints/custom.pqcEnforceQuantumSafeKmsAlgorithms
resourceTypes:
  - cloudkms.googleapis.com/CryptoKey
methodTypes:
  - CREATE
  - UPDATE
condition: >-
  resource.versionTemplate.algorithm in [
    'GOOGLE_SYMMETRIC_ENCRYPTION',
    'KEM_XWING',
    'ML_KEM_768',
    'ML_KEM_1024',
    'PQ_SIGN_ML_DSA_44',
    'PQ_SIGN_ML_DSA_65',
    'PQ_SIGN_ML_DSA_87',
    'PQ_SIGN_ML_DSA_44_EXTERNAL_MU',
    'PQ_SIGN_ML_DSA_65_EXTERNAL_MU',
    'PQ_SIGN_ML_DSA_87_EXTERNAL_MU',
    'PQ_SIGN_SLH_DSA_SHA2_128S',
    'PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256',
    'HMAC_SHA256',
    'HMAC_SHA384',
    'HMAC_SHA512'
  ]
actionType: ALLOW
displayName: Enforce Post-Quantum & Grover-Resilient Cloud KMS Algorithms (NIST FIPS 203/204/205)
description: Blocks creation of classical RSA/ECDSA/Ed25519 keys vulnerable to Shor's Algorithm.
```

### 6.2. Custom Constraint 2 — Enforce `<= 90-Day` Rotation on Symmetric Keys
```yaml
name: organizations/31564119954/customConstraints/custom.pqcEnforceSymmetricKeyRotation90d
resourceTypes:
  - cloudkms.googleapis.com/CryptoKey
methodTypes:
  - CREATE
  - UPDATE
condition: >-
  resource.purpose != 'ENCRYPT_DECRYPT' ||
  (has(resource.rotationPeriod) && duration(resource.rotationPeriod) <= duration('7776000s'))
actionType: ALLOW
displayName: Enforce <= 90-Day Automatic Rotation on Symmetric Cloud KMS Keys (NIST SP 800-57 / CIS 1.10)
description: Requires automatic key rotation period <= 90 days (7,776,000 seconds) for all symmetric ENCRYPT_DECRYPT keys.
```

### 6.3. Organization Policy Enforcement Commands
```bash
gcloud org-policies set-custom-constraint custom-pqc-kms-algorithms.yaml
gcloud org-policies set-policy enforce-pqc-kms-algorithms-policy.yaml --organization=31564119954
gcloud org-policies set-custom-constraint custom-pqc-kms-rotation-90d.yaml
gcloud org-policies set-policy enforce-pqc-kms-rotation-90d-policy.yaml --organization=31564119954
```

### 6.4. Post-Implementation Verification Checklist
- [ ] **1. Verify PQC Key Creation & HSM Protection Level:** Confirm all new `KEM_XWING`, `ML_KEM_1024`, and `PQ_SIGN_ML_DSA_65` keys show `primary.state=ENABLED` and `protectionLevel=HSM`.
- [ ] **2. Verify Least-Privilege IAM Bindings:** Confirm consuming Service Accounts hold `roles/cloudkms.cryptoKeyDecapsulator` or `roles/cloudkms.signerVerifier` on the new PQC keys.
- [ ] **3. Verify Symmetric CMEK Rotation Schedule:** Confirm all `GOOGLE_SYMMETRIC_ENCRYPTION` keys report `rotationPeriod=7776000s` (90 days).
- [ ] **4. Verify API Gateway & Proxy Header Buffers:** Execute synthetic test requests with `4.5 KB` `Authorization: Bearer` headers (`ML-DSA-65` JWS) and confirm HTTP `200 OK` (no HTTP `431`).
- [ ] **5. Verify TLS 1.3 Hybrid PQC Handshake:** Run `openssl s_client -connect <LB_IP>:443 -tls1_3 -curves X25519MLKEM768` against external/internal Load Balancers.
- [ ] **6. Verify Legacy Key Version Decommissioning:** Confirm legacy `RSA_*` and `EC_*` versions are in `DISABLED` or `DESTROY_SCHEDULED` state and archive the `CycloneDX v1.6 CBOM`.