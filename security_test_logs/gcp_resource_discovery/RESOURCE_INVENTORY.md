# GCP Existing Resource Discovery — Read-Only Inventory

## 1. Execution Metadata & Safety Attestation

| Field | Value |
| :--- | :--- |
| **Repository** | `g-jsaccomani/pqc_inventory_agent` |
| **Inventory Window (UTC)** | `2026-11-20T00:32:45Z` – `2026-11-20T00:37:34Z` |
| **Authenticated Account** | `admin@<redacted>.altostrat.com` *(personal domain prefix redacted; verified via OAuth `tokeninfo` before running any GCP query)* |
| **Organization** | `organizations/31564119954` (`<redacted>.altostrat.com`, `ACTIVE`) |
| **Authentication Isolation** | Executed using an isolated temporary `0700` `CLOUDSDK_CONFIG` directory (workstation `~/.config/gcloud` left untouched); temporary credentials were revoked (`gcloud auth revoke`) and the temporary directory was deleted immediately after discovery completed. |
| **Workstation Default Project** | `pqc-inventory-agent-cd06` *(read from non-secret workstation `config_default` metadata; unchanged)* |
| **Isolated Session Active Project** | `None` *(explicit `--project=<project-id>` passed to every read-only command)* |
| **Default Compute Region / Zone** | Not configured (`[compute]` section absent in both workstation and isolated configs) |
| **Execution Mode** | **Strictly Read-Only** |

> **Explicit Read-Only & Non-Billing Statement:**
> No Google Cloud resources were created, updated, started, stopped, restarted, deployed, or deleted during this inventory. No APIs were enabled or disabled, no IAM policies or service accounts were modified, no databases were connected to or queried, no Vertex AI models or endpoints were invoked, no Cloud Build jobs or container image pushes were triggered, and no billable execution was triggered. No tokens, passwords, private keys, connection strings, or IP addresses were retrieved or recorded.

---

## 2. Accessible Organization, Folders & Projects

### 2.1 Folder Hierarchy (`organizations/31564119954`)

All **7** folders directly under `organizations/31564119954` are `ACTIVE` (no nested child folders):

| Folder Resource Name | Display Name | Lifecycle State | Role in Portfolio |
| :--- | :--- | :---: | :--- |
| `folders/534285347409` | `fldr-functional-lab` | `ACTIVE` | Functional Lab & isolated PQC validation targets |
| `folders/288882693571` | `fldr-pqc-inventory` | `ACTIVE` | PQC Inventory Agent platform project |
| `folders/421230859806` | `agentic_cti` | `ACTIVE` | Sibling portfolio project (out of scope for PQC) |
| `folders/436889370233` | `agentic_iam` | `ACTIVE` | Sibling portfolio project (out of scope for PQC) |
| `folders/476018967395` | `fldr-cspr-copilot` | `ACTIVE` | Sibling portfolio project (out of scope for PQC) |
| `folders/1030700844136` | `fldr-agentic-grc` | `ACTIVE` | Sibling portfolio project (out of scope for PQC) |
| `folders/848348788945` | `fldr-aispr-platform` | `ACTIVE` | Sibling portfolio project (out of scope for PQC) |

### 2.2 Accessible Projects (`10` Active Projects)

| Project ID | Display Name | Parent Folder | Billing | Key Labels | Relevance to PQC Validation |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **`pqc-inventory-agent-validation`** | PQC Inventory Agent Validation | `fldr-functional-lab` (`534285347409`) | Enabled | `environment=functional-lab`, `theme=pqc-inventory`, `tier=validation` | **Primary isolated Docker / Cloud Build validation project** |
| **`fnlab-ai-data-8fa913`** | Functional Lab - AI and Data | `fldr-functional-lab` (`534285347409`) | Enabled | `environment=functional-lab`, `theme=fnlab-ai`, `tier=lab-target` | **Primary isolated PostgreSQL 16 & Vertex AI validation project** |
| **`pqc-inventory-agent-cd06`** | Agentic PQC Inventory | `fldr-pqc-inventory` (`288882693571`) | Enabled | `theme=pqc-inventory`, `tier=platform` | Platform / runtime project (**do not use for destructive tests**) |
| `fnlab-sec-mgmt-8fa913` | Functional Lab - Sec and Mgmt | `fldr-functional-lab` (`534285347409`) | Enabled | `environment=functional-lab`, `theme=fnlab-sec`, `tier=lab-target` | Read-only lab target for PQC inventory scans |
| `fnlab-apps-8fa913` | Functional Lab - Apps and APIs | `fldr-functional-lab` (`534285347409`) | Enabled | `environment=functional-lab`, `theme=fnlab-apps`, `tier=lab-target` | Read-only lab target for PQC inventory scans |
| `prj-agentic-cti-dev` | Agentic CTI - Aegis-Intel | `agentic_cti` (`421230859806`) | Enabled | `platform=agentic-cti` | Sibling project (out of scope) |
| `prj-agentic-iam-dev` | Agentic IAM Accelerator - dev | `agentic_iam` (`436889370233`) | Enabled | `environment=dev`, `platform=agentic-iam-accelerator` | Sibling project (out of scope) |
| `cspr-copilot-cd06` | Agentic CSPR Copilot | `fldr-cspr-copilot` (`476018967395`) | Enabled | `theme=cspr-copilot`, `tier=platform` | Sibling project (out of scope) |
| `agentic-grc-cd06` | Agentic GRC Copilot | `fldr-agentic-grc` (`1030700844136`) | Enabled | `theme=agentic-grc`, `tier=platform` | Sibling project (out of scope) |
| `aispr-core-1cab11` | Agentic AISPR Platform | `fldr-aispr-platform` (`848348788945`) | Enabled | `theme=aispr-platform`, `tier=platform` | Sibling project (out of scope) |

### 2.3 Required API Enablement Matrix

| Project ID | Total APIs | `sqladmin` | `aiplatform` | `cloudbuild` | `artifactregistry` | `run` | `cloudkms` | `cloudasset` | `secretmanager` | `storage` | `compute` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`pqc-inventory-agent-validation`** | 30 | No | No | **Yes** | **Yes** | No | No | No | No | **Yes** | No |
| **`fnlab-ai-data-8fa913`** | 30 | **Yes** | **Yes** | No | No | No | **Yes** | No | No | **Yes** | **Yes** |
| **`pqc-inventory-agent-cd06`** | 57 | No | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |
| `fnlab-sec-mgmt-8fa913` | 30 | No | No | No | No | No | **Yes** | No | **Yes** | **Yes** | **Yes** |
| `fnlab-apps-8fa913` | 25 | No | No | No | No | No | **Yes** | No | No | **Yes** | **Yes** |
| `prj-agentic-cti-dev` | 53 | No | **Yes** | **Yes** | **Yes** | **Yes** | No | No | **Yes** | **Yes** | **Yes** |
| `prj-agentic-iam-dev` | 47 | No | **Yes** | **Yes** | **Yes** | **Yes** | No | **Yes** | **Yes** | **Yes** | **Yes** |
| `cspr-copilot-cd06` | 41 | No | **Yes** | **Yes** | **Yes** | **Yes** | No | No | **Yes** | **Yes** | **Yes** |
| `agentic-grc-cd06` | 44 | No | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | No | **Yes** |
| `aispr-core-1cab11` | 27 | No | **Yes** | **Yes** | **Yes** | **Yes** | No | **Yes** | **Yes** | **Yes** | **Yes** |

---

## 3. PostgreSQL (Cloud SQL) Discovery

- **API Coverage:** `sqladmin.googleapis.com` is enabled in **1 of 10** accessible projects (`fnlab-ai-data-8fa913`). It is disabled in the other 9 projects, including `pqc-inventory-agent-validation` and `pqc-inventory-agent-cd06`.
- **Discovered Instances:** **1** Cloud SQL instance across all accessible projects.

### 3.1 Cloud SQL Instance Inventory

| Attribute | Value |
| :--- | :--- |
| **Instance Name** | `pqc-pg16-validation` |
| **Project ID** | `fnlab-ai-data-8fa913` *(folder `fldr-functional-lab`)* |
| **Database Engine & Version** | `POSTGRES_16` (`CLOUD_SQL_INSTANCE`, `ENTERPRISE` edition) |
| **Machine Tier & Storage** | `db-f1-micro`, `PD_SSD`, `10 GB` (`storageAutoResize: true`) |
| **Region / Zone** | `us-central1` / `us-central1-c` |
| **Availability Type** | `ZONAL` |
| **Lifecycle State** | `RUNNABLE` (`activationPolicy: ALWAYS`) |
| **Creation Time (UTC)** | `2026-11-18T10:05:06.373Z` |
| **Labels** | `component=pqc-inventory-agent`, `env=validation`, `phase=phase-01-02` |
| **Deletion Protection** | Disabled (`deletionProtectionEnabled: false`) |
| **Public / Private IP Config** | Public IPv4 enabled (`PRIMARY` + `OUTGOING` allocated; **IP addresses intentionally omitted**); Private IP / VPC peering **not configured** (`hasPrivateNetwork: false`); **0 authorized public networks** (`authorizedNetworksCount: 0`) |
| **TLS / SSL Setting** | `sslMode: ALLOW_UNENCRYPTED_AND_ENCRYPTED` (`requireSsl: false`) |
| **Automated Backups** | **Disabled** (`enabled: false`; PITR not enabled; inactive default retention settings: `7` backups / `7` log days) |
| **Maintenance Window** | Not explicitly configured (`maintenanceWindow: {}`, Google-managed default) |

### 3.2 Suitability Assessment for Isolated Integration Tests

- **Suitable for Isolated Integration Tests:** **Yes.**
  - Explicitly created and labeled (`component=pqc-inventory-agent`, `env=validation`) inside the non-production Functional Lab project (`fnlab-ai-data-8fa913`), isolated from `pqc-inventory-agent-cd06`.
  - Runs the target engine version (`POSTGRES_16`) and is already `RUNNABLE` (no instance start or provisioning needed).
  - Has **`authorizedNetworksCount: 0`**, preventing direct unauthenticated public network access while supporting safe loopback access via Cloud SQL Auth Proxy or an ephemeral mTLS 1.3 client-certificate tunnel without modifying firewall rules.
- **Non-Production Caveats (Not Suitable for Production):** `db-f1-micro`, `ZONAL` availability, automated backups disabled, deletion protection disabled, no Private IP, and `requireSsl=false`. Production deployments must provision a dedicated hardened Cloud SQL instance with `REGIONAL` HA, backups/PITR enabled, deletion protection, Private IP or enforced TLS (`ENCRYPTED_ONLY` / `TRUSTED_CLIENT_CERTIFICATE_REQUIRED`), and `sqladmin.googleapis.com` enabled in the target production project.

---

## 4. Vertex AI Discovery

### 4.1 Projects with `aiplatform.googleapis.com` Enabled (`7` of `10`)

- **PQC-Relevant Projects with Vertex AI Enabled:**
  1. `fnlab-ai-data-8fa913` — Non-production Functional Lab project (**recommended for isolated Gemini inference smoke tests**).
  2. `pqc-inventory-agent-cd06` — PQC Inventory Agent platform project (active Cloud Run service `agentic-pqc`).
- **PQC-Relevant Project with Vertex AI Disabled:**
  - `pqc-inventory-agent-validation` — Intentionally kept minimal (Cloud Build / Artifact Registry / Storage only; `aiplatform.googleapis.com` disabled).
- **Sibling Portfolio Projects with Vertex AI Enabled (Out of Scope for PQC):** `prj-agentic-cti-dev`, `prj-agentic-iam-dev`, `cspr-copilot-cd06`, `agentic-grc-cd06`, `aispr-core-1cab11`.

### 4.2 Regions Used by Existing Deployments & Configurations

- **Cloud Run & Regional Infrastructure:** Consistently deployed in **`us-central1`** across `pqc-inventory-agent-cd06` (`agentic-pqc`, `Ready=True`) and all 5 sibling Cloud Run services (`maegor-cti`, `agentic-iam-accelerator`, `agentic-cspr`, `agentic-grc`, `agentic-aispr`). Repository deployment scripts (`scripts/deploy_cloud_run.sh`, `scripts/setup_and_deploy_vertex.sh`) also default to `us-central1`.
- **Vertex AI GenAI Endpoint Location:** Non-secret Cloud Run configuration on `pqc-inventory-agent-cd06/agentic-pqc` (and sibling services) sets **`GOOGLE_GENAI_USE_VERTEXAI=TRUE`** and **`GOOGLE_CLOUD_LOCATION=global`**, matching the repository's canonical default model `gemini-3.1-pro-preview-customtools` served via Google-managed Vertex AI `global` publisher endpoints.

### 4.3 Existing Vertex AI Model Endpoints & Reasoning Engines

- **Custom Vertex AI Endpoints:** **`0`** found across `us-central1`, `us-east1`, `us-west1`, `europe-west1`, and `southamerica-east1` in `pqc-inventory-agent-cd06` and `fnlab-ai-data-8fa913` (and `0` in `us-central1` across the other 5 Vertex AI-enabled sibling projects).
- **Vertex AI Reasoning Engines / Agent Engines (`us-central1`):** **`0`** found in `pqc-inventory-agent-cd06` and `fnlab-ai-data-8fa913`.
- **Operational Meaning:** No dedicated custom endpoint lifecycle management or idle endpoint cost exists; Gemini inference tests target Google-managed publisher models directly.

### 4.4 Principal Permissions for Planned Gemini Inference Test (Read-Only Check)

Verified via read-only `projects:testIamPermissions` (no model invoked, no IAM modified):

| Project ID | Direct Role(s) for Principal | `aiplatform.endpoints.predict` | `aiplatform.endpoints.list` | `aiplatform.models.list` | `serviceusage.services.use` | Tested Permissions Granted |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `fnlab-ai-data-8fa913` | `roles/owner` | **Granted** | **Granted** | **Granted** | **Granted** | `14 / 14` |
| `pqc-inventory-agent-cd06` | `roles/owner`, `roles/iap.httpsResourceAccessor` | **Granted** | **Granted** | **Granted** | **Granted** | `14 / 14` |
| `pqc-inventory-agent-validation` | `roles/owner` | **Granted** *(API disabled)* | **Granted** *(API disabled)* | **Granted** *(API disabled)* | **Granted** | `14 / 14` |

*(Additional permissions also verified granted across all three projects: `cloudsql.instances.list`, `cloudsql.instances.get`, `cloudbuild.builds.list`, `cloudbuild.builds.create`, `artifactregistry.repositories.list`, `artifactregistry.repositories.downloadArtifacts`, `artifactregistry.repositories.uploadArtifacts`, `run.services.list`, `cloudkms.cryptoKeys.list`, `resourcemanager.projects.get`.)*

- **Conclusion:** The authenticated principal holds all IAM permissions required for the planned single-turn Vertex AI Gemini inference test in `fnlab-ai-data-8fa913` (where `aiplatform.googleapis.com` is already enabled).

---

## 5. Docker, Cloud Build & Artifact Registry Inventory

### 5.1 Cloud Build Configuration, Triggers & Worker Pools

- **Repository Build Config:** `cloudbuild.docker-validation.yaml` is committed in the repository root (`machineType: E2_STANDARD_2`, `logging: CLOUD_LOGGING_ONLY`, `timeout: 900s`, ephemeral local Docker tags removed via `EXIT` trap, zero published images).
- **Persistent Cloud Build Triggers:** **`0`** triggers across all 7 Cloud Build-enabled projects (`global` and `us-central1` explicitly verified on `pqc-inventory-agent-validation` and `pqc-inventory-agent-cd06`).
- **Private Worker Pools (`us-central1`):** **`0`** in `pqc-inventory-agent-validation` and `pqc-inventory-agent-cd06` (both use Google-managed default worker pools).

### 5.2 Recent Cloud Build History

| Project ID | Region | Recent Builds | Latest Build Summary |
| :--- | :--- | :---: | :--- |
| **`pqc-inventory-agent-validation`** | `us-central1` | 1 | `605c784d-6949-4891-bfd0-0ba519a6c68d` — `SUCCESS` (`2026-11-19T14:12:48Z` – `14:15:37Z`, `E2_STANDARD_2`, `images=[]`; Phase 3.5 Docker validation) |
| **`pqc-inventory-agent-validation`** | `global` | 0 | None |
| **`pqc-inventory-agent-cd06`** | `us-central1` | 5+ *(latest 5 inspected)* | `48156f0c-0389-49bf-832a-3dd14976b89e` — `SUCCESS` (`2026-11-17T16:57:48Z` – `17:00:33Z`, published `cloud-run-source-deploy/agentic-pqc:latest`); all 5 recent builds `SUCCESS` (`2026-11-16` – `2026-11-17`) |
| **`pqc-inventory-agent-cd06`** | `global` | 1 | `729aea6a-6157-4671-8283-e0b93282206e` — `SUCCESS` (`2026-11-13T15:11:46Z` – `15:16:03Z`, published `gcr.io/pqc-inventory-agent-cd06/pqc-inventory-agent`) |
| `cspr-copilot-cd06` | `global` | 1 | `068b5efb-...` — `FAILURE` (`2026-11-13`) |
| `agentic-grc-cd06` | `global` | 3 | Latest `6e055416-...` — `FAILURE` (`2026-11-13`), prior `dae76257-...` — `SUCCESS` (`2026-09-15`) |
| `prj-agentic-cti-dev`, `prj-agentic-iam-dev`, `aispr-core-1cab11` | `global` | 0 | None in `global` |

### 5.3 Artifact Registry Repositories

| Project ID | Repository Name | Location | Format / Mode | Approx. Size | Last Updated (UTC) | Relevance to PQC |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| **`pqc-inventory-agent-validation`** | *(none)* | — | — | — | — | Clean validation project (`0` repos; no images pushed during validation) |
| **`pqc-inventory-agent-cd06`** | `cloud-run-source-deploy` | `us-central1` | `DOCKER` / `STANDARD` | `7.70 GB` | `2026-11-17T17:00:39Z` | **Active PQC Cloud Run images** |
| **`pqc-inventory-agent-cd06`** | `gcr.io` | `us` | `DOCKER` / `STANDARD` | `328.6 MB` | `2026-11-13T15:16:15Z` | Legacy PQC container registry repository |
| `prj-agentic-cti-dev` | `cloud-run-source-deploy` | `us-central1` | `DOCKER` / `STANDARD` | `385.9 MB` | `2026-11-16T19:35:23Z` | Out of scope |
| `prj-agentic-iam-dev` | `cloud-run-source-deploy` | `us-central1` | `DOCKER` / `STANDARD` | `4.47 GB` | `2026-11-20T00:15:15Z` | Out of scope |
| `cspr-copilot-cd06` | `cloud-run-source-deploy` | `us-central1` | `DOCKER` / `STANDARD` | `248.2 MB` | `2026-11-16T19:31:29Z` | Out of scope |
| `agentic-grc-cd06` | `cloud-run-source-deploy` | `us-central1` | `DOCKER` / `STANDARD` | `6.38 GB` | `2026-11-17T17:26:13Z` | Out of scope |
| `aispr-core-1cab11` | `cloud-run-source-deploy` | `us-central1` | `DOCKER` / `STANDARD` | `267.7 MB` | `2026-11-16T19:31:22Z` | Out of scope |

### 5.4 Existing Docker Images Relevant to PQC Inventory Agent

All existing PQC Docker images reside in `pqc-inventory-agent-cd06` (none in `pqc-inventory-agent-validation`):

| Repository Path | Package | Active Tag / Latest Digest Prefix | Last Updated (UTC) | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `us-central1-docker.pkg.dev/pqc-inventory-agent-cd06/cloud-run-source-deploy` | `agentic-pqc` | `latest` (`sha256:f1cec2758b50...`) | `2026-11-17T17:00:33Z` | Actively deployed on Cloud Run `agentic-pqc` (`us-central1`); multiple historical untagged manifests retained |
| `us-central1-docker.pkg.dev/pqc-inventory-agent-cd06/cloud-run-source-deploy` | `pqc-inventory-agent` | Untagged manifests only | `2026-11-12T20:01:57Z` | Earlier package naming (`2026-10-01` – `2026-11-12`) |
| `us-docker.pkg.dev/pqc-inventory-agent-cd06/gcr.io` | `pqc-inventory-agent` | `latest` (`sha256:9ca186b9978f...`) + 2 untagged manifests | `2026-11-13T15:16:15Z` | Legacy `gcr.io`-backed repository |

---

## 6. Existing Validation Resources & `pqc-inventory-agent-validation` Verification

### 6.1 Confirmation of `pqc-inventory-agent-validation`

- **Status:** **EXISTS, `ACTIVE`, AND ACCESSIBLE.**
- **Project Number:** `678301206512`
- **Parent Folder:** `folders/534285347409` (`fldr-functional-lab`)
- **Creation Time (UTC):** `2026-11-19T14:08:25.645Z`
- **Billing:** Enabled (`billingEnabled: true`)
- **Enabled Key APIs:** `cloudbuild.googleapis.com`, `artifactregistry.googleapis.com`, `containerregistry.googleapis.com`, `storage.googleapis.com`, `logging.googleapis.com`, `iam.googleapis.com`, `serviceusage.googleapis.com`
- **Intentionally Disabled APIs:** `aiplatform.googleapis.com`, `sqladmin.googleapis.com`, `run.googleapis.com`, `compute.googleapis.com`, `cloudkms.googleapis.com`, `secretmanager.googleapis.com`, `cloudasset.googleapis.com`, `cloudresourcemanager.googleapis.com`
- **Existing Storage Buckets:** `1` (`pqc-inventory-agent-validation_cloudbuild`, location `US`, `STANDARD`, UBLA enabled)
- **Existing Artifact Registry / Cloud Build Triggers / Worker Pools:** `0` repos, `0` triggers, `0` private pools.

### 6.2 Supporting Functional Lab & Platform Assets (Metadata Only)

- **`fnlab-ai-data-8fa913` (`fldr-functional-lab`):**
  - Cloud SQL: `pqc-pg16-validation` (`POSTGRES_16`, `RUNNABLE`, `us-central1`).
  - Vertex AI: `aiplatform.googleapis.com` enabled (0 custom endpoints, 0 Reasoning Engines).
  - Cloud KMS: 1 keyring in `us-central1` (`kr-ai-data-cmek`).
  - Cloud Storage: 7 regional (`US-CENTRAL1`, UBLA enabled) lab buckets (`bkt-fnlab-*`, `bkt-iso-*`, `poc-bucket-*`).
- **`fnlab-sec-mgmt-8fa913` & `fnlab-apps-8fa913` (`fldr-functional-lab`):**
  - Active non-production lab projects with `cloudkms.googleapis.com` and `compute.googleapis.com` enabled — suitable as read-only PQC inventory scanning targets for scope-isolation testing.
- **`pqc-inventory-agent-cd06` (`fldr-pqc-inventory` — Platform Project, Do Not Mutate During Tests):**
  - Cloud Run: `agentic-pqc` (`us-central1`, `Ready=True`).
  - Cloud KMS: 2 keyrings in `global` (`kr-pqc-audit-lab`, `kr-pqc-enterprise-prod`).
  - Cloud Storage: 3 buckets (`pqc-inventory-agent-cd06-pqc-agent-staging`, `pqc-inventory-agent-cd06_cloudbuild`, `run-sources-pqc-inventory-agent-cd06-us-central1`).

---

## 7. Missing Permissions, Access Limitations & Configuration Gaps

1. **IAM Access Limitations:** **None** on the PQC and Functional Lab validation projects. Read-only `projects:testIamPermissions` confirmed `14/14` tested permissions on `pqc-inventory-agent-validation`, `fnlab-ai-data-8fa913`, and `pqc-inventory-agent-cd06`, plus `roles/resourcemanager.folderAdmin` on `fldr-functional-lab` and organization-level discovery roles (`roles/compute.viewer`, `roles/iam.admin`, `roles/securitycenter.admin`, etc.).
2. **Intentionally Disabled APIs Across Validation Projects (Design Separation):**
   - `pqc-inventory-agent-validation` does not have `aiplatform.googleapis.com` or `sqladmin.googleapis.com` enabled — keep it isolated as a build-only Docker validation project rather than enabling runtime APIs there.
   - `fnlab-ai-data-8fa913` does not have `cloudbuild.googleapis.com`, `artifactregistry.googleapis.com`, or `run.googleapis.com` enabled — keep builds in `pqc-inventory-agent-validation`.
3. **Platform Production Prerequisite Observation:**
   - `pqc-inventory-agent-cd06` currently has **`sqladmin.googleapis.com` disabled** (no Cloud SQL instance provisioned yet), whereas `scripts/deploy_cloud_run.sh` requires a production Cloud SQL PostgreSQL instance (`PQC_CLOUD_SQL_CONNECTION_NAME`) before production rollout.
4. **Workstation CLI Configuration Notes:**
   - No default `compute/region` or `compute/zone` is set in workstation `gcloud` config; scripts and validation commands should continue passing explicit `--region=us-central1` / `GOOGLE_CLOUD_LOCATION=global`.
   - On corporate workstations with mTLS / internal-user environment overrides, `gcloud` commands targeting the Argolis admin account must run with an isolated `CLOUDSDK_CONFIG` (e.g., `~/.config/gcloud-argolis` or a temporary `0700` directory) and corporate `CLOUDSDK_CONTEXT_AWARE_*` / `CLOUDSDK_INTERNAL_USER` / `GOOGLE_AUTH_*` variables unset, verifying `tokeninfo` email before executing GCP operations.

---

## 8. Recommended Reuse Strategy for Future Isolated Tests

Reuse existing resources with **zero new infrastructure provisioning**, **zero new API enablement**, and **zero impact on `pqc-inventory-agent-cd06`**:

| Validation Gate | Recommended Target Project | Existing Resource to Reuse | Isolation & Safety Controls |
| :--- | :--- | :--- | :--- |
| **1. Docker Build, Non-Root (`10001`), & Read-Only Rootfs Tests** | `pqc-inventory-agent-validation` | Cloud Build (`us-central1`, `cloudbuild.docker-validation.yaml`, default `E2_STANDARD_2` pool) | Keep `CLOUD_LOGGING_ONLY`, ephemeral `$BUILD_ID` tags, `EXIT` trap cleanup, and zero Artifact Registry pushes. Do not enable Vertex AI, Cloud Run, or Cloud SQL in this project. |
| **2. Live PostgreSQL 16 Alembic & Multi-Instance Persistence Tests** | `fnlab-ai-data-8fa913` | Cloud SQL instance `pqc-pg16-validation` (`POSTGRES_16`, `us-central1`, `RUNNABLE`, `authorizedNetworks=0`) | Connect strictly over an ephemeral loopback Cloud SQL Auth Proxy or mTLS 1.3 tunnel; target only a disposable `pqc_test_*` database with `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`; never add public `authorizedNetworks`; rotate/discard any ephemeral test password immediately after execution. |
| **3. Live Vertex AI / Gemini Inference & Telemetry Smoke Test** | `fnlab-ai-data-8fa913` | Pre-enabled `aiplatform.googleapis.com` publisher model (`location=global`, `gemini-3.1-pro-preview-customtools`) | Execute a single bounded prompt (`PQC_LIVE_LLM_TEST=1`) with explicit Phase 3 timeouts (`60s`/`90s`) using temporary isolated user ADC that is revoked and deleted immediately after the test. |
| **4. Read-Only PQC Inventory & Scope-Isolation Integration Tests (Phase 4+)** | `fnlab-sec-mgmt-8fa913`, `fnlab-apps-8fa913`, `fnlab-ai-data-8fa913` *(or folder `folders/534285347409`)* | Pre-enabled `cloudkms`, `compute`, and `storage` lab assets | Pass explicit `--project` or `--folder=534285347409` scope boundaries; never default to organization-wide scans across unrelated sibling projects. |
| **5. Platform Environment Protection** | `pqc-inventory-agent-cd06` | Active Cloud Run service `agentic-pqc` and Artifact Registry images | Treat as protected platform runtime; exclude from automated validation mutations until explicit release deployment approval. |
