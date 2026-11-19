# GCP Cloud Build Docker Validation Report — Phase 3.5 (`P3-04`)

## 1. Objective & Validation Scope
Execute real Docker build and live container runtime verification in an isolated Google Cloud project modeled after the reference `functional-lab` environment under the functional-lab parent folder, validating:
- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Scope:** Phase 3.5 (`P3-04`) — Docker non-root execution (`UID 10001`), read-only root filesystem (`--read-only --tmpfs /tmp:rw,noexec,nosuid`), `/app` immutability, migration CLI help execution, and both existing Docker-gated `pytest` regression tests that were previously `BLOCKED` on the local macOS workstation (where Docker CLI/daemon is not installed).

---

## 2. Reference Environment Preflight
Preflight inspection was executed strictly read-only against the designated organization and the functional-lab parent folder before creating any resources.

### Verified Target Hierarchy & Reference Baseline
- **Organization:** The designated organization (verified active prior to project creation).
- **Parent Folder:** The functional-lab parent folder (verified active under the designated organization; numeric folder ID resolved and validated during preflight).
- **Reference `functional-lab` Projects (Untouched):** Three existing reference lab projects under the functional-lab parent folder were inspected read-only to confirm parent hierarchy, active billing linkage, and baseline configuration. None of these projects have Cloud Build enabled, and none were modified.
- **Cloud Build Region Verified:** Confirmed active regional Cloud Build support in `us-central1` within the designated organization.
- **Relevant Organization Policies Observed:**
  - `constraints/iam.automaticIamGrantsForDefaultServiceAccounts = True` (default service accounts receive zero automatic roles).
  - `constraints/storage.uniformBucketLevelAccess = True`.
  - `constraints/iam.disableServiceAccountKeyCreation = True`.
  - `constraints/compute.skipDefaultNetworkCreation = True`.

---

## 3. Isolated Validation Project Created
- **Project ID:** `pqc-inventory-agent-validation` *(preferred ID available; created cleanly)*
- **Display Name:** `PQC Inventory Agent Validation`
- **Parent Hierarchy:** The functional-lab parent folder under the designated organization
- **Creation Timestamp (UTC):** `2026-11-19T14:08:25.645Z`

---

## 4. Billing Status & Enabled APIs
- **Billing Account:** Linked to the configured billing account (`billingEnabled: true`, `open: true`).
- **Explicitly Enabled API:** `cloudbuild.googleapis.com`
- **GCP Default / Transitive Services Active After Creation + Cloud Build Enablement:** `cloudapis.googleapis.com`, `cloudbuild.googleapis.com`, `logging.googleapis.com`, `storage.googleapis.com`, `storage-api.googleapis.com`, `storage-component.googleapis.com`, `serviceusage.googleapis.com`, `servicemanagement.googleapis.com`, `iam.googleapis.com`, `iamcredentials.googleapis.com`, `pubsub.googleapis.com`, `artifactregistry.googleapis.com` *(transitive Cloud Build dependency — 0 repositories created)*, `containerregistry.googleapis.com` *(transitive — unused)*, `containeranalysis.googleapis.com` *(transitive — unused)*, plus standard GCP default project APIs.
- **Explicitly Confirmed NOT Enabled:** `aiplatform.googleapis.com` (Vertex AI), `sqladmin.googleapis.com` (Cloud SQL), `cloudkms.googleapis.com` (Cloud KMS), `container.googleapis.com` (GKE), `run.googleapis.com` (Cloud Run), `compute.googleapis.com` (Compute Engine).

---

## 5. Cloud Build Service Account & Least-Privilege IAM
- **Execution Identity (`us-central1`):** The dedicated Cloud Build execution service account for `pqc-inventory-agent-validation` *(provisioned with zero initial roles due to `constraints/iam.automaticIamGrantsForDefaultServiceAccounts = True`)*.
- **Least-Privilege Roles Granted to the Execution Service Account:**
  - `roles/logging.logWriter` — required for `options.logging: CLOUD_LOGGING_ONLY`.
  - `roles/storage.objectViewer` — read-only access to fetch the source archive staged by `gcloud builds submit`.
- **Security Controls Verified:**
  - Zero `roles/editor` or `roles/owner` bindings granted to any service account.
  - Zero broad IAM bindings copied from reference `functional-lab` projects.
  - Zero service account keys created (`constraints/iam.disableServiceAccountKeyCreation = True`).
  - Zero production credentials or secrets used.
  - Zero permanent Cloud Build triggers (`gcloud builds triggers list` returned `[]`).

---

## 6. Repository & Tested Commit Lineage
- **Repository:** `https://github.com/g-jsaccomani/pqc_inventory_agent.git` (`g-jsaccomani/pqc_inventory_agent`)
- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Tested Source Tree Base Commit SHA:** `adb9e0660ac4b17951d1c47215a1968a8462ee49` *(plus newly authored `cloudbuild.docker-validation.yaml` submitted via `gcloud builds submit`, 112 files / 3.2 MiB uncompressed; `.env`, `.venv/`, `.git/`, `data/`, `*.db` excluded)*.
- **Source Archive SHA-256 (Cloud Build Provenance):** `DldIwpBBP6bHhAMjX8Qnq1qRk_JgbuhIKxU4CBqfE-0=`

---

## 7. Cloud Build Execution Metadata
| Field | Value |
| :--- | :--- |
| **Project ID** | `pqc-inventory-agent-validation` |
| **Build ID** | `605c784d-6949-4891-bfd0-0ba519a6c68d` |
| **Region** | `us-central1` |
| **Machine Type / Pool** | `E2_STANDARD_2` (default worker pool) |
| **Logging Mode** | `CLOUD_LOGGING_ONLY` |
| **Timeout** | `900s` |
| **Build URL** | `https://console.cloud.google.com/cloud-build/builds;region=us-central1/605c784d-6949-4891-bfd0-0ba519a6c68d?project=pqc-inventory-agent-validation` |
| **Create Time (UTC)** | `2026-11-19T14:12:48.557508521Z` |
| **Start Time (UTC)** | `2026-11-19T14:12:49.297434163Z` |
| **Finish Time (UTC)** | `2026-11-19T14:15:37.458246Z` |
| **Wall-Clock Duration** | `2m48s` (`168.16s` start-to-finish; `195.820s` total CPU duration) |
| **Published Images** | `-` *(none)* |
| **Final Status** | **`SUCCESS`** |

---

## 8. Docker Image Build Result
- **Result:** **PASS**
- **Built Image ID:** `76112c405d6c`
- **Ephemeral Tag:** `pqc-inventory-agent:cb-605c784d-6949-4891-bfd0-0ba519a6c68d`
- **Dockerfile Steps:** `18/18` completed cleanly, including `google-cloud-cli`, Python `requirements.txt`, `chown -R root:root /app`, `chmod 0755 /app/scripts/run_db_migrations.py /app/scripts/migrate_sqlite_to_postgres.py`, and `USER 10001:10001`.
- **Ephemeral Cleanup:** Executed unconditionally via `trap cleanup EXIT`, removing `pqc-inventory-agent:cb-605c784d-6949-4891-bfd0-0ba519a6c68d`, `pqc-pytest-runner:cb-605c784d-6949-4891-bfd0-0ba519a6c68d`, and pytest smoke tags.

---

## 9. Check A — Non-Root Execution (`UID 10001`)
- **Commands:**
  - `docker run --rm --entrypoint id "$IMAGE" -u` → `10001`
  - `docker run --rm --entrypoint id "$IMAGE" -g` → `10001`
  - `docker run --rm --entrypoint id "$IMAGE" -un` → `pqcapp`
- **Result:** **PASS** — Container runs strictly as unprivileged user `pqcapp` (`UID 10001`, `GID 10001`).

---

## 10. Check B & B2 — Read-Only Root Filesystem & `/app` Immutability
- **Check B Command:**
  ```bash
  docker run --rm \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid \
    --entrypoint python \
    "$IMAGE" \
    scripts/run_db_migrations.py --help
  ```
- **Check B Result:** **PASS** — Exited `0`; output included `--db-url`, `--require-postgres`, and `--verify-only` without requiring rootfs write access.
- **Check B2 Result:** **PASS** — Inside `--read-only --tmpfs /tmp:rw,noexec,nosuid` as `euid == 10001`, writing to `/app/main.py` and `/app/pqc_agent/rogue.py` failed with `EACCES`/`EROFS`, while `tools.report_exporter._ensure_writable_output_dir()` resolved and wrote cleanly inside `/tmp/pqc-exports`.

---

## 11. Check C — Existing Docker-Gated `pytest` Regression Tests
Executed directly inside the Cloud Build worker against the shared Docker daemon using an ephemeral local-only runner built from the validated image plus the worker's `docker` CLI (`Docker version 20.10.24`, Python `3.12.16`, `pytest 9.2.0`) and `/workspace` mounted via `--volumes-from`:

| Test Name | Outcome | Duration |
| :--- | :--- | :--- |
| `tests/test_phase3_container_hardening.py::test_p3_04_live_docker_non_root_uid_and_read_only_migration_help` | **`PASSED`** | — |
| `tests/test_pre_merge_hotfix.py::test_pre_merge_01_live_docker_build_and_container_smoke` | **`PASSED`** | — |
| **Total (`pytest -v -rs`)** | **`2 passed, 0 failed, 0 skipped`** | **`16.31s`** |

---

## 12. Skipped Checks & Exact Reasons
- **Docker checks skipped in Cloud Build:** **`0`** *(both Docker-gated tests previously blocked locally executed and passed in full).*
- **Out-of-scope non-Docker opt-in tests in the broader repository suite (intentionally NOT executed in this Cloud Build run):**
  1. `tests/test_phase2_persistence_and_credentials.py::test_live_postgres_16_alembic_and_multi_instance_persistence` — requires external PostgreSQL 16 (`PQC_TEST_POSTGRES_URL` + `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`); external DB connections are explicitly out of scope for this validation.
  2. `tests/test_pqc_inventory.py::test_live_vertex_ai_gemini_turn` — requires live Vertex AI API (`PQC_LIVE_LLM_TEST=1`); Vertex AI API is intentionally disabled in `pqc-inventory-agent-validation`.

---

## 13. Relevant Cloud Build Log Excerpts
*(Retrieved verbatim from Cloud Logging for `build_id=605c784d-6949-4891-bfd0-0ba519a6c68d`; zero secrets present.)*

```text
Step 15/18 : RUN chown -R root:root /app     && find /app -type d -exec chmod 0755 {} +     && find /app -type f -exec chmod 0644 {} +     && chmod 0755 /app/scripts/run_db_migrations.py /app/scripts/migrate_sqlite_to_postgres.py
 ---> 23f51ba7e01e
Step 16/18 : USER 10001:10001
 ---> ee54ae5ca2d5
Step 17/18 : EXPOSE 8080
 ---> eb608357f128
Step 18/18 : CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
 ---> 76112c405d6c
Successfully built 76112c405d6c
Successfully tagged pqc-inventory-agent:cb-605c784d-6949-4891-bfd0-0ba519a6c68d

=== CHECK A: Non-root execution (expected UID=10001, GID=10001, user=pqcapp) ===
Effective container identity: uid=10001 gid=10001 user=pqcapp
PASS: Check A (UID 10001 / GID 10001 / user pqcapp verified)

=== CHECK B: Read-only root filesystem + scripts/run_db_migrations.py --help ===
usage: run_db_migrations.py [-h] [--db-url DB_URL] [--require-postgres]
                            [--verify-only]
...
  --require-postgres  Fail closed unless the resolved target database backend
                      is PostgreSQL.
PASS: Check B (--read-only rootfs migration help exited 0 with --require-postgres)

=== CHECK B2: In-container /app write-denial & writable /tmp fallback under --read-only ===
PASS: /app immutable (EACCES/EROFS) and export dir writable at /tmp/pqc-exports (mode=0o755)

=== CHECK C: Existing live Docker pytest regression tests ===
Resolved Cloud Build step container for /workspace volume sharing: 88867c14b764
Docker version 20.10.24, build 297e128
============================= test session starts ==============================
platform linux -- Python 3.12.16, pytest-9.2.0, pluggy-1.7.0 -- /usr/local/bin/python3.12
collecting ... collected 2 items

tests/test_phase3_container_hardening.py::test_p3_04_live_docker_non_root_uid_and_read_only_migration_help PASSED [ 50%]
tests/test_pre_merge_hotfix.py::test_pre_merge_01_live_docker_build_and_container_smoke PASSED [ 100%]

======================== 2 passed, 1 warning in 16.31s =========================
PASS: All mandatory Cloud Build Docker validation checks (A, B, B2, C) succeeded; zero images published, zero deployments performed.
=== CLEANUP: Removing ephemeral local Docker images ===
DONE
```

---

## 14. Remediation Performed
- **Application / Dockerfile Remediation Required:** **None.** The existing Phase 3.5 (`P3-04`) `Dockerfile` and `tools/report_exporter.py` passed every live Docker check on the first Cloud Build run.
- **Environment / IAM Setup Applied (Validation Project Only):** Granted least-privilege `roles/logging.logWriter` and `roles/storage.objectViewer` to the dedicated Cloud Build execution service account on `pqc-inventory-agent-validation`, required because `constraints/iam.automaticIamGrantsForDefaultServiceAccounts = True` leaves new default service accounts with zero roles.

---

## 15. Estimated Build Cost
- **Build Duration:** `2m48s` (`2.80` build-minutes) on `E2_STANDARD_2` (2 vCPU) in `us-central1`.
- **Estimated Cost (Estimated Only):** **~$0.02 USD** *(estimated from standard GCP Cloud Build `E2_STANDARD_2` per-minute compute pricing plus negligible <$0.001 for 3.2 MiB temporary source staging and Cloud Logging ingestion; final settled billing line items are not available immediately in real time).*

---

## 16. No-Publish & No-Deployment Statement
- **No container image was published:** `cloudbuild.docker-validation.yaml` contains no `images:` block, `IMAGES` reported `-`, and `gcloud artifacts repositories list --project=pqc-inventory-agent-validation` returned `[]` (zero repositories).
- **No application or runtime infrastructure was deployed:** Cloud Run, Cloud SQL, Vertex AI, Cloud KMS, GKE, and Compute Engine APIs remain disabled in `pqc-inventory-agent-validation`, zero Cloud Build triggers exist, and none of the reference `functional-lab` projects or production resources were modified.
