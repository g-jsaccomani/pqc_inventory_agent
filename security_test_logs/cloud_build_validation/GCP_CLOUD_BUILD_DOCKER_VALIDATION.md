# GCP Cloud Build Docker Validation Report — Phase 3.5 (`P3-04`)

## 1. Objective & Validation Scope
Execute real Docker image build and live container runtime verification in an isolated Google Cloud validation project (`pqc-inventory-agent-validation`), validating:
- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Tested Source Tree Base Commit SHA:** `adb9e0660ac4b17951d1c47215a1968a8462ee49` *(submitted with `cloudbuild.docker-validation.yaml`; 112 tracked files / 3.2 MiB uncompressed; `.env`, `.venv/`, `.git/`, `data/`, and `*.db` excluded)*
- **Scope:** Phase 3.5 (`P3-04`) — Docker non-root execution (`UID/GID 10001`, user `pqcapp`), read-only root filesystem (`--read-only --tmpfs /tmp:rw,noexec,nosuid`), `/app` immutability, migration CLI help execution, and both existing Docker-gated `pytest` regression tests that cannot execute in local environments without a Docker daemon.

---

## 2. Cloud Build Execution Summary
| Field | Value |
| :--- | :--- |
| **Validation Project ID** | `pqc-inventory-agent-validation` |
| **Build ID** | `605c784d-6949-4891-bfd0-0ba519a6c68d` |
| **Region** | `us-central1` |
| **Machine Type / Pool** | `E2_STANDARD_2` (default worker pool) |
| **Logging Mode** | `CLOUD_LOGGING_ONLY` |
| **Timeout** | `900s` |
| **Wall-Clock Duration** | `2m48s` (`168.16s` wall-clock; `195.820s` total CPU duration) |
| **Published Images** | `-` *(none)* |
| **Final Status** | **`SUCCESS`** |

### Validation Isolation Controls
- **Execution Scope:** Only `cloudbuild.googleapis.com` was explicitly enabled for validation. Runtime and stateful service APIs (`aiplatform.googleapis.com`, `sqladmin.googleapis.com`, `cloudkms.googleapis.com`, `container.googleapis.com`, `run.googleapis.com`, `compute.googleapis.com`) remained disabled.
- **Least-Privilege Build Execution:** Cloud Build executed with only the minimum roles required for log emission and source retrieval (`roles/logging.logWriter` and `roles/storage.objectViewer`), with zero broad roles (`roles/editor`, `roles/owner`), zero service account keys, zero production secrets, and zero permanent Cloud Build triggers.

---

## 3. Docker Image Build Result
- **Result:** **PASS**
- **Built Image ID:** `76112c405d6c`
- **Ephemeral Tag:** `pqc-inventory-agent:cb-605c784d-6949-4891-bfd0-0ba519a6c68d`
- **Dockerfile Steps:** `18/18` completed cleanly, including `google-cloud-cli`, Python `requirements.txt`, `chown -R root:root /app`, `chmod 0755 /app/scripts/run_db_migrations.py /app/scripts/migrate_sqlite_to_postgres.py`, and `USER 10001:10001`.
- **Ephemeral Cleanup:** Executed unconditionally via `trap cleanup EXIT`, removing `pqc-inventory-agent:cb-605c784d-6949-4891-bfd0-0ba519a6c68d`, `pqc-pytest-runner:cb-605c784d-6949-4891-bfd0-0ba519a6c68d`, and pytest smoke tags.

---

## 4. Check A — Non-Root Execution (`UID/GID 10001`)
- **Commands:**
  - `docker run --rm --entrypoint id "$IMAGE" -u` → `10001`
  - `docker run --rm --entrypoint id "$IMAGE" -g` → `10001`
  - `docker run --rm --entrypoint id "$IMAGE" -un` → `pqcapp`
- **Result:** **PASS** — Container runs strictly as unprivileged user `pqcapp` (`UID 10001`, `GID 10001`).

---

## 5. Check B & B2 — Read-Only Root Filesystem & `/app` Immutability
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

## 6. Check C — Existing Docker-Gated `pytest` Regression Tests
Executed inside the Cloud Build worker against the worker's Docker daemon using an ephemeral local-only runner built from the validated image plus the worker's `docker` CLI (`Docker version 20.10.24`, Python `3.12.16`, `pytest 9.2.0`):

| Test Name | Outcome | Duration |
| :--- | :--- | :--- |
| `tests/test_phase3_container_hardening.py::test_p3_04_live_docker_non_root_uid_and_read_only_migration_help` | **`PASSED`** | — |
| `tests/test_pre_merge_hotfix.py::test_pre_merge_01_live_docker_build_and_container_smoke` | **`PASSED`** | — |
| **Total (`pytest -v -rs`)** | **`2 passed, 0 failed, 0 skipped`** | **`16.31s`** |

---

## 7. Intentionally Unexecuted External Integration Tests
- **Docker checks skipped in Cloud Build:** **`0`** *(both Docker-gated tests executed and passed in full).*
- **Out-of-scope external integration tests intentionally NOT executed in this Docker validation run:**
  1. `tests/test_phase2_persistence_and_credentials.py::test_live_postgres_16_alembic_and_multi_instance_persistence` — requires an external PostgreSQL 16 database (`PQC_TEST_POSTGRES_URL` + `PQC_ALLOW_DESTRUCTIVE_TEST_DB=true`); external database connections are out of scope for isolated Docker container validation.
  2. `tests/test_pqc_inventory.py::test_live_vertex_ai_gemini_turn` — requires live Vertex AI API access (`PQC_LIVE_LLM_TEST=1`); Vertex AI API is intentionally disabled in `pqc-inventory-agent-validation`.

---

## 8. Relevant Cloud Build Log Excerpts
*(Sanitized excerpts from Cloud Build `605c784d-6949-4891-bfd0-0ba519a6c68d`.)*

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

## 9. Estimated Build Cost
- **Build Duration:** `2m48s` (`2.80` build-minutes) on `E2_STANDARD_2` (2 vCPU) in `us-central1`.
- **Estimated Cost (Estimate Only):** **~$0.02 USD** *(estimated from standard GCP Cloud Build `E2_STANDARD_2` per-minute compute rates plus negligible temporary source staging and Cloud Logging ingestion; this is an estimate rather than a settled invoice figure).*

---

## 10. No-Publish & No-Deployment Confirmation
- **No container image was published:** `cloudbuild.docker-validation.yaml` omits the `images:` section, Cloud Build reported `IMAGES: -`, and `pqc-inventory-agent-validation` contains zero Artifact Registry repositories (`[]`).
- **No application or runtime infrastructure was deployed:** Cloud Run, Cloud SQL, Vertex AI, Cloud KMS, GKE, and Compute Engine APIs remained disabled, zero permanent Cloud Build triggers were created, and no application code or `Dockerfile` changes were required.
