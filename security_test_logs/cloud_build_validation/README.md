# GCP Cloud Build Docker Validation — Operational Guide

This directory stores the evidence and instructions for running real Docker build and runtime hardening checks (Phase 3.5 / `P3-04`) on Google Cloud Build without requiring a local Docker daemon.

## Target Isolated GCP Project
- **Project ID:** `pqc-inventory-agent-validation`
- **Parent Hierarchy:** The functional-lab parent folder under the designated organization
- **Region:** `us-central1`
- **Machine Type:** `E2_STANDARD_2` (default worker pool, `900s` timeout, `CLOUD_LOGGING_ONLY`)
- **Execution Identity:** The dedicated Cloud Build execution service account
  - Least-privilege IAM bindings: `roles/logging.logWriter` and `roles/storage.objectViewer` only.

## Exact Command to Rerun Validation

Ensure your active `gcloud` CLI profile is authenticated to an authorized account for `pqc-inventory-agent-validation`, then run from the repository root on the target branch:

```bash
gcloud config set project pqc-inventory-agent-validation

gcloud builds submit \
  --project=pqc-inventory-agent-validation \
  --config=cloudbuild.docker-validation.yaml \
  --region=us-central1 \
  .
```

### Viewing Build Logs (`CLOUD_LOGGING_ONLY`)
Because `cloudbuild.docker-validation.yaml` uses `logging: CLOUD_LOGGING_ONLY`, stream logs directly via `gcloud beta builds submit` or inspect a completed build with:

```bash
gcloud logging read \
  'resource.type="build" AND resource.labels.build_id="BUILD_ID"' \
  --project=pqc-inventory-agent-validation \
  --order=asc \
  --format='value(textPayload)'
```

## What the Build Verifies
1. **Image Build:** Builds the repository `Dockerfile` with an ephemeral local tag (`pqc-inventory-agent:cb-$BUILD_ID`).
2. **Check A (Non-Root):** Asserts `id -u == 10001`, `id -g == 10001`, `id -un == pqcapp`.
3. **Check B (Read-Only Rootfs):** Runs `python scripts/run_db_migrations.py --help` under `--read-only --tmpfs /tmp:rw,noexec,nosuid` and asserts exit `0` + `--require-postgres`.
4. **Check B2 (`/app` Immutability):** Confirms writes to `/app/main.py` and `/app/pqc_agent/rogue.py` fail with `EACCES`/`EROFS` while `report_exporter._ensure_writable_output_dir()` writes cleanly under `/tmp/`.
5. **Check C (Existing Docker `pytest` Regression Tests):** Runs both live Docker tests:
   - `tests/test_phase3_container_hardening.py::test_p3_04_live_docker_non_root_uid_and_read_only_migration_help`
   - `tests/test_pre_merge_hotfix.py::test_pre_merge_01_live_docker_build_and_container_smoke`
6. **Cleanup & Safety:** Removes ephemeral local images via an `EXIT` trap, publishes **no** image to Artifact Registry or Docker Hub, and performs **no** application deployment.

## Latest Evidence Report
- [GCP_CLOUD_BUILD_DOCKER_VALIDATION.md](./GCP_CLOUD_BUILD_DOCKER_VALIDATION.md)
