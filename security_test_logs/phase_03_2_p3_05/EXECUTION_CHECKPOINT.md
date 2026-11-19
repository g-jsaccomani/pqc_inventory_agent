# Phase 3.2 (`P3-05`) — Multimodal Upload Hardening Checkpoint

- **Repository:** `g-jsaccomani/pqc_inventory_agent`
- **Target Branch:** `security-hardening/phase-03-runtime-resilience`
- **Baseline `main` Commit SHA:** `62f7247b52effc3f3cf2086a86f06071eea1b6fc` (untouched)
- **Parent Commit SHA:** `6a872b911f5cf3ca0c3a9657058b988bffd6f9dd`
- **Commit Message:** `fix(security): harden multimodal upload validation and tenant artifact cache`

## Completed Scope
- [x] Created `pqc_agent/upload_validator.py` (streaming chunked size/count quotas, filename sanitization, allowlist + MIME + magic-byte validation, private-key rejection, `.docx` ZIP-bomb/zip-slip/XXE guard, bounded `.pdf` extraction, PNG/JPEG dimension bounds, zero `latin-1` binary fallback).
- [x] Hardened `tools/calibration_engine.py` with thread-safe, tenant-partitioned bounded LRU + byte-budget + TTL `_UPLOADED_ARTIFACT_CACHE`.
- [x] Integrated atomic pre-persistence upload validation & sanitized GCS filenames in `pqc_agent/workspace_server.py`, plus `DistributedAuthStore.is_session_owned_by_other_user()` in `pqc_agent/auth_store.py` preventing cross-tenant `session_id` collisions in `POST /api/sessions` and `POST /api/chat`.
- [x] Added `tests/test_phase3_upload_security.py` (`22 passed, 0 failed`).
- [x] Verified complete test suite (`326 passed, 3 skipped, 0 failed`), `compileall`, and `git diff --check`.
- [x] Committed and pushed to `origin/security-hardening/phase-03-runtime-resilience`.
