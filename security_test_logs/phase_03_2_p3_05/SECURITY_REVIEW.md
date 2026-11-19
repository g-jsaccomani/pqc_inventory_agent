# Phase 3.2 (`P3-05`) — Multimodal Upload Security Review

- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Phase:** `3.2 — P3-05 Multimodal Upload Size Limits, MIME Validation, Magic-Byte Sniffing & Tenant Cache Isolation`

---

## 1. Root Cause & Remediations Implemented

1. **Streaming Upload Quotas (`pqc_agent/upload_validator.py`):**
   - Replaced unbounded `await up_file.read()` in `POST /api/chat` with `read_bounded_upload()` pulling fixed `64 KiB` chunks and aborting immediately on `PQC_MAX_UPLOAD_FILE_BYTES` (`10 MiB` default) or `PQC_MAX_UPLOAD_TOTAL_BYTES` (`25 MiB` default) with HTTP `413`.
   - Enforced `PQC_MAX_UPLOAD_FILES_PER_TURN` (`5` default) and `0`-byte rejection atomically via `validate_upload_batch()` BEFORE creating sessions, persisting to GCS, writing cache entries, or invoking Gemini.
2. **Filename Sanitization (`sanitize_upload_filename` + `ResilientGcsArtifactService`):**
   - Normalizes Unicode (`NFKC`), strips POSIX/Windows path segments, NUL/control chars, leading dots, and unsafe symbols, caps filenames to `128` chars, and enforces sanitization directly inside `ResilientGcsArtifactService.save_artifact()` / `load_artifact()` so traversal segments cannot reach GCS object keys.
3. **Allowlist, MIME Consistency & Magic-Byte Sniffing (`validate_and_extract_upload`):**
   - Restricted extensions to `.pdf`, `.docx`, `.png`, `.jpg`, `.jpeg`, `.pem`, `.crt`, `.cer`, `.txt`, `.md`, `.markdown`, `.csv`, `.json`, `.yaml`, `.yml`.
   - Removed `.key` from `_guess_gemini_mime_type()` and explicitly blocked `.key`/`.p12`/`.pfx`/`.jks`/`.keystore` plus PEM & DER private keys (`400 UPLOAD_PRIVATE_KEY_REJECTED`).
   - Eliminated `latin-1` binary fallback across `tools/calibration_engine.py` and `pqc_agent/workspace_server.py`; text uploads reject binary headers (`MZ`, `\x7fELF`, `PK`, `%PDF-`, PNG/JPEG, archives), NUL bytes, non-UTF-8 payloads, and binary control chars while accepting UTF-8 BOM (`utf-8-sig`) and CRLF.
4. **Parser DoS & XXE Protection:**
   - `.docx`: Pre-parse `ZipFile` inspection enforces entry cap (`500`), total uncompressed limit (`32 MiB`, verified both from `ZipInfo` headers and actual decompressed chunk streams), compression ratio (`<= 100:1`), zip-slip path rejection, required OOXML members (`[Content_Types].xml` + `word/document.xml`), and XML `<!DOCTYPE`/`<!ENTITY` blocking prior to `python-docx`.
   - `.pdf`: Strict byte-0 `%PDF-` check, page cap (`200`), bounded extracted text (`256 KiB`), and fail-closed `400 UPLOAD_CORRUPT_DOCUMENT` on malformed PDFs.
   - `.png`/`.jpg`: Header signature + `IHDR`/`SOF*` dimension bounds (`<= 16384` per side, `<= 40M` pixels).
5. **Tenant-Partitioned Bounded LRU Cache & Cross-Tenant Session Guard (`tools/calibration_engine.py`, `pqc_agent/auth_store.py`, `pqc_agent/workspace_server.py`):**
   - Partitioned `_UPLOADED_ARTIFACT_CACHE` strictly by `(normalize_user_id(user_id), session_id, sanitized_filename)` inside a thread-safe `OrderedDict` enforcing `PQC_UPLOAD_CACHE_MAX_ENTRIES` (`128`), `PQC_UPLOAD_CACHE_MAX_BYTES` (`32 MiB`), and `PQC_UPLOAD_CACHE_TTL_SECONDS` (`3600s`).
   - Added `DistributedAuthStore.is_session_owned_by_other_user()` pre-check in `POST /api/sessions` and `POST /api/chat` to reject cross-tenant `session_id` collisions with HTTP `403` before creating any ADK session row or saving artifacts.
   - Framed `[UPLOADED_ARTIFACTS_CONTEXT]` explicitly instructing the model to treat uploaded document content strictly as untrusted data.

---

## 2. Final Assessment

**PASS.** All five `P3-05` vulnerabilities (`P3-05-V1` through `P3-05-V5`) plus the discovered cross-tenant orphaned session creation edge case in `POST /api/sessions`/`POST /api/chat` are closed with zero regressions across existing suites.
