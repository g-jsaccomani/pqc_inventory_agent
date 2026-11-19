# Phase 3.4 (`P3-02`) — Vertex AI Timeouts, Retries & Circuit-Breaker Resilience

- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Parent Commit SHA:** `d5f4f145a0524522d839d677a35b49d6c7d5cd58`
- **Commit Message:** `feat(resilience): add Vertex AI timeouts, bounded retries, and per-model circuit breaker`

## Summary of Implementation
1. **`pqc_agent/resilience.py`:**
   - Configurable timeouts (`PQC_VERTEX_PROBE_TIMEOUT_SECONDS=15`, `PQC_VERTEX_REQUEST_TIMEOUT_SECONDS=120`, `PQC_AGENT_TURN_TIMEOUT_SECONDS=240`) with `build_vertex_http_options()` converting seconds into exact `google.genai.types.HttpOptions(timeout=<ms>)` integer milliseconds.
   - `is_transient_vertex_error()` distinguishing upstream availability/quota faults (`429`, `500`, `502`, `503`, `504`, `TimeoutError`) from non-transient client/auth errors (`400`, `401`, `403`, `404`, `422`).
   - Thread-safe per-model `VertexCircuitBreaker` (`CLOSED` -> `OPEN` -> `HALF_OPEN` single trial -> `CLOSED`, default threshold `5`, cooldown `30s`) ensuring sustained outage on one model fast-fails without blocking unaffected models.
   - Full-jitter exponential backoff retry helper (`compute_backoff_delay`, `call_with_retry_sync`) strictly respecting remaining turn deadline.
2. **Wired Across All Vertex AI Entrypoints:**
   - `pqc_agent/agent.py` (`build_generate_content_config`) and `pqc_agent/model_registry.py` (`vertex_generate_probe`): explicit millisecond `HttpOptions(timeout=...)` + bounded transient retry on probes.
   - `pqc_agent/workspace_server.py` (`POST /api/chat`) and `main.py` (`run_adk_agent_turn`): per-model circuit breaker fast-fail (`503 MODEL_CIRCUIT_OPEN` with `Retry-After` header), wall-clock `asyncio.timeout()` (`504 MODEL_TIMEOUT`), and bounded transient retries.
   - Verified Cloud Run `--timeout=600` in `scripts/deploy_cloud_run.sh` and `scripts/setup_and_deploy_vertex.sh` safely exceeds `PQC_AGENT_TURN_TIMEOUT_SECONDS=240`.

## Test Results
- `.venv/bin/pytest -v -rs tests/test_phase3_vertex_resilience.py`: **7 passed, 0 failed, 0 skipped** (`2.88s`)
- `.venv/bin/pytest -v -rs tests/test_pqc_inventory.py -k "model or chat"`: **6 passed, 1 skipped (live Vertex AI), 0 failed** (`8.87s`)
- `.venv/bin/python -m compileall -q pqc_agent tools tests main.py` & `git diff --check`: exit code `0`
