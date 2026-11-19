# Phase 3.2 (`P3-05`) — Test Execution Results

- **Environment:** macOS, Python `3.12.13` (`.venv/bin/python`), `pytest` (`.venv/bin/pytest`)
- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Parent Commit SHA:** `6a872b911f5cf3ca0c3a9657058b988bffd6f9dd`

## Executed Quality Gates

| # | Command | Passed | Failed | Skipped | Duration | Exit Code |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| 1 | `.venv/bin/pytest -v -rs tests/test_phase3_upload_security.py` | **22** | **0** | **0** | `3.64s` | `0` |
| 2 | `.venv/bin/pytest -v -rs` (complete project suite) | **326** | **0** | **3** | `62.06s` | `0` |
| 3 | `.venv/bin/python -m compileall -q pqc_agent tools tests` | — | **0** | — | `<1s` | `0` |
| 4 | `git diff --check` | — | **0** | — | `<1s` | `0` |

## Skipped Tests (Pre-existing Environment-Gated)
1. `tests/test_phase2_persistence_and_credentials.py:1507` — Live PostgreSQL 16 test (`PQC_TEST_POSTGRES_URL` opt-in).
2. `tests/test_pqc_inventory.py:974` — Live Vertex AI Gemini test (`PQC_LIVE_LLM_TEST=1`).
3. `tests/test_pre_merge_hotfix.py:210` — Live Docker smoke test (Docker CLI/daemon unavailable locally).
