# Phase 3.1 (`P3-01` P0 Hotfix) — Test Execution Results

- **Environment:** macOS, Python `3.12.13` (`.venv/bin/python`), `pytest` (`.venv/bin/pytest`)
- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Parent Commit SHA:** `44e6cd4c7192b89af3f0e61c2e6a69dc23cf16d9`

---

## 1. Executed Quality Gate Commands & Exact Counts

| # | Command | Passed | Failed | Skipped | Duration | Exit Code |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| 1 | `.venv/bin/pytest -v -rs tests/test_phase3_adc_authorization.py` | **41** | **0** | **0** | `4.95s` | `0` |
| 2 | `.venv/bin/pytest -v -rs tests/test_phase3_egress_security.py` | **181** | **0** | **0** | `2.09s` | `0` |
| 3 | `.venv/bin/pytest -v -rs` (complete test suite) | **304** | **0** | **3** | `54.16s` | `0` |
| 4 | `.venv/bin/python -m compileall -q pqc_agent tools tests` | — | **0** | — | `<1s` | `0` |
| 5 | `git diff --check` | — | **0** | — | `<1s` | `0` |

---

## 2. Full Suite Breakdown (`304 passed, 3 skipped, 0 failed`)

- `tests/test_phase3_adc_authorization.py`: **41 passed** (all 21 P0 hotfix scenarios + parametrized alias, flag, resource-URI, and executable-hardening cases)
- `tests/test_phase3_egress_security.py`: **181 passed** (all Phase 3.1 SSRF/egress, `gcloud` grammar/flag allowlist, env sanitization, and confused-deputy checks preserved intact)
- `tests/test_auth_hardening.py`: **all passed** (Phase 1 OAuth/PKCE/CSRF/tenant isolation checks)
- `tests/test_phase2_persistence_and_credentials.py`: **all unit/integration tests passed**, **1 skipped** (live PostgreSQL 16 test)
- `tests/test_pqc_inventory.py`: **all offline & API tests passed**, **1 skipped** (live Vertex AI LLM turn test)
- `tests/test_pre_merge_hotfix.py`: **all non-Docker checks passed**, **1 skipped** (live Docker daemon test)

---

## 3. Skipped Tests & Environmental Limitations

All 3 skipped tests are pre-existing environment-gated integration tests unrelated to this hotfix:

1. `tests/test_phase2_persistence_and_credentials.py:1507` — `SKIPPED`: `Live PostgreSQL 16 integration test requires disposable PQC_TEST_POSTGRES_URL and explicit PQC_ALLOW_DESTRUCTIVE_TEST_DB=true opt-in.`
2. `tests/test_pqc_inventory.py:974` — `SKIPPED`: `Set PQC_LIVE_LLM_TEST=1 with Vertex AI access to run.`
3. `tests/test_pre_merge_hotfix.py:210` — `SKIPPED`: `BLOCKED: Docker CLI/daemon is not installed in this workstation environment.`

No new skips were introduced, and zero existing security assertions were weakened or removed.

---

## 4. Compilation & Diff-Check Results

- `.venv/bin/python -m compileall -q pqc_agent tools tests`: exit code `0` (all Python modules across `pqc_agent/`, `tools/`, and `tests/` compiled with zero syntax or bytecode errors).
- `git diff --check`: exit code `0` (zero trailing whitespace errors, conflict markers, or malformed EOF lines).
