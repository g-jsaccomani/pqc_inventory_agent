# Phase 3 — Merge Readiness Checklist

| # | Check Category | Verification Item | Status | Evidence / Observed Result |
| :-: | :--- | :--- | :---: | :--- |
| 1 | **Preconditions** | Repository root & branch `security-hardening/phase-03-runtime-resilience` confirmed | **PASS** | `git branch --show-current` -> `security-hardening/phase-03-runtime-resilience` |
| 2 | **Preconditions** | Expected pre-signoff `HEAD` matches `91b102c5057eafe0e049bfd9b2d5207dfed67da3` | **PASS** | `git rev-parse HEAD` == `origin/security-hardening/phase-03-runtime-resilience` == `91b102c5057eafe0e049bfd9b2d5207dfed67da3` |
| 3 | **Preconditions** | Tracked working tree clean (`0` modified/staged tracked files) | **PASS** | Only 2 pre-existing untracked local prompt reference files outside Git |
| 4 | **Preconditions** | `origin` fetched & ancestry verified (`origin/main` is direct ancestor of `HEAD`) | **PASS** | `main` == `origin/main` == `62f7247b52effc3f3cf2086a86f06071eea1b6fc`; `15` ahead, `0` behind |
| 5 | **Diff Hygiene** | Final commit `91b102c5057eafe0e049bfd9b2d5207dfed67da3` contains only the 6 expected evidence files | **PASS** | Verified via `git show --stat --name-status 91b102c5057eafe0e049bfd9b2d5207dfed67da3` |
| 6 | **Diff Hygiene** | Zero merge conflicts against `origin/main` | **PASS** | `git merge-tree --write-tree origin/main HEAD` -> clean (`NONE`) |
| 7 | **Diff Hygiene** | Zero whitespace/diff formatting errors & clean Python bytecode compilation | **PASS** | `git diff --check origin/main..HEAD` (exit `0`), `compileall` (exit `0`) |
| 8 | **Security (`P3-01`)** | SSRF, outbound egress guard, trusted `gcloud` path, env scrubbing, deny-by-default ADC & tenant boundaries | **PASS** | `pqc_agent/egress_guard.py`, `tools/gcloud_bridge.py`, `tests/test_phase3_egress_security.py`, `tests/test_phase3_adc_authorization.py` |
| 9 | **Security (`P3-05`)** | Bounded streaming uploads, MIME/magic-byte validation, private-key/XXE/ZIP-bomb blocking, tenant session/cache isolation | **PASS** | `pqc_agent/upload_validator.py`, `tools/calibration_engine.py`, `pqc_agent/auth_store.py`, `tests/test_phase3_upload_security.py` |
| 10 | **Correctness (`P3-03`)** | Exhaustive PQC scorecard denominators, TLS 1.3 `DEFERRED` exclusion, `completeness_status` | **PASS** | `tools/gcp_inventory.py`, `tests/test_phase3_scorecard_correctness.py` |
| 11 | **Resilience (`P3-02`)** | Vertex AI HTTP millisecond timeouts, bounded jitter retries, per-model circuit breaker | **PASS** | `pqc_agent/resilience.py`, `pqc_agent/agent.py`, `pqc_agent/workspace_server.py`, `main.py`, `tests/test_phase3_vertex_resilience.py` |
| 12 | **Container (`P3-04`)** | Non-root `UID/GID 10001`, immutable `root:root` `/app`, read-only report exporter fallback | **PASS** | `Dockerfile`, `tools/report_exporter.py`, `tests/test_phase3_container_hardening.py` |
| 13 | **Live Gate A** | PostgreSQL 16.15 live persistence, Alembic `20261117_0002`, multi-instance & concurrency | **PASS** *(Reviewed)* | `1 passed, 0 failed` (`150.30s`), `39/39` warnings classified, tunnel/certs/password cleanup verified |
| 14 | **Live Gate B** | Vertex AI live Gemini turn (`gemini-3.1-pro-preview-customtools`, `global`) | **PASS** *(Reviewed)* | `1 passed, 0 failed` (`6.52s`), real tokens (`3197`/`53`/`74`), `38/38` warnings classified, ADC revoked |
| 15 | **Live Gate C** | Cloud Build live Docker non-root & `--read-only` validation | **PASS** *(Reviewed)* | `2 passed, 0 failed, 0 skipped` (`16.31s`), Build `605c784d-6949-4891-bfd0-0ba519a6c68d`, valid for `90278884...` |
| 16 | **Regression** | Safe local regression suites & independent Phase 3 re-verification | **PASS** | Full safe suite `343 passed, 0 failed, 4 skipped` (recorded); Phase 3 suite `261 passed, 0 failed, 1 skipped` (independently re-run `11.34s`) |
| 17 | **Warnings** | All PostgreSQL (`39`), Vertex AI (`38`), and safe-suite (`496`) warnings traced & classified | **PASS** | `0` blockers, `0` security-relevant, `0` reliability concerns, `0` unresolved; non-blocking deprecation/experimental & local env notices only |
| 18 | **Secrets / Hygiene** | Secret scan across `origin/main..HEAD` and `phase_03_final_integration/` | **PASS** *(Accepted Low Risk)* | `0` secrets, tokens, keys, or private cloud IDs; low-severity historical `file://` path links in earlier Phase 3.0/3.1 docs documented as accepted risk |
| 19 | **Governance** | GitHub PRs, branch protection & CI checks inspected (read-only) | **WARN** *(Accepted Risk)* | `0` open PRs; `main` unprotected (`HTTP 404`), `0` CI check-runs; manual human sign-off gates merge |
| 20 | **Change Control** | No merge, no PR creation, no Phase 4 start, no deployment, no production or history mutation | **PASS** | Verified strictly adhered to throughout review |
