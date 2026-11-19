# Phase 3.3 (`P3-03`) — PQC Scorecard Denominator Correctness & Edge Cases

- **Branch:** `security-hardening/phase-03-runtime-resilience`
- **Parent Commit SHA:** `7cc289c795c98c54a31149a0abf5a136d84018bf`
- **Commit Message:** `fix(scorecard): enforce exhaustive denominators, TLS PQC readiness, and completeness status`

## Summary of Fixes
1. **Exhaustive Active Key Partitioning (`P3-03-V1`, `P3-03-V3`):**
   - `compute_scorecard_from_keys()` in `tools/gcp_inventory.py` partitions every active KMS key into `asym`, `sym` (including Cloud EKM `EXTERNAL_KEY_MANAGER` and unknown symmetric-purpose keys), or `uncategorized` (`partition_check_sum == active_keys`).
   - Active `UNKNOWN_REQUIRES_REVIEW` and `EXTERNAL_KEY_MANAGER` keys receive `0` numerator credit in their respective denominators, eliminating silent inflation to `100.0%`.
   - Active uncategorized keys (unrecognized family AND unrecognized purpose) proportionally penalize `weighted_kms_pqc_maturity`.
2. **Asymmetric Key Activity on Version-Listing Errors (`P3-03-V2`):**
   - `build_key_record()` conservatively keeps non-disabled/non-destroyed keys with `versions_listing_error` and `primary_state="NO_PRIMARY"` active (`activity_assumed_due_to_version_error=True`), preventing 403/transient `list_crypto_key_versions` errors from erasing asymmetric keys from denominators.
3. **TLS 1.3 `postQuantumKeyExchange=DEFERRED` Awareness (`P3-03-V4`):**
   - Added `https_proxies_pqc_ready_tls_1_3` metric and `counts.https_proxies_tls_1_3_with_pqc_deferred` alongside backward-compatible `https_proxies_requiring_tls_1_3`.
4. **Inventory Completeness Status (`P3-03-V5`):**
   - Added top-level `inventory_complete` and `completeness_status` (`COMPLETE`, `PARTIAL_WITH_ERRORS`, `EMPTY_SCOPE`, `COLLECTION_FAILED`).
5. **Import-Order Resilience:**
   - Moved `pqc_agent` imports inside `tools/calibration_engine.py` and `tools/gcloud_bridge.py` to lazy function scope, eliminating circular imports when `tools` is imported before `pqc_agent`.

## Test Results
- `.venv/bin/pytest -v -rs tests/test_phase3_scorecard_correctness.py`: **6 passed, 0 failed, 0 skipped**
- `.venv/bin/pytest -v -rs tests/test_pqc_inventory.py -k scorecard`: **1 passed, 0 failed**
- `.venv/bin/python -m compileall -q pqc_agent tools tests` & `git diff --check`: exit code `0`
