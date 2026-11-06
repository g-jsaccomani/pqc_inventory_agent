"""Post-Quantum Cryptography (PQC) evidence-collection and calculation tools for Google Cloud.

Tools only collect facts and compute auditable numbers; the Gemini agents perform all reasoning.
"""

from tools.calibration_engine import (
    calibrate_assessment_context,
    get_historical_calibration_profile,
    read_uploaded_artifact,
    register_uploaded_artifact_for_analysis,
)
from tools.gcloud_bridge import (
    execute_gcloud_command,
    get_active_gcp_credentials,
    get_current_tenant_user,
    get_gcp_connection_config,
    get_recent_gcloud_traces,
    normalize_user_id,
    set_current_tenant_user,
    set_gcp_connection_config,
    validate_gcloud_command,
)
from tools.gcp_inventory import (
    classify_algorithm,
    collect_kms_inventory,
    collect_workload_evidence,
    compute_pqc_scorecard,
    discover_all_crypto_assets,
    export_cyclonedx_cbom,
)
from tools.pqc_detectors import collect_kms_import_jobs, collect_tls_policies
from tools.quantum_engine import map_algorithm_to_quantum_profile, run_quantum_cryptanalysis_simulation
from tools.report_exporter import render_styled_consulting_html, save_assessment_report

__all__ = [
    "calibrate_assessment_context",
    "classify_algorithm",
    "collect_kms_import_jobs",
    "collect_kms_inventory",
    "collect_tls_policies",
    "collect_workload_evidence",
    "compute_pqc_scorecard",
    "discover_all_crypto_assets",
    "execute_gcloud_command",
    "export_cyclonedx_cbom",
    "get_active_gcp_credentials",
    "get_current_tenant_user",
    "get_gcp_connection_config",
    "get_historical_calibration_profile",
    "get_recent_gcloud_traces",
    "map_algorithm_to_quantum_profile",
    "normalize_user_id",
    "read_uploaded_artifact",
    "register_uploaded_artifact_for_analysis",
    "render_styled_consulting_html",
    "run_quantum_cryptanalysis_simulation",
    "save_assessment_report",
    "set_current_tenant_user",
    "set_gcp_connection_config",
    "validate_gcloud_command",
]

