"""Unit and integration tests for the Post-Quantum Cryptography (PQC) Inventory & Governance Agent."""

import json

from main import build_executive_markdown_report, run_local_harness
from tools.gcp_inventory import (
    _classify_cai_crypto_asset,
    _compute_metrics_for_keys,
    _evaluate_mosca_theorem_risk,
    _resolve_scope,
    classify_crypto_key,
    discover_all_crypto_assets,
    export_cyclonedx_cbom,
    generate_application_pqc_refactoring_guide,
    generate_pqc_migration_plan,
    scan_pqc_readiness,
)


def test_resolve_scope_org_and_project():
    """Validates that empty, 'org', 'current', or '31564119954' inputs resolve to Organization Mode."""
    for token in ("", "org", "organization", "current", "current environment", "31564119954", "organizations/31564119954"):
        mode, scope_uri, clean_id = _resolve_scope(token)
        assert mode == "ORG"
        assert scope_uri == "organizations/31564119954"
        assert clean_id == "31564119954"

    mode, scope_uri, clean_id = _resolve_scope("pqc-inventory-agent-cd06")
    assert mode == "PROJECT"
    assert scope_uri == "projects/pqc-inventory-agent-cd06"
    assert clean_id == "pqc-inventory-agent-cd06"


def test_classify_pqc_approved_algorithms_and_cnsa_2_0():
    """Validates all NIST FIPS 203 (KEM_XWING, ML_KEM_768/1024), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) algorithms."""
    xwing = classify_crypto_key(
        key_ring="kr-pqc",
        key_name="key-xwing",
        purpose="KEY_ENCAPSULATION",
        algorithm="KEM_XWING",
    )
    assert xwing["quantum_status"] == "APPROVED_PQC"
    assert xwing["priority"] == "LOW"
    assert "FIPS 203" in xwing["nist_standard_target"]
    assert xwing["pqc_artifact_sizes_bytes"]["ciphertext_or_signature_bytes"] == 1120

    mlkem1024 = classify_crypto_key(
        key_ring="kr-pqc",
        key_name="key-mlkem1024",
        purpose="KEY_ENCAPSULATION",
        algorithm="ML_KEM_1024",
    )
    assert mlkem1024["quantum_status"] == "APPROVED_PQC"
    assert mlkem1024["cnsa_2_0_compliance"] == "CNSA_2_0_MANDATORY_COMPLIANT"

    mldsa65_mu = classify_crypto_key(
        key_ring="kr-pqc",
        key_name="key-mldsa65-mu",
        purpose="ASYMMETRIC_SIGN",
        algorithm="PQ_SIGN_ML_DSA_65_EXTERNAL_MU",
    )
    assert mldsa65_mu["quantum_status"] == "APPROVED_PQC"
    assert "FIPS 204" in mldsa65_mu["nist_standard_target"]
    assert mldsa65_mu["pqc_artifact_sizes_bytes"]["ciphertext_or_signature_bytes"] == 3309
    assert any("External-Mu" in note for note in mldsa65_mu["engineering_notes"])

    mldsa87 = classify_crypto_key(
        key_ring="kr-pqc",
        key_name="key-mldsa87",
        purpose="ASYMMETRIC_SIGN",
        algorithm="PQ_SIGN_ML_DSA_87",
    )
    assert mldsa87["quantum_status"] == "APPROVED_PQC"
    assert mldsa87["cnsa_2_0_compliance"] == "CNSA_2_0_MANDATORY_COMPLIANT"

    slhdsa = classify_crypto_key(
        key_ring="kr-pqc",
        key_name="key-slhdsa",
        purpose="ASYMMETRIC_SIGN",
        algorithm="PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256",
    )
    assert slhdsa["quantum_status"] == "APPROVED_PQC"
    assert "FIPS 205" in slhdsa["nist_standard_target"]
    assert slhdsa["pqc_artifact_sizes_bytes"]["ciphertext_or_signature_bytes"] == 7856


def test_classify_vulnerable_classical_rsa_ecc_and_ed25519():
    """Validates that classical asymmetric RSA, ECDSA, Ed25519, and secp256k1 keys are flagged as VULNERABLE_CLASSICAL_RSA_ECC."""
    rsa_decrypt_sha1 = classify_crypto_key(
        key_ring="kr-legacy",
        key_name="rsa-oaep-sha1-key",
        purpose="ASYMMETRIC_DECRYPT",
        algorithm="RSA_DECRYPT_OAEP_2048_SHA1",
    )
    assert rsa_decrypt_sha1["quantum_status"] == "VULNERABLE_CLASSICAL_RSA_ECC"
    assert rsa_decrypt_sha1["priority"] == "CRITICAL"
    assert "KEM_XWING" in rsa_decrypt_sha1["recommended_algorithm"]
    assert "SHA-1" in rsa_decrypt_sha1["remediation_guidance"]
    assert any("Decapsulate" in note for note in rsa_decrypt_sha1["engineering_notes"])

    ed25519_sign = classify_crypto_key(
        key_ring="kr-legacy",
        key_name="ed25519-key",
        purpose="ASYMMETRIC_SIGN",
        algorithm="EC_SIGN_ED25519",
    )
    assert ed25519_sign["quantum_status"] == "VULNERABLE_CLASSICAL_RSA_ECC"
    assert ed25519_sign["priority"] == "HIGH"
    assert "PQ_SIGN_ML_DSA_65" in ed25519_sign["recommended_algorithm"]
    assert any("3,309-byte" in note for note in ed25519_sign["engineering_notes"])


def test_classify_symmetric_keys_grover_and_rotation_hygiene():
    """Validates AES-256 (Grover resilient), rotation hygiene (NIST SP 800-57), and HMAC-SHA1/SHA224 detection."""
    sym_rotated = classify_crypto_key(
        key_ring="kr-data",
        key_name="cmek-bq-rotated",
        purpose="ENCRYPT_DECRYPT",
        algorithm="GOOGLE_SYMMETRIC_ENCRYPTION",
        rotation_period_days=90,
    )
    assert sym_rotated["quantum_status"] == "SECURE_SYMMETRIC"
    assert sym_rotated["hygiene_status"] == "COMPLIANT_ROTATION_90D"

    sym_unrotated = classify_crypto_key(
        key_ring="kr-data",
        key_name="cmek-bq-unrotated",
        purpose="ENCRYPT_DECRYPT",
        algorithm="GOOGLE_SYMMETRIC_ENCRYPTION",
        rotation_period_days=None,
    )
    assert sym_unrotated["quantum_status"] == "SECURE_SYMMETRIC"
    assert sym_unrotated["hygiene_status"] == "NON_COMPLIANT_NO_ROTATION"

    weak_mac_224 = classify_crypto_key(
        key_ring="kr-legacy",
        key_name="hmac-sha224",
        purpose="MAC",
        algorithm="HMAC_SHA224",
    )
    assert weak_mac_224["quantum_status"] == "WEAK_SYMMETRIC_GROVER_RISK"


def test_inactive_destroyed_keys_excluded_from_active_metrics():
    """Ensures keys in DESTROY_SCHEDULED / without ENABLED versions do not inflate active PQC readiness scores."""
    active_vuln = classify_crypto_key(
        key_ring="kr-1",
        key_name="rsa-active",
        purpose="ASYMMETRIC_SIGN",
        algorithm="RSA_SIGN_PSS_2048_SHA256",
        primary_state="NO_PRIMARY",
        enabled_versions_count=1,
    )
    destroyed_sym = classify_crypto_key(
        key_ring="kr-1",
        key_name="test-hsm-key",
        purpose="ENCRYPT_DECRYPT",
        algorithm="GOOGLE_SYMMETRIC_ENCRYPTION",
        primary_state="DESTROY_SCHEDULED",
        enabled_versions_count=0,
    )
    assert destroyed_sym["is_active"] is False
    metrics = _compute_metrics_for_keys([active_vuln, destroyed_sym])
    assert metrics["total_kms_keys_scanned"] == 2
    assert metrics["active_kms_keys_count"] == 1
    assert metrics["inactive_or_destroyed_keys_count"] == 1
    assert metrics["pqc_readiness_score_pct"] == 0.0


def test_scan_pqc_readiness_simulation_project():
    """Tests scan_pqc_readiness with simulation project ('meu-projeto-gcp')."""
    raw_json = scan_pqc_readiness(project_id="meu-projeto-gcp", location_id="global")
    items = json.loads(raw_json)
    assert isinstance(items, list)
    assert len(items) >= 6

    statuses = {item["quantum_status"] for item in items}
    assert "VULNERABLE_CLASSICAL_RSA_ECC" in statuses
    assert "APPROVED_PQC" in statuses
    assert "SECURE_SYMMETRIC" in statuses


def test_discover_all_crypto_assets_and_migration_plan():
    """Tests discovery via Cloud Asset Inventory and CBOM migration plan generation."""
    cai_data = json.loads(discover_all_crypto_assets("meu-projeto-gcp"))
    assert "assets" in cai_data
    assert len(cai_data["assets"]) >= 2

    plan = json.loads(generate_pqc_migration_plan("meu-projeto-gcp"))
    assert "cbom_summary" in plan
    assert "projects_breakdown" in plan
    assert "application_compatibility_matrix" in plan
    assert len(plan["application_compatibility_matrix"]) >= 8
    assert plan["cbom_summary"]["vulnerable_classical_rsa_ecc_count"] == 3
    assert plan["cbom_summary"]["asymmetric_pqc_migration_score_pct"] == 50.0
    assert plan["cbom_summary"]["pqc_incompatible_applications_requiring_refactoring_count"] == 3
    assert len(plan["remediation_playbooks"]) == 3
    for playbook in plan["remediation_playbooks"]:
        assert "gcloud kms keys create" in playbook["gcloud_command"]
        assert "--protection-level=hsm" in playbook["gcloud_command"]
        assert "--protection-level=software" not in playbook["gcloud_command"]
        assert "gcloud kms keys create" in playbook["gcloud_cnsa_2_0_command"]
        assert "--protection-level=hsm" in playbook["gcloud_cnsa_2_0_command"]
        assert "gcloud kms keys versions disable" in playbook["post_migration_disable_legacy_command"]
        assert len(playbook["affected_applications"]) >= 1
        assert playbook["pqc_application_compatibility"]["is_compatible_with_pqc_model"] is False
        if "jwt" in playbook["legacy_key"].lower() or "token" in playbook["legacy_key"].lower():
            assert "16KB in API Gateways/Envoy" in playbook["rationale"]
            assert "~4.4KB" in playbook["rationale"]
            assert playbook["technical_note_jwt_header_buffer"] is not None


def test_local_harness_execution():
    """Validates Phase 4.1 local harness execution."""
    result = run_local_harness('{"project_id": "meu-projeto-gcp"}', invoke_llm=False)
    assert result["harness_status"] == "SUCCESS"
    assert result["project_id"] == "meu-projeto-gcp"
    assert result["cbom_summary"]["total_kms_keys_scanned"] == 8


def test_build_executive_markdown_report():
    """Validates Google Cloud Consulting (PSO) Executive PQC Deliverable layout in Markdown."""
    report_md = build_executive_markdown_report("meu-projeto-gcp")

    # 1. Official Google Cloud Consulting Header & Metadata Table
    assert report_md.startswith("# GOOGLE CLOUD CONSULTING\n## Post-Quantum Cryptography (PQC) Executive Readiness Assessment & Step-by-Step Execution Guide")
    assert "| **Target Organization / Scope** |" in report_md
    assert "| **Telemetry & Validation Status** |" in report_md
    assert "| **Reference Frameworks** |" in report_md
    assert "| **Overall Posture Rating** |" in report_md
    assert "| **Executive Risk Summary** |" in report_md

    # 2. BLUF & Clean Executive Labels (No raw variable/enum names leaked)
    assert "## 1. Executive Summary & Consultative Diagnosis (BLUF)" in report_md
    assert "Critical — Active HNDL Exposure" in report_md
    assert "High — 2030 Deprecation Risk" in report_md
    assert "Compliant — Native PQC" in report_md
    assert "Compliant — Grover-Resilient CMEK" in report_md
    assert "mosca_immediate_hndl_breach_keys_count" not in report_md
    assert "HIGH_TOPOLOGY_MAPPED" not in report_md
    assert "COMPATIBLE_ZERO_REFACTORING_CMEK" not in report_md

    # 3. Sections 2, 3, 4, 5, and 6 structure + --protection-level=hsm + 16KB JWT header buffer warning
    assert "## 2. Executive PQC Maturity Scorecard (Backend-Validated)" in report_md
    assert "## 3. Application Risk, Quantum Circuit Fall-Order & Mosca Theorem Matrix" in report_md
    assert "## 4. Recommended Google Cloud Target Architecture & Product BOM" in report_md
    assert "Binary Authorization + Security Command Center (SCC) Enterprise" in report_md
    assert "## 5. Step-by-Step Customer Environment Execution Guide (30-60-90 Day Prescriptive Plan)" in report_md
    assert "## 6. Technical Engineering Appendix (Complete Step-by-Step Runbooks, Code Diffs & Validation Checklist)" in report_md
    assert "KEM_XWING" in report_md
    assert "PQ_SIGN_ML_DSA_65" in report_md
    assert "gcloud kms keys create" in report_md
    assert "--protection-level=hsm" in report_md
    assert "--protection-level=software" not in report_md
    assert "16KB in API Gateways/Envoy" in report_md
    assert "~4.4KB" in report_md

    # 4. Verify no table in the report exceeds 5 columns
    for line in report_md.splitlines():
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            cols = [c.strip() for c in stripped.strip("|").split("|")]
            assert len(cols) <= 5, f"Table row exceeds 5 columns ({len(cols)}): {line}"



def test_classify_cai_crypto_asset():
    """Validates Improvement 2: Deep Data-in-Transit (TLS/SSL Policy) and PKI asset classification."""
    ssl_policy = _classify_cai_crypto_asset(
        "compute.googleapis.com/SslPolicy",
        "prod-ssl-policy",
        "proj-1",
        "global",
        "ACTIVE",
        {"minTlsVersion": "TLS_1_2", "profile": "MODERN"},
    )
    assert ssl_policy["quantum_status"] == "VULNERABLE_TRANSIT_HNDL_PRE_TLS13"
    assert "--min-tls-version=1.3" in ssl_policy["remediation"]

    tls13_policy = _classify_cai_crypto_asset(
        "compute.googleapis.com/SslPolicy",
        "pqc-ready-ssl-policy",
        "proj-1",
        "global",
        "ACTIVE",
        {"minTlsVersion": "TLS_1_3", "profile": "RESTRICTED"},
    )
    assert tls13_policy["quantum_status"] == "APPROVED_PQC_HYBRID_TRANSIT_CAPABLE"

    cert = _classify_cai_crypto_asset(
        "compute.googleapis.com/SslCertificate",
        "api-ingress-cert",
        "proj-1",
        "global",
        "ACTIVE",
        {"type": "MANAGED", "subjectAlternativeNames": ["api.example.com"]},
    )
    assert cert["quantum_status"] == "CLASSICAL_X509_PKI_SHOR_EXPOSED"


def test_mosca_theorem_risk_quantification():
    """Validates Improvement 3: Mosca's Theorem (X + Y > Z) risk quantification."""
    # RSA Decrypt key -> X=10y, Y=2.0y => X+Y=12.0y > Z_2030 (4.0y) and Z_2035 (9.0y)
    rsa_dec = classify_crypto_key(
        key_ring="kr-legacy",
        key_name="key-rsa-decrypt",
        purpose="ASYMMETRIC_DECRYPT",
        algorithm="RSA_DECRYPT_OAEP_2048_SHA256",
    )
    mosca_dec = rsa_dec["mosca_risk_analysis"]
    assert mosca_dec["mosca_inequality_breached"] is True
    assert mosca_dec["mosca_status"] == "CRITICAL_MOSCA_BREACH_ACTIVE_HNDL"
    assert mosca_dec["x_plus_y_total_years"] == 12.0

    # RSA Sign key -> X=3y, Y=1.5y => X+Y=4.5y > Z_2030 (4.0y)
    rsa_sig = classify_crypto_key(
        key_ring="kr-legacy",
        key_name="key-rsa-sign",
        purpose="ASYMMETRIC_SIGN",
        algorithm="RSA_SIGN_PSS_2048_SHA256",
    )
    mosca_sig = rsa_sig["mosca_risk_analysis"]
    assert mosca_sig["mosca_inequality_breached"] is True
    assert mosca_sig["mosca_status"] == "HIGH_MOSCA_BREACH_NIST_2030_DEADLINE"


def test_export_cyclonedx_cbom():
    """Validates Improvement 4: Official OWASP CycloneDX v1.6 CBOM JSON Exporter."""
    cbom_json = export_cyclonedx_cbom("meu-projeto-gcp")
    cbom = json.loads(cbom_json)
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert cbom["serialNumber"].startswith("urn:uuid:")
    crypto_components = [c for c in cbom["components"] if c["type"] == "cryptographic-asset"]
    app_components = [c for c in cbom["components"] if c["type"] == "application"]
    assert len(crypto_components) == 8
    assert len(app_components) >= 6
    # Verify NIST Quantum Security Levels and OIDs
    xwing_comp = next(c for c in crypto_components if "kem-xwing" in c["name"])
    assert xwing_comp["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    assert xwing_comp["cryptoProperties"]["oid"] == "1.3.6.1.4.1.62253.25722"
    rsa_comp = next(c for c in crypto_components if "cmek-pix-envelope-rsa" in c["name"])
    assert rsa_comp["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    assert len(cbom["dependencies"]) >= 7


def test_generate_application_pqc_refactoring_guide():
    """Validates Improvement 5: Interactive Application PQC Code & Gateway Refactoring Generator."""
    guide_json = generate_application_pqc_refactoring_guide("meu-projeto-gcp", "all")
    guide = json.loads(guide_json)
    assert guide["total_incompatible_keys_requiring_refactoring"] == 3
    blueprints = guide["refactoring_blueprints"]
    decrypt_bp = next(b for b in blueprints if "DECRYPT" in b["legacy_algorithm"])
    assert "kms_client.decapsulate" in decrypt_bp["code_refactoring_snippets"]["python_after_pqc_kem_xwing_hpke"]
    assert "HKDF" in decrypt_bp["code_refactoring_snippets"]["python_after_pqc_kem_xwing_hpke"]
    sign_bp = next(b for b in blueprints if "SIGN" in b["legacy_algorithm"])
    assert "shake_256" in sign_bp["code_refactoring_snippets"]["python_after_pqc_mldsa65_external_mu_large_payloads"]
    assert "max_request_headers_kb: 32" in sign_bp["api_gateway_and_proxy_configurations"]["envoy_istio_gateway_patch_yaml"]


def test_preventive_org_policy_guardrails():
    """Validates Improvement 6: Preventive Governance & GCP Organization Policy Guardrails."""
    plan = json.loads(generate_pqc_migration_plan("meu-projeto-gcp"))
    guardrails = plan["preventive_org_policy_guardrails"]
    assert "custom.pqcEnforceQuantumSafeKmsAlgorithms" in guardrails["custom_constraint_quantum_safe_algorithms_yaml"]
    assert "KEM_XWING" in guardrails["custom_constraint_quantum_safe_algorithms_yaml"]
    assert "PQ_SIGN_ML_DSA_65" in guardrails["custom_constraint_quantum_safe_algorithms_yaml"]
    assert "custom.pqcEnforceSymmetricKeyRotation90d" in guardrails["custom_constraint_symmetric_rotation_90d_yaml"]
    assert len(guardrails["gcloud_enforcement_commands"]) == 4


def test_adk_system_instruction_no_template_variables():
    """Validates that SYSTEM_INSTRUCTION contains no unescaped curly braces that Google ADK treats as session variables."""
    from pqc_agent.agent import SYSTEM_INSTRUCTION

    assert "{" not in SYSTEM_INSTRUCTION
    assert "}" not in SYSTEM_INSTRUCTION
    assert "Recommended Google Cloud Security Architecture & Product BOM" in SYSTEM_INSTRUCTION


def test_gemini_3_1_and_product_bom_engine():
    """Validates Gemini 3.1 architecture config in main.py/app.yaml and programmatic Cloud Product Upsell BOM."""
    import pathlib
    import main

    # 1. Verify main.py model and generation_config
    assert main.MODEL_NAME == "gemini-3.1-pro-preview-customtools"
    assert main.GENERATION_CONFIG["thinking_level"] == "MEDIUM"
    assert main.GENERATION_CONFIG["max_output_tokens"] == 1048576
    assert "Recommended Google Cloud Security Architecture & Product BOM" in main.SYSTEM_INSTRUCTION

    # 2. Verify app.yaml contains gemini-3.1-pro-preview-customtools and generation_config
    app_yaml_text = pathlib.Path(__file__).resolve().parent.parent.joinpath("app.yaml").read_text()
    assert "gemini-3.1-pro-preview-customtools" in app_yaml_text
    assert 'thinking_level: "MEDIUM"' in app_yaml_text
    assert "max_output_tokens: 1048576" in app_yaml_text

    # 3. Verify programmatic Product BOM in generate_pqc_migration_plan and build_executive_markdown_report
    plan = json.loads(generate_pqc_migration_plan("meu-projeto-gcp"))
    bom = plan["recommended_google_cloud_security_architecture_and_product_bom"]
    assert len(bom) == 5
    all_products = [p for item in bom for p in item["recommended_gcp_products"]]
    assert any("Cloud HSM" in p for p in all_products)
    assert any("Google Tink SDK" in p for p in all_products)
    assert any("VPC Service Controls (VPC-SC)" in p for p in all_products)
    assert any("Private Service Connect (PSC)" in p for p in all_products)
    assert any("Google Cloud Global Load Balancing (L7)" in p for p in all_products)
    assert any("Certificate Authority Service (CAS)" in p for p in all_products)
    assert any("Binary Authorization" in p for p in all_products)

    md_report = main.build_executive_markdown_report("meu-projeto-gcp")
    assert "Recommended Google Cloud Security Architecture & Product BOM" in md_report
    assert "VULNERABLE_TO_SNDL_ATTACKS" in md_report
    assert "VULNERABLE_KEY_IMPORT_TRANSPORT" in md_report
    assert "SECURE_PQC_BYOK" in md_report


def test_pqc_detectors_ssl_policies_and_import_jobs():
    """Validates tools/pqc_detectors.py: scan_ssl_policies and scan_import_jobs_pqc."""
    import main
    from pqc_agent.agent import root_agent
    from tools.pqc_detectors import (
        _classify_import_job,
        _evaluate_ssl_policy_dict,
        scan_import_jobs_pqc,
        scan_ssl_policies,
    )

    # 1. Verify SSL Policy evaluation logic
    ssl_data = json.loads(scan_ssl_policies("meu-projeto-gcp"))
    assert ssl_data["total_ssl_policies_scanned"] == 2
    assert ssl_data["vulnerable_to_sndl_attacks_count"] == 1
    assert ssl_data["quantum_ready_hybrid_tls13_count"] == 1
    assert ssl_data["ssl_pqc_readiness_score_pct"] == 50.0
    statuses = {p["policy_name"]: p["pqc_status"] for p in ssl_data["ssl_policies"]}
    assert statuses["ssl-policy-legacy-tls12-ingress"] == "VULNERABLE_TO_SNDL_ATTACKS"
    assert statuses["ssl-policy-pqc-hybrid-tls13-prod"] == "QUANTUM_READY_HYBRID_TLS_1_3"

    # Direct helper checks
    eval_vuln = _evaluate_ssl_policy_dict(
        policy_name="pol-tls12",
        resource_name="//compute.googleapis.com/projects/p1/global/sslPolicies/pol-tls12",
        project_id="p1",
        location="global",
        min_tls_version="TLS_1_2",
        profile="MODERN",
    )
    assert eval_vuln["pqc_status"] == "VULNERABLE_TO_SNDL_ATTACKS"
    assert eval_vuln["supports_hybrid_pqc_key_share_x25519_mlkem768"] is False
    assert len(eval_vuln["step_by_step_execution_guide"]) >= 3

    eval_ok = _evaluate_ssl_policy_dict(
        policy_name="pol-tls13",
        resource_name="//compute.googleapis.com/projects/p1/global/sslPolicies/pol-tls13",
        project_id="p1",
        location="global",
        min_tls_version="TLS_1_3",
        profile="RESTRICTED",
    )
    assert eval_ok["pqc_status"] == "QUANTUM_READY_HYBRID_TLS_1_3"
    assert eval_ok["supports_hybrid_pqc_key_share_x25519_mlkem768"] is True

    # 2. Verify Cloud KMS ImportJob evaluation logic
    ij_data = json.loads(scan_import_jobs_pqc("meu-projeto-gcp", "all"))
    assert ij_data["total_import_jobs_scanned"] == 2
    assert ij_data["vulnerable_key_import_transport_count"] == 1
    assert ij_data["secure_pqc_byok_count"] == 1
    assert ij_data["byok_pqc_readiness_score_pct"] == 50.0
    ij_statuses = {j["import_job_name"]: j["pqc_status"] for j in ij_data["import_jobs"]}
    assert ij_statuses["ij-legacy-byok-rsa3072"] == "VULNERABLE_KEY_IMPORT_TRANSPORT"
    assert ij_statuses["ij-pqc-byok-xwing-prod"] == "SECURE_PQC_BYOK"

    # Direct helper checks
    rsa_ij = _classify_import_job(
        project_id="p1",
        location="global",
        key_ring="kr1",
        job_name="ij-rsa",
        resource_name="projects/p1/locations/global/keyRings/kr1/importJobs/ij-rsa",
        state_name="ACTIVE",
        import_method_name="RSA_OAEP_4096_SHA256_AES_256",
        protection_level_name="HSM",
    )
    assert rsa_ij["pqc_status"] == "VULNERABLE_KEY_IMPORT_TRANSPORT"
    assert len(rsa_ij["step_by_step_execution_guide"]) >= 4

    xwing_ij = _classify_import_job(
        project_id="p1",
        location="global",
        key_ring="kr1",
        job_name="ij-xwing",
        resource_name="projects/p1/locations/global/keyRings/kr1/importJobs/ij-xwing",
        state_name="ACTIVE",
        import_method_name="HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM",
        protection_level_name="HSM",
    )
    assert xwing_ij["pqc_status"] == "SECURE_PQC_BYOK"

    # 3. Verify registration in root_agent.tools and main.py SYSTEM_INSTRUCTION
    tool_names = [getattr(t, "__name__", str(t)) for t in root_agent.tools]
    assert "scan_ssl_policies" in tool_names
    assert "scan_import_jobs_pqc" in tool_names
    assert "run_quantum_cryptanalysis_simulation" in tool_names
    assert "scan_ssl_policies" in main.SYSTEM_INSTRUCTION
    assert "scan_import_jobs_pqc" in main.SYSTEM_INSTRUCTION
    assert "run_quantum_cryptanalysis_simulation" in main.SYSTEM_INSTRUCTION
    assert "{" not in main.SYSTEM_INSTRUCTION
    assert "}" not in main.SYSTEM_INSTRUCTION


def test_quantum_cryptanalysis_simulation_engine():
    """Validates Phase 1 Quantum Physics & Cryptanalysis Simulation Engine (Gidney-Ekerå, Roetteler, Core-SVP & Monte Carlo Q-VaR)."""
    from tools.quantum_engine import (
        map_algorithm_to_quantum_profile,
        run_quantum_cryptanalysis_simulation,
    )

    # 1. Verify Quantum Circuit Resource Estimates & Fall Order (ECDSA P-256 < ECDSA P-384 < RSA-2048 < RSA-3072 < RSA-4096)
    p256 = map_algorithm_to_quantum_profile("EC_SIGN_P256_SHA256")
    p384 = map_algorithm_to_quantum_profile("EC_SIGN_P384_SHA384")
    rsa2048 = map_algorithm_to_quantum_profile("RSA_DECRYPT_OAEP_2048_SHA256")
    rsa3072 = map_algorithm_to_quantum_profile("RSA_SIGN_PSS_3072_SHA256")
    rsa4096 = map_algorithm_to_quantum_profile("RSA_SIGN_PSS_4096_SHA256")

    assert p256["logical_qubits"] == 2330
    assert p256["physical_qubits_superconducting_1e3"] == 13400000
    assert p384["logical_qubits"] == 3484
    assert rsa2048["logical_qubits"] == 4098
    assert rsa2048["physical_qubits_superconducting_1e3"] == 20000000
    assert rsa3072["logical_qubits"] == 6146
    assert rsa4096["logical_qubits"] == 8194

    # Prove mathematically that ECDSA P-256 and P-384 require fewer logical qubits than RSA-2048 and fall first
    assert p256["logical_qubits"] < p384["logical_qubits"] < rsa2048["logical_qubits"] < rsa3072["logical_qubits"] < rsa4096["logical_qubits"]
    assert p256["fall_order_rank"] == 1
    assert p384["fall_order_rank"] == 2
    assert rsa2048["fall_order_rank"] == 3

    # 2. Verify Core-SVP Lattice Hardness for PQC algorithms and Grover resilience for AES-256
    xwing = map_algorithm_to_quantum_profile("KEM_XWING")
    mlkem1024 = map_algorithm_to_quantum_profile("ML_KEM_1024")
    mldsa65 = map_algorithm_to_quantum_profile("PQ_SIGN_ML_DSA_65")
    mldsa87 = map_algorithm_to_quantum_profile("PQ_SIGN_ML_DSA_87")
    aes256 = map_algorithm_to_quantum_profile("GOOGLE_SYMMETRIC_ENCRYPTION")

    assert xwing["core_svp_quantum_bits"] == 167
    assert mlkem1024["core_svp_quantum_bits"] == 226
    assert mldsa65["core_svp_quantum_bits"] == 174
    assert mldsa87["core_svp_quantum_bits"] == 232
    assert aes256["quantum_security_bits"] == 128

    # 3. Verify full simulation tool execution & 10,000-iteration Monte Carlo curve
    raw_sim = run_quantum_cryptanalysis_simulation("meu-projeto-gcp", "global")
    sim = json.loads(raw_sim)
    assert sim["quantum_engine_version"].startswith("2.0.0")
    assert "data_validation_manifest" in sim
    assert "validated_executive_scorecard" in sim
    insights = sim["executive_quantum_physics_insights"]
    assert insights["total_active_keys_analyzed"] == 8
    assert insights["shor_vulnerable_keys_count"] == 3
    assert insights["ecdsa_p256_ed25519_keys_falling_first_count"] == 1
    assert insights["rsa_2048_keys_falling_third_count"] == 1
    assert insights["rsa_3072_4096_keys_count"] == 1

    # Verify Priority Fall Order Ranking places ECDSA P-256 at index 0 (before RSA-2048 and RSA-4096)
    ranking = sim["priority_shor_fall_order_ranking"]
    assert len(ranking) == 3
    assert ranking[0]["current_algorithm"] == "EC_SIGN_P256_SHA256"
    assert ranking[0]["logical_qubits_to_break"] == 2330
    assert "gcloud kms keys create" in ranking[0]["gcloud_remediation_command"]
    assert ranking[1]["current_algorithm"] == "RSA_DECRYPT_OAEP_2048_SHA256"
    assert ranking[1]["logical_qubits_to_break"] == 4098
    assert ranking[2]["current_algorithm"] == "RSA_SIGN_PSS_4096_SHA256"
    assert ranking[2]["logical_qubits_to_break"] == 8194

    # Verify 10,000-iteration Monte Carlo CRQC & Q-VaR 95% properties
    mc = sim["monte_carlo_crqc_and_qvar_simulation"]
    assert mc["monte_carlo_iterations"] == 10000
    assert mc["quantum_value_at_risk_qvar_95_unmitigated_usd_millions"] > 10.0
    assert mc["quantum_value_at_risk_qvar_95_post_gcp_bom_remediation_usd_millions"] < mc["quantum_value_at_risk_qvar_95_unmitigated_usd_millions"]
    curve = mc["annual_crqc_probability_curve_2026_2035"]
    assert len(curve) == 10
    for row in curve:
        assert row["ecdsa_p256_breach_prob_pct"] >= row["ecdsa_p384_breach_prob_pct"]
        assert row["ecdsa_p384_breach_prob_pct"] >= row["rsa_2048_breach_prob_pct"]
        assert row["rsa_2048_breach_prob_pct"] >= row["rsa_4096_breach_prob_pct"]


def test_tenant_project_redirection_and_consultative_guide_validation():
    """Validates automatic redirection of internal Vertex AI Agent Engine tenant projects and consultative guide output."""
    from tools.gcp_inventory import _is_internal_runtime_tenant_project, _resolve_scope, generate_pqc_migration_plan
    from tools.quantum_engine import run_quantum_cryptanalysis_simulation

    # 1. Verify internal tenant project detection and auto-redirection to Organization 31564119954
    assert _is_internal_runtime_tenant_project("project-cb232322-97f9-4f78-97f") is True
    assert _is_internal_runtime_tenant_project("vertex-runtime-tp") is True
    assert _is_internal_runtime_tenant_project("gcp-ZeroTrust-pqc-prod") is False

    scope_type, scope_path, clean_id = _resolve_scope("project-cb232322-97f9-4f78-97f")
    assert scope_type == "ORG"
    assert scope_path == "organizations/31564119954"
    assert clean_id == "31564119954"

    # 2. Verify data_validation_manifest, validated_executive_scorecard, and consultative guides
    plan = json.loads(generate_pqc_migration_plan("meu-projeto-gcp"))
    manifest = plan["data_validation_manifest"]
    assert manifest["data_source_authenticity"] == "SIMULATED_BENCHMARK_DATASET"
    assert manifest["metrics_validation_status"] == "DETERMINISTIC_BACKEND_VALIDATED_DO_NOT_RECALCULATE"

    scorecard = plan["validated_executive_scorecard"]
    # Verify deterministic scores (never 37.5%)
    assert scorecard["weighted_pqc_maturity_score_pct"] == 70.0
    assert scorecard["asymmetric_pqc_migration_score_pct"] == 50.0
    assert scorecard["symmetric_grover_resilience_score_pct"] == 100.0
    assert scorecard["symmetric_rotation_hygiene_score_pct"] == 100.0
    assert scorecard["application_pqc_compatibility_score_pct"] == 62.5
    assert scorecard["weighted_pqc_maturity_score_pct"] != 37.5

    qsim = json.loads(run_quantum_cryptanalysis_simulation("meu-projeto-gcp"))
    q_scorecard = qsim["validated_executive_scorecard"]
    assert q_scorecard["ssl_pqc_readiness_score_pct"] == 50.0
    assert q_scorecard["byok_pqc_readiness_score_pct"] == 50.0

    # Verify consultative execution guide on every remediation playbook
    for pb in plan["remediation_playbooks"]:
        guide = pb["consultative_execution_guide"]
        assert "current_state_evaluation" in guide
        assert "architectural_impact_assessment" in guide
        assert len(guide["step_by_step_execution_plan"]) == 5
        assert "gcloud kms keys add-iam-policy-binding" in pb["iam_binding_command"]
        assert "gcloud kms keys describe" in pb["post_change_validation_command"]

    # Verify 5-workstream customer_environment_execution_guide
    env_guide = plan["customer_environment_execution_guide"]
    assert len(env_guide) == 5


def test_performance_ttl_cache_and_compact_json_token_optimization():
    """Validates in-memory TTL cache hit performance (<15ms) and compact JSON token optimization."""
    import time
    from tools.gcp_inventory import _SCAN_CACHE, generate_pqc_migration_plan, scan_pqc_readiness
    from tools.quantum_engine import run_quantum_cryptanalysis_simulation

    # Warm cache and verify compact JSON (no multi-line indentation bloat)
    raw_kms = scan_pqc_readiness("meu-projeto-gcp", "global")
    assert "\n  " not in raw_kms
    assert len(_SCAN_CACHE) >= 1

    t0 = time.perf_counter()
    raw_plan = generate_pqc_migration_plan("meu-projeto-gcp", "global")
    raw_qsim = run_quantum_cryptanalysis_simulation("meu-projeto-gcp", "global")
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert "\n  " not in raw_plan
    assert "\n  " not in raw_qsim
    # Both generate_pqc_migration_plan + 10,000-iteration Monte Carlo quantum simulation should complete fast
    assert elapsed_ms < 150.0, f"Expected fast cached execution (<150ms), took {elapsed_ms:.2f}ms"


def test_export_pqc_assessment_reports_executive_and_technical(tmp_path):
    """Validates the 4-part Executive, Technical, CycloneDX CBOM, and Consolidated report exporter."""
    import pathlib
    import main
    from pqc_agent.agent import root_agent
    from tools.report_exporter import export_pqc_assessment_reports

    tool_names = [getattr(t, "__name__", str(t)) for t in root_agent.tools]
    assert "export_pqc_assessment_reports" in tool_names
    assert "export_pqc_assessment_reports" in main.SYSTEM_INSTRUCTION

    raw_export = export_pqc_assessment_reports("meu-projeto-gcp", "global", output_dir=str(tmp_path))
    export_manifest = json.loads(raw_export)
    assert export_manifest["export_status"] == "SUCCESS"
    assert len(export_manifest["exported_deliverables"]) == 4

    exec_item = export_manifest["exported_deliverables"][0]
    tech_item = export_manifest["exported_deliverables"][1]
    cbom_item = export_manifest["exported_deliverables"][2]
    cons_item = export_manifest["exported_deliverables"][3]

    exec_md_text = pathlib.Path(exec_item["markdown_path"]).read_text(encoding="utf-8")
    exec_html_text = pathlib.Path(exec_item["html_print_to_pdf_path"]).read_text(encoding="utf-8")
    tech_md_text = pathlib.Path(tech_item["markdown_path"]).read_text(encoding="utf-8")
    tech_html_text = pathlib.Path(tech_item["html_print_to_pdf_path"]).read_text(encoding="utf-8")
    cbom_json_text = pathlib.Path(cbom_item["json_path"]).read_text(encoding="utf-8")
    cons_md_text = pathlib.Path(cons_item["markdown_path"]).read_text(encoding="utf-8")

    assert "Executive Board & CISO Readiness Report" in exec_md_text
    assert "Recommended Google Cloud Target Architecture & Product BOM" in exec_md_text
    assert "@media print" in exec_html_text
    assert "<table>" in exec_html_text

    assert "TECHNICAL ENGINEERING PLAYBOOK" in tech_md_text
    assert "gcloud kms keys create" in tech_md_text
    assert "--protection-level=hsm" in tech_md_text
    assert "max_request_headers_kb: 32" in tech_md_text
    assert "@media print" in tech_html_text
    assert "<pre><code>" in tech_html_text

    assert json.loads(cbom_json_text)["bomFormat"] == "CycloneDX"
    assert len(cons_md_text) > len(exec_md_text)

    # Verify <= 5 columns rule across both Executive and Technical Markdown reports
    for doc_name, md_doc in [("Executive", exec_md_text), ("Technical", tech_md_text)]:
        for line in md_doc.splitlines():
            stripped = line.strip()
            if stripped.startswith("|") and stripped.endswith("|"):
                cols = [c.strip() for c in stripped.strip("|").split("|")]
                assert len(cols) <= 5, f"{doc_name} table row exceeds 5 columns ({len(cols)}): {line}"


def test_persistent_session_service_and_sessions_api(tmp_path):
    """Validates Component 1: DatabaseSessionService, GcsArtifactService, and /api/sessions CRUD endpoints."""
    from fastapi.testclient import TestClient
    from pqc_agent.workspace_server import (
        DatabaseSessionService,
        ResilientGcsArtifactService,
        create_workspace_app,
    )

    db_file = tmp_path / "pqc_sessions_test.db"
    db_url = f"sqlite:///{db_file}"
    app_instance = create_workspace_app(
        session_db_url=db_url,
        artifact_bucket="gs://pqc-inventory-agent-cd06-pqc-agent-staging",
    )

    assert isinstance(app_instance.state.session_service, DatabaseSessionService)
    assert isinstance(app_instance.state.artifact_service, ResilientGcsArtifactService)
    assert app_instance.state.artifact_service.bucket_name == "pqc-inventory-agent-cd06-pqc-agent-staging"

    with TestClient(app_instance) as client:
        # 1. Create a new session via POST /api/sessions
        create_resp = client.post(
            "/api/sessions",
            json={"user_id": "ciso-architect", "title": "Org 31564119954 Executive PQC Review"},
        )
        assert create_resp.status_code == 200
        created = create_resp.json()
        session_id = created["session_id"]
        assert created["user_id"] == "ciso-architect"
        assert created["title"] == "Org 31564119954 Executive PQC Review"

        # 2. List sessions via GET /api/sessions?user_id=ciso-architect
        list_resp = client.get("/api/sessions", params={"user_id": "ciso-architect"})
        assert list_resp.status_code == 200
        listed = list_resp.json()
        assert listed["total_sessions"] >= 1
        found = next((s for s in listed["sessions"] if s["session_id"] == session_id), None)
        assert found is not None
        assert found["title"] == "Org 31564119954 Executive PQC Review"

        # 3. Retrieve session details via GET /api/sessions/{session_id}
        get_resp = client.get(f"/api/sessions/{session_id}", params={"user_id": "ciso-architect"})
        assert get_resp.status_code == 200
        detail = get_resp.json()
        assert detail["session_id"] == session_id
        assert detail["title"] == "Org 31564119954 Executive PQC Review"
        assert isinstance(detail["messages"], list)

        # 4. Delete session via DELETE /api/sessions/{session_id}
        del_resp = client.delete(f"/api/sessions/{session_id}", params={"user_id": "ciso-architect"})
        assert del_resp.status_code == 200
        assert del_resp.json()["deleted"] is True

        # Confirm session is removed
        missing_resp = client.get(f"/api/sessions/{session_id}", params={"user_id": "ciso-architect"})
        assert missing_resp.status_code == 404


def test_multimodal_file_upload_and_artifact_calibration(tmp_path):
    """Validates Component 2: Multimodal file upload in POST /api/chat and analyze_uploaded_pqc_artifact tool."""
    from fastapi.testclient import TestClient
    from pqc_agent.workspace_server import create_workspace_app
    from tools.calibration_engine import (
        analyze_uploaded_pqc_artifact,
        register_uploaded_artifact_for_analysis,
    )

    questionnaire_md = (
        "# Customer PQC Discovery Questionnaire\n"
        "- Customer Name: Banco Atlântico Global\n"
        "- Industry Sector: Financial Services & Central Banking (BFSI)\n"
        "- Confidentiality Shelf-Life (X): 15 years\n"
        "- Migration Timeline (Y): 3.0 years\n"
        "- Gateway Header Limit: 16 KB\n"
        "- Regulatory Frameworks: BACEN, PCI-DSS 4.0, CNSA 2.0\n"
        "- Critical Applications: PIX Core Settlement, OpenFinance Gateway\n"
    )

    register_uploaded_artifact_for_analysis(
        filename="discovery_questionnaire_banco_atlantico.md",
        mime_type="text/markdown",
        raw_bytes=questionnaire_md.encode("utf-8"),
    )

    analysis_json = analyze_uploaded_pqc_artifact(
        artifact_name="discovery_questionnaire_banco_atlantico.md",
        scope="organizations/31564119954",
    )
    analysis = json.loads(analysis_json)
    assert analysis["status"] == "ARTIFACT_ANALYZED_AND_AUTO_CALIBRATED"
    assert analysis["detected_artifact_type"] == "DISCOVERY_QUESTIONNAIRE_OR_POLICY_DOC"
    extracted = analysis["extracted_parameters"]
    assert extracted["industry_sector"] == "BFSI_BANKING"
    assert extracted["confidentiality_years_x"] == 15.0
    assert extracted["migration_years_y"] == 3.0
    assert extracted["gateway_header_limit_kb"] == 16

    # Also test CSV inventory upload and PEM certificate upload via analyze_uploaded_pqc_artifact
    csv_inventory = (
        "key_name,algorithm,purpose,project_id\n"
        "pix-signing-rsa2048,RSA_SIGN_PSS_2048_SHA256,ASYMMETRIC_SIGN,fin-core-prod\n"
        "vault-kem-xwing,KEM_XWING,KEY_ENCAPSULATION,fin-core-prod\n"
        "legacy-ecdsa-p256,EC_SIGN_P256_SHA256,ASYMMETRIC_SIGN,fin-core-prod\n"
    )
    register_uploaded_artifact_for_analysis(
        filename="crypto_inventory.csv",
        mime_type="text/csv",
        raw_bytes=csv_inventory.encode("utf-8"),
    )
    csv_analysis = json.loads(
        analyze_uploaded_pqc_artifact("crypto_inventory.csv", scope="organizations/31564119954")
    )
    assert csv_analysis["detected_artifact_type"] == "CSV_CRYPTOGRAPHIC_INVENTORY"
    assert csv_analysis["inventory_analysis_summary"]["total_items_parsed"] == 3
    assert csv_analysis["inventory_analysis_summary"]["vulnerable_classical_rsa_ecc_count"] == 2
    assert csv_analysis["inventory_analysis_summary"]["approved_pqc_count"] == 1

    # Test POST /api/chat multipart upload with offline/deterministic fallback
    db_file = tmp_path / "chat_upload_test.db"
    app_instance = create_workspace_app(
        session_db_url=f"sqlite:///{db_file}",
        artifact_bucket="gs://pqc-inventory-agent-cd06-pqc-agent-staging",
    )

    with TestClient(app_instance) as client:
        resp = client.post(
            "/api/chat",
            data={
                "user_id": "sec-architect",
                "message": "",
                "project_id": "meu-projeto-gcp",
                "connection_mode": "adc",
            },
            files=[
                (
                    "files",
                    (
                        "customer_discovery.md",
                        questionnaire_md.encode("utf-8"),
                        "text/markdown",
                    ),
                )
            ],
        )
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["session_id"]
        assert len(payload["uploaded_artifacts"]) == 1
        assert payload["uploaded_artifacts"][0]["filename"] == "customer_discovery.md"
        assert len(payload["tool_traces"]) >= 1


def test_gcloud_bridge_connection_modes_and_safe_command_execution():
    """Validates Component 3: Antigravity-style gcloud CLI execution & Dynamic Credential Bridge."""
    from tools.gcloud_bridge import (
        execute_gcloud_command,
        get_gcp_connection_config,
        set_gcp_connection_config,
        validate_gcloud_command,
    )

    # 1. Test allowed read-only diagnostic commands
    for safe_cmd in [
        "gcloud kms keys list --location=global --format=json",
        "gcloud kms keyrings describe kr-1 --location=global",
        "gcloud asset search-all-resources --scope=organizations/31564119954",
        "gcloud asset search-all-iam-policies --scope=organizations/31564119954",
        "gcloud projects get-iam-policy pqc-inventory-agent-cd06",
        "gcloud config list",
        "gcloud version",
    ]:
        is_valid, tokens, msg = validate_gcloud_command(safe_cmd)
        assert is_valid is True, f"Expected '{safe_cmd}' to be valid, got: {msg}"

    # 2. Test blocked destructive commands & shell injection metacharacters
    for blocked_cmd in [
        "gcloud kms keys versions destroy 1 --key=k1 --keyring=kr1 --location=global",
        "gcloud projects delete my-prod-project",
        "gcloud projects remove-iam-policy-binding pqc-inventory-agent-cd06 --member=user:a@b.com --role=roles/owner",
        "gcloud kms keys create new-key --keyring=kr1 --location=global",
        "gcloud version; rm -rf /",
        "gcloud version && cat /etc/passwd",
    ]:
        is_valid, tokens, msg = validate_gcloud_command(blocked_cmd)
        assert is_valid is False, f"Expected '{blocked_cmd}' to be blocked!"
        exec_res = json.loads(execute_gcloud_command(blocked_cmd))
        assert exec_res["status"] == "BLOCKED_DESTRUCTIVE_OR_INVALID_COMMAND"

    # 3. Execute a safe read-only gcloud command (`gcloud version`)
    ver_res = json.loads(execute_gcloud_command("gcloud version"))
    assert ver_res["status"] in ("SUCCESS", "GCLOUD_BINARY_NOT_FOUND")
    if ver_res["status"] == "SUCCESS":
        assert "Google Cloud SDK" in ver_res["stdout"]

    # 4. Test Dynamic GCP Connection Manager mode switching (adc, impersonation, access_token)
    imp_state = set_gcp_connection_config(
        mode="impersonation",
        project_id="pqc-inventory-agent-cd06",
        organization_id="31564119954",
        impersonated_service_account="pqc-reader@customer-project.iam.gserviceaccount.com",
    )
    assert imp_state["mode"] == "impersonation"
    assert imp_state["impersonated_service_account"] == "pqc-reader@customer-project.iam.gserviceaccount.com"

    tok_state = set_gcp_connection_config(
        mode="access_token",
        project_id="pqc-inventory-agent-cd06",
        organization_id="31564119954",
        access_token="ya29.a0AfH6SMBx_example_short_lived_token",
    )
    assert tok_state["mode"] == "access_token"
    assert tok_state["has_access_token"] is True
    assert "ya29.a0AfH6SMBx_example_short_lived_token" not in json.dumps(tok_state)

    adc_state = set_gcp_connection_config(
        mode="adc",
        project_id="pqc-inventory-agent-cd06",
        organization_id="31564119954",
    )
    assert adc_state["mode"] == "adc"
    assert get_gcp_connection_config()["mode"] == "adc"


def test_gemini_enterprise_workspace_portal_ui_and_dev_ui(tmp_path):
    """Validates Component 4: Gemini Enterprise-style Workspace Portal at GET / and ADK /dev-ui/ availability."""
    from fastapi.testclient import TestClient
    from pqc_agent.workspace_server import create_workspace_app

    db_file = tmp_path / "portal_ui_test.db"
    app_instance = create_workspace_app(
        session_db_url=f"sqlite:///{db_file}",
        artifact_bucket="gs://pqc-inventory-agent-cd06-pqc-agent-staging",
    )

    with TestClient(app_instance) as client:
        # 1. Root route (/) serves the Gemini Enterprise-style Workspace Portal HTML
        root_resp = client.get("/")
        assert root_resp.status_code == 200
        html = root_resp.text
        assert "Agentic PQC Workspace Portal" in html
        assert "New PQC Assessment" in html
        assert "GCP / gcloud Connection" in html
        assert "Download Report (.md)" in html
        assert "Tool &amp; gcloud Execution Trace" in html or "Tool & gcloud Execution Trace" in html
        assert "/dev-ui/?app=pqc_agent" in html

        # Verify all 5 Organization-Level Quick-Action Phase Prompts use P1..P5 (without PHASE text)
        assert "Agentic PQC Workspace" in html
        assert "Agentic Post-Quantum Cryptography" in html
        for p_idx in range(1, 6):
            assert f"PHASE 0{p_idx}" not in html
            assert f">P{p_idx}<" in html
        assert "🛡️" not in html
        assert "await createNewSession(PHASE_TITLES[index]" in html
        assert "Thinking (" in html
        assert "model-dropdown-menu" in html

        # 2. Verify /api/models endpoint returns the 12-model catalog
        models_resp = client.get("/api/models")
        assert models_resp.status_code == 200
        models_payload = models_resp.json()
        assert models_payload["default_model"] == "gemini-3.1-pro"
        model_ids = [m["id"] for m in models_payload["models"]]
        assert len(model_ids) == 12
        assert "gemini-pro-next" in model_ids
        assert "gemini-4-argon-high" in model_ids
        assert "gemini-3.1-pro" in model_ids
        assert "claude-opus-5.5-max" in model_ids

        # 3. Verify conversational follow-up & model selection in POST /api/chat
        chat_resp = client.post(
            "/api/chat",
            json={
                "user_id": "test_user",
                "message": "Can you resume more?",
                "model": "gemini-4-argon-high",
            },
        )
        assert chat_resp.status_code == 200
        chat_data = chat_resp.json()
        assert chat_data["model_id"] == "gemini-4-argon-high"
        assert "Concise Executive Summary" in chat_data["response"] or len(chat_data["response"]) > 20

        # 4. Verify /dev-ui/ route remains available for debugging
        dev_ui_resp = client.get("/dev-ui/", follow_redirects=True)
        assert dev_ui_resp.status_code == 200

        # 5. Verify /api/health endpoint
        health_resp = client.get("/api/health")
        assert health_resp.status_code == 200
        health = health_resp.json()
        assert health["status"] == "HEALTHY"
        assert health["dev_ui_available"] is True



def test_dockerfile_and_deployment_persistence_configuration():
    """Validates Component 5: Dockerfile gcloud installation and Cloud Run GCS volume mount configuration."""
    import pathlib

    repo_root = pathlib.Path(__file__).resolve().parent.parent
    dockerfile_text = (repo_root / "Dockerfile").read_text(encoding="utf-8")
    deploy_cr_text = (repo_root / "scripts" / "deploy_cloud_run.sh").read_text(encoding="utf-8")
    deploy_vertex_text = (repo_root / "scripts" / "setup_and_deploy_vertex.sh").read_text(encoding="utf-8")

    # Dockerfile checks
    assert "google-cloud-cli" in dockerfile_text
    assert "SESSION_DB_URL=sqlite:///data/pqc_sessions.db" in dockerfile_text
    assert "PQC_ARTIFACT_BUCKET=gs://pqc-inventory-agent-cd06-pqc-agent-staging" in dockerfile_text
    assert 'CMD ["uvicorn", "main:app"' in dockerfile_text

    # Cloud Run GCS Volume Mount checks
    for script_text in (deploy_cr_text, deploy_vertex_text):
        assert "--add-volume" in script_text
        assert "name=pqc-data,type=cloud-storage,bucket=" in script_text
        assert "--add-volume-mount" in script_text
        assert "volume=pqc-data,mount-path=/data" in script_text
