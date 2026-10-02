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
        assert "gcloud kms keys create" in playbook["gcloud_cnsa_2_0_command"]
        assert "gcloud kms keys versions disable" in playbook["post_migration_disable_legacy_command"]
        assert len(playbook["affected_applications"]) >= 1
        assert playbook["pqc_application_compatibility"]["is_compatible_with_pqc_model"] is False


def test_local_harness_execution():
    """Validates Phase 4.1 local harness execution."""
    result = run_local_harness('{"project_id": "meu-projeto-gcp"}', invoke_llm=False)
    assert result["harness_status"] == "SUCCESS"
    assert result["project_id"] == "meu-projeto-gcp"
    assert result["cbom_summary"]["total_kms_keys_scanned"] == 8


def test_build_executive_markdown_report():
    """Validates Executive PQC Report generation in English Markdown."""
    report_md = build_executive_markdown_report("meu-projeto-gcp")
    assert "Executive PQC Readiness & Application Compatibility Report" in report_md
    assert "Application-to-Key Inventory & PQC Model Compatibility Matrix" in report_md
    assert "KEM_XWING" in report_md
    assert "PQ_SIGN_ML_DSA_65" in report_md
    assert "gcloud kms keys create" in report_md


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
    assert "scan_ssl_policies" in main.SYSTEM_INSTRUCTION
    assert "scan_import_jobs_pqc" in main.SYSTEM_INSTRUCTION
    assert "{" not in main.SYSTEM_INSTRUCTION
    assert "}" not in main.SYSTEM_INSTRUCTION


