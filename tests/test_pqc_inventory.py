"""Test suite for the Agentic PQC Workspace (LLM-first architecture).

These tests prove three things:
1. Tools only collect evidence and compute auditable numbers (no hardcoded catalogs, prose verdicts or silent demo data).
2. The agent is a Gemini multi-agent ADK system and the portal only offers verified Gemini models.
3. Every answer carries real model telemetry, and model failures are surfaced explicitly (no templated fallback).
"""

import asyncio
import json
import os
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEMO_SCOPE = "demo-pqc-project"
FORBIDDEN_PROSE_FIELDS = {
    "remediation_guidance",
    "engineering_notes",
    "consuming_applications",
    "pqc_application_compatibility",
    "mosca_risk_analysis",
    "step_by_step_execution_guide",
    "gcloud_remediation_command",
    "architectural_upsell_recommendation",
}


def _clear_cache():
    from tools.gcp_inventory import _SCAN_CACHE

    _SCAN_CACHE.clear()


def _all_keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _all_keys(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _all_keys(item)


def _make_test_registry():
    from pqc_agent.model_registry import ModelRegistry

    def probe(model, level):
        if model in ("fake-ok-model", "fake-fail-model"):
            return True, {"model_version": f"{model}-001"}
        return False, {"error_code": 404, "error": "Publisher model not found"}

    return ModelRegistry(
        candidates=[
            {"model": "fake-ok-model", "label": "Fake OK", "thinking_levels": [None]},
            {"model": "fake-fail-model", "label": "Fake Fail", "thinking_levels": [None]},
            {"model": "fake-missing-model", "label": "Fake Missing", "thinking_levels": [None]},
        ],
        probe=probe,
        default_model="fake-ok-model",
        default_thinking_level="",
    )


def _make_app(tmp_path, registry=None):
    from pqc_agent.workspace_server import create_workspace_app

    return create_workspace_app(
        session_db_url=f"sqlite:///{tmp_path / 'sessions.db'}",
        artifact_bucket="gs://pqc-inventory-agent-cd06-pqc-agent-staging",
        model_registry=registry or _make_test_registry(),
        verify_models_on_startup=False,
    )


# ---------------------------------------------------------------------------
# 1. Evidence and calculation tools
# ---------------------------------------------------------------------------


def test_resolve_scope_org_folder_project_and_tenant_redirect():
    from tools.gcp_inventory import _resolve_scope

    assert _resolve_scope("organizations/31564119954") == ("ORG", "organizations/31564119954", "31564119954")
    assert _resolve_scope("org")[0] == "ORG"
    assert _resolve_scope("folders/123")[1] == "folders/123"
    assert _resolve_scope("projects/my-proj") == ("PROJECT", "projects/my-proj", "my-proj")
    assert _resolve_scope("my-proj") == ("PROJECT", "projects/my-proj", "my-proj")
    assert _resolve_scope("project-cb232322-97f9-4f78-97f")[0] == "ORG"
    assert _resolve_scope("vertex-runtime-tp")[0] == "ORG"


def test_classify_algorithm_pqc_classical_symmetric_and_unknown_fail_closed():
    from tools.gcp_inventory import classify_algorithm

    assert classify_algorithm("KEM_XWING", "KEY_ENCAPSULATION")["quantum_status"] == "QUANTUM_SAFE_PQC"
    assert classify_algorithm("ML_KEM_1024")["nist_pqc_security_category"] == 5
    assert classify_algorithm("PQ_SIGN_ML_DSA_65_EXTERNAL_MU")["quantum_status"] == "QUANTUM_SAFE_PQC"

    rsa = classify_algorithm("RSA_DECRYPT_OAEP_2048_SHA256", "ASYMMETRIC_DECRYPT")
    assert rsa["quantum_status"] == "QUANTUM_VULNERABLE_SHOR"
    assert {a["algorithm"] for a in rsa["cloud_kms_pqc_alternatives"]} == {"KEM_XWING", "ML_KEM_768", "ML_KEM_1024"}
    ecdsa = classify_algorithm("EC_SIGN_P256_SHA256", "ASYMMETRIC_SIGN")
    assert ecdsa["quantum_status"] == "QUANTUM_VULNERABLE_SHOR"
    assert "PQ_SIGN_ML_DSA_65" in {a["algorithm"] for a in ecdsa["cloud_kms_pqc_alternatives"]}
    assert "SHA1_DEPRECATED_HASH" in classify_algorithm("RSA_DECRYPT_OAEP_3072_SHA1")["deprecated_primitive_flags"]

    assert classify_algorithm("GOOGLE_SYMMETRIC_ENCRYPTION")["estimated_post_quantum_security_bits"] == 128
    assert classify_algorithm("AES_128_GCM")["quantum_status"] == "BELOW_PQ_SECURITY_TARGET"
    assert classify_algorithm("HMAC_SHA1")["quantum_status"] == "BELOW_PQ_SECURITY_TARGET"
    assert classify_algorithm("HMAC_SHA256")["quantum_status"] == "QUANTUM_RESISTANT_SYMMETRIC"

    # Unknown or external algorithms must never be reported as safe.
    for algo in ("", "UNKNOWN_ALGORITHM", "SOMETHING_NEW_2027", "EXTERNAL_SYMMETRIC_ENCRYPTION"):
        assert classify_algorithm(algo)["quantum_status"] == "UNKNOWN_REQUIRES_REVIEW"


def test_key_record_is_downgrade_aware_and_tracks_inactive_keys():
    from tools.gcp_inventory import build_key_record

    mixed = build_key_record(
        project_id="p",
        location="global",
        key_ring="kr",
        key_name="k",
        purpose="ASYMMETRIC_SIGN",
        algorithm="PQ_SIGN_ML_DSA_65",
        enabled_version_ids=["1", "2"],
        enabled_version_algorithms=["PQ_SIGN_ML_DSA_65", "EC_SIGN_P256_SHA256"],
    )
    assert mixed["version_algorithms_mismatch"] is True
    assert mixed["effective_algorithm"] == "EC_SIGN_P256_SHA256"
    assert mixed["algorithm_facts"]["quantum_status"] == "QUANTUM_VULNERABLE_SHOR"

    destroyed = build_key_record(
        project_id="p", location="global", key_ring="kr", key_name="old", purpose="ENCRYPT_DECRYPT",
        algorithm="GOOGLE_SYMMETRIC_ENCRYPTION", primary_state="DESTROYED", enabled_version_ids=[],
    )
    assert destroyed["is_active"] is False

    unknown_versions = build_key_record(
        project_id="p", location="global", key_ring="kr", key_name="k2", purpose="ENCRYPT_DECRYPT",
        algorithm="GOOGLE_SYMMETRIC_ENCRYPTION", versions_listing_error="PermissionDenied",
    )
    assert unknown_versions["versions_listing_error"] == "PermissionDenied"
    assert unknown_versions["enabled_version_ids"] == []


def test_demo_inventory_is_labeled_and_contains_no_prose_or_verdicts():
    _clear_cache()
    from tools.gcp_inventory import SIMULATED_DATA_SOURCE, collect_kms_inventory

    inventory = json.loads(collect_kms_inventory(DEMO_SCOPE))
    assert inventory["data_source"] == SIMULATED_DATA_SOURCE
    assert "DEMO DATA" in inventory["simulation_notice"]
    assert inventory["key_count"] == 8
    assert all(k["data_source"] == SIMULATED_DATA_SOURCE for k in inventory["keys"])
    assert inventory["cloud_kms_pqc_alternatives_reference"]
    assert not FORBIDDEN_PROSE_FIELDS.intersection(set(_all_keys(inventory)))


def test_live_mode_never_falls_back_to_demo_data(monkeypatch):
    _clear_cache()
    import tools.gcp_inventory as inv
    import tools.pqc_detectors as det

    class PermissionDeniedClient:
        def __init__(self, *args, **kwargs):
            raise PermissionError("403 caller does not have permission")

    monkeypatch.setattr(inv.kms_v1, "KeyManagementServiceClient", PermissionDeniedClient)
    monkeypatch.setattr(inv.asset_v1, "AssetServiceClient", PermissionDeniedClient)
    monkeypatch.setattr(det.asset_v1, "AssetServiceClient", PermissionDeniedClient)
    monkeypatch.setattr(det.kms_v1, "KeyManagementServiceClient", PermissionDeniedClient)

    payloads = [
        json.loads(inv.collect_kms_inventory("projects/customer-prod-123")),
        json.loads(inv.collect_workload_evidence("projects/customer-prod-123")),
        json.loads(inv.discover_all_crypto_assets("projects/customer-prod-123")),
        json.loads(det.collect_tls_policies("projects/customer-prod-123")),
        json.loads(det.collect_kms_import_jobs("projects/customer-prod-123")),
    ]
    for payload in payloads:
        assert "error" in payload
        assert payload["data_source"] == inv.LIVE_DATA_SOURCE
        assert "SIMULATED" not in json.dumps(payload)
        assert not payload.get("keys") and not payload.get("workloads")


def test_no_hardcoded_workload_catalog_or_hidden_key_ring_exclusions(monkeypatch):
    import tools.gcp_inventory as inv

    assert not hasattr(inv, "KNOWN_WORKLOAD_BINDINGS")
    for path in (REPO_ROOT / "tools").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "kr-pqc-audit-lab" not in text, path.name
        assert "KNOWN_WORKLOAD_BINDINGS" not in text, path.name

    monkeypatch.delenv("PQC_EXCLUDED_KEY_RINGS", raising=False)
    assert inv.excluded_key_rings() == set()
    monkeypatch.setenv("PQC_EXCLUDED_KEY_RINGS", "kr-a, kr-b")
    assert inv.excluded_key_rings() == {"kr-a", "kr-b"}


def test_workload_evidence_returns_exact_cmek_references_without_inferred_links():
    _clear_cache()
    from tools.gcp_inventory import collect_workload_evidence

    evidence = json.loads(collect_workload_evidence(DEMO_SCOPE))
    refs = {(r["kms_key"].split("/")[-1], r["consumer_asset_type"]) for r in evidence["cmek_references"]}
    assert refs == {
        ("bq-customer-pii-cmek", "bigquery.googleapis.com/Dataset"),
        ("gcs-archive-cmek", "storage.googleapis.com/Bucket"),
    }
    assert all("service_account" not in w for w in evidence["workloads"])
    assert all("application_name" not in r for r in evidence["cmek_references"])


def test_scorecard_is_reproducible_with_numerators_and_denominators():
    _clear_cache()
    from tools.gcp_inventory import compute_pqc_scorecard

    metrics = json.loads(compute_pqc_scorecard(DEMO_SCOPE))["metrics"]
    assert (metrics["asymmetric_pqc_migration"]["numerator"], metrics["asymmetric_pqc_migration"]["denominator"]) == (2, 5)
    assert metrics["asymmetric_pqc_migration"]["value_pct"] == 40.0
    assert metrics["symmetric_quantum_resistance"]["value_pct"] == 100.0
    assert (metrics["symmetric_rotation_hygiene"]["numerator"], metrics["symmetric_rotation_hygiene"]["denominator"]) == (1, 2)
    assert metrics["algorithmic_quantum_safe"]["value_pct"] == 62.5
    assert metrics["weighted_kms_pqc_maturity"]["value_pct"] == 56.5
    assert metrics["https_proxies_requiring_tls_1_3"]["denominator"] == 2
    assert metrics["https_proxies_requiring_tls_1_3"]["value_pct"] == 0.0
    assert metrics["byok_import_jobs_using_pqc_wrapping"]["value_pct"] == 50.0
    for metric in metrics.values():
        assert metric["definition"]


def test_quantum_engine_cites_literature_and_produces_no_financial_figures():
    _clear_cache()
    from tools.quantum_engine import map_algorithm_to_quantum_profile, run_quantum_cryptanalysis_simulation

    result = json.loads(run_quantum_cryptanalysis_simulation(DEMO_SCOPE))
    text = json.dumps(result).lower()
    assert "usd" not in text and "qvar" not in text and "q_var" not in text
    assert "not a forecast" in result["illustrative_crqc_scenario_model"]["disclaimer"].lower()
    assert result["illustrative_crqc_scenario_model"]["assumptions"]["iterations"] == 10000
    assert result["estimate_caveats"]

    rsa = map_algorithm_to_quantum_profile("RSA_SIGN_PSS_2048_SHA256")
    assert rsa["logical_qubits"] == 4098
    assert any("arXiv:2505.15917" in e["source"] for e in rsa["physical_estimates"])
    assert map_algorithm_to_quantum_profile("EC_SIGN_P384_SHA384")["logical_qubits"] == 3484
    assert map_algorithm_to_quantum_profile("NEW_ALGO")["quantum_status"] == "UNKNOWN_REQUIRES_REVIEW"
    assert map_algorithm_to_quantum_profile("AES_128_GCM")["quantum_status"] == "BELOW_PQ_SECURITY_TARGET"


def test_tls_and_import_job_evidence_are_facts_only():
    _clear_cache()
    from tools.pqc_detectors import collect_kms_import_jobs, collect_tls_policies

    tls = json.loads(collect_tls_policies(DEMO_SCOPE))
    policies = {p["policy_name"]: p for p in tls["ssl_policies"]}
    assert policies["ssl-policy-legacy-tls12-ingress"]["post_quantum_key_exchange"] == "DEFERRED"
    assert policies["ssl-policy-legacy-tls12-ingress"]["post_quantum_key_exchange_deferred"] is True
    assert policies["ssl-policy-tls13-restricted"]["post_quantum_key_exchange"] == "ENABLED"
    assert policies["ssl-policy-tls13-restricted"]["post_quantum_key_exchange_deferred"] is False

    proxies = {p["proxy_name"]: p for p in tls["target_proxies"]}
    assert proxies["openbanking-https-proxy"]["effective_min_tls_version"] == "TLS_1_2"
    assert proxies["openbanking-https-proxy"]["effective_post_quantum_key_exchange"] == "DEFERRED"
    assert proxies["openbanking-https-proxy"]["effective_post_quantum_key_exchange_deferred"] is True
    assert proxies["internal-admin-https-proxy"]["effective_policy_source"] == "GCP_DEFAULT_SSL_POLICY"
    assert proxies["internal-admin-https-proxy"]["effective_min_tls_version"] == "TLS_1_0"
    assert proxies["internal-admin-https-proxy"]["effective_post_quantum_key_exchange"] == "DEFAULT"
    assert proxies["internal-admin-https-proxy"]["effective_post_quantum_key_exchange_deferred"] is False

    jobs = {j["import_job_name"]: j for j in json.loads(collect_kms_import_jobs(DEMO_SCOPE))["import_jobs"]}
    assert jobs["ij-byok-legacy-rsa3072"]["transport_quantum_status"] == "QUANTUM_VULNERABLE_SHOR"
    assert jobs["ij-byok-hpke-xwing"]["wrapping_family"] == "HPKE_POST_QUANTUM_KEM"
    assert not FORBIDDEN_PROSE_FIELDS.intersection(set(_all_keys(tls)) | set(_all_keys(list(jobs.values()))))


def test_cyclonedx_cbom_includes_only_validated_correlations():
    _clear_cache()
    from tools.gcp_inventory import export_cyclonedx_cbom

    correlations = json.dumps(
        [
            {
                "application_name": "customer_pii dataset",
                "workload_resource": "//bigquery.googleapis.com/projects/demo-pqc-project/datasets/customer_pii",
                "kms_key": "projects/demo-pqc-project/locations/us-central1/keyRings/kr-data-lake-encryption/cryptoKeys/bq-customer-pii-cmek",
                "evidence_level": "STRONG",
                "evidence": "Cloud Asset Inventory kmsKey reference",
            },
            {"application_name": "invented app", "kms_key": "projects/x/locations/y/keyRings/z/cryptoKeys/does-not-exist"},
        ]
    )
    bom = json.loads(export_cyclonedx_cbom(DEMO_SCOPE, validated_correlations_json=correlations))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    apps = [c for c in bom["components"] if c["type"] == "application"]
    assert [a["name"] for a in apps] == ["customer_pii dataset"]
    assert len(bom["export_notes"]["rejected_correlations"]) == 1
    crypto = [c for c in bom["components"] if c["type"] == "cryptographic-asset"]
    assert len(crypto) == 8
    aes = next(c for c in crypto if c["name"].endswith("bq-customer-pii-cmek"))
    assert aes["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 5


def test_calibration_records_provenance_and_never_leaks_other_scopes():
    from tools.calibration_engine import calibrate_assessment_context, get_historical_calibration_profile

    recorded = json.loads(
        calibrate_assessment_context(
            scope="organizations/111",
            industry_sector="banking",
            confidentiality_years_x=20,
            parameter_source_note="CISO interview",
        )
    )
    entry = recorded["recorded_entry"]
    assert entry["industry_sector"] == "BFSI_BANKING"
    assert entry["parameter_sources"]["confidentiality_years_x"] == "provided"
    assert entry["parameter_sources"]["migration_years_y"] == "sector_baseline_default"
    assert entry["mosca"]["x_plus_y"] == 23.0
    assert entry["mosca"]["inequality_x_plus_y_greater_than_z"] is True

    same_scope = json.loads(get_historical_calibration_profile("organizations/111"))
    assert same_scope["calibration_mode"] == "CALIBRATED_FOR_SCOPE"
    other_scope = json.loads(get_historical_calibration_profile("organizations/222"))
    assert other_scope["calibration_mode"] == "DEFAULT_BASELINE_NOT_CALIBRATED"
    assert other_scope["active_profile"]["industry_sector"] == "ENTERPRISE_DEFAULT"


def test_read_uploaded_artifact_returns_raw_content_scoped_to_session():
    from tools.calibration_engine import read_uploaded_artifact, register_uploaded_artifact_for_analysis

    register_uploaded_artifact_for_analysis(
        filename="questionnaire.md",
        raw_bytes=b"# Discovery\n- Data shelf-life: 15 years\n",
        mime_type="text/markdown",
        session_id="session-a",
    )

    class _Session:
        def __init__(self, sid):
            self.id = sid

    class _Ctx:
        def __init__(self, sid):
            self.session = _Session(sid)

        async def list_artifacts(self):
            raise RuntimeError("artifact service unavailable in unit test")

        async def load_artifact(self, name):
            raise RuntimeError("artifact service unavailable in unit test")

    same = json.loads(asyncio.run(read_uploaded_artifact("questionnaire.md", tool_context=_Ctx("session-a"))))
    assert same["status"] == "OK"
    assert "Data shelf-life: 15 years" in same["extracted_text"]
    assert "extracted_parameters" not in same
    other = json.loads(asyncio.run(read_uploaded_artifact("questionnaire.md", tool_context=_Ctx("session-b"))))
    assert other["status"] == "NO_ARTIFACT_FOUND"


def test_save_assessment_report_persists_llm_authored_content_verbatim():
    from tools.report_exporter import save_assessment_report

    rejected = json.loads(asyncio.run(save_assessment_report("Empty", "short")))
    assert rejected["status"] == "REJECTED"

    markdown = "# PQC Readiness - Executive Report\n\nWritten by the report_writer_agent from validated findings.\n"
    saved = json.loads(asyncio.run(save_assessment_report("PQC Readiness - Executive Report", markdown, "executive", "organizations/1")))
    assert saved["status"] == "SAVED"
    assert pathlib.Path(saved["local_files"]["markdown"]).read_text(encoding="utf-8").strip() == markdown.strip()
    assert "PQC Readiness - Executive Report" in pathlib.Path(saved["local_files"]["html"]).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 2. Gemini multi-agent architecture and model catalog
# ---------------------------------------------------------------------------


def test_agent_is_gemini_multi_agent_tree_with_template_safe_instructions():
    import pqc_agent.agent as agent_module
    from google.adk.tools.agent_tool import AgentTool

    root = agent_module.root_agent
    specialists = [t.agent for t in root.tools if isinstance(t, AgentTool)]
    assert [s.name for s in specialists] == [
        "discovery_agent",
        "correlation_analyst_agent",
        "quantum_risk_agent",
        "remediation_architect_agent",
        "report_writer_agent",
    ]
    assert root.model.startswith("gemini-")
    assert all(s.model == root.model for s in specialists)

    tool_names = {s.name: {getattr(t, "__name__", getattr(t, "name", "")) for t in s.tools} for s in specialists}
    assert "collect_workload_evidence" in tool_names["correlation_analyst_agent"]
    assert "compute_pqc_scorecard" in tool_names["quantum_risk_agent"]
    assert "save_assessment_report" in tool_names["report_writer_agent"]

    instructions = [root.instruction] + [s.instruction for s in specialists]
    assert all("{" not in text and "}" not in text for text in instructions)
    assert "Never invent" in root.instruction
    assert not hasattr(agent_module, "MODEL_CATALOG")
    source = (REPO_ROOT / "pqc_agent" / "agent.py").read_text(encoding="utf-8").lower()
    assert "claude" not in source


def test_model_registry_offers_only_verified_gemini_models():
    from pqc_agent.model_registry import ModelRegistry

    default_registry = ModelRegistry(probe=lambda m, l: (False, {"error": "offline"}))
    assert default_registry.candidates
    assert all(c["model"].startswith("gemini-") for c in default_registry.candidates)

    calls = []

    def probe(model, level):
        calls.append((model, level))
        if model == "gemini-a" and level is not None:
            return False, {"error_code": 400, "error": "thinking_level not supported"}
        if model in ("gemini-a", "gemini-b"):
            return True, {"model_version": f"{model}-001"}
        return False, {"error_code": 404}

    registry = ModelRegistry(
        candidates=[
            {"model": "gemini-a", "label": "Gemini A", "thinking_levels": ["HIGH", "MEDIUM"]},
            {"model": "gemini-b", "label": "Gemini B", "thinking_levels": ["HIGH", "MEDIUM"]},
            {"model": "gemini-gone", "label": "Gemini Gone", "thinking_levels": [None]},
        ],
        probe=probe,
        default_model="gemini-b",
        default_thinking_level="MEDIUM",
    )
    registry.verify_all(force=True)
    catalog = registry.catalog()
    ids = [m["id"] for m in catalog["models"]]
    assert ids == ["gemini-a", "gemini-b:high", "gemini-b:medium"]
    assert catalog["default_model"] == "gemini-b:medium"
    assert [u["model"] for u in catalog["unavailable_candidates"]] == ["gemini-gone"]
    assert registry.resolve("claude-opus-5.5-max") is None
    assert registry.resolve("gemini-gone") is None
    assert registry.resolve("gemini-b")["thinking_level"] == "MEDIUM"


def test_api_models_and_chat_report_real_model_telemetry(tmp_path):
    from fastapi.testclient import TestClient

    with TestClient(_make_app(tmp_path)) as client:
        models = client.get("/api/models", params={"refresh": "true"}).json()
        assert [m["id"] for m in models["models"]] == ["fake-ok-model", "fake-fail-model"]
        assert models["default_model"] == "fake-ok-model"
        assert [u["model"] for u in models["unavailable_candidates"]] == ["fake-missing-model"]

        resp = client.post("/api/chat", json={"user_id": "tester", "message": "Can you summarize?", "model": "fake-ok-model"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "OK"
        assert data["response"].startswith("Fake model answer to: Can you summarize?")
        served = data["served_by"]
        assert served["models_used"] == ["fake-ok-model-001"]
        assert served["llm_call_count"] == 1
        assert (served["prompt_tokens"], served["output_tokens"], served["thinking_tokens"]) == (11, 7, 3)
        assert served["agents_involved"] == ["pqc_inventory_agent"]

        history = client.get(f"/api/sessions/{data['session_id']}", params={"user_id": "tester"}).json()
        assistant = [m for m in history["messages"] if m["role"] == "assistant"]
        assert assistant[-1]["served_by"]["models_used"] == ["fake-ok-model-001"]


def test_chat_model_failure_is_explicit_and_never_replaced_by_templates(tmp_path):
    from fastapi.testclient import TestClient

    with TestClient(_make_app(tmp_path)) as client:
        resp = client.post("/api/chat", json={"user_id": "tester", "message": "Can you resume more?", "model": "fake-fail-model"})
        assert resp.status_code == 502
        data = resp.json()
        assert data["status"] == "MODEL_ERROR"
        assert data["response"] == ""
        assert data["error"]["code"]
        assert "404" in (data["error"]["message"] or "")
        blob = json.dumps(data)
        for canned in ("Executive Summary", "GOOGLE CLOUD CONSULTING", "64.0%", "82.4%", "legacy-rsa-oaep-decrypt"):
            assert canned not in blob


def test_chat_rejects_unverified_and_legacy_model_ids(tmp_path):
    from fastapi.testclient import TestClient

    with TestClient(_make_app(tmp_path)) as client:
        for model_id in ("fake-missing-model", "claude-opus-5.5-max", "gemini-4-argon-high"):
            resp = client.post("/api/chat", json={"user_id": "tester", "message": "hello", "model": model_id})
            assert resp.status_code == 400, model_id
            body = resp.json()
            assert body["status"] == "MODEL_NOT_AVAILABLE"
            assert "fake-ok-model" in body["available_models"]


def test_persistent_session_service_and_sessions_api(tmp_path):
    from fastapi.testclient import TestClient
    from pqc_agent.workspace_server import DatabaseSessionService, ResilientGcsArtifactService

    app_instance = _make_app(tmp_path)
    assert isinstance(app_instance.state.session_service, DatabaseSessionService)
    assert isinstance(app_instance.state.artifact_service, ResilientGcsArtifactService)

    with TestClient(app_instance) as client:
        created = client.post("/api/sessions", json={"user_id": "ciso", "title": "Executive PQC Review"}).json()
        session_id = created["session_id"]
        listed = client.get("/api/sessions", params={"user_id": "ciso"}).json()
        assert any(s["session_id"] == session_id and s["title"] == "Executive PQC Review" for s in listed["sessions"])
        detail = client.get(f"/api/sessions/{session_id}", params={"user_id": "ciso"}).json()
        assert detail["messages"] == []
        assert client.delete(f"/api/sessions/{session_id}", params={"user_id": "ciso"}).json()["deleted"] is True
        assert client.get(f"/api/sessions/{session_id}", params={"user_id": "ciso"}).status_code == 404


def test_multimodal_upload_is_attached_for_the_model_without_pre_analysis(tmp_path):
    from fastapi.testclient import TestClient

    questionnaire = "# Discovery\n- Industry: banking\n- Data shelf-life (X): 15 years\n".encode("utf-8")
    with TestClient(_make_app(tmp_path)) as client:
        resp = client.post(
            "/api/chat",
            data={"user_id": "tester", "message": "What does this file say?", "model_id": "fake-ok-model"},
            files=[("files", ("discovery.md", questionnaire, "text/markdown"))],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "OK"
        assert data["uploaded_artifacts"][0]["filename"] == "discovery.md"
        assert all(tc["name"] != "analyze_uploaded_pqc_artifact" for tc in data["tool_calls"])
        detail = client.get(f"/api/sessions/{data['session_id']}", params={"user_id": "tester"}).json()
        assert "discovery.md" in detail["artifacts"]


def test_gcloud_bridge_connection_modes_and_safe_command_execution():
    from tools.gcloud_bridge import execute_gcloud_command, get_gcp_connection_config, set_gcp_connection_config, validate_gcloud_command

    for safe_cmd in (
        "gcloud kms keys list --location=global --format=json",
        "gcloud asset search-all-resources --scope=organizations/31564119954",
        "gcloud projects get-iam-policy pqc-inventory-agent-cd06",
        "gcloud version",
    ):
        assert validate_gcloud_command(safe_cmd)[0] is True, safe_cmd

    for blocked_cmd in (
        "gcloud kms keys versions destroy 1 --key=k1 --keyring=kr1 --location=global",
        "gcloud projects delete my-prod-project",
        "gcloud kms keys create new-key --keyring=kr1 --location=global",
        "gcloud version; rm -rf /",
    ):
        assert validate_gcloud_command(blocked_cmd)[0] is False, blocked_cmd
        assert json.loads(execute_gcloud_command(blocked_cmd))["status"] == "BLOCKED_DESTRUCTIVE_OR_INVALID_COMMAND"

    token_state = set_gcp_connection_config(mode="access_token", access_token="ya29.example_short_lived_token")
    assert token_state["has_access_token"] is True
    assert "ya29.example_short_lived_token" not in json.dumps(token_state)
    set_gcp_connection_config(mode="adc")
    assert get_gcp_connection_config()["mode"] == "adc"


def test_portal_ui_is_gemini_only_dynamic_and_transparent(tmp_path):
    from fastapi.testclient import TestClient

    with TestClient(_make_app(tmp_path)) as client:
        html = client.get("/").text
        for removed in ("Claude", "Gemini 4 Argon", "Gemini 3.8 Flash", "Gemini Pro Next", "PHASE 01", "🛡️"):
            assert removed not in html, removed
        for required in (
            "loadModelCatalog",
            "/api/models",
            "served-by-badge",
            "msg-error-card",
            "Answered by",
            "await createNewSession(PHASE_TITLES[index]",
            "Running specialist agents on",
            "Thinking (",
        ):
            assert required in html, required
        for chip in ("P1", "P2", "P3", "P4", "P5"):
            assert f"<strong>{chip}</strong>" in html
        assert client.get("/dev-ui/", follow_redirects=True).status_code == 200


def test_deployment_configuration_disables_simulation_and_keeps_persistence():
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    deploy_cr = (REPO_ROOT / "scripts" / "deploy_cloud_run.sh").read_text(encoding="utf-8")
    deploy_vertex = (REPO_ROOT / "scripts" / "setup_and_deploy_vertex.sh").read_text(encoding="utf-8")

    assert "PQC_SIMULATION_MODE=FALSE" in dockerfile
    assert 'CMD ["uvicorn", "main:app"' in dockerfile
    for script in (deploy_cr, deploy_vertex):
        assert "PQC_SIMULATION_MODE=FALSE" in script
        assert "PQC_SIMULATION_MODE=AUTO" not in script
        assert "name=pqc-data,type=cloud-storage,bucket=" in script
        assert "volume=pqc-data,mount-path=/data" in script


def test_tools_smoke_runner_never_invokes_the_llm():
    _clear_cache()
    import main

    result = main.run_tools_smoke_test(DEMO_SCOPE)
    assert result["llm_invoked"] is False
    assert result["kms_inventory_summary"]["data_source"] == "SIMULATED_DEMO_DATASET"


@pytest.mark.skipif(os.getenv("PQC_LIVE_LLM_TEST") != "1", reason="Set PQC_LIVE_LLM_TEST=1 with Vertex AI access to run.")
def test_live_vertex_gemini_turn_reports_model_telemetry():
    import main

    result = asyncio.run(main.run_adk_agent_turn("In one sentence, what does ML-KEM standardize? Do not call tools."))
    assert result["status"] == "OK", result["error"]
    assert result["served_by"]["models_used"]
    assert result["served_by"]["prompt_tokens"] > 0
