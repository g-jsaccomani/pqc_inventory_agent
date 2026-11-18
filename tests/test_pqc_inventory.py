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
    from pqc_agent import auth_store
    from pqc_agent.workspace_server import create_workspace_app

    db_url = f"sqlite:///{tmp_path / 'sessions.db'}"
    os.environ["SESSION_DB_URL"] = db_url
    auth_store.clear_fallback_auth_stores()
    return create_workspace_app(
        session_db_url=db_url,
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


def test_api_models_and_chat_report_real_model_telemetry(tmp_path, signin):
    from fastapi.testclient import TestClient

    with TestClient(_make_app(tmp_path)) as client:
        assert client.get("/api/models", params={"refresh": "true"}).status_code == 401  # billed probes need sign-in
        auth = {"X-PQC-User-Token": signin(client, "tester@google.com")}
        models = client.get("/api/models", params={"refresh": "true"}, headers=auth).json()
        assert [m["id"] for m in models["models"]] == ["fake-ok-model", "fake-fail-model"]
        assert models["default_model"] == "fake-ok-model"
        assert [u["model"] for u in models["unavailable_candidates"]] == ["fake-missing-model"]

        resp = client.post("/api/chat", headers=auth, json={"message": "Can you summarize?", "model": "fake-ok-model"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "OK"
        assert data["user_id"] == "tester@google.com"
        assert data["response"].startswith("Fake model answer to: Can you summarize?")
        served = data["served_by"]
        assert served["models_used"] == ["fake-ok-model-001"]
        assert served["llm_call_count"] == 1
        assert (served["prompt_tokens"], served["output_tokens"], served["thinking_tokens"]) == (11, 7, 3)
        assert served["agents_involved"] == ["pqc_inventory_agent"]

        history = client.get(f"/api/sessions/{data['session_id']}", headers=auth).json()
        assistant = [m for m in history["messages"] if m["role"] == "assistant"]
        assert assistant[-1]["served_by"]["models_used"] == ["fake-ok-model-001"]


def test_chat_model_failure_is_explicit_and_never_replaced_by_templates(tmp_path, signin):
    from fastapi.testclient import TestClient

    with TestClient(_make_app(tmp_path)) as client:
        auth = {"X-PQC-User-Token": signin(client, "tester@google.com")}
        resp = client.post("/api/chat", headers=auth, json={"message": "Can you resume more?", "model": "fake-fail-model"})
        assert resp.status_code == 502
        data = resp.json()
        assert data["status"] == "MODEL_ERROR"
        assert data["response"] == ""
        assert data["error"]["code"]
        assert "404" in (data["error"]["message"] or "")
        blob = json.dumps(data)
        for canned in ("Executive Summary", "GOOGLE CLOUD CONSULTING", "64.0%", "82.4%", "legacy-rsa-oaep-decrypt"):
            assert canned not in blob


def test_chat_rejects_unverified_and_legacy_model_ids(tmp_path, signin):
    from fastapi.testclient import TestClient

    with TestClient(_make_app(tmp_path)) as client:
        auth = {"X-PQC-User-Token": signin(client, "tester@google.com")}
        for model_id in ("fake-missing-model", "claude-opus-5.5-max", "gemini-4-argon-high", "gemini-2.5-flash"):
            resp = client.post("/api/chat", headers=auth, json={"message": "hello", "model": model_id})
            assert resp.status_code == 400, model_id
            body = resp.json()
            assert body["status"] == "MODEL_NOT_AVAILABLE"
            assert "fake-ok-model" in body["available_models"]


def test_persistent_session_service_and_sessions_api(tmp_path, signin):
    from fastapi.testclient import TestClient
    from pqc_agent.workspace_server import DatabaseSessionService, ResilientGcsArtifactService

    app_instance = _make_app(tmp_path)
    assert isinstance(app_instance.state.session_service, DatabaseSessionService)
    assert isinstance(app_instance.state.artifact_service, ResilientGcsArtifactService)

    with TestClient(app_instance) as client:
        auth = {"X-PQC-User-Token": signin(client, "ciso@google.com")}
        created = client.post("/api/sessions", headers=auth, json={"title": "Executive PQC Review"}).json()
        session_id = created["session_id"]
        assert created["user_id"] == "ciso@google.com"
        listed = client.get("/api/sessions", headers=auth, params={"user_id": "ciso@google.com"}).json()
        assert any(s["session_id"] == session_id and s["title"] == "Executive PQC Review" for s in listed["sessions"])
        detail = client.get(f"/api/sessions/{session_id}", headers=auth).json()
        assert detail["messages"] == []
        assert client.delete(f"/api/sessions/{session_id}", headers=auth).json()["deleted"] is True
        assert client.get(f"/api/sessions/{session_id}", headers=auth).status_code == 404


def test_multimodal_upload_is_attached_for_the_model_without_pre_analysis(tmp_path, signin):
    from fastapi.testclient import TestClient

    questionnaire = "# Discovery\n- Industry: banking\n- Data shelf-life (X): 15 years\n".encode("utf-8")
    with TestClient(_make_app(tmp_path)) as client:
        auth = {"X-PQC-User-Token": signin(client, "tester@google.com")}
        resp = client.post(
            "/api/chat",
            headers=auth,
            data={"message": "What does this file say?", "model_id": "fake-ok-model"},
            files=[("files", ("discovery.md", questionnaire, "text/markdown"))],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "OK"
        assert data["uploaded_artifacts"][0]["filename"] == "discovery.md"
        assert all(tc["name"] != "analyze_uploaded_pqc_artifact" for tc in data["tool_calls"])
        detail = client.get(f"/api/sessions/{data['session_id']}", headers=auth).json()
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


def test_portal_ui_is_gemini_only_dynamic_and_transparent(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.delenv("K_SERVICE", raising=False)  # local development: ADK dev UI enabled by default
    with TestClient(_make_app(tmp_path)) as client:
        html = client.get("/").text
        for removed in ("Claude", "Gemini 4 Argon", "Gemini 3.8 Flash", "Gemini Pro Next", "PHASE 01", "🛡️", "X-PQC-User-Id"):
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
            "/api/auth/config",
            "gcloud auth print-access-token",
            "PQC_SIGNIN_COMPLETE",
        ):
            assert required in html, required
        for chip in ("P1", "P2", "P3", "P4", "P5"):
            assert f"<strong>{chip}</strong>" in html
        assert client.get("/dev-ui/", follow_redirects=True).status_code == 200


def test_deployment_configuration_disables_simulation_and_keeps_persistence():
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    app_yaml = (REPO_ROOT / "app.yaml").read_text(encoding="utf-8")
    deploy_cr = (REPO_ROOT / "scripts" / "deploy_cloud_run.sh").read_text(encoding="utf-8")
    deploy_vertex = (REPO_ROOT / "scripts" / "setup_and_deploy_vertex.sh").read_text(encoding="utf-8")

    assert "PQC_SIMULATION_MODE=FALSE" in dockerfile
    assert 'CMD ["uvicorn", "main:app"' in dockerfile
    assert "COPY scripts/run_db_migrations.py ./scripts/run_db_migrations.py" in dockerfile
    for cfg_text in (dockerfile, app_yaml, deploy_cr, deploy_vertex):
        assert "sqlite:///data/pqc_sessions.db" not in cfg_text
        assert "type=cloud-storage" not in cfg_text
        assert "mount-path=/data" not in cfg_text
        assert "calibration-history.jsonl" not in cfg_text
    assert "Cloud SQL for PostgreSQL" in app_yaml
    assert "20261117_0002" in app_yaml
    assert "EncryptedDatabaseCredentialService" in app_yaml
    for script in (deploy_cr, deploy_vertex):
        assert "PQC_SIMULATION_MODE=FALSE" in script
        assert "PQC_SIMULATION_MODE=AUTO" not in script
        assert "--add-cloudsql-instances=" in script
        assert "PQC_CLOUD_SQL_CONNECTION_NAME=" in script
        assert "PQC_KMS_KEY_NAME=" in script
        assert "PQC_ARTIFACT_BUCKET=gs://" in script
        assert "--set-secrets=" in script
        assert "scripts/run_db_migrations.py,--require-postgres" in script
        assert "--tasks=1" in script
        assert "--max-retries=0" in script
        # Hardened auth on Cloud Run: verified sign-in only, ADK DevServer and ADK REST API off.
        assert "PQC_ALLOW_UNVERIFIED_SIGNIN=false" in script
        assert "PQC_ENABLE_ADK_DEV_UI=false" in script
        assert "PQC_ENABLE_ADK_API=false" in script
        assert "PQC_ALLOW_UNVERIFIED_SIGNIN=true" not in script


def test_tools_smoke_runner_never_invokes_the_llm():
    _clear_cache()
    import main

    result = main.run_tools_smoke_test(DEMO_SCOPE)
    assert result["llm_invoked"] is False
    assert result["kms_inventory_summary"]["data_source"] == "SIMULATED_DEMO_DATASET"


def test_multi_tenant_google_auth_regional_sessions_and_isolated_connections(tmp_path, google_verifier, monkeypatch):
    from fastapi.testclient import TestClient

    from pqc_agent import auth_guard

    app_instance = _make_app(tmp_path)
    with TestClient(app_instance) as client:
        # 1. Email-only sign-in is rejected (no verified credential); a verified external domain is forbidden
        email_only = client.post("/api/auth/google", json={"email": "alice@google.com", "region": "NorthAm"})
        assert email_only.status_code == 401
        bad_auth = client.post(
            "/api/auth/google", json={"google_access_token": "valid:attacker@evil.example.com", "region": "NorthAm"}
        )
        assert bad_auth.status_code == 403

        # 2. Sign in 4 Googlers across NorthAm, EMEA, India, and APAC (verified Google tokens)
        alice_login = client.post(
            "/api/auth/google",
            json={"google_access_token": "valid:alice@google.com", "name": "Alice NorthAm", "timezone": "America/New_York"},
        )
        assert alice_login.status_code == 200
        alice_data = alice_login.json()
        assert alice_data["authenticated"] is True
        assert alice_data["user"]["email"] == "alice@google.com"
        assert alice_data["user"]["region"] == "NorthAm"
        assert "token" not in alice_data
        alice_token = alice_login.cookies.get("pqc_session_token")
        assert alice_token

        rahul_login = client.post(
            "/api/auth/google",
            json={"google_access_token": "valid:rahul@google.com", "name": "Rahul India", "timezone": "Asia/Kolkata"},
        )
        assert rahul_login.status_code == 200
        rahul_data = rahul_login.json()
        assert rahul_data["user"]["region"] == "India"
        assert "token" not in rahul_data
        rahul_token = rahul_login.cookies.get("pqc_session_token")
        assert rahul_token

        anna_login = client.post(
            "/api/auth/google",
            json={"google_access_token": "valid:anna@google.com", "name": "Anna EMEA", "timezone": "Europe/London"},
        )
        assert anna_login.status_code == 200
        assert anna_login.json()["user"]["region"] == "EMEA"
        assert "token" not in anna_login.json()
        anna_token = anna_login.cookies.get("pqc_session_token")
        assert anna_token

        kenji_login = client.post(
            "/api/auth/google",
            json={"google_access_token": "valid:kenji@google.com", "name": "Kenji APAC", "timezone": "Asia/Tokyo"},
        )
        assert kenji_login.status_code == 200
        assert kenji_login.json()["user"]["region"] == "APAC"
        assert "token" not in kenji_login.json()
        kenji_token = kenji_login.cookies.get("pqc_session_token")
        assert kenji_token

        # 3. Isolated GCP Connection Config per @google.com user
        client.post(
            "/api/connection",
            headers={"X-PQC-User-Token": alice_token},
            json={
                "mode": "impersonation",
                "organization_id": "111111111111",
                "project_id": "alice-northam-proj",
                "impersonated_service_account": "pqc-sa@alice-northam-proj.iam.gserviceaccount.com",
            },
        )
        client.post(
            "/api/connection",
            headers={"X-PQC-User-Token": rahul_token},
            json={
                "mode": "adc",
                "organization_id": "222222222222",
                "project_id": "rahul-india-proj",
            },
        )

        alice_conn = client.get("/api/connection", headers={"X-PQC-User-Token": alice_token}).json()
        rahul_conn = client.get("/api/connection", headers={"X-PQC-User-Token": rahul_token}).json()
        anna_conn = client.get("/api/connection", headers={"X-PQC-User-Token": anna_token}).json()

        assert alice_conn["user_id"] == "alice@google.com"
        assert alice_conn["mode"] == "impersonation"
        assert alice_conn["organization_id"] == "111111111111"
        assert alice_conn["project_id"] == "alice-northam-proj"

        assert rahul_conn["user_id"] == "rahul@google.com"
        assert rahul_conn["mode"] == "adc"
        assert rahul_conn["organization_id"] == "222222222222"
        assert rahul_conn["project_id"] == "rahul-india-proj"

        # Anna in EMEA still has the default demo connection untouched
        assert anna_conn["user_id"] == "anna@google.com"
        assert anna_conn["mode"] == "adc"
        assert anna_conn["organization_id"] == "31564119954"

        # 4. Isolated Persistent Sessions per @google.com user
        alice_sess = client.post(
            "/api/sessions",
            headers={"X-PQC-User-Token": alice_token},
            json={"title": "NorthAm Banking PQC Review"},
        ).json()
        rahul_sess = client.post(
            "/api/sessions",
            headers={"X-PQC-User-Token": rahul_token},
            json={"title": "India Telecom PQC Review"},
        ).json()

        assert alice_sess["user_id"] == "alice@google.com"
        assert alice_sess["scope"] == "organizations/111111111111"
        assert rahul_sess["user_id"] == "rahul@google.com"
        assert rahul_sess["scope"] == "organizations/222222222222"

        alice_list = client.get("/api/sessions", headers={"X-PQC-User-Token": alice_token}).json()
        rahul_list = client.get("/api/sessions", headers={"X-PQC-User-Token": rahul_token}).json()
        assert [s["title"] for s in alice_list["sessions"]] == ["NorthAm Banking PQC Review"]
        assert [s["title"] for s in rahul_list["sessions"]] == ["India Telecom PQC Review"]

        # Rahul cannot read or delete Alice's session (strict tenant boundary)
        cross_read = client.get(
            f"/api/sessions/{alice_sess['session_id']}",
            headers={"X-PQC-User-Token": rahul_token},
        )
        assert cross_read.status_code == 404

        cross_delete = client.delete(
            f"/api/sessions/{alice_sess['session_id']}",
            headers={"X-PQC-User-Token": rahul_token},
        )
        assert cross_delete.status_code == 404

        # 5. Cloud IAP: the plain header is NEVER trusted; only a verified X-Goog-IAP-JWT-Assertion authenticates
        client.cookies.clear()
        forged_me = client.get(
            "/api/auth/me",
            headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:alice@google.com"},
        ).json()
        assert forged_me["authenticated"] is False
        assert forged_me["iap_active"] is False

        def fake_verify_iap_jwt(token, audience=None):
            if token == "signed-iap-jwt-for-alice":
                return {"iss": auth_guard.IAP_ISSUER, "email": "alice@google.com", "sub": "accounts.google.com:1"}
            return None

        monkeypatch.setattr(auth_guard, "verify_iap_jwt", fake_verify_iap_jwt)
        iap_me = client.get(
            "/api/auth/me",
            headers={
                "X-Goog-IAP-JWT-Assertion": "signed-iap-jwt-for-alice",
                "X-Goog-Authenticated-User-Email": "accounts.google.com:rahul@google.com",  # ignored
            },
        ).json()
        assert iap_me["authenticated"] is True
        assert iap_me["iap_active"] is True
        assert iap_me["user"]["email"] == "alice@google.com"
        assert iap_me["session_count"] == 1
        assert iap_me["connection"]["organization_id"] == "111111111111"
        bad_jwt_me = client.get("/api/auth/me", headers={"X-Goog-IAP-JWT-Assertion": "forged"}).json()
        assert bad_jwt_me["authenticated"] is False

        # 6. Tenants summary (signed-in users only) shows all 4 regions
        assert client.get("/api/auth/tenants").status_code == 401
        tenants_summary = client.get("/api/auth/tenants", headers={"X-PQC-User-Token": alice_token}).json()
        for reg in ("NorthAm", "EMEA", "India", "APAC"):
            assert tenants_summary["by_region"].get(reg, 0) >= 1


def test_oauth_3lo_tool_context_consent_card_and_credential_injection(tmp_path, signin):
    from unittest.mock import MagicMock

    from fastapi.testclient import TestClient

    from pqc_agent.workspace_server import (
        GCP_OAUTH_CREDENTIAL_KEY,
        PqcOAuth3LOPlugin,
        _TURN_OAUTH_CONSENT_CARDS,
        build_gcp_oauth_auth_config,
    )

    app_instance = _make_app(tmp_path)
    with TestClient(app_instance) as client:
        # 1. Sign in an EMEA Googler and switch their connection mode to 3-Legged OAuth (with empty token)
        token = signin(client, "emea.arch@google.com", name="EMEA Architect", region="EMEA")

        conn_res = client.post(
            "/api/connection",
            headers={"X-PQC-User-Token": token},
            json={"mode": "oauth_3lo", "organization_id": "9988776655", "access_token": ""},
        ).json()
        assert conn_res["mode"] == "access_token"
        assert conn_res["auth_flow"] == "oauth2_3lo"
        assert conn_res["has_access_token"] is False
        assert conn_res["oauth_consent_required"] is True

        # 2. Configure an OAuth Client ID and inspect `/api/auth/oauth/authorize?format=json`
        client.cookies.clear()  # from here on the identity comes only from the explicit session token header
        assert client.post(
            "/api/auth/oauth/config",
            headers={"X-PQC-User-Token": "forged.token"},
            json={"client_id": "attacker-client.apps.googleusercontent.com"},
        ).status_code == 401
        cfg_res = client.post(
            "/api/auth/oauth/config",
            headers={"X-PQC-User-Token": token},
            json={"client_id": "777888999-test.apps.googleusercontent.com"},
        ).json()
        assert cfg_res["client_id"] == "777888999-test.apps.googleusercontent.com"

        authz_json = client.get(
            "/api/auth/oauth/authorize",
            headers={"X-PQC-User-Token": token},
            params={"format": "json", "scope": "organizations/9988776655"},
        ).json()
        assert authz_json["client_id_configured"] is True
        assert "https://accounts.google.com/o/oauth2/v2/auth" in authz_json["google_auth_url"]
        assert "cloud-platform.read-only" in authz_json["google_auth_url"]

        # 3. Verify PqcOAuth3LOPlugin pauses protected tool execution and calls ToolContext.request_credential
        plugin = PqcOAuth3LOPlugin()
        fake_tool = MagicMock()
        fake_tool.name = "collect_kms_inventory"

        fake_inv_ctx = MagicMock()
        fake_inv_ctx.user_id = "emea.arch@google.com"
        fake_inv_ctx.session.id = "sess-3lo-1"

        fake_tool_ctx = MagicMock()
        fake_tool_ctx._invocation_context = fake_inv_ctx
        fake_tool_ctx.function_call_id = "fc-kms-3lo-001"
        fake_tool_ctx.state = {}

        async def _fake_load_cred(_cfg):
            return None

        async def _fake_save_cred(_cfg):
            return None

        fake_tool_ctx.load_credential = _fake_load_cred
        fake_tool_ctx.save_credential = _fake_save_cred

        cards_bucket = []
        tok_ctx = _TURN_OAUTH_CONSENT_CARDS.set(cards_bucket)
        try:
            gate_result = asyncio.run(
                plugin.before_tool_callback(
                    tool=fake_tool,
                    tool_args={"scope": "organizations/9988776655"},
                    tool_context=fake_tool_ctx,
                )
            )
        finally:
            _TURN_OAUTH_CONSENT_CARDS.reset(tok_ctx)

        assert gate_result is not None
        assert gate_result["status"] == "OAUTH_3LO_CONSENT_REQUIRED"
        assert gate_result["oauth_consent_required"] is True
        assert fake_tool_ctx.request_credential.called
        assert len(cards_bucket) == 1
        assert cards_bucket[0]["tool_name"] == "collect_kms_inventory"
        assert cards_bucket[0]["target_scope"] == "organizations/9988776655"

        # 4. User grants consent via `/api/auth/tool-consent` -> injects token into ADK session & connection
        sess_created = client.post(
            "/api/sessions",
            headers={"X-PQC-User-Token": token},
            json={"title": "EMEA 3LO Session"},
        ).json()
        consent_res = client.post(
            "/api/auth/tool-consent",
            headers={"X-PQC-User-Token": token},
            json={
                "session_id": sess_created["session_id"],
                "access_token": "ya29.emea_delegated_oauth_3lo_token_123456",
                "tool_name": "collect_kms_inventory",
                "target_scope": "organizations/9988776655",
            },
        ).json()
        assert consent_res["status"] == "AUTHORIZED"
        assert consent_res["credential_key"] == GCP_OAUTH_CREDENTIAL_KEY
        assert consent_res["connection"]["has_access_token"] is True
        assert consent_res["connection"]["oauth_consent_required"] is False

        # 5. Now `before_tool_callback` allows the tool to proceed (`None`)
        gate_after_consent = asyncio.run(
            plugin.before_tool_callback(
                tool=fake_tool,
                tool_args={"scope": "organizations/9988776655"},
                tool_context=fake_tool_ctx,
            )
        )
        assert gate_after_consent is None


@pytest.mark.skipif(os.getenv("PQC_LIVE_LLM_TEST") != "1", reason="Set PQC_LIVE_LLM_TEST=1 with Vertex AI access to run.")
def test_live_vertex_gemini_turn_reports_model_telemetry():
    import main

    result = asyncio.run(main.run_adk_agent_turn("In one sentence, what does ML-KEM standardize? Do not call tools."))
    assert result["status"] == "OK", result["error"]
    assert result["served_by"]["models_used"]
    assert result["served_by"]["prompt_tokens"] > 0


def test_all_five_phases_and_connection_modes_through_chat_api(tmp_path, monkeypatch):
    """Verifies P1-P5 phase prompts and all connection_mode FormData fields on POST /api/chat without HTTP 500."""
    from fastapi.testclient import TestClient
    from google.genai import types
    import pqc_agent.workspace_server as ws_mod
    from tools.gcp_inventory import (
        collect_kms_inventory,
        collect_workload_evidence,
        compute_pqc_scorecard,
        discover_all_crypto_assets,
        export_cyclonedx_cbom,
    )
    from tools.pqc_detectors import collect_kms_import_jobs, collect_tls_policies
    from tools.quantum_engine import run_quantum_cryptanalysis_simulation

    monkeypatch.setenv("PQC_DATA_DIR", str(tmp_path / "tenant_store"))
    monkeypatch.setenv("PQC_ALLOW_UNVERIFIED_SIGNIN", "true")

    # 1. Verify all underlying phase tools execute cleanly on DEMO_SCOPE
    kms = json.loads(collect_kms_inventory(DEMO_SCOPE))
    workloads = json.loads(collect_workload_evidence(DEMO_SCOPE))
    tls = json.loads(collect_tls_policies(DEMO_SCOPE))
    imports = json.loads(collect_kms_import_jobs(DEMO_SCOPE))
    assets = json.loads(discover_all_crypto_assets(DEMO_SCOPE))
    scorecard = json.loads(compute_pqc_scorecard(DEMO_SCOPE))
    qsim = json.loads(run_quantum_cryptanalysis_simulation(DEMO_SCOPE))
    cbom = json.loads(export_cyclonedx_cbom(DEMO_SCOPE))
    assert len(kms["keys"]) > 0
    assert len(workloads["workloads"]) > 0
    assert len(tls["ssl_policies"]) > 0
    assert len(imports["import_jobs"]) > 0
    assert assets["scope"] == f"projects/{DEMO_SCOPE}"
    assert "metrics" in scorecard
    assert "illustrative_crqc_scenario_model" in qsim
    assert cbom["bomFormat"] == "CycloneDX"

    # 2. Verify all 5 phases (P1-P5) and connection_mode values ('adc', 'access_token', 'impersonation') via POST /api/chat
    app = _make_app(tmp_path)

    with TestClient(app) as client:
        auth_resp = client.post(
            "/api/auth/google",
            json={"email": "jsaccomani@google.com", "name": "Joabson Saccomani", "region": "LATAM"},
        )
        assert auth_resp.status_code == 200
        assert "token" not in auth_resp.json()
        token = auth_resp.cookies.get("pqc_session_token")
        assert token

        for idx, mode in enumerate(["adc", "access_token", "impersonation", "adc", "access_token"]):
            sess = client.post(
                "/api/sessions",
                headers={"X-PQC-User-Token": token},
                json={"title": f"P{idx + 1} Phase Test", "scope": "organizations/31564119954"},
            ).json()
            res = client.post(
                "/api/chat",
                headers={"X-PQC-User-Token": token},
                data={
                    "message": f"Run Phase P{idx + 1} assessment on organizations/31564119954",
                    "session_id": sess["session_id"],
                    "model_id": "fake-ok-model",
                    "scope": "organizations/31564119954",
                    "connection_mode": mode,
                    "impersonated_sa": "sa@proj.iam.gserviceaccount.com" if mode == "impersonation" else "",
                },
            )
            assert res.status_code == 200, res.text
            body = res.json()
            assert body["status"] == "OK"
            assert f"Run Phase P{idx + 1} assessment" in body["response"]

        # Verify fast cached session listing returns all 5 sessions with accurate message_count
        listed = client.get("/api/sessions", headers={"X-PQC-User-Token": token}).json()
        assert listed["total"] == 5
        assert all(s["message_count"] >= 2 for s in listed["sessions"])


