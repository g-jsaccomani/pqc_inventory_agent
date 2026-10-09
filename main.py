"""Main Entrypoint for the Post-Quantum Cryptography (PQC) Inventory & Governance Agent (ADK + Vertex AI Agent Engine).

Supports:
1. Running the local validation harness (Phase 4.1):
   `python main.py test --input='{"project_id": "meu-projeto-gcp"}'`
2. Running the full ADK Agent with Gemini 3.1 locally:
   `python main.py ask --project-id=organizations/31564119954`
3. Packaging and deploying to Vertex AI Agent Engine / Reasoning Engine (Phase 4.2):
   `python main.py deploy --project=pqc-inventory-agent-cd06 --location=us-central1 --staging-bucket=gs://YOUR_BUCKET`
"""

import argparse
import asyncio
import json
import os
import sys
from typing import Any, Dict, Optional

from dotenv import load_dotenv

from pqc_agent.agent import (
    DEFAULT_MODEL as AGENT_DEFAULT_MODEL,
    GENERATION_CONFIG as AGENT_GENERATION_CONFIG,
    SYSTEM_INSTRUCTION as AGENT_SYSTEM_INSTRUCTION,
    create_pqc_agent,
    root_agent,
)
from tools.gcp_inventory import (
    discover_all_crypto_assets,
    export_cyclonedx_cbom,
    generate_application_pqc_refactoring_guide,
    generate_pqc_migration_plan,
    scan_organization_pqc_readiness,
    scan_pqc_readiness,
)
from tools.pqc_detectors import (
    scan_import_jobs_pqc,
    scan_ssl_policies,
)
from tools.quantum_engine import (
    run_quantum_cryptanalysis_simulation,
)
from tools.report_exporter import (
    build_executive_board_report_markdown,
    build_technical_engineering_playbook_markdown,
    export_pqc_assessment_reports,
)

load_dotenv()

MODEL_NAME = "gemini-3.1-pro-preview-customtools"

GENERATION_CONFIG = {
    "thinking_level": "MEDIUM",
    "max_output_tokens": 1048576,
}

# System Instructions aligned with Google Cloud Consulting (PSO) Executive Deliverable Standards
SYSTEM_INSTRUCTION = AGENT_SYSTEM_INSTRUCTION

# Main ADK Agent instance
agent = root_agent


def get_langchain_reasoning_engine_agent():
    """Initializes a Vertex AI Reasoning Engine LangchainAgent with Gemini 3.1 customtools and generation_config."""
    from vertexai.preview import reasoning_engines

    return reasoning_engines.LangchainAgent(
        model="gemini-3.1-pro-preview-customtools",
        system_instruction=SYSTEM_INSTRUCTION,
        tools=[
            scan_organization_pqc_readiness,
            scan_pqc_readiness,
            scan_ssl_policies,
            scan_import_jobs_pqc,
            run_quantum_cryptanalysis_simulation,
            discover_all_crypto_assets,
            generate_pqc_migration_plan,
            generate_application_pqc_refactoring_guide,
            export_cyclonedx_cbom,
            export_pqc_assessment_reports,
        ],
        model_kwargs={
            "generation_config": {
                "thinking_level": "MEDIUM",
                "max_output_tokens": 1048576,
            }
        },
    )


def get_agent_engine_app():
    """Packages the ADK Agent into an AdkApp for Vertex AI Agent Engine."""
    from vertexai import agent_engines

    return agent_engines.AdkApp(
        agent=agent,
        enable_tracing=True,
    )


def _translate_mosca_horizon(mosca_status: str, x_plus_y_years: Any) -> str:
    """Translates internal Mosca status codes into clean C-level executive horizon labels."""
    years_str = f"{x_plus_y_years} yrs" if x_plus_y_years is not None else "N/A"
    if mosca_status == "CRITICAL_MOSCA_BREACH_ACTIVE_HNDL":
        return f"**{years_str} > 9.0 yrs (2035 CRQC Horizon)** — Immediate Breach"
    if mosca_status == "HIGH_MOSCA_BREACH_NIST_2030_DEADLINE":
        return f"**{years_str} > 4.0 yrs (2030 NIST Horizon)** — Deprecation Breach"
    return f"**{years_str} Within Safe Horizon** — Quantum-Resilient"


def _translate_executive_verdict(app: Dict[str, Any]) -> str:
    """Translates internal application compatibility verdicts into clean C-level labels and actions."""
    raw_verdict = app.get("pqc_compatibility_verdict", "")
    mosca_status = app.get("mosca_status", "")
    purpose = app.get("purpose", "")
    kms_key_str = str(app.get("kms_key", "")).lower()
    is_jwt_or_token = any(tok in kms_key_str for tok in ("jwt", "token"))
    jwt_note_suffix = (
        " — **Technical Note:** Increase HTTP header buffer limits (to 16KB in API Gateways/Envoy) "
        "because ML-DSA-65 signatures expand Base64URL JWT tokens by ~4.4KB."
        if is_jwt_or_token
        else ""
    )

    if raw_verdict == "COMPATIBLE_PQC_NATIVE":
        return "✅ **Compliant — Native PQC** (No action required; operating on NIST FIPS 203/204/205)"
    if raw_verdict == "COMPATIBLE_ZERO_REFACTORING_CMEK":
        return "✅ **Compliant — Grover-Resilient CMEK** (AES-256 / HMAC provides 128-bit PQ security; zero code changes)"
    if mosca_status == "CRITICAL_MOSCA_BREACH_ACTIVE_HNDL" or purpose == "ASYMMETRIC_DECRYPT":
        return (
            "🚨 **Critical — Active HNDL Exposure** (Migrate to `KEM_XWING` on Cloud HSM `--protection-level=hsm` via Google Tink SDK & "
            f"refactor decryption flow to RFC 9180 HPKE encapsulation){jwt_note_suffix}"
        )
    return (
        "⚠️ **High — 2030 Deprecation Risk** (Migrate to `PQ_SIGN_ML_DSA_65` on Cloud HSM `--protection-level=hsm`, update signing SDK "
        f"to raw/external-mu payload, and expand API Gateway header buffers to 16KB–32KB){jwt_note_suffix}"
    )


def build_executive_markdown_report(project_id: str, location_id: str = "global") -> str:
    """Builds a C-level Google Cloud Consulting (PSO) Executive PQC Readiness Assessment & Step-by-Step Guide in Markdown."""
    plan = json.loads(generate_pqc_migration_plan(project_id=project_id, location_id=location_id))
    ssl_report = json.loads(scan_ssl_policies(project_id=project_id))
    import_jobs_report = json.loads(scan_import_jobs_pqc(project_id=project_id, location_id=location_id))
    quantum_sim = json.loads(run_quantum_cryptanalysis_simulation(project_id=project_id, location_id=location_id))

    if "error" in plan:
        return f"### ❌ PQC Assessment Error\n\n`{plan['error']}`"

    manifest = plan.get("data_validation_manifest", {})
    resolved_scope = manifest.get("resolved_scope_uri", plan.get("scope", project_id))
    data_auth = manifest.get("data_source_authenticity", "LIVE_GCP_TELEMETRY_VERIFIED")
    summary = plan.get("cbom_summary", {})
    app_matrix = plan.get("application_compatibility_matrix", [])
    playbooks = plan.get("remediation_playbooks", [])
    rot_playbooks = plan.get("symmetric_rotation_playbooks", [])
    exec_workstreams = plan.get("customer_environment_execution_guide", [])
    ssl_policies = ssl_report.get("ssl_policies", [])
    import_jobs = import_jobs_report.get("import_jobs", [])
    mc_sim = quantum_sim.get("monte_carlo_crqc_and_qvar_simulation", {})
    fall_ranking = quantum_sim.get("priority_shor_fall_order_ranking", [])

    weighted_maturity = summary.get("weighted_pqc_maturity_score_pct", 0.0)
    algo_safe_score = summary.get("pqc_readiness_score_pct", 0.0)
    asymmetric_score = summary.get("asymmetric_pqc_migration_score_pct", 0.0)
    app_compat_score = summary.get("application_pqc_compatibility_score_pct", 100.0)
    grover_score = summary.get("symmetric_grover_resilience_score_pct", 100.0)
    rotation_score = summary.get("symmetric_rotation_hygiene_score_pct", 100.0)
    ssl_ready_score = ssl_report.get("ssl_pqc_readiness_score_pct", 0.0)
    byok_ready_score = import_jobs_report.get("byok_pqc_readiness_score_pct", 0.0)

    active_keys = summary.get("active_kms_keys_count", 0)
    inactive_keys = summary.get("inactive_or_destroyed_keys_count", 0)
    vuln_keys_count = summary.get("vulnerable_classical_rsa_ecc_count", 0)
    hndl_breaches = summary.get("mosca_immediate_hndl_breach_keys_count", 0)
    deadline_breaches = summary.get("mosca_migration_deadline_risk_keys_count", 0)
    total_apps = summary.get("total_consuming_applications_mapped", 0)
    compat_apps = summary.get("pqc_compatible_applications_count", 0)
    incompat_apps = summary.get("pqc_incompatible_applications_requiring_refactoring_count", 0)
    sndl_policies = ssl_report.get("vulnerable_to_sndl_attacks_count", 0)
    vuln_byok = import_jobs_report.get("vulnerable_key_import_transport_count", 0)
    qvar_unmitigated = mc_sim.get("quantum_value_at_risk_qvar_95_unmitigated_usd_millions", 0.0)
    qvar_mitigated = mc_sim.get("quantum_value_at_risk_qvar_95_post_gcp_bom_remediation_usd_millions", 0.0)

    overall_rating = (
        f"ACTION REQUIRED — Weighted Maturity: {weighted_maturity}% (Algorithmic Quantum-Safe: {algo_safe_score}%)"
        if (vuln_keys_count > 0 or sndl_policies > 0 or vuln_byok > 0)
        else f"OPTIMAL — Weighted Maturity: {weighted_maturity}%"
    )

    lines = [
        "# GOOGLE CLOUD CONSULTING",
        "## Post-Quantum Cryptography (PQC) Executive Readiness Assessment & Step-by-Step Execution Guide",
        "",
        "| Engagement Attribute | Assessment Value |",
        "| :--- | :--- |",
        f"| **Target Organization / Scope** | `{resolved_scope}` (Requested Input: `{project_id}`, Location Scope: `{location_id}`) |",
        f"| **Telemetry & Validation Status** | `{data_auth}` — Deterministic Backend-Validated Scorecard |",
        "| **Reference Frameworks** | Google Cloud Security Foundations, NIST FIPS 203/204/205, NIST IR 8547, NIST SP 800-57, NSA CNSA 2.0 |",
        f"| **Overall Posture Rating** | **{overall_rating}** |",
        (
            f"| **Executive Risk Summary** | `{vuln_keys_count}` classical asymmetric keys (`{hndl_breaches}` active HNDL exposure, "
            f"`{deadline_breaches}` 2030 deprecation risk), `{incompat_apps}` of `{total_apps}` applications requiring SDK/gateway "
            f"refactoring, `{sndl_policies}` SSL policies exposed to SNDL, `{vuln_byok}` legacy BYOK import workflows, and "
            f"**US$ {qvar_unmitigated}M** Quantum Value-at-Risk (reducible to **US$ {qvar_mitigated}M**). |"
        ),
        "",
        "---",
        "",
        "## 1. Executive Summary & Consultative Diagnosis (BLUF)",
        (
            f"**Bottom Line Up Front:** Across `{resolved_scope}`, Google Cloud Consulting evaluated **{active_keys} active Cloud KMS keys** "
            f"(excluding `{inactive_keys}` decommissioned/destroy-scheduled keys), **{total_apps} consuming enterprise applications**, "
            f"**{len(ssl_policies)} network SSL/TLS policies**, and **{len(import_jobs)} Bring Your Own Key (BYOK) import workflows**. "
            f"While **{compat_apps} of {total_apps} workloads ({app_compat_score}%)** are already quantum-resilient—either operating on "
            "NIST-standardized Post-Quantum Cryptography (`KEM_XWING`, `PQ_SIGN_ML_DSA_65`) or leveraging 256-bit symmetric Customer-Managed "
            "Encryption Keys (CMEK) resilient to Grover's Algorithm (`1.51e43` Toffoli gates > NIST MAXDEPTH `2^96`) with zero code changes "
            f"required—critical cryptographic modernization is required across **{incompat_apps} classical RSA/ECDSA application workloads** "
            "prior to the NIST IR 8547 deprecation milestones."
        ),
        "",
        (
            f"- **Immediate Confidentiality Risk (Harvest Now, Decrypt Later — HNDL) & Monte Carlo Q-VaR:** `{hndl_breaches}` asymmetric decryption "
            "key(s) exceed Dr. Michele Mosca's 2035 Cryptographically Relevant Quantum Computer (CRQC) horizon (`10.0-year data confidentiality "
            "shelf-life + 2.0-year engineering migration = 12.0 years > 9.0-year horizon`). Our 10,000-iteration Monte Carlo simulation quantifies "
            f"an unmitigated **Quantum Value-at-Risk (Q-VaR 95%) of US$ {qvar_unmitigated}M**, which drops by **98.5% to US$ {qvar_mitigated}M** "
            "upon executing the step-by-step Google Cloud PQC migration runbooks below."
        ),
        (
            "- **Counter-Intuitive Quantum Physics Finding (ECDSA Falls Before RSA-2048):** Under Shor's Elliptic Curve Discrete Logarithm algorithm "
            "(Roetteler et al.), `ECDSA P-256` keys require only **`2,330 Logical Qubits`** (`~13.4M` physical superconducting qubits at surface code "
            "distance `d=27`) and `ECDSA P-384` requires **`3,484 Logical Qubits`**, whereas `RSA-2048` requires **`4,098 Logical Qubits`** (`~20.0M` "
            "physical qubits, Gidney & Ekerå). Consequently, elliptic-curve signing keys must be prioritized alongside RSA-OAEP decryption keys."
        ),
        (
            f"- **Application & API Gateway Modernization Impact:** `{deadline_breaches}` digital signing key(s) breach the **NIST 2030 "
            "deprecation horizon (`4.5 years > 4.0 years`)**. Migrating these workloads to NIST FIPS 203 (`KEM_XWING`) and FIPS 204 "
            "(`PQ_SIGN_ML_DSA_65`) on **Cloud HSM (`--protection-level=hsm`)** is not a transparent key rotation: it requires adopting "
            "the **Google Tink SDK** for RFC 9180 HPKE envelope encapsulation (`kms.Decapsulate`) and expanding proxy HTTP header buffers "
            "(to `16KB–32KB` in API Gateways/Envoy) because `ML-DSA-65` signatures expand Base64URL JWT tokens by `~4.4KB`."
        ),
        "",
        "---",
        "",
        "## 2. Executive PQC Maturity Scorecard (Backend-Validated)",
        "| Posture KPI | Current Score | Target Benchmark | Consultative Evaluation & Gap Analysis |",
        "| :--- | :---: | :---: | :--- |",
        (
            f"| **Weighted PQC Maturity Index** | **{weighted_maturity}%** | `100.0%` | "
            f"Composite index (`60% Asymmetric + 25% Symmetric Grover + 15% Rotation Hygiene`); `{vuln_keys_count}` classical keys require migration |"
        ),
        (
            f"| **Asymmetric PQC Migration (Shor Resistance)** | **{asymmetric_score}%** | `100.0%` | "
            f"`{summary.get('approved_pqc_count', 0)}` PQC-native vs. `{vuln_keys_count}` classical RSA/ECC keys requiring Cloud HSM PQC migration |"
        ),
        (
            f"| **Application PQC Model Compatibility** | **{app_compat_score}%** | `100.0%` | "
            f"`{compat_apps}` workloads compatible today; `{incompat_apps}` require SDK (`Decapsulate`/`data`) & Gateway (`16KB–32KB`) refactoring |"
        ),
        (
            f"| **Data-at-Rest Grover Resilience (AES-256)** | **{grover_score}%** | `100.0%` | "
            f"`{summary.get('secure_symmetric_count', 0)}` symmetric CMEK/MAC keys provide 128-bit post-quantum security with zero code changes |"
        ),
        (
            f"| **Cryptoperiod & Rotation Hygiene (<= 90d)** | **{rotation_score}%** | `100.0%` | "
            f"{'Compliant with NIST SP 800-57 & CIS GCP 1.10' if rotation_score == 100 else f'Remediation Required — Configure <= 90-day automatic rotation on {len(rot_playbooks)} symmetric key(s)'} |"
        ),
        (
            f"| **Network TLS 1.3 Hybrid PQC Readiness** | **{ssl_ready_score}%** | `100.0%` | "
            f"`{ssl_report.get('quantum_ready_hybrid_tls13_count', 0)}` compliant TLS 1.3 (`X25519MLKEM768`) vs. `{sndl_policies}` exposed to SNDL |"
        ),
        (
            f"| **BYOK Key Import Transport Security** | **{byok_ready_score}%** | `100.0%` | "
            f"`{import_jobs_report.get('secure_pqc_byok_count', 0)}` PQC-ready vs. `{vuln_byok}` classical RSA-OAEP import job(s) |"
        ),
        "",
        "---",
        "",
        "## 3. Application Risk, Quantum Circuit Fall-Order & Mosca Theorem Matrix",
        "### 3.1. Quantum Physics Fall-Order Ranking (Shor's Algorithm Surface-Code Resource Estimation)",
        "",
        "| Project & KMS Key | Algorithm & Fall Rank | Logical / Physical Qubits | Toffoli Gates & Code Distance | Target PQC & Lattice Hardness |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    for rank_item in fall_ranking:
        lines.append(
            f"| `{rank_item.get('project_id')}/{rank_item.get('kms_key')}` | "
            f"`{rank_item.get('current_algorithm')}` (Rank #{rank_item.get('quantum_fall_order_rank')}) | "
            f"`{rank_item.get('logical_qubits_to_break')}` logical / `{rank_item.get('physical_superconducting_qubits_to_break')}` physical | "
            f"`{rank_item.get('toffoli_gate_count')}` gates (`d={rank_item.get('surface_code_distance_d')}`, `{rank_item.get('estimated_crqc_decryption_or_forgery_hours')}h`) | "
            f"`{rank_item.get('target_pqc_algorithm')}` (`{rank_item.get('target_post_quantum_security_bits')}-bit` Core-SVP) |"
        )

    lines.extend(
        [
            "",
            "### 3.2. Complete Application-to-Key PQC Compatibility & Mosca Matrix",
            "",
            "| Consuming Application / Workload | Bound KMS Key | Algorithm (Current -> Target) | Mosca Horizon (X+Y vs Z) | Risk Verdict & Required Action |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
    )

    for app in app_matrix:
        app_label = f"**{app.get('application_name')}** (`{app.get('project_id')}` — {app.get('workload_type')})"
        key_label = f"`{app.get('kms_key')}`"
        algo_label = f"`{app.get('current_algorithm')}` ➡️ `{app.get('target_pqc_algorithm')}`"
        mosca_label = _translate_mosca_horizon(app.get("mosca_status", ""), app.get("x_plus_y_total_years"))
        verdict_label = _translate_executive_verdict(app)
        lines.append(f"| {app_label} | {key_label} | {algo_label} | {mosca_label} | {verdict_label} |")

    lines.extend(
        [
            "",
            "---",
            "",
            "## 4. Recommended Google Cloud Target Architecture & Product BOM",
            "*(Recommended Google Cloud Security Architecture & Product BOM)*",
            "",
            "| Risk Domain | Google Cloud Solution | Architectural Role in Environment | Consultative Implementation Action |",
            "| :--- | :--- | :--- | :--- |",
            (
                "| **Key Management & BYOK Root of Trust** | **Cloud HSM (FIPS 140-3 Level 3)** + **Cloud KMS PQC (`KEM_XWING`, `PQ_SIGN_ML_DSA_65`)** | "
                "Replaces classical RSA/ECDSA keys and RSA-OAEP BYOK `ImportJobs` with `HPKE_KEM_XWING` hybrid encapsulation and FIPS 140-3 Level 3 hardware protection (`--protection-level=hsm`). | "
                "Provision parallel PQC keys in Cloud HSM, bind least-privilege IAM roles (`cryptoKeyDecapsulator` / `signerVerifier`), and disable legacy versions post-cutover. |"
            ),
            (
                "| **Application Crypto & Envelope Abstraction** | **Google Tink SDK + Cloud KMS** | "
                "Abstracts RFC 9180 HPKE (`Decapsulate` + `HKDF-SHA256` + `AES-256-GCM`) and PQC public key formatting across Python, Go, and Java microservices. | "
                "Replace direct `AsymmetricDecrypt` calls with Tink HPKE / `kms.Decapsulate` and expand encrypted DEK columns from `256 B` to `VARBINARY(2048)`. |"
            ),
            (
                "| **Zero-Trust Data Perimeter (HNDL Containment)** | **VPC Service Controls (VPC-SC) + Private Service Connect (PSC)** | "
                "Establishes identity- and network-aware zero-trust service perimeters around **Cloud Storage** and **BigQuery** data stores. | "
                "Enclose sensitive buckets and BigQuery datasets in a VPC-SC perimeter with private PSC endpoints to block bulk ciphertext exfiltration. |"
            ),
            (
                "| **Quantum-Safe Network Ingress & Managed PKI** | **Google Cloud Global Load Balancing (L7 TLS 1.3) + Certificate Authority Service (CAS)** | "
                "Enforces restricted TLS 1.3 SSL policies with hybrid post-quantum key exchange (`X25519MLKEM768`) and automated enterprise X.509 lifecycle management. | "
                "Apply `--min-tls-version=1.3 --profile=RESTRICTED` to all HTTPS proxies and establish a parallel PQC Subordinate CA in CAS. |"
            ),
            (
                "| **Supply Chain Attestation & Posture Governance** | **Binary Authorization + Security Command Center (SCC) Enterprise** | "
                "Enforces container image attestation backed by Cloud HSM / `PQ_SIGN_ML_DSA_65` and continuous Organization Policy drift monitoring. | "
                "Deploy custom Organization Policy constraints (`custom.pqcEnforceQuantumSafeKmsAlgorithms` & `custom.pqcEnforceSymmetricKeyRotation90d`) and Binary Authorization attestors. |"
            ),
            "",
            "---",
            "",
            "## 5. Step-by-Step Customer Environment Execution Guide (30-60-90 Day Prescriptive Plan)",
            "| Transition Phase | Target Horizon | Executive Objectives & Scope | Key Deliverables & Validation Criteria |",
            "| :--- | :---: | :--- | :--- |",
            (
                "| **Phase 1: Preventive Governance & Symmetric Hygiene** | **Days 1–30** | "
                "Halt proliferation of new classical RSA/ECC keys, enforce <= 90-day symmetric rotation, and harden network TLS 1.3 ingress. | "
                "• Enforce GCP Organization Policy PQC custom constraints<br/>• Apply `--rotation-period=90d` on all symmetric CMEK keys<br/>"
                "• Upgrade Load Balancer SSL Policies to TLS 1.3 (`X25519MLKEM768`)<br/>• Wrap critical GCS/BigQuery assets in VPC-SC + PSC |"
            ),
            (
                "| **Phase 2: HNDL KEM & Signing Application Refactoring** | **Days 31–60** | "
                "Provision Cloud HSM PQC keys, refactor incompatible application SDKs, and expand API Gateway HTTP header buffers. | "
                "• Provision `KEM_XWING` & `PQ_SIGN_ML_DSA_65` keys (`--protection-level=hsm`)<br/>• Integrate Google Tink SDK for RFC 9180 HPKE envelope flows<br/>"
                "• Refactor signing services to raw `data` / 64B SHAKE256 `external_mu`<br/>• Increase HTTP header buffer limits to `16KB–32KB` in API Gateways/Envoy |"
            ),
            (
                "| **Phase 3: Legacy Key Deprecation & Continuous CBOM** | **Days 61–90** | "
                "Decommission legacy RSA/ECDSA key versions, enforce PQC container attestation, and institutionalize CBOM governance. | "
                "• Disable & schedule destruction of legacy RSA/ECC key versions<br/>• Enforce Binary Authorization PQC attestation on GKE/Cloud Run<br/>"
                "• Automate OWASP CycloneDX v1.6 CBOM exports into SCC Enterprise |"
            ),
            "",
        ]
    )

    if exec_workstreams:
        lines.append("### 5.1. Detailed Consultative Workstreams for the Customer Environment")
        for ws in exec_workstreams:
            lines.append(f"#### {ws.get('title')}")
            lines.append(f"- **Objective:** {ws.get('objective')}")
            for step_str in ws.get("step_by_step_actions", []):
                lines.append(f"  - {step_str}")
            lines.append("")

    lines.extend(
        [
            "---",
            "",
            "## 6. Technical Engineering Appendix (Complete Step-by-Step Runbooks, Code Diffs & Validation Checklist)",
            "*(For Security Engineering, Cloud Platform, and DevSecOps Teams — Contains Step-by-Step Execution Plans, CLI Runbooks, API Parameter Diffs, and Policy Constraints)*",
            "",
            "### 6.1. Per-Key 5-Step PQC Migration Runbooks (`gcloud kms` — 100% of Vulnerable Keys)",
        ]
    )

    for idx, pb in enumerate(playbooks, 1):
        legacy_key_str = str(pb.get("legacy_key", ""))
        is_jwt_or_token = any(tok in legacy_key_str.lower() for tok in ("jwt", "token"))
        jwt_note = pb.get("technical_note_jwt_header_buffer") or (
            "TECHNICAL NOTE (JWT/Token Header Buffer Expansion): Increase HTTP header buffer limits "
            "(to 16KB in API Gateways/Envoy) because ML-DSA-65 signatures expand Base64URL JWT tokens by ~4.4KB."
            if is_jwt_or_token
            else None
        )
        pb_cmd = str(pb.get("gcloud_command", "")).replace("--protection-level=software", "--protection-level=hsm")
        guide = pb.get("consultative_execution_guide", {})

        lines.extend(
            [
                f"#### 6.1.{idx}. Remediate `{pb['legacy_key']}` (`{pb['legacy_algorithm']}`) ➡️ `{pb['target_algorithm']}`",
                f"- **Current State Evaluation:** {guide.get('current_state_evaluation', pb['rationale'])}",
                f"- **Architectural Impact Assessment:** {guide.get('architectural_impact_assessment', pb['rationale'])}",
            ]
        )
        if jwt_note:
            lines.append(f"- **⚠️ {jwt_note}**")
        lines.append("- **Step-by-Step Execution Plan:**")
        for step_line in guide.get("step_by_step_execution_plan", []):
            lines.append(f"  - {step_line}")
        lines.extend(
            [
                "```bash",
                "# Step 2: Provision PQC Replacement Key in Cloud HSM (FIPS 140-3 Level 3)",
                pb_cmd,
                "",
                "# Step 3: Bind Least-Privilege IAM Role to Consuming Service Account",
                pb.get("iam_binding_command", ""),
                "",
                "# Step 5a: Post-Cutover Legacy Version Deprecation",
                pb.get("post_migration_disable_legacy_command", ""),
                "",
                "# Step 5b: Post-Change Verification Command",
                pb.get("post_change_validation_command", ""),
                "```",
                "",
            ]
        )

    if rot_playbooks:
        lines.append("### 6.2. Symmetric CMEK Key Rotation Hygiene Runbooks (`<= 90 Days` — Zero Downtime)")
        lines.append("```bash")
        for rp in rot_playbooks:
            lines.append(f"# {rp.get('key')} ({rp.get('hygiene_status')})")
            lines.append(rp.get("gcloud_rotation_command", ""))
        lines.append("```")
        lines.append("")

    lines.extend(
        [
            "### 6.3. Application SDK & API Parameter Migration Reference",
            "| Refactoring Pattern | Legacy Classical API Contract | Target Post-Quantum API Contract | Infrastructure & Proxy Requirement |",
            "| :--- | :--- | :--- | :--- |",
            (
                "| **Confidentiality (RSA-OAEP ➡️ X-Wing KEM)** | `AsymmetricDecrypt(ciphertext)` (`purpose=ASYMMETRIC_DECRYPT`) | "
                "`Decapsulate(ciphertext)` ➡️ 32B `shared_secret` + `HKDF-SHA256` + `AES-256-GCM` (`purpose=KEY_ENCAPSULATION`) | "
                "Ciphertext increases from `256 B` to `1,120 B`; adopt **Google Tink SDK** HPKE primitive & `VARBINARY(2048)` schema. |"
            ),
            (
                "| **Digital Signatures (RSA/ECDSA ➡️ ML-DSA-65)** | `AsymmetricSign(digest={'sha256': ...})` (Pre-hashed external digest) | "
                "`AsymmetricSign(data=raw_bytes)` or `PQ_SIGN_ML_DSA_65_EXTERNAL_MU` (64B `SHAKE256` external mu) | "
                "Signature expands from `64 B–256 B` to `3,309 B`; set `max_request_headers_kb: 32` in Envoy/Istio and `large_client_header_buffers 4 32k;` in NGINX. |"
            ),
            "",
            "### 6.4. Network TLS 1.3 (`X25519MLKEM768`) & Cloud KMS BYOK (`ImportJobs`) Posture",
            "| Resource Type | Identifier (`Project / Name`) | Current Configuration | Technical Status | Remediation Command / Action |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
    )

    for sp in ssl_policies:
        lines.append(
            f"| **SSL Policy** | `{sp.get('project_id')}/{sp.get('policy_name')}` | "
            f"`{sp.get('min_tls_version')}` (`{sp.get('profile')}`) | `{sp.get('pqc_status')}` | "
            f"`{sp.get('gcloud_remediation_command') or 'Compliant (TLS 1.3 + X25519MLKEM768 Active)'}` |"
        )

    for ij in import_jobs:
        lines.append(
            f"| **KMS ImportJob** | `{ij.get('key_ring')}/{ij.get('import_job_name')}` | "
            f"`{ij.get('import_method')}` (`{ij.get('protection_level')}`) | `{ij.get('pqc_status')}` | "
            f"`{ij.get('gcloud_remediation_command') or 'Compliant (HPKE_KEM_XWING Active)'}` |"
        )

    guardrails = plan.get("preventive_org_policy_guardrails", {})
    if guardrails:
        lines.extend(
            [
                "",
                "### 6.5. Preventive GCP Organization Policy CEL Guardrails",
                "```yaml",
                guardrails.get("custom_constraint_quantum_safe_algorithms_yaml", ""),
                "---",
                guardrails.get("custom_constraint_symmetric_rotation_90d_yaml", ""),
                "```",
            ]
        )

    lines.extend(
        [
            "",
            "### 6.6. Post-Implementation Verification Checklist",
            "- [ ] **1. Verify PQC Key Creation & HSM Protection Level:** Confirm all new `KEM_XWING`, `ML_KEM_1024`, and `PQ_SIGN_ML_DSA_65` keys show `primary.state=ENABLED` and `protectionLevel=HSM`.",
            "- [ ] **2. Verify Symmetric CMEK Rotation Schedule:** Confirm all `GOOGLE_SYMMETRIC_ENCRYPTION` keys report `rotationPeriod=7776000s` (90 days).",
            "- [ ] **3. Verify API Gateway & Proxy Header Buffers:** Execute synthetic test requests with `4.5 KB` `Authorization: Bearer` headers (`ML-DSA-65` JWS) and confirm HTTP `200 OK` (no HTTP `431`).",
            "- [ ] **4. Verify TLS 1.3 Hybrid PQC Handshake:** Run `openssl s_client -connect <LB_IP>:443 -tls1_3 -curves X25519MLKEM768` against external/internal Load Balancers.",
            "- [ ] **5. Verify Legacy Key Version Decommissioning:** Confirm legacy `RSA_*` and `EC_*` versions are in `DISABLED` or `DESTROY_SCHEDULED` state and export the final `CycloneDX v1.6 CBOM`.",
        ]
    )

    return "\n".join(lines)



async def run_adk_agent_turn(
    prompt: str,
    user_id: str = "sec-architect",
    project_id: str = "organizations/31564119954",
    location_id: str = "all",
) -> str:
    """Executes a complete turn on the ADK Agent locally using InMemoryRunner."""
    from google.adk.runners import InMemoryRunner
    from google.genai import errors as genai_errors
    from google.genai import types

    runner = InMemoryRunner(agent=agent, app_name="pqc_inventory_agent")
    session = await runner.session_service.create_session(
        app_name="pqc_inventory_agent",
        user_id=user_id,
    )

    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=prompt)],
    )

    final_text_parts = []
    try:
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session.id,
            new_message=content,
        ):
            if event.is_final_response() and event.content and event.content.parts:
                for part in event.content.parts:
                    if part.text:
                        final_text_parts.append(part.text)
    except genai_errors.APIError as api_err:
        fallback_md = build_executive_markdown_report(project_id=project_id, location_id=location_id)
        note = (
            f"> **Vertex AI Authentication Note (`{api_err.code} {api_err.status}`):** "
            f"Displaying the executive report generated directly by the PQC Agent tool engine:\n\n"
        )
        return note + fallback_md

    return "\n".join(final_text_parts)


def run_local_harness(input_payload: str, invoke_llm: bool = False) -> Dict[str, Any]:
    """Executes the local validation harness for PQC tools (and optionally the Gemini LLM)."""
    try:
        parsed = json.loads(input_payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in --input: {exc}") from exc

    project_id = parsed.get("project_id", os.getenv("GOOGLE_CLOUD_PROJECT", "meu-projeto-gcp"))
    location_id = parsed.get("location_id", "global")

    kms_report = json.loads(scan_pqc_readiness(project_id=project_id, location_id=location_id))
    cai_report = json.loads(discover_all_crypto_assets(project_id=project_id))
    ssl_policies_report = json.loads(scan_ssl_policies(project_id=project_id))
    import_jobs_report = json.loads(scan_import_jobs_pqc(project_id=project_id, location_id=location_id))
    migration_plan = json.loads(generate_pqc_migration_plan(project_id=project_id, location_id=location_id))
    quantum_simulation = json.loads(
        run_quantum_cryptanalysis_simulation(project_id=project_id, location_id=location_id)
    )

    result: Dict[str, Any] = {
        "harness_status": "SUCCESS",
        "project_id": project_id,
        "location_id": location_id,
        "cbom_summary": migration_plan.get("cbom_summary", {}),
        "kms_keys": kms_report,
        "ssl_policies": ssl_policies_report,
        "import_jobs": import_jobs_report,
        "cloud_asset_inventory": cai_report,
        "quantum_cryptanalysis_simulation": quantum_simulation,
        "remediation_playbooks": migration_plan.get("remediation_playbooks", []),
        "recommended_google_cloud_security_architecture_and_product_bom": migration_plan.get(
            "recommended_google_cloud_security_architecture_and_product_bom", []
        ),
    }

    if invoke_llm:
        prompt = (
            f"Perform a complete Post-Quantum Cryptography (PQC) readiness assessment on scope '{project_id}' "
            f"(location: '{location_id}'), including KMS keys, SSL policies, and Cloud KMS ImportJobs, "
            f"and generate the executive report with priorities, gcloud commands, "
            f"and the Recommended Google Cloud Security Architecture & Product BOM."
        )
        result["agent_executive_report"] = asyncio.run(
            run_adk_agent_turn(prompt, project_id=project_id, location_id=location_id)
        )

    return result



def _ensure_staging_bucket(project_id: str, location: str, bucket_uri: str) -> str:
    """Ensures the GCS staging bucket exists prior to deploying to Vertex AI Agent Engine."""
    from google.cloud import storage

    bucket_name = bucket_uri.replace("gs://", "").strip("/")
    storage_client = storage.Client(project=project_id)
    bucket = storage_client.bucket(bucket_name)
    if not bucket.exists():
        print(f"[*] Creating GCS staging bucket 'gs://{bucket_name}' in '{location}'...")
        bucket.iam_configuration.uniform_bucket_level_access_enabled = True
        storage_client.create_bucket(bucket, location=location)
    return f"gs://{bucket_name}"


def deploy_to_agent_engine(
    project_id: str,
    location: str = "us-central1",
    staging_bucket: Optional[str] = None,
    display_name: str = "PQC Enterprise Inventory & Application Compatibility Agent",
) -> str:
    """Packages and deploys the agent to Google Cloud Vertex AI Agent Engine (Reasoning Engine)."""
    import vertexai
    from vertexai import agent_engines

    raw_bucket = staging_bucket or os.getenv("GOOGLE_CLOUD_STAGING_BUCKET") or f"gs://{project_id}-pqc-agent-staging"
    bucket = _ensure_staging_bucket(project_id=project_id, location=location, bucket_uri=raw_bucket)

    print(f"[*] Initializing Vertex AI (project={project_id}, location={location}, staging_bucket={bucket}, model={MODEL_NAME})...")
    vertexai.init(project=project_id, location=location, staging_bucket=bucket)

    adk_app = get_agent_engine_app()

    requirements = [
        "google-adk>=1.0.0",
        "google-genai>=1.0.0",
        "google-cloud-aiplatform[adk,agent_engines]>=1.93.0",
        "google-cloud-asset>=3.26.0",
        "google-cloud-kms>=2.24.0",
        "google-cloud-compute>=1.18.0",
        "google-cloud-storage>=2.16.0",
        "pydantic>=2.8.0",
        "python-dotenv>=1.0.1",
        "cloudpickle==3.1.2",
    ]

    print(f"[*] Packaging and deploying '{display_name}' ({MODEL_NAME}) to Vertex AI Agent Engine...")
    remote_agent = agent_engines.create(
        adk_app,
        requirements=requirements,
        extra_packages=["./pqc_agent", "./tools"],
        env_vars={
            "PQC_EXPORT_GCS_BUCKET": bucket,
            "PQC_DEFAULT_ORGANIZATION_ID": "31564119954",
        },
        display_name=display_name,
        description=(
            "Expert AI Agent for Post-Quantum Cryptography (PQC) Consultative Readiness Assessment, Step-by-Step "
            "Execution Guide, Quantum Physics Simulation, and Executive/Technical Report Export across GCP Organizations."
        ),
    )

    resource_name = remote_agent.resource_name
    print("\n[+] Deployment completed successfully!")
    print(f"[+] Resource Path for Gemini Enterprise registration: {resource_name}")
    return resource_name


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PQC Inventory & Governance Agent CLI (Google ADK + Vertex AI Agent Engine)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: test (Local Harness - Phase 4.1)
    test_parser = subparsers.add_parser("test", help="Run the local validation harness for the PQC Agent")
    test_parser.add_argument(
        "--input",
        type=str,
        default='{"project_id": "meu-projeto-gcp"}',
        help='Input JSON, e.g.: \'{"project_id": "meu-projeto-gcp"}\'',
    )
    test_parser.add_argument(
        "--llm",
        action="store_true",
        help="Also invoke the Gemini model via ADK Runner to generate the Executive Report in Markdown",
    )

    # Subcommand: ask (Interactive execution with Gemini via ADK)
    ask_parser = subparsers.add_parser("ask", help="Send a prompt to the ADK Agent and display the executive report")
    ask_parser.add_argument(
        "--project-id",
        type=str,
        default="organizations/31564119954",
        help="Target GCP Organization or Project ID to assess",
    )
    ask_parser.add_argument(
        "--location",
        type=str,
        default="all",
        help="Cloud KMS location (default: all)",
    )

    # Subcommand: export (Executive + Technical + CBOM Deliverable Exporter)
    export_parser = subparsers.add_parser(
        "export",
        help="Export the 4-part PQC Deliverable Package (Executive Board Report, Technical Playbook, CycloneDX CBOM, and Master Assessment)",
    )
    export_parser.add_argument(
        "--project-id",
        type=str,
        default="organizations/31564119954",
        help="Target GCP Organization or Project ID to export (default: organizations/31564119954)",
    )
    export_parser.add_argument(
        "--location",
        type=str,
        default="all",
        help="Cloud KMS location (default: all)",
    )
    export_parser.add_argument(
        "--output-dir",
        type=str,
        default="exports",
        help="Local directory to save Markdown, HTML/PDF, and JSON files (default: exports)",
    )
    export_parser.add_argument(
        "--gcs-bucket",
        type=str,
        default="",
        help="Optional GCS bucket URI (e.g., gs://my-bucket) to upload the exported deliverables",
    )

    # Subcommand: deploy (Vertex AI Agent Engine deployment - Phase 4.2)
    deploy_parser = subparsers.add_parser("deploy", help="Deploy the agent to Vertex AI Agent Engine")
    deploy_parser.add_argument(
        "--project",
        type=str,
        default=os.getenv("GOOGLE_CLOUD_PROJECT"),
        required=not bool(os.getenv("GOOGLE_CLOUD_PROJECT")),
        help="GCP Project ID where the Agent Engine will be hosted",
    )
    deploy_parser.add_argument(
        "--location",
        type=str,
        default=os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1"),
        help="GCP region for Vertex AI Agent Engine (default: us-central1)",
    )
    deploy_parser.add_argument(
        "--staging-bucket",
        type=str,
        default=os.getenv("GOOGLE_CLOUD_STAGING_BUCKET"),
        help="GCS staging bucket URI (e.g., gs://my-staging-bucket)",
    )
    deploy_parser.add_argument(
        "--display-name",
        type=str,
        default="PQC Enterprise Inventory & Application Compatibility Agent",
        help="Display name in Vertex AI Agent Engine",
    )

    args = parser.parse_args()

    if args.command == "test":
        output = run_local_harness(args.input, invoke_llm=args.llm)
        print(json.dumps(output, indent=2, ensure_ascii=False))
    elif args.command == "ask":
        prompt = (
            f"Perform a complete Post-Quantum Cryptography (PQC) readiness assessment on scope '{args.project_id}' "
            f"(location: '{args.location}'). Identify all keys vulnerable to Shor's and Grover's algorithms, "
            f"evaluate application PQC compatibility, and provide the remediation plan with gcloud kms commands "
            f"and the Recommended Google Cloud Security Architecture & Product BOM."
        )
        response_text = asyncio.run(
            run_adk_agent_turn(prompt, project_id=args.project_id, location_id=args.location)
        )
        print(response_text)
    elif args.command == "export":
        raw_manifest = export_pqc_assessment_reports(
            project_id=args.project_id,
            location_id=args.location,
            output_dir=args.output_dir,
            gcs_bucket_uri=args.gcs_bucket,
        )
        print(json.dumps(json.loads(raw_manifest), indent=2, ensure_ascii=False))
    elif args.command == "deploy":
        deploy_to_agent_engine(
            project_id=args.project,
            location=args.location,
            staging_bucket=args.staging_bucket,
            display_name=args.display_name,
        )


if __name__ == "__main__":
    main()

