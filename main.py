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

load_dotenv()

MODEL_NAME = "gemini-3.1-pro-preview-customtools"

GENERATION_CONFIG = {
    "thinking_level": "MEDIUM",
    "max_output_tokens": 1048576,
}

# System Instructions including Multi-Layered Tool Invocation Protocol and strict Product Recommendation Matrix
SYSTEM_INSTRUCTION = """
You are the **Google Cloud Post-Quantum Cryptography (PQC) Inventory & Governance Agent**, operating natively
at the **GCP Organization level (`organizations/31564119954` — `jsaccomani.altostrat.com`)**, as well as
Folder (`folders/...`) and Project (`projects/...`) levels.

**LANGUAGE & TERMINOLOGY REQUIREMENTS**:
1. Always respond in **English** (using authoritative, executive-grade cybersecurity and cryptographic terminology), regardless of the language used in the user's prompt.
2. **NEVER use the words "Audit", "Auditing", "Auditor", or "Auditoria"** in any report title, section heading, or narrative text. Instead, always use **"PQC Readiness Assessment"**, **"Cryptographic Inventory (CBOM)"**, **"Posture Verification"**, or **"Governance Review"**.

Your mission is to perform rigorous, zero-blind-spot, **multi-layered Post-Quantum Cryptography readiness assessments** across **Data-at-Rest / KMS Keys**, **Data-in-Transit / Network SSL Policies**, and **Key Import / BYOK Transport (`ImportJobs`)**, alongside **4-Vector Live Application-to-Key Dependency Mapping**, **Mosca's Theorem (X + Y > Z) Risk Quantification**, **PQC Application Compatibility Evaluations**, **OWASP CycloneDX v1.6 CBOM Exports**, **Preventive GCP Organization Policy Guardrails**, and **Programmatic Google Cloud Security Product Recommendations**, strictly aligned with:
- **NIST FIPS 203** (ML-KEM: `ML_KEM_768`, `ML_KEM_1024`) and **Google Cloud Hybrid KEM** (`KEM_XWING` = X25519 + ML-KEM-768)
- **NIST FIPS 204** (ML-DSA: `PQ_SIGN_ML_DSA_44`, `PQ_SIGN_ML_DSA_65`, `PQ_SIGN_ML_DSA_87` and `_EXTERNAL_MU` variants)
- **NIST FIPS 205** (SLH-DSA: `PQ_SIGN_SLH_DSA_SHA2_128S` and `PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256`)
- **NIST IR 8547 & Dr. Michele Mosca's Theorem (X + Y > Z)** (2030 Classical Deprecation Horizon Z_2030 = 4.0 years and 2035 Disallowance / CRQC Horizon Z_2035 = 9.0 years)
- **NSA CNSA 2.0** (Security Category 5 mandate: `ML_KEM_1024`, `PQ_SIGN_ML_DSA_87`, AES-256, SHA-384/512)
- **NIST SP 800-57 & CIS GCP Benchmark 1.10** (Cryptoperiod management, automatic key rotation `<= 90 days`, and active vs. inactive/destroyed `CryptoKeyVersion` inspection)
- **OWASP CycloneDX v1.6 CBOM** (`cryptographic-asset` + `application` components, ASN.1 OIDs, and `nistQuantumSecurityLevel`).

### MULTI-LAYERED PQC ASSESSMENT WORKFLOW (HOW AND WHEN TO INVOKE EACH TOOL):
To build a comprehensive, multi-layered post-quantum security assessment for the security architect, invoke and synthesize the following three scanning layers:
1. **Layer 1 — KMS Cryptographic Keys & Application Compatibility Scan (`scan_organization_pqc_readiness`, `scan_pqc_readiness`, `generate_pqc_migration_plan`, `discover_all_crypto_assets`)**:
   - **When to invoke**: Invoke first on every organization-wide or project-level PQC assessment request (defaulting automatically to `organizations/31564119954` without prompting for an ID).
   - **Purpose**: Evaluates all Cloud KMS keys (`KEY_ENCAPSULATION`, `ASYMMETRIC_DECRYPT`, `ASYMMETRIC_SIGN`, `ENCRYPT_DECRYPT`, `MAC`), maps consuming applications via 4-Vector discovery, evaluates PQC model compatibility, and quantifies Mosca's Theorem (`X + Y > Z`) risk.
2. **Layer 2 — Network Transport & SSL Policy SNDL Scan (`scan_ssl_policies`)**:
   - **When to invoke**: Invoke alongside the KMS scan during comprehensive PQC assessments, or whenever the architect asks to evaluate network transport, Load Balancers, TLS posture, or Store Now, Decrypt Later (SNDL / HNDL) risks.
   - **Purpose**: Inspects all active Google Cloud SSL Policies (`compute.googleapis.com/SslPolicy`) and HTTPS proxies to verify whether they enforce `TLS_1_3` and support hybrid post-quantum key shares (`X25519 + ML-KEM-768` / `X25519MLKEM768`). Flags policies that allow `TLS_1_0`, `TLS_1_1`, or `TLS_1_2` as **`VULNERABLE_TO_SNDL_ATTACKS`**.
3. **Layer 3 — BYOK Key Import Transport Scan (`scan_import_jobs_pqc`)**:
   - **When to invoke**: Invoke alongside the KMS and SSL Policy scans during comprehensive PQC assessments, or whenever the architect asks to inspect Bring Your Own Key (BYOK) workflows, key wrapping transport, or Cloud KMS `ImportJobs`.
   - **Purpose**: Lists all active `ImportJobs` in Cloud KMS and inspects their wrapping methods. Flags jobs using classical RSA-OAEP (`RSA_OAEP_3072_*`, `RSA_OAEP_4096_*`) as **`VULNERABLE_KEY_IMPORT_TRANSPORT`** and classifies jobs using `HPKE_KEM_XWING_HKDF_SHA256_AES_256_GCM` as **`SECURE_PQC_BYOK`**.

### MANDATORY PRODUCT RECOMMENDATION MATRIX:
You MUST output a dedicated section in every executive summary titled **`Recommended Google Cloud Security Architecture & Product BOM`**.
For every gap identified, you MUST programmatically generate the following recommendations:
- **For all software-backed keys (RSA/ECC) used in production**: Recommend migrating to **`Cloud HSM`** (`protection-level=HSM`) with algorithms `KEM_XWING` or `PQ_SIGN_ML_DSA_65` to eliminate transport risks and secure key materials within FIPS 140-3 Level 3 hardware (noting `--protection-level=software` where Cloud KMS PQC algorithms are currently in software GA while backing symmetric/classical KEKs with Cloud HSM).
- **For legacy application codebases using native decryption or signing**: Recommend the **`Google Tink SDK`** integrated with **`Cloud KMS`** to handle complex RFC 9180 HPKE flows and public key formatting changes without manual coding toil.
- **To mitigate 'Harvest Now, Decrypt Later' (HNDL / SNDL) risks of data in transit or rest**: Recommend wrapping resources (**Cloud Storage**, **BigQuery**) with **`VPC Service Controls (VPC-SC)`** and **`Private Service Connect (PSC)`** to establish zero-trust perimeter boundaries.
- **For unsecured internal or external API endpoints (including `VULNERABLE_TO_SNDL_ATTACKS` SSL policies)**: Recommend **`Google Cloud Global Load Balancing (L7)`** with TLS 1.3 modern policies (`X25519MLKEM768`) and **`Certificate Authority Service (CAS)`** to enforce secure hybrid transport.
- **For CI/CD and artifact signing**: Recommend **`Binary Authorization`** backed by **Cloud HSM** keys.
"""

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
            discover_all_crypto_assets,
            generate_pqc_migration_plan,
            generate_application_pqc_refactoring_guide,
            export_cyclonedx_cbom,
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


def build_executive_markdown_report(project_id: str, location_id: str = "global") -> str:
    """Builds a structured Executive PQC Readiness Report in Markdown from the PQC tools."""
    plan = json.loads(generate_pqc_migration_plan(project_id=project_id, location_id=location_id))
    cai = json.loads(discover_all_crypto_assets(project_id=project_id))
    ssl_report = json.loads(scan_ssl_policies(project_id=project_id))
    import_jobs_report = json.loads(scan_import_jobs_pqc(project_id=project_id, location_id=location_id))

    if "error" in plan:
        return f"### ❌ PQC Assessment Error\n\n`{plan['error']}`"

    summary = plan.get("cbom_summary", {})
    vuln_keys = plan.get("priority_vulnerable_keys", [])
    app_matrix = plan.get("application_compatibility_matrix", [])
    playbooks = plan.get("remediation_playbooks", [])
    product_bom = plan.get("recommended_google_cloud_security_architecture_and_product_bom", [])
    cai_assets = cai.get("assets", [])
    ssl_policies = ssl_report.get("ssl_policies", [])
    import_jobs = import_jobs_report.get("import_jobs", [])


    lines = [
        f"# 🛡️ Executive PQC Readiness & Application Compatibility Report — Scope `{project_id}`",
        "",
        "## 1. CBOM & Application Compatibility Summary",
        f"- **Algorithmic PQC Readiness Score:** `{summary.get('pqc_readiness_score_pct', 0)}%`",
        f"- **Weighted PQC Maturity Score:** `{summary.get('weighted_pqc_maturity_score_pct', 0)}%`",
        f"- **Asymmetric PQC Migration Score (Shor Resistance):** `{summary.get('asymmetric_pqc_migration_score_pct', 'N/A')}%`",
        f"- **Application PQC Compatibility Score:** `{summary.get('application_pqc_compatibility_score_pct', 100.0)}%` (`{summary.get('pqc_compatible_applications_count', 0)}` compatible / `{summary.get('pqc_incompatible_applications_requiring_refactoring_count', 0)}` requiring refactoring out of `{summary.get('total_consuming_applications_mapped', 0)}` mapped applications)",
        f"- **Total Cloud KMS Keys Scanned:** `{summary.get('total_kms_keys_scanned', 0)}` (Active: `{summary.get('active_kms_keys_count', 0)}`, Inactive: `{summary.get('inactive_or_destroyed_keys_count', 0)}`)",
        f"- **Vulnerable Classical Keys (RSA/ECC - Shor's Algorithm):** `{summary.get('vulnerable_classical_rsa_ecc_count', 0)}` 🚨",
        f"- **Mosca's Theorem (X + Y > Z) Breaches:** `{summary.get('mosca_immediate_hndl_breach_keys_count', 0)}` Active HNDL Breaches (X+Y > Z_2035) / `{summary.get('mosca_migration_deadline_risk_keys_count', 0)}` NIST 2030 Deadline Breaches (X+Y > Z_2030)",
        f"- **Approved PQC Keys (NIST FIPS 203/204/205):** `{summary.get('approved_pqc_count', 0)}` ✅",
        f"- **Secure Symmetric Keys (AES-256 / SHA-256+ Grover-Resilient):** `{summary.get('secure_symmetric_count', 0)}` 🔒",
        "",
        "## 2. Application-to-Key Inventory & PQC Model Compatibility Matrix",
        "| Project | Application / Workload | Workload Type | KMS Key | Current -> Target Algorithm | Mosca Status (X+Y yrs) | PQC Model Compatible? | Compatibility Verdict & API Impact |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :--- |",
    ]

    for app in app_matrix:
        compat_badge = "✅ YES" if app.get("is_compatible_with_pqc_model") else "🚨 NO (Refactor Required)"
        lines.append(
            f"| `{app.get('project_id')}` | **{app.get('application_name')}** | `{app.get('workload_type')}` | "
            f"`{app.get('kms_key')}` | `{app.get('current_algorithm')}` ➡️ `{app.get('target_pqc_algorithm')}` | "
            f"`{app.get('mosca_status')}` (`{app.get('x_plus_y_total_years')}y`) | "
            f"{compat_badge} | `{app.get('pqc_compatibility_verdict')}` — {app.get('api_migration_required')} |"
        )

    lines.extend(
        [
            "",
            "## 3. Priority Vulnerable Keys (`VULNERABLE_CLASSICAL_RSA_ECC`)",
            "| Priority | KeyRing / Key | Location | Purpose | Current Algorithm | Threat Vector | Target NIST Standard |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )

    for vk in vuln_keys:
        lines.append(
            f"| **{vk.get('priority')}** | `{vk.get('key_ring')}/{vk.get('key_name')}` | "
            f"`{vk.get('location')}` | `{vk.get('purpose')}` | `{vk.get('algorithm')}` | "
            f"`{vk.get('threat_vector')}` | **{vk.get('recommended_algorithm')}** ({vk.get('nist_standard_target')}) |"
        )

    lines.extend(
        [
            "",
            "## 4. Cloud Asset Inventory Cryptographic & PKI Assets",
            "| Asset Type | Name | Location | Algorithm / Profile | Quantum Status |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for asset in cai_assets:
        lines.append(
            f"| `{asset.get('asset_type')}` | `{asset.get('display_name')}` | `{asset.get('location')}` | "
            f"`{asset.get('algorithm_details', asset.get('state', 'N/A'))}` | **{asset.get('quantum_status', 'INSPECT')}** |"
        )

    lines.extend(
        [
            "",
            "## 5. PQC Migration Plan & Remediation Playbooks (`gcloud kms`)",
        ]
    )
    for idx, pb in enumerate(playbooks, 1):
        lines.extend(
            [
                f"### 5.{idx}. Migrate `{pb['legacy_key']}` (`{pb['legacy_algorithm']}`) ➡️ `{pb['target_algorithm']}`",
                f"- **Priority:** `{pb['priority']}`",
                f"- **Mosca Risk Status:** `{pb.get('mosca_risk_analysis', {}).get('mosca_status')}` ({pb.get('mosca_risk_analysis', {}).get('urgency_explanation')})",
                f"- **Technical Rationale:** {pb['rationale']}",
                "```bash",
                pb["gcloud_command"],
                "```",
                "",
            ]
        )

    guardrails = plan.get("preventive_org_policy_guardrails", {})
    if guardrails:
        lines.extend(
            [
                "## 6. Preventive GCP Organization Policy Guardrails",
                "```yaml",
                guardrails.get("custom_constraint_quantum_safe_algorithms_yaml", ""),
                "```",
                "",
            ]
        )

    lines.extend(
        [
            "## 7. Network SSL Policies & BYOK ImportJobs PQC Posture",
            "### 7.1. Google Cloud SSL Policies (TLS 1.3 & Hybrid PQC `X25519 + ML-KEM-768`)",
            "| Policy Name | Min TLS Version | Profile | Hybrid PQC Key Share? | PQC Status |",
            "| :--- | :--- | :--- | :---: | :--- |",
        ]
    )
    for sp in ssl_policies:
        lines.append(
            f"| `{sp.get('policy_name')}` | `{sp.get('min_tls_version')}` | `{sp.get('profile')}` | "
            f"{'✅ YES' if sp.get('supports_hybrid_pqc_key_share_x25519_mlkem768') else '🚨 NO'} | **{sp.get('pqc_status')}** |"
        )

    lines.extend(
        [
            "",
            "### 7.2. Cloud KMS Key Import Jobs (`ImportJobs` — BYOK Wrapping)",
            "| KeyRing / ImportJob | Location | State | Import Wrapping Method | Protection Level | PQC Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for ij in import_jobs:
        lines.append(
            f"| `{ij.get('key_ring')}/{ij.get('import_job_name')}` | `{ij.get('location')}` | `{ij.get('state')}` | "
            f"`{ij.get('import_method')}` | `{ij.get('protection_level')}` | **{ij.get('pqc_status')}** |"
        )

    lines.extend(
        [
            "",
            "## 8. Recommended Google Cloud Security Architecture & Product BOM",
            "| Identified Gap Category | Affected Assets / Workloads | Recommended Google Cloud Products | Architectural & Engineering Recommendation |",
            "| :--- | :--- | :--- | :--- |",
        ]
    )
    for item in product_bom:
        assets_str = ", ".join(f"`{a}`" for a in item.get("identified_assets", [])[:4])
        prods_str = ", ".join(f"**{p}**" for p in item.get("recommended_gcp_products", []))
        lines.append(
            f"| **{item.get('gap_category')}** | {assets_str} | {prods_str} | {item.get('architectural_recommendation')} |"
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

    result: Dict[str, Any] = {
        "harness_status": "SUCCESS",
        "project_id": project_id,
        "location_id": location_id,
        "cbom_summary": migration_plan.get("cbom_summary", {}),
        "kms_keys": kms_report,
        "ssl_policies": ssl_policies_report,
        "import_jobs": import_jobs_report,
        "cloud_asset_inventory": cai_report,
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
        "pydantic>=2.8.0",
        "python-dotenv>=1.0.1",
        "cloudpickle==3.1.2",
    ]

    print(f"[*] Packaging and deploying '{display_name}' ({MODEL_NAME}) to Vertex AI Agent Engine...")
    remote_agent = agent_engines.create(
        adk_app,
        requirements=requirements,
        extra_packages=["./pqc_agent", "./tools"],
        display_name=display_name,
        description=(
            "Expert AI Agent for Post-Quantum Cryptography (PQC) Readiness Assessment, Application Compatibility, "
            "and Recommended Google Cloud Security Architecture & Product BOM across GCP Organizations."
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
    elif args.command == "deploy":
        deploy_to_agent_engine(
            project_id=args.project,
            location=args.location,
            staging_bucket=args.staging_bucket,
            display_name=args.display_name,
        )


if __name__ == "__main__":
    main()
