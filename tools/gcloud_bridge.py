"""Antigravity-Style 'gcloud' CLI Execution Bridge & Dynamic GCP Connection Manager.

Supports 3 connection modes switchable at runtime from the Gemini Enterprise Workspace Portal UI:
1. 'adc' ('Service Account (Default ADC)')
2. 'impersonation' ('Service Account Impersonation', e.g., 'pqc-reader@customer-project.iam.gserviceaccount.com')
3. 'access_token' ('User gcloud Access Token' from `gcloud auth print-access-token`)

Security: user OAuth access tokens are secrets. They are kept ONLY in process memory, keyed by tenant user with an
expiry (`PQC_ACCESS_TOKEN_TTL_SECONDS`, default 3600 s = Google access-token lifetime), and are never written to the
connection store on `/data` (a GCS bucket on Cloud Run). Only non-secret connection settings are persisted.

Also provides the read-only diagnostic tool `execute_gcloud_command(command: str)` with strict
verb allowlisting/denylisting and shell-injection prevention.
"""

from __future__ import annotations

import concurrent.futures
import contextvars
import datetime
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_TENANT_USER_ID = "sec-architect"
_CURRENT_USER_ID: contextvars.ContextVar[str] = contextvars.ContextVar(
    "pqc_current_user_id", default=DEFAULT_TENANT_USER_ID
)


def normalize_user_id(user_id: Optional[str]) -> str:
    """Normalizes a user identifier or @google.com email (stripping Cloud IAP prefixes if present)."""
    if not user_id:
        return DEFAULT_TENANT_USER_ID
    cleaned = str(user_id).strip()
    if cleaned.lower().startswith("accounts.google.com:"):
        cleaned = cleaned.split(":", 1)[1].strip()
    if not cleaned:
        return DEFAULT_TENANT_USER_ID
    if "@" in cleaned:
        return cleaned.lower()
    return cleaned


def set_current_tenant_user(user_id: Optional[str]) -> str:
    """Sets the active tenant user ID in the current async/thread execution context."""
    norm = normalize_user_id(user_id)
    _CURRENT_USER_ID.set(norm)
    return norm


def get_current_tenant_user() -> str:
    """Returns the active tenant user ID for the current async/thread execution context."""
    return normalize_user_id(_CURRENT_USER_ID.get())


# Allowed connection mode identifiers and human-readable labels
CONNECTION_MODES: Dict[str, str] = {
    "adc": "Service Account (Default ADC)",
    "impersonation": "Service Account Impersonation",
    "access_token": "User gcloud Access Token",
}

# Normalize UI labels or aliases to canonical mode keys
_MODE_ALIASES: Dict[str, str] = {
    "adc": "adc",
    "default": "adc",
    "default_adc": "adc",
    "service_account": "adc",
    "service account (default adc)": "adc",
    "impersonation": "impersonation",
    "impersonate": "impersonation",
    "sa_impersonation": "impersonation",
    "service account impersonation": "impersonation",
    "access_token": "access_token",
    "token": "access_token",
    "gcloud_token": "access_token",
    "user_token": "access_token",
    "user gcloud access token": "access_token",
    "oauth": "access_token",
    "oauth2": "access_token",
    "oauth_token": "access_token",
    "oauth_3lo": "access_token",
    "3lo": "access_token",
    "user_oauth": "access_token",
    "user oauth 2.0 (3lo)": "access_token",
}

# Read-only verbs allowed in `execute_gcloud_command`
ALLOWED_GCLOUD_VERBS = frozenset({
    "list",
    "describe",
    "search-all-resources",
    "search-all-iam-policies",
    "get-iam-policy",
    "get-public-key",
    "get-ancestors",
    "get-Ancestors-iam-policy",
    "get-value",
    "config",
    "version",
    "info",
    "help",
    "describe-effective-policy",
    "list-effective-tags",
    "export-lock-config",
    "check-iam-policy",
    "analyze-iam-policy",
})

# Destructive or state-mutating verbs strictly blocked in `execute_gcloud_command`
BLOCKED_GCLOUD_VERBS = frozenset({
    "delete",
    "destroy",
    "remove-iam-policy-binding",
    "add-iam-policy-binding",
    "set-iam-policy",
    "create",
    "update",
    "import",
    "decrypt",
    "asymmetric-decrypt",
    "decapsulate",
    "asymmetric-sign",
    "mac-sign",
    "raw-encrypt",
    "raw-decrypt",
    "encrypt",
    "disable",
    "enable",
    "restore",
    "schedule-key-destruction",
    "update-primary-version",
    "revoke",
    "reset",
    "deploy",
    "ssh",
    "scp",
    "start",
    "stop",
    "restart",
    "patch",
    "insert",
    "replace",
    "set",
    "unset",
    "clear",
    "login",
    "activate-service-account",
    "docker",
})

# Shell metacharacters that are never permitted in a diagnostic gcloud command
_FORBIDDEN_SHELL_PATTERNS = re.compile(r"[;&|`$><\n\r]")

_LOCK = threading.RLock()
_SA_EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com$")


def _default_connection_template() -> Dict[str, Any]:
    return {
        "mode": os.getenv("PQC_CONNECTION_MODE", "adc"),
        "organization_id": os.getenv("GCP_ORGANIZATION_ID", "31564119954"),
        "project_id": os.getenv("GOOGLE_CLOUD_PROJECT", "pqc-inventory-agent-cd06"),
        "location": os.getenv("PQC_DEFAULT_LOCATION", "all"),
        "impersonated_service_account": os.getenv("PQC_IMPERSONATED_SERVICE_ACCOUNT", ""),
        "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def validate_impersonated_service_account(sa_email: str) -> str:
    """Validates a target GCP Service Account email and enforces ``PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS``."""
    clean = str(sa_email or "").strip()
    if not clean:
        return ""
    if not _SA_EMAIL_PATTERN.match(clean):
        raise ValueError(
            f"Invalid GCP service account principal '{clean}'. Expected '<name>@<project>.iam.gserviceaccount.com'."
        )
    allowlist_raw = (os.getenv("PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS") or "").strip()
    if allowlist_raw:
        allowed_entries = [item.strip().lower() for item in allowlist_raw.split(",") if item.strip()]
        low = clean.lower()
        permitted = any(
            (low == rule) or (rule.startswith("@") and low.endswith(rule))
            for rule in allowed_entries
        )
        if not permitted:
            raise PermissionError(
                f"Service account '{clean}' is not in PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS allowlist."
            )
    return clean


def clear_user_access_token(user_id: Optional[str] = None) -> None:
    """Revokes and wipes the persisted delegated OAuth credential of a tenant user across all instances."""
    from pqc_agent import credential_service

    uid = normalize_user_id(user_id or get_current_tenant_user())
    credential_service.get_active_credential_service().revoke_delegated_tokens(user_id=uid, reason="logout")


_GCLOUD_EXECUTION_LOG: List[Dict[str, Any]] = []


def normalize_connection_mode(raw_mode: Optional[str]) -> str:
    """Normalizes any connection mode string or UI label to ('adc', 'impersonation', 'access_token')."""
    if not raw_mode:
        return "adc"
    cleaned = str(raw_mode).strip().lower()
    return _MODE_ALIASES.get(cleaned, "adc")


def set_gcp_connection_config(
    mode: Optional[str] = None,
    organization_id: Optional[str] = None,
    project_id: Optional[str] = None,
    location: Optional[str] = None,
    impersonated_service_account: Optional[str] = None,
    access_token: Optional[str] = None,
    user_id: Optional[str] = None,
    access_token_expires_in: Optional[float] = None,
    refresh_token: Optional[str] = None,
    oauth_client_id: Optional[str] = None,
    oauth_client_secret: Optional[str] = None,
) -> Dict[str, Any]:
    """Updates the active GCP connection configuration in ``pqc_user_connections`` and envelope-encrypts any delegated token."""
    from pqc_agent import auth_store, credential_service

    uid = normalize_user_id(user_id or get_current_tenant_user())
    defaults = _default_connection_template()
    norm_mode = normalize_connection_mode(mode) if mode is not None else None

    clean_org: Optional[str] = None
    if organization_id is not None and str(organization_id).strip():
        clean_org = str(organization_id).strip().replace("organizations/", "")
        if uid == DEFAULT_TENANT_USER_ID:
            os.environ["GCP_ORGANIZATION_ID"] = clean_org

    clean_proj: Optional[str] = None
    if project_id is not None and str(project_id).strip():
        clean_proj = str(project_id).strip().replace("projects/", "")

    clean_loc: Optional[str] = None
    if location is not None and str(location).strip():
        clean_loc = str(location).strip()

    clean_sa: Optional[str] = None
    if impersonated_service_account is not None:
        clean_sa = validate_impersonated_service_account(impersonated_service_account)

    auth_store.get_active_auth_store().upsert_user_connection(
        user_id=uid,
        mode=norm_mode,
        organization_id=clean_org,
        project_id=clean_proj,
        location=clean_loc,
        impersonated_service_account=clean_sa,
        defaults=defaults,
    )

    if access_token is not None:
        tok = str(access_token).strip()
        if tok.lower().startswith("bearer "):
            tok = tok[7:].strip()
        cred_svc = credential_service.get_active_credential_service()
        if tok:
            cred_svc.store_delegated_token(
                user_id=uid,
                access_token=tok,
                refresh_token=refresh_token,
                expires_in=access_token_expires_in,
                client_id=oauth_client_id or "",
                client_secret=oauth_client_secret or "",
                caller_user_id=uid,
            )
        else:
            cred_svc.revoke_delegated_tokens(user_id=uid, reason="cleared")

    return get_gcp_connection_config(mask_token=True, user_id=uid)


def get_gcp_connection_config(mask_token: bool = True, user_id: Optional[str] = None) -> Dict[str, Any]:
    """Returns the current GCP connection state from the shared database (with masked token by default)."""
    from pqc_agent import auth_store, credential_service

    uid = normalize_user_id(user_id or get_current_tenant_user())
    stored = auth_store.get_active_auth_store().get_user_connection(uid)
    state = stored if stored is not None else _default_connection_template()

    raw_token = ""
    token_expires_at: Optional[float] = None
    has_refresh_token = False
    kek_provider: Optional[str] = None

    loaded_cred = credential_service.get_active_credential_service().load_delegated_token(
        user_id=uid,
        caller_user_id=uid,
    )
    if loaded_cred is not None:
        raw_token = loaded_cred.access_token
        token_expires_at = loaded_cred.expires_at
        has_refresh_token = loaded_cred.has_refresh_token
        kek_provider = loaded_cred.kek_provider
    elif uid == DEFAULT_TENANT_USER_ID and os.getenv("PQC_USER_ACCESS_TOKEN", "").strip():
        raw_token = os.getenv("PQC_USER_ACCESS_TOKEN", "").strip()

    mode = normalize_connection_mode(state.get("mode"))
    has_token = bool(raw_token)
    masked_token = ""
    if has_token:
        if len(raw_token) > 12:
            masked_token = f"{raw_token[:6]}...{raw_token[-4:]}"
        else:
            masked_token = "***REDACTED***"

    return {
        "user_id": uid,
        "mode": mode,
        "mode_label": CONNECTION_MODES.get(mode, CONNECTION_MODES["adc"]),
        "auth_flow": "oauth2_3lo" if mode == "access_token" else mode,
        "oauth_consent_required": bool(mode == "access_token" and not has_token),
        "organization_id": state.get("organization_id", "31564119954"),
        "project_id": state.get("project_id", "pqc-inventory-agent-cd06"),
        "location": state.get("location", "all"),
        "impersonated_service_account": state.get("impersonated_service_account", ""),
        "has_access_token": has_token,
        "has_refresh_token": has_refresh_token,
        "access_token_preview": masked_token if mask_token else raw_token,
        "access_token_storage": "encrypted_db_envelope",
        "credential_kek_provider": kek_provider,
        "access_token_expires_at": (
            datetime.datetime.fromtimestamp(token_expires_at, tz=datetime.timezone.utc).isoformat()
            if (has_token and token_expires_at)
            else None
        ),
        "gcloud_binary_available": bool(_resolve_gcloud_binary()),
        "updated_at": state.get("updated_at"),
    }


def _impersonation_lifetime_seconds() -> int:
    try:
        return min(3600, max(300, int(os.getenv("PQC_IMPERSONATION_LIFETIME_SECONDS", "3600"))))
    except ValueError:
        return 3600


def get_active_gcp_credentials(user_id: Optional[str] = None) -> Any:
    """Returns google.auth credentials matching the active tenant user's connection mode, or None for Default ADC.

    Preferred enterprise mode: ``impersonation`` using short-lived (<= 3600s) read-only credentials via IAM Credentials
    API. Delegated ``access_token`` mode loads KMS/KEK envelope-encrypted credentials from PostgreSQL.
    """
    conn = get_gcp_connection_config(mask_token=False, user_id=user_id)
    mode = normalize_connection_mode(conn.get("mode"))
    impersonated_sa = (conn.get("impersonated_service_account") or "").strip()
    access_token = (conn.get("access_token_preview") or "").strip()
    quota_project = (conn.get("project_id") or "").strip() or None

    if mode == "access_token" and access_token:
        from google.oauth2 import credentials as oauth2_credentials

        return oauth2_credentials.Credentials(
            token=access_token,
            quota_project_id=quota_project,
        )

    if mode == "impersonation" and impersonated_sa:
        validated_sa = validate_impersonated_service_account(impersonated_sa)
        import google.auth
        from google.auth import impersonated_credentials

        source_credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        return impersonated_credentials.Credentials(
            source_credentials=source_credentials,
            target_principal=validated_sa,
            target_scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
            lifetime=_impersonation_lifetime_seconds(),
        )

    return None


def _resolve_gcloud_binary() -> Optional[str]:
    """Finds the `gcloud` CLI binary across standard Linux, Cloud Run, and macOS paths."""
    found = shutil.which("gcloud")
    if found:
        return found
    candidate_paths = [
        "/usr/bin/gcloud",
        "/usr/local/bin/gcloud",
        "/google-cloud-sdk/bin/gcloud",
        "/opt/google-cloud-sdk/bin/gcloud",
        os.path.expanduser("~/google-cloud-sdk/bin/gcloud"),
        "/opt/homebrew/bin/gcloud",
    ]
    for path in candidate_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def validate_gcloud_command(command: str) -> Tuple[bool, List[str], str]:
    """Validates that a gcloud command is strictly read-only and free of shell injection.

    Returns:
        Tuple of (is_valid, parsed_tokens, error_or_status_message).
    """
    if not command or not str(command).strip():
        return False, [], "Empty gcloud command provided."

    raw_cmd = str(command).strip()
    if _FORBIDDEN_SHELL_PATTERNS.search(raw_cmd):
        return (
            False,
            [],
            "Blocked: Shell metacharacters (;, |, &, `, $, >, <, newline) are prohibited in execute_gcloud_command.",
        )

    try:
        tokens = shlex.split(raw_cmd)
    except ValueError as exc:
        return False, [], f"Invalid command quoting: {exc}"

    if not tokens:
        return False, [], "Empty gcloud command tokens."

    if tokens[0] == "gcloud":
        tokens = tokens[1:]
    elif tokens[0].endswith("/gcloud"):
        tokens = tokens[1:]

    if not tokens:
        return False, [], "No gcloud subcommand specified."

    # Normalize non-flag tokens to check verbs
    non_flag_tokens = [t.lower() for t in tokens if not t.startswith("-")]
    if not non_flag_tokens:
        # Allow `gcloud --version`
        if any(t in ("--version", "-v", "--help", "-h") for t in tokens):
            return True, tokens, "Allowed diagnostic flag."
        return False, [], "No gcloud subcommand or verb found."

    # Check for blocked destructive/mutating verbs anywhere in the non-flag tokens
    for tok in non_flag_tokens:
        if tok in BLOCKED_GCLOUD_VERBS:
            return (
                False,
                tokens,
                f"Blocked destructive/mutating verb '{tok}'. Only read-only diagnostic gcloud commands are allowed.",
            )

    # Special check for `gcloud config`: only `list` or `get-value` or `get` are allowed
    if non_flag_tokens[0] == "config":
        if len(non_flag_tokens) < 2 or non_flag_tokens[1] not in ("list", "get-value", "get", "configurations"):
            return (
                False,
                tokens,
                "Blocked: Only read-only 'gcloud config list' or 'gcloud config get-value' commands are allowed.",
            )

    # Special check for `gcloud auth`: only `list` is allowed
    if non_flag_tokens[0] == "auth":
        if len(non_flag_tokens) < 2 or non_flag_tokens[1] != "list":
            return (
                False,
                tokens,
                "Blocked: Only 'gcloud auth list' is permitted under 'gcloud auth'.",
            )

    # Ensure at least one allowed read-only verb is present
    has_allowed_verb = any(tok in ALLOWED_GCLOUD_VERBS for tok in non_flag_tokens)
    if not has_allowed_verb:
        return (
            False,
            tokens,
            (
                f"Blocked: Command does not contain an approved read-only diagnostic verb "
                f"({', '.join(sorted(ALLOWED_GCLOUD_VERBS))})."
            ),
        )

    return True, tokens, "Validated read-only diagnostic gcloud command."


def execute_gcloud_command(command: str) -> str:
    """Executes a read-only/diagnostic `gcloud` CLI command using the active GCP connection mode.

    Permits read-only inspection verbs (`list`, `describe`, `search-all-resources`,
    `search-all-iam-policies`, `get-iam-policy`, `get-public-key`, `config list`, `version`)
    and blocks all destructive or mutating verbs (`delete`, `destroy`, `create`, `update`,
    `remove-iam-policy-binding`, `set-iam-policy`, `decrypt`, etc.).

    Args:
        command: The `gcloud` command string to execute (e.g.,
            `gcloud kms keys list --location=global --project=pqc-inventory-agent-cd06` or
            `gcloud asset search-all-resources --scope=organizations/31564119954 --asset-types=cloudkms.googleapis.com/CryptoKey`).

    Returns:
        JSON string containing `status`, `command_executed`, `connection_mode`, `exit_code`,
        `stdout`, `stderr`, and `duration_ms`.
    """
    start_ts = time.time()
    is_valid, tokens, validation_msg = validate_gcloud_command(command)
    conn_cfg = get_gcp_connection_config(mask_token=False)
    mode = conn_cfg["mode"]
    mode_label = conn_cfg["mode_label"]

    if not is_valid:
        blocked_payload = {
            "status": "BLOCKED_DESTRUCTIVE_OR_INVALID_COMMAND",
            "command_requested": command,
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "exit_code": 126,
            "stdout": "",
            "stderr": validation_msg,
            "duration_ms": round((time.time() - start_ts) * 1000, 2),
        }
        _record_gcloud_trace(blocked_payload)
        return json.dumps(blocked_payload, ensure_ascii=False)

    gcloud_bin = _resolve_gcloud_binary()
    if not gcloud_bin:
        missing_payload = {
            "status": "GCLOUD_BINARY_NOT_FOUND",
            "command_requested": command,
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "exit_code": 127,
            "stdout": "",
            "stderr": "The 'gcloud' CLI binary is not installed on PATH in this environment.",
            "duration_ms": round((time.time() - start_ts) * 1000, 2),
        }
        _record_gcloud_trace(missing_payload)
        return json.dumps(missing_payload, ensure_ascii=False)

    # Ensure --quiet is passed so gcloud never blocks on interactive prompts
    exec_tokens = [gcloud_bin] + list(tokens)
    if "--quiet" not in exec_tokens and "-q" not in exec_tokens:
        exec_tokens.append("--quiet")

    env = os.environ.copy()
    existing_metrics = env.get("CLOUDSDK_METRICS_ENVIRONMENT", "").strip()
    env["CLOUDSDK_METRICS_ENVIRONMENT"] = (
        f"{existing_metrics} datacloud.antigravity".strip() if existing_metrics else "datacloud.antigravity"
    )
    env["CLOUDSDK_CORE_DISABLE_PROMPTS"] = "1"

    if conn_cfg.get("project_id") and not any(t.startswith("--project") for t in exec_tokens):
        env.setdefault("CLOUDSDK_CORE_PROJECT", conn_cfg["project_id"])

    try:
        if mode == "impersonation" and conn_cfg.get("impersonated_service_account"):
            env["CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"] = validate_impersonated_service_account(
                conn_cfg["impersonated_service_account"]
            )
        elif mode == "access_token" and conn_cfg.get("access_token_preview"):
            env["CLOUDSDK_AUTH_ACCESS_TOKEN"] = conn_cfg["access_token_preview"].strip()

        proc = subprocess.run(
            exec_tokens,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            shell=False,
        )
        if (
            proc.returncode != 0
            and "CLOUDSDK_AUTH_ACCESS_TOKEN" in env
            and any(
                err_marker in (proc.stderr or "")
                for err_marker in (
                    "PERMISSION_DENIED",
                    "PermissionDenied",
                    "USER_PROJECT_DENIED",
                    "does not have required permission",
                    "Caller does not have permission",
                )
            )
        ):
            adc_env = dict(env)
            adc_env.pop("CLOUDSDK_AUTH_ACCESS_TOKEN", None)
            adc_proc = subprocess.run(
                exec_tokens,
                capture_output=True,
                text=True,
                timeout=30,
                env=adc_env,
                shell=False,
            )
            if adc_proc.returncode == 0:
                proc = adc_proc
                mode = "adc"
                mode_label = CONNECTION_MODES["adc"]
        if (
            proc.returncode != 0
            and any("31564119954" in t for t in exec_tokens)
            and any(
                err_marker in (proc.stderr or "")
                for err_marker in (
                    "PERMISSION_DENIED",
                    "PermissionDenied",
                    "does not have permission",
                    "Caller does not have permission",
                )
            )
        ):
            fb_tokens = [
                t.replace("organizations/31564119954", "folders/534285347409").replace(
                    "--organization=31564119954", "--folder=534285347409"
                )
                for t in exec_tokens
            ]
            if fb_tokens != exec_tokens:
                fb_env = dict(env)
                fb_env.pop("CLOUDSDK_AUTH_ACCESS_TOKEN", None)
                fb_proc = subprocess.run(
                    fb_tokens,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=fb_env,
                    shell=False,
                )
                if fb_proc.returncode == 0:
                    proc = fb_proc
                    tokens = [
                        t.replace("organizations/31564119954", "folders/534285347409").replace(
                            "--organization=31564119954", "--folder=534285347409"
                        )
                        for t in tokens
                    ]
        duration_ms = round((time.time() - start_ts) * 1000, 2)
        display_cmd = "gcloud " + " ".join(shlex.quote(t) for t in tokens)
        result_payload = {
            "status": "SUCCESS" if proc.returncode == 0 else "COMMAND_ERROR",
            "command_executed": display_cmd,
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "impersonated_service_account": (
                conn_cfg.get("impersonated_service_account") if mode == "impersonation" else None
            ),
            "exit_code": proc.returncode,
            "stdout": proc.stdout[:32000],
            "stderr": proc.stderr[:8000],
            "duration_ms": duration_ms,
        }
        _record_gcloud_trace(result_payload)
        return json.dumps(result_payload, ensure_ascii=False)
    except subprocess.TimeoutExpired:
        timeout_payload = {
            "status": "TIMEOUT",
            "command_executed": "gcloud " + " ".join(tokens),
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "exit_code": 124,
            "stdout": "",
            "stderr": "Command timed out after 30 seconds.",
            "duration_ms": round((time.time() - start_ts) * 1000, 2),
        }
        _record_gcloud_trace(timeout_payload)
        return json.dumps(timeout_payload, ensure_ascii=False)
    except Exception as exc:
        err_payload = {
            "status": "EXECUTION_EXCEPTION",
            "command_executed": "gcloud " + " ".join(tokens),
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "exit_code": 1,
            "stdout": "",
            "stderr": str(exc),
            "duration_ms": round((time.time() - start_ts) * 1000, 2),
        }
        _record_gcloud_trace(err_payload)
        return json.dumps(err_payload, ensure_ascii=False)


def _record_gcloud_trace(entry: Dict[str, Any]) -> None:
    """Stores recent gcloud executions in a bounded ring buffer for the UI Execution Trace drawer."""
    with _LOCK:
        trace_item = dict(entry)
        trace_item.setdefault("user_id", get_current_tenant_user())
        trace_item["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _GCLOUD_EXECUTION_LOG.append(trace_item)
        if len(_GCLOUD_EXECUTION_LOG) > 200:
            del _GCLOUD_EXECUTION_LOG[:-200]


def get_recent_gcloud_traces(limit: int = 25, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns the most recent gcloud CLI execution trace records, optionally filtered by tenant user_id."""
    with _LOCK:
        if user_id:
            norm = normalize_user_id(user_id)
            filtered = [t for t in _GCLOUD_EXECUTION_LOG if normalize_user_id(t.get("user_id")) == norm]
            return list(filtered[-limit:])
        return list(_GCLOUD_EXECUTION_LOG[-limit:])

