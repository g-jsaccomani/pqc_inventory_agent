"""Antigravity-Style 'gcloud' CLI Execution Bridge & Dynamic GCP Connection Manager.

Supports 3 connection modes switchable at runtime from the Gemini Enterprise Workspace Portal UI:
1. 'adc' ('Service Account (Default ADC)')
2. 'impersonation' ('Service Account Impersonation', e.g., 'pqc-reader@customer-project.iam.gserviceaccount.com')
3. 'access_token' ('User gcloud Access Token' from `gcloud auth print-access-token` or 3LO OAuth)

Security Guarantees (Phase 1–3 Hardened):
- Delegated user OAuth tokens are envelope-encrypted in PostgreSQL (`EncryptedDatabaseCredentialService`) and never
  written to plaintext files, logs, or frontend payloads.
- `validate_gcloud_command()` enforces a strict structured grammar: executable must be `gcloud`, top-level service
  groups and `(group, ..., verb)` paths must match explicit read-only policies, flags are validated against per-command
  allowlists with typed value validators, duplicate flags are rejected, and dangerous flags (`--api-endpoint-overrides`,
  `--property`, `--impersonate-service-account`, `--flags-file`, `--credential-file-override`, `--access-token-file`,
  `--account`, `--configuration`, `--log-http`, URL values, etc.) fail closed unconditionally.
- `build_sanitized_gcloud_env()` constructs a clean subprocess environment from an explicit safe-variable allowlist,
  stripping inherited `CLOUDSDK_API_ENDPOINT_OVERRIDES_*`, proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, etc.), and
  ambient credential overrides while preserving legitimate Cloud Run ADC behavior.
- `execute_gcloud_command()` enforces strict tenant credential boundaries: `access_token` mode uses ONLY the caller's
  delegated token and NEVER falls back to server ADC on `PERMISSION_DENIED`, missing token, or token expiration.
"""

from __future__ import annotations

from dataclasses import dataclass
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
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

from pqc_agent import egress_guard

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
ALLOWED_GCLOUD_VERBS: FrozenSet[str] = frozenset(
    {
        "list",
        "describe",
        "search-all-resources",
        "search-all-iam-policies",
        "get-iam-policy",
        "get-public-key",
        "get-ancestors",
        "list-available-features",
        "version",
    }
)

# Destructive, mutating, cryptographic-operation, or configuration-altering verbs strictly blocked
BLOCKED_GCLOUD_VERBS: FrozenSet[str] = frozenset(
    {
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
        "print-access-token",
        "print-identity-token",
        "docker",
        "submit",
        "call",
        "exec",
        "execute",
    }
)

# Mandatory blocked gcloud global/command flags (canonical lowercase hyphenated form)
BLOCKED_GCLOUD_FLAGS: FrozenSet[str] = frozenset(
    {
        "--api-endpoint-overrides",
        "--property",
        "--properties",
        "--impersonate-service-account",
        "--flags-file",
        "--credential-file-override",
        "--access-token-file",
        "--authorization-token-file",
        "--account",
        "--configuration",
        "--log-http",
        "--http-timeout",
        "--authority-selector",
        "--trace-token",
        "--billing-project",
        "--output-file",
    }
)

# Prefix checks to block argparse/calliope flag abbreviations (e.g. `--api-endpoint=...`, `--impersonate=...`)
_BLOCKED_FLAG_PREFIXES: Tuple[str, ...] = (
    "--api-endpoint",
    "--propert",
    "--impersonate",
    "--flags-file",
    "--credential",
    "--access-token",
    "--authorization-token",
    "--account",
    "--config",
    "--log-http",
    "--no-",
)

# Shell metacharacters and ASCII control chars prohibited in diagnostic gcloud commands
_FORBIDDEN_SHELL_PATTERNS = re.compile(r"[;&|`$><\n\r]")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# Patterns strictly forbidden in any flag value or positional argument (SSRF / URL / endpoint override prevention)
_URL_SCHEME_IN_VALUE_RE = re.compile(r"(?i)(?:[a-z][a-z0-9+.-]*://|https?:|//169\.254\.|metadata\.google\.internal)")
_ENDPOINT_INJECTION_RE = re.compile(r"(?i)(?:api_endpoint_overrides|api-endpoint-overrides|169\.254\.169\.254)")

_PROJECT_ID_RE = re.compile(r"^(?:[a-z0-9.-]+:)?[a-z][a-z0-9-]{4,29}[a-z0-9]$")
_LOCATION_RE = re.compile(r"^[a-zA-Z0-9_-]{2,64}$")
_NUMERIC_ID_RE = re.compile(r"^[0-9]{1,32}$")
_SCOPE_RE = re.compile(
    r"^(?:organizations/[0-9]{1,32}|folders/[0-9]{1,32}|projects/(?:[a-z0-9.-]+:)?[a-z][a-z0-9-]{4,29}[a-z0-9])$"
)
_RESOURCE_NAME_OR_PATH_RE = re.compile(r"^[a-zA-Z0-9_./:@-]{1,320}$")
_ASSET_TYPES_RE = re.compile(r"^[a-zA-Z0-9.*,/_-]+$")
_FLATTEN_RE = re.compile(r"^[a-zA-Z0-9_.\[\],-]+$")
_POSITIVE_INT_RE = re.compile(r"^[1-9][0-9]{0,4}$")
_FORMAT_RE = re.compile(
    r"^(?:json|yaml|text|list|none|(?:value|table|csv)(?:\[[a-zA-Z0-9_.,=-]+\])?\([a-zA-Z0-9_.,:\[\]()=/ -]{1,160}\))$"
)
_BUCKET_ARG_RE = re.compile(r"^(?:gs://)?[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$")

_LOCK = threading.RLock()
_SA_EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com$")


@dataclass(frozen=True)
class _FlagSpec:
    name: str
    takes_value: bool
    validator: Optional[Callable[[str], Optional[str]]] = None


@dataclass(frozen=True)
class _CommandPolicy:
    command_path: Tuple[str, ...]
    allowed_flags: FrozenSet[str]
    positional_count: int = 0
    positional_validator: Optional[Callable[[str], Optional[str]]] = None


def _check_common_arg_safety(value: str, *, allow_gs_uri: bool = False) -> Optional[str]:
    if not value:
        return "Empty argument value is not permitted."
    if len(value) > 512:
        return "Argument value exceeds maximum length (512 chars)."
    if _CONTROL_CHARS_RE.search(value):
        return "Argument value contains prohibited control characters."
    if value.startswith("@"):
        return "Leading '@' file-reference syntax is prohibited."
    if ".." in value:
        return "Path traversal sequences ('..') are prohibited."
    if _ENDPOINT_INJECTION_RE.search(value):
        return "Endpoint override or metadata address injection in argument value is prohibited."
    check_target = value[5:] if (allow_gs_uri and value.startswith("gs://")) else value
    if _URL_SCHEME_IN_VALUE_RE.search(check_target):
        return "HTTP/HTTPS or external URI schemes in gcloud arguments are prohibited."
    return None


def _validate_project_value(val: str) -> Optional[str]:
    err = _check_common_arg_safety(val)
    if err:
        return err
    if not _PROJECT_ID_RE.match(val):
        return f"Invalid '--project' identifier '{val}'."
    return None


def _validate_location_value(val: str) -> Optional[str]:
    err = _check_common_arg_safety(val)
    if err:
        return err
    if not _LOCATION_RE.match(val):
        return f"Invalid location/region/zone value '{val}'."
    return None


def _validate_numeric_id_value(val: str) -> Optional[str]:
    err = _check_common_arg_safety(val)
    if err:
        return err
    if not _NUMERIC_ID_RE.match(val):
        return f"Expected numeric organization/folder ID, got '{val}'."
    return None


def _validate_scope_value(val: str) -> Optional[str]:
    err = _check_common_arg_safety(val)
    if err:
        return err
    if not _SCOPE_RE.match(val):
        return f"Invalid '--scope' value '{val}'. Expected organizations/<id>, folders/<id>, or projects/<id>."
    return None


def _validate_resource_ref_value(val: str) -> Optional[str]:
    err = _check_common_arg_safety(val)
    if err:
        return err
    if val.startswith("-") or "//" in val:
        return f"Malformed resource identifier '{val}'."
    if not _RESOURCE_NAME_OR_PATH_RE.match(val):
        return f"Invalid resource identifier '{val}'."
    return None


def _validate_bucket_positional(val: str) -> Optional[str]:
    err = _check_common_arg_safety(val, allow_gs_uri=True)
    if err:
        return err
    if not _BUCKET_ARG_RE.match(val):
        return f"Invalid Cloud Storage bucket identifier '{val}'."
    return None


def _validate_asset_types_value(val: str) -> Optional[str]:
    err = _check_common_arg_safety(val)
    if err:
        return err
    if "//" in val or not _ASSET_TYPES_RE.match(val):
        return f"Invalid '--asset-types' value '{val}'."
    return None


def _validate_query_or_filter_value(val: str) -> Optional[str]:
    err = _check_common_arg_safety(val)
    if err:
        return err
    if not val.isascii():
        return "Filter/query expressions must be printable ASCII."
    return None


def _validate_format_value(val: str) -> Optional[str]:
    err = _check_common_arg_safety(val)
    if err:
        return err
    if not _FORMAT_RE.match(val):
        return f"Unsupported or unsafe '--format' projection '{val}'."
    return None


def _validate_positive_int_value(val: str) -> Optional[str]:
    err = _check_common_arg_safety(val)
    if err:
        return err
    if not _POSITIVE_INT_RE.match(val) or int(val) > 10000:
        return f"Flag value '{val}' must be an integer between 1 and 10000."
    return None


def _validate_flatten_value(val: str) -> Optional[str]:
    err = _check_common_arg_safety(val)
    if err:
        return err
    if not _FLATTEN_RE.match(val):
        return f"Invalid '--flatten' expression '{val}'."
    return None


_FLAG_SPECS: Dict[str, _FlagSpec] = {
    "--project": _FlagSpec("--project", True, _validate_project_value),
    "--location": _FlagSpec("--location", True, _validate_location_value),
    "--region": _FlagSpec("--region", True, _validate_location_value),
    "--zone": _FlagSpec("--zone", True, _validate_location_value),
    "--scope": _FlagSpec("--scope", True, _validate_scope_value),
    "--organization": _FlagSpec("--organization", True, _validate_numeric_id_value),
    "--folder": _FlagSpec("--folder", True, _validate_numeric_id_value),
    "--keyring": _FlagSpec("--keyring", True, _validate_resource_ref_value),
    "--key": _FlagSpec("--key", True, _validate_resource_ref_value),
    "--pool": _FlagSpec("--pool", True, _validate_resource_ref_value),
    "--issuer-pool": _FlagSpec("--issuer-pool", True, _validate_resource_ref_value),
    "--asset-types": _FlagSpec("--asset-types", True, _validate_asset_types_value),
    "--query": _FlagSpec("--query", True, _validate_query_or_filter_value),
    "--filter": _FlagSpec("--filter", True, _validate_query_or_filter_value),
    "--format": _FlagSpec("--format", True, _validate_format_value),
    "--limit": _FlagSpec("--limit", True, _validate_positive_int_value),
    "--page-size": _FlagSpec("--page-size", True, _validate_positive_int_value),
    "--flatten": _FlagSpec("--flatten", True, _validate_flatten_value),
    "--uri": _FlagSpec("--uri", False),
    "--global": _FlagSpec("--global", False),
    "--quiet": _FlagSpec("--quiet", False),
    "--version": _FlagSpec("--version", False),
}

_COMMON_LIST_FLAGS: FrozenSet[str] = frozenset(
    {"--filter", "--format", "--limit", "--page-size", "--flatten", "--uri", "--quiet"}
)
_COMMON_DESCRIBE_FLAGS: FrozenSet[str] = frozenset({"--format", "--quiet"})
_COMMON_IAM_FLAGS: FrozenSet[str] = frozenset(
    {"--filter", "--format", "--limit", "--page-size", "--flatten", "--quiet"}
)


def _build_command_policies() -> Dict[Tuple[str, ...], _CommandPolicy]:
    policies: List[_CommandPolicy] = [
        # Version
        _CommandPolicy(("version",), frozenset({"--format", "--quiet"}), 0),
        # Cloud KMS
        _CommandPolicy(
            ("kms", "keyrings", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location"},
            0,
        ),
        _CommandPolicy(
            ("kms", "keyrings", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("kms", "keyrings", "get-iam-policy"),
            _COMMON_IAM_FLAGS | {"--project", "--location"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("kms", "keys", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location", "--keyring"},
            0,
        ),
        _CommandPolicy(
            ("kms", "keys", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location", "--keyring"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("kms", "keys", "get-iam-policy"),
            _COMMON_IAM_FLAGS | {"--project", "--location", "--keyring"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("kms", "keys", "versions", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location", "--keyring", "--key"},
            0,
        ),
        _CommandPolicy(
            ("kms", "keys", "versions", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location", "--keyring", "--key"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("kms", "keys", "versions", "get-public-key"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location", "--keyring", "--key"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("kms", "import-jobs", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location", "--keyring"},
            0,
        ),
        _CommandPolicy(
            ("kms", "import-jobs", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location", "--keyring"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("kms", "import-jobs", "get-iam-policy"),
            _COMMON_IAM_FLAGS | {"--project", "--location", "--keyring"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(("kms", "locations", "list"), _COMMON_LIST_FLAGS | {"--project"}, 0),
        # Cloud Asset Inventory
        _CommandPolicy(
            ("asset", "search-all-resources"),
            frozenset(
                {
                    "--scope",
                    "--asset-types",
                    "--query",
                    "--filter",
                    "--format",
                    "--limit",
                    "--page-size",
                    "--flatten",
                    "--project",
                    "--quiet",
                }
            ),
            0,
        ),
        _CommandPolicy(
            ("asset", "search-all-iam-policies"),
            frozenset(
                {
                    "--scope",
                    "--asset-types",
                    "--query",
                    "--filter",
                    "--format",
                    "--limit",
                    "--page-size",
                    "--flatten",
                    "--project",
                    "--quiet",
                }
            ),
            0,
        ),
        _CommandPolicy(
            ("asset", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--organization", "--folder", "--asset-types"},
            0,
        ),
        # Compute Engine TLS / Load Balancer / Workload correlation
        _CommandPolicy(
            ("compute", "ssl-policies", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--region", "--global"},
            0,
        ),
        _CommandPolicy(
            ("compute", "ssl-policies", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--region", "--global"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("compute", "ssl-policies", "list-available-features"),
            frozenset({"--project", "--region", "--filter", "--format", "--quiet"}),
            0,
        ),
        _CommandPolicy(
            ("compute", "target-https-proxies", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--region", "--global"},
            0,
        ),
        _CommandPolicy(
            ("compute", "target-https-proxies", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--region", "--global"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(("compute", "target-ssl-proxies", "list"), _COMMON_LIST_FLAGS | {"--project"}, 0),
        _CommandPolicy(
            ("compute", "target-ssl-proxies", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("compute", "ssl-certificates", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--region", "--global"},
            0,
        ),
        _CommandPolicy(
            ("compute", "ssl-certificates", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--region", "--global"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("compute", "forwarding-rules", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--region", "--global"},
            0,
        ),
        _CommandPolicy(
            ("compute", "forwarding-rules", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--region", "--global"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("compute", "instances", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--zone"},
            0,
        ),
        _CommandPolicy(
            ("compute", "instances", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--zone"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("compute", "disks", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--zone", "--region"},
            0,
        ),
        _CommandPolicy(
            ("compute", "disks", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--zone", "--region"},
            1,
            _validate_resource_ref_value,
        ),
        # Certificate Authority Service (Private CA)
        _CommandPolicy(
            ("privateca", "pools", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location"},
            0,
        ),
        _CommandPolicy(
            ("privateca", "pools", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("privateca", "pools", "get-iam-policy"),
            _COMMON_IAM_FLAGS | {"--project", "--location"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("privateca", "roots", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location", "--pool"},
            0,
        ),
        _CommandPolicy(
            ("privateca", "roots", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location", "--pool"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("privateca", "subordinates", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location", "--pool"},
            0,
        ),
        _CommandPolicy(
            ("privateca", "subordinates", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location", "--pool"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("privateca", "certificates", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location", "--issuer-pool"},
            0,
        ),
        _CommandPolicy(
            ("privateca", "certificates", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location", "--issuer-pool"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("privateca", "templates", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location"},
            0,
        ),
        _CommandPolicy(
            ("privateca", "templates", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location"},
            1,
            _validate_resource_ref_value,
        ),
        # Certificate Manager
        _CommandPolicy(
            ("certificate-manager", "certificates", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location"},
            0,
        ),
        _CommandPolicy(
            ("certificate-manager", "certificates", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("certificate-manager", "maps", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location"},
            0,
        ),
        _CommandPolicy(
            ("certificate-manager", "maps", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("certificate-manager", "trust-configs", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location"},
            0,
        ),
        _CommandPolicy(
            ("certificate-manager", "trust-configs", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location"},
            1,
            _validate_resource_ref_value,
        ),
        # Resource Hierarchy (Projects, Folders, Organizations)
        _CommandPolicy(("projects", "list"), _COMMON_LIST_FLAGS, 0),
        _CommandPolicy(("projects", "describe"), _COMMON_DESCRIBE_FLAGS, 1, _validate_project_value),
        _CommandPolicy(("projects", "get-iam-policy"), _COMMON_IAM_FLAGS, 1, _validate_project_value),
        _CommandPolicy(("projects", "get-ancestors"), _COMMON_DESCRIBE_FLAGS, 1, _validate_project_value),
        _CommandPolicy(
            ("folders", "list"),
            _COMMON_LIST_FLAGS | {"--organization", "--folder"},
            0,
        ),
        _CommandPolicy(("folders", "describe"), _COMMON_DESCRIBE_FLAGS, 1, _validate_numeric_id_value),
        _CommandPolicy(("folders", "get-iam-policy"), _COMMON_IAM_FLAGS, 1, _validate_numeric_id_value),
        _CommandPolicy(("organizations", "list"), _COMMON_LIST_FLAGS, 0),
        _CommandPolicy(("organizations", "describe"), _COMMON_DESCRIBE_FLAGS, 1, _validate_numeric_id_value),
        _CommandPolicy(("organizations", "get-iam-policy"), _COMMON_IAM_FLAGS, 1, _validate_numeric_id_value),
        # Workload verification groups for MEDIUM-evidence correlation
        _CommandPolicy(("iam", "service-accounts", "list"), _COMMON_LIST_FLAGS | {"--project"}, 0),
        _CommandPolicy(
            ("iam", "service-accounts", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("iam", "service-accounts", "get-iam-policy"),
            _COMMON_IAM_FLAGS | {"--project"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("run", "services", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--region"},
            0,
        ),
        _CommandPolicy(
            ("run", "services", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--region"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("run", "jobs", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--region"},
            0,
        ),
        _CommandPolicy(
            ("run", "jobs", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--region"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(
            ("container", "clusters", "list"),
            _COMMON_LIST_FLAGS | {"--project", "--location", "--region", "--zone"},
            0,
        ),
        _CommandPolicy(
            ("container", "clusters", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--location", "--region", "--zone"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(("sql", "instances", "list"), _COMMON_LIST_FLAGS | {"--project"}, 0),
        _CommandPolicy(
            ("sql", "instances", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(("storage", "buckets", "list"), _COMMON_LIST_FLAGS | {"--project"}, 0),
        _CommandPolicy(
            ("storage", "buckets", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project"},
            1,
            _validate_bucket_positional,
        ),
    ]
    return {p.command_path: p for p in policies}


_COMMAND_POLICIES: Dict[Tuple[str, ...], _CommandPolicy] = _build_command_policies()
ALLOWED_GCLOUD_GROUPS: FrozenSet[str] = frozenset(path[0] for path in _COMMAND_POLICIES)

# Safe OS/Cloud Run environment variables preserved across sanitized gcloud subprocess invocations
_SAFE_BASE_ENV_VARS: Tuple[str, ...] = (
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "K_SERVICE",
    "K_REVISION",
    "K_CONFIGURATION",
    "GOOGLE_CLOUD_PROJECT",
)


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
    """Normalizes any connection mode string or UI label to ('adc', 'impersonation', 'access_token').

    Fails closed with ``ValueError`` if a non-empty unrecognized mode string is supplied, preventing
    untrusted callers from silently resetting or escalating a connection mode to ``adc``.
    """
    if raw_mode is None:
        return "adc"
    cleaned = str(raw_mode).strip().lower()
    if not cleaned:
        return "adc"
    resolved = _MODE_ALIASES.get(cleaned)
    if resolved is None:
        raise ValueError(
            f"Unsupported GCP connection mode '{raw_mode}'. Allowed modes: adc, impersonation, access_token."
        )
    return resolved


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

    try:
        mode = normalize_connection_mode(state.get("mode"))
    except ValueError:
        mode = "adc"

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

    Fails closed with ``PermissionError`` if ``mode == 'access_token'`` has no valid delegated token or if
    ``mode == 'impersonation'`` has no valid allowlisted service account, preventing silent fallback to ADC.
    """
    conn = get_gcp_connection_config(mask_token=False, user_id=user_id)
    mode = normalize_connection_mode(conn.get("mode"))
    impersonated_sa = (conn.get("impersonated_service_account") or "").strip()
    access_token = (conn.get("access_token_preview") or "").strip()
    quota_project = (conn.get("project_id") or "").strip() or None

    if mode == "access_token":
        if not access_token:
            raise PermissionError(
                "ACCESS_TOKEN_REQUIRED: Delegated OAuth access token is missing or expired for mode 'access_token'."
            )
        from google.oauth2 import credentials as oauth2_credentials

        return oauth2_credentials.Credentials(
            token=access_token,
            quota_project_id=quota_project,
        )

    if mode == "impersonation":
        if not impersonated_sa:
            raise PermissionError(
                "IMPERSONATION_TARGET_REQUIRED: No impersonated service account configured for mode 'impersonation'."
            )
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


def _is_blocked_flag_name(canon_flag: str) -> bool:
    if canon_flag in BLOCKED_GCLOUD_FLAGS:
        return True
    return any(canon_flag.startswith(prefix) for prefix in _BLOCKED_FLAG_PREFIXES)


def validate_gcloud_command(command: str) -> Tuple[bool, List[str], str]:
    """Validates a gcloud CLI command against a strict structured grammar and per-command flag allowlist.

    Returns:
        Tuple of ``(is_valid, canonical_subtokens_without_gcloud, status_or_error_message)``.
    """
    if not isinstance(command, str) or not command.strip():
        return False, [], "Empty gcloud command provided."

    raw_cmd = command.strip()
    if _FORBIDDEN_SHELL_PATTERNS.search(raw_cmd) or _CONTROL_CHARS_RE.search(raw_cmd):
        return (
            False,
            [],
            "Blocked: Shell metacharacters or control characters (;, |, &, `, $, >, <, newline) are prohibited.",
        )

    try:
        tokens = shlex.split(raw_cmd, posix=True)
    except ValueError as exc:
        return False, [], f"Invalid command quoting: {exc}"

    if not tokens:
        return False, [], "Empty gcloud command tokens."

    if tokens[0] != "gcloud":
        return False, [], "Blocked: Executable must be literally 'gcloud'."

    subtokens = tokens[1:]
    if not subtokens:
        return False, [], "No gcloud subcommand specified."

    non_flag_tokens: List[str] = []
    parsed_flags: List[Tuple[str, Optional[str]]] = []
    seen_flags: set[str] = set()

    idx = 0
    while idx < len(subtokens):
        tok = subtokens[idx]
        if tok in ("-", "--"):
            return False, subtokens, f"Blocked ambiguous option marker '{tok}'."

        if tok.startswith("-"):
            if tok == "-q":
                raw_flag, has_eq, inline_val = "--quiet", False, ""
            elif not tok.startswith("--"):
                return False, subtokens, f"Blocked short or non-canonical flag '{tok}'."
            else:
                raw_flag, has_eq, inline_val = tok.partition("=")

            canon_flag = raw_flag.lower().replace("_", "-")
            if _is_blocked_flag_name(canon_flag):
                return (
                    False,
                    subtokens,
                    f"Blocked dangerous gcloud flag '{raw_flag}' (endpoint, credential, or config override prohibited).",
                )
            if raw_flag != canon_flag:
                return (
                    False,
                    subtokens,
                    f"Blocked non-canonical flag spelling '{raw_flag}'; use exact lowercase hyphenated flags.",
                )

            spec = _FLAG_SPECS.get(raw_flag)
            if spec is None:
                return False, subtokens, f"Blocked unknown or unapproved gcloud flag '{raw_flag}'."

            if raw_flag in seen_flags:
                return False, subtokens, f"Blocked repeated gcloud flag '{raw_flag}'."
            seen_flags.add(raw_flag)

            if not spec.takes_value:
                if has_eq:
                    return False, subtokens, f"Boolean flag '{raw_flag}' does not accept a value."
                parsed_flags.append((raw_flag, None))
                idx += 1
                continue

            if has_eq:
                if not inline_val:
                    return False, subtokens, f"Flag '{raw_flag}' requires a non-empty value."
                flag_val = inline_val
                idx += 1
            else:
                if idx + 1 >= len(subtokens) or subtokens[idx + 1].startswith("-"):
                    return False, subtokens, f"Flag '{raw_flag}' requires an explicit value."
                flag_val = subtokens[idx + 1]
                idx += 2

            val_err = spec.validator(flag_val) if spec.validator else _check_common_arg_safety(flag_val)
            if val_err:
                return False, subtokens, f"Blocked invalid value for '{raw_flag}': {val_err}"

            parsed_flags.append((raw_flag, flag_val))
            continue

        non_flag_tokens.append(tok)
        idx += 1

    # Standalone `gcloud --version`
    if not non_flag_tokens:
        if "--version" in seen_flags and seen_flags.issubset({"--version", "--format", "--quiet"}):
            canonical_version_tokens = [
                f"{fname}={fval}" if fval is not None else fname for fname, fval in parsed_flags
            ]
            return True, canonical_version_tokens, "Allowed diagnostic version flag."
        return False, subtokens, "No gcloud subcommand or verb found."

    if "--version" in seen_flags:
        return False, subtokens, "Blocked '--version' combined with subcommands."

    if non_flag_tokens[0] in ("alpha", "beta", "preview"):
        return False, subtokens, f"Blocked gcloud release track '{non_flag_tokens[0]}'; use GA commands only."

    if non_flag_tokens[0] in ("config", "auth"):
        return (
            False,
            subtokens,
            f"Blocked gcloud '{non_flag_tokens[0]}' group: configuration and credential commands are prohibited.",
        )

    if non_flag_tokens[0] not in ALLOWED_GCLOUD_GROUPS:
        return (
            False,
            subtokens,
            f"Blocked unapproved gcloud service group '{non_flag_tokens[0]}'.",
        )

    matched_policy: Optional[_CommandPolicy] = None
    for path_len in range(min(len(non_flag_tokens), 5), 0, -1):
        candidate_tuple = tuple(non_flag_tokens[:path_len])
        if any(seg != seg.lower() for seg in candidate_tuple):
            continue
        if candidate_tuple in _COMMAND_POLICIES:
            matched_policy = _COMMAND_POLICIES[candidate_tuple]
            break

    if matched_policy is None:
        for tok in non_flag_tokens:
            low_tok = tok.lower()
            if low_tok in BLOCKED_GCLOUD_VERBS:
                return (
                    False,
                    subtokens,
                    f"Blocked destructive/mutating verb '{low_tok}'. Only read-only diagnostic commands are allowed.",
                )
        return (
            False,
            subtokens,
            "Blocked unapproved gcloud subcommand or verb; command is not in the read-only PQC grammar.",
        )

    cmd_len = len(matched_policy.command_path)
    positional_args = non_flag_tokens[cmd_len:]
    if len(positional_args) != matched_policy.positional_count:
        for extra in positional_args:
            if extra.lower() in BLOCKED_GCLOUD_VERBS:
                return (
                    False,
                    subtokens,
                    f"Blocked destructive/mutating verb '{extra.lower()}'.",
                )
        return (
            False,
            subtokens,
            (
                f"Blocked: Command 'gcloud {' '.join(matched_policy.command_path)}' expects "
                f"{matched_policy.positional_count} positional argument(s), got {len(positional_args)}."
            ),
        )

    for pos_val in positional_args:
        pos_validator = matched_policy.positional_validator or _validate_resource_ref_value
        pos_err = pos_validator(pos_val)
        if pos_err:
            return False, subtokens, f"Blocked invalid positional argument: {pos_err}"

    for fname, _ in parsed_flags:
        if fname not in matched_policy.allowed_flags:
            return (
                False,
                subtokens,
                f"Blocked flag '{fname}': not permitted for 'gcloud {' '.join(matched_policy.command_path)}'.",
            )

    if "--global" in seen_flags and ("--region" in seen_flags or "--zone" in seen_flags):
        return False, subtokens, "Blocked conflicting scope flags ('--global' cannot be combined with '--region'/'--zone')."

    canonical_tokens: List[str] = list(matched_policy.command_path) + list(positional_args)
    for fname, fval in parsed_flags:
        canonical_tokens.append(f"{fname}={fval}" if fval is not None else fname)

    return True, canonical_tokens, "Validated read-only diagnostic gcloud command."


def _ensure_isolated_gcloud_config_dir(suffix: str) -> str:
    path = os.path.join(tempfile.gettempdir(), f"pqc-gcloud-{suffix}-{os.getuid()}")
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def build_sanitized_gcloud_env(
    *,
    mode: str,
    project_id: Optional[str] = None,
    has_explicit_project_flag: bool = False,
    access_token: Optional[str] = None,
    impersonated_service_account: Optional[str] = None,
    source_env: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    """Constructs a sanitized subprocess environment from an explicit allowlist.

    Unconditionally excludes `CLOUDSDK_API_ENDPOINT_OVERRIDES_*`, `CLOUDSDK_PROXY_*`, `HTTP_PROXY`,
    `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` (and lowercase variants), `GCE_METADATA_*`, custom CA/TLS
    override variables, and ambient `CLOUDSDK_AUTH_*` overrides.
    """
    src = source_env if source_env is not None else os.environ
    env: Dict[str, str] = {}

    for key in _SAFE_BASE_ENV_VARS:
        val = src.get(key)
        if val and not _CONTROL_CHARS_RE.search(val):
            env[key] = val

    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    cloudsdk_py = src.get("CLOUDSDK_PYTHON", "").strip()
    if cloudsdk_py and os.path.isfile(cloudsdk_py) and os.access(cloudsdk_py, os.X_OK):
        env["CLOUDSDK_PYTHON"] = cloudsdk_py

    env["CLOUDSDK_CORE_DISABLE_PROMPTS"] = "1"
    env["CLOUDSDK_CORE_DISABLE_USAGE_REPORTING"] = "true"
    env["CLOUDSDK_METRICS_ENVIRONMENT"] = "datacloud.antigravity"

    if project_id and not has_explicit_project_flag and _validate_project_value(project_id) is None:
        env["CLOUDSDK_CORE_PROJECT"] = project_id

    canonical_mode = normalize_connection_mode(mode)
    if canonical_mode == "access_token":
        clean_tok = (access_token or "").strip()
        if not clean_tok:
            raise PermissionError(
                "ACCESS_TOKEN_REQUIRED: Delegated OAuth access token is missing or expired for mode 'access_token'."
            )
        # Isolate CLOUDSDK_CONFIG to an empty directory and omit GOOGLE_APPLICATION_CREDENTIALS so gcloud
        # can NEVER fall back to workstation or container ambient credentials.
        env["CLOUDSDK_CONFIG"] = _ensure_isolated_gcloud_config_dir("token-isolated")
        env["CLOUDSDK_AUTH_ACCESS_TOKEN"] = clean_tok
    elif canonical_mode == "impersonation":
        clean_sa = validate_impersonated_service_account(impersonated_service_account or "")
        if not clean_sa:
            raise PermissionError(
                "IMPERSONATION_TARGET_REQUIRED: Service account principal is required for mode 'impersonation'."
            )
        gac = src.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        if gac and os.path.isfile(gac):
            env["GOOGLE_APPLICATION_CREDENTIALS"] = gac
        src_cfg = src.get("CLOUDSDK_CONFIG", "").strip()
        if src_cfg and os.path.isdir(src_cfg) and _check_common_arg_safety(src_cfg) is None:
            env["CLOUDSDK_CONFIG"] = src_cfg
        env["CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"] = clean_sa
    else:
        # Trusted explicit 'adc' mode: preserve Cloud Run ADC / local ADC without endpoint or proxy overrides.
        gac = src.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        if gac and os.path.isfile(gac):
            env["GOOGLE_APPLICATION_CREDENTIALS"] = gac
        src_cfg = src.get("CLOUDSDK_CONFIG", "").strip()
        if src_cfg and os.path.isdir(src_cfg) and _check_common_arg_safety(src_cfg) is None:
            env["CLOUDSDK_CONFIG"] = src_cfg

    # Defense-in-depth post-assertion: ensure zero endpoint override or proxy keys exist.
    for k in list(env.keys()):
        ku = k.upper()
        if (
            ku.startswith("CLOUDSDK_API_ENDPOINT_OVERRIDES")
            or ku.startswith("CLOUDSDK_PROXY")
            or ku.endswith("_PROXY")
            or ku in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
        ):
            env.pop(k, None)

    return env


def _scrub_output(text: Optional[str], *, secret_values: Sequence[str] = ()) -> str:
    cleaned = egress_guard.redact_sensitive_text(text or "")
    for secret in secret_values:
        s = (secret or "").strip()
        if len(s) >= 8 and s in cleaned:
            cleaned = cleaned.replace(s, "[REDACTED]")
    return cleaned


def execute_gcloud_command(command: str) -> str:
    """Executes a strictly validated read-only `gcloud` CLI command using the tenant's active connection mode.

    Security invariants:
    - Validates command group, verb, positional arguments, and per-command flags via `validate_gcloud_command()`.
    - Sanitizes subprocess environment via `build_sanitized_gcloud_env()`.
    - Enforces strict tenant isolation in `access_token` mode: never retries with or falls back to server ADC.
    """
    start_ts = time.time()
    is_valid, tokens, validation_msg = validate_gcloud_command(command)
    conn_cfg = get_gcp_connection_config(mask_token=False)
    mode = conn_cfg["mode"]
    mode_label = conn_cfg["mode_label"]
    raw_token = (conn_cfg.get("access_token_preview") or "").strip()

    if not is_valid:
        blocked_payload = {
            "status": "BLOCKED_DESTRUCTIVE_OR_INVALID_COMMAND",
            "command_requested": _scrub_output(command, secret_values=(raw_token,)),
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "exit_code": 126,
            "stdout": "",
            "stderr": _scrub_output(validation_msg, secret_values=(raw_token,)),
            "duration_ms": round((time.time() - start_ts) * 1000, 2),
        }
        _record_gcloud_trace(blocked_payload)
        return json.dumps(blocked_payload, ensure_ascii=False)

    display_cmd = "gcloud " + " ".join(shlex.quote(t) for t in tokens)

    # Fail closed BEFORE resolving/spawning gcloud if delegated or impersonated credentials are missing/invalid.
    try:
        has_project_flag = any(t == "--project" or t.startswith("--project=") for t in tokens)
        env = build_sanitized_gcloud_env(
            mode=mode,
            project_id=conn_cfg.get("project_id"),
            has_explicit_project_flag=has_project_flag,
            access_token=raw_token if mode == "access_token" else None,
            impersonated_service_account=(
                conn_cfg.get("impersonated_service_account") if mode == "impersonation" else None
            ),
        )
    except (PermissionError, ValueError) as cred_err:
        err_code = (
            "ACCESS_TOKEN_REQUIRED"
            if mode == "access_token"
            else ("IMPERSONATION_ERROR" if mode == "impersonation" else "CREDENTIAL_CONFIG_ERROR")
        )
        denied_payload = {
            "status": "COMMAND_ERROR",
            "error_code": err_code,
            "command_executed": display_cmd,
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "exit_code": 1,
            "stdout": "",
            "stderr": _scrub_output(str(cred_err), secret_values=(raw_token,)),
            "duration_ms": round((time.time() - start_ts) * 1000, 2),
        }
        _record_gcloud_trace(denied_payload)
        return json.dumps(denied_payload, ensure_ascii=False)

    gcloud_bin = _resolve_gcloud_binary()
    if not gcloud_bin:
        missing_payload = {
            "status": "GCLOUD_BINARY_NOT_FOUND",
            "command_requested": _scrub_output(command, secret_values=(raw_token,)),
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "exit_code": 127,
            "stdout": "",
            "stderr": "The 'gcloud' CLI binary is not installed on PATH in this environment.",
            "duration_ms": round((time.time() - start_ts) * 1000, 2),
        }
        _record_gcloud_trace(missing_payload)
        return json.dumps(missing_payload, ensure_ascii=False)

    exec_tokens = [gcloud_bin] + list(tokens)
    if "--quiet" not in tokens:
        exec_tokens.append("--quiet")

    try:
        proc = subprocess.run(
            exec_tokens,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            shell=False,
        )

        # Scope-narrowing helper ONLY when already explicitly running in trusted server 'adc' mode on the
        # built-in lab org (31564119954 -> folder 534285347409). NEVER runs in 'access_token' or 'impersonation' mode!
        if (
            mode == "adc"
            and proc.returncode != 0
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
                fb_proc = subprocess.run(
                    fb_tokens,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=env,
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
                    display_cmd = "gcloud " + " ".join(shlex.quote(t) for t in tokens)

        duration_ms = round((time.time() - start_ts) * 1000, 2)
        result_payload = {
            "status": "SUCCESS" if proc.returncode == 0 else "COMMAND_ERROR",
            "command_executed": display_cmd,
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "impersonated_service_account": (
                conn_cfg.get("impersonated_service_account") if mode == "impersonation" else None
            ),
            "exit_code": proc.returncode,
            "stdout": _scrub_output(proc.stdout, secret_values=(raw_token,))[:32000],
            "stderr": _scrub_output(proc.stderr, secret_values=(raw_token,))[:8000],
            "duration_ms": duration_ms,
        }
        _record_gcloud_trace(result_payload)
        return json.dumps(result_payload, ensure_ascii=False)
    except subprocess.TimeoutExpired:
        timeout_payload = {
            "status": "TIMEOUT",
            "command_executed": display_cmd,
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
            "command_executed": display_cmd,
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "exit_code": 1,
            "stdout": "",
            "stderr": _scrub_output(str(exc), secret_values=(raw_token,)),
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
