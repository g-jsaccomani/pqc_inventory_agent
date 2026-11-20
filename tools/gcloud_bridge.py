"""Antigravity-Style 'gcloud' CLI Execution Bridge & Dynamic GCP Connection Manager.

Supports 3 connection modes:
1. 'access_token' ('User gcloud Access Token' / 3-Legged OAuth — default for all external/non-admin users)
2. 'impersonation' ('Service Account Impersonation' — default-deny; requires explicit server-side allowlist
   `PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS`)
3. 'adc' ('Service Account (Default ADC)' — default-deny; restricted strictly to server-authorized administrators
   in `PQC_ADMIN_EMAILS`)

Security Guarantees (Phase 1–3.1 + P0 Authorization Hotfix):
- **Default-Deny Server ADC & Impersonation:** External users cannot activate, persist, default into, or auto-switch
  into `mode='adc'` or unauthorized `mode='impersonation'`. Authorization is enforced across HTTP routes,
  `set_gcp_connection_config()`, `get_gcp_connection_config()`, `get_active_gcp_credentials()`,
  `build_sanitized_gcloud_env()`, and `execute_gcloud_command()`.
- **Independent Tenant & Resource Scope Enforcement:** `authorize_gcloud_command_scope()` validates `--project`,
  `--organization`, `--folder`, `--scope`, positional hierarchy arguments, embedded `projects/...`,
  `organizations/...`, `folders/...` resource paths, and service-account principals independently of the command
  grammar, rejecting unscoped enumeration and cross-tenant queries before any subprocess executes.
- **Trusted Executable Resolution:** `resolve_trusted_gcloud_binary()` never consults `PATH` or `shutil.which()`;
  it resolves only root/system-installed `gcloud` binaries from `TRUSTED_GCLOUD_PATHS` with `realpath` and
  world-writable permission checks.
- **Zero Confused-Deputy Fallback:** Delegated `access_token` failures never retry or escalate to server ADC.
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
import stat
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)

DEFAULT_TENANT_USER_ID = "sec-architect"
_CURRENT_USER_ID: contextvars.ContextVar[str] = contextvars.ContextVar(
    "pqc_current_user_id", default=DEFAULT_TENANT_USER_ID
)


def normalize_user_id(user_id: Optional[str]) -> str:
    """Normalizes a user identifier or corporate email (stripping Cloud IAP prefixes if present)."""
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


def _is_authenticated_email_identity(user_id: Optional[str]) -> bool:
    norm = normalize_user_id(user_id)
    if not norm or norm == DEFAULT_TENANT_USER_ID or "@" not in norm:
        return False
    local_part, _, domain = norm.rpartition("@")
    return bool(local_part and domain)


def is_adc_authorized_user(user_id: Optional[str]) -> bool:
    """Returns True ONLY if `user_id` is explicitly authorized for server ADC via `PQC_ADMIN_EMAILS`.

    Default-deny in all environments (including local dev/test): never trusts client parameters, scopes,
    headers, project IDs, organization IDs, session IDs, or absence of `K_SERVICE`.
    """
    if not _is_authenticated_email_identity(user_id):
        return False
    from pqc_agent import auth_guard

    norm_uid = normalize_user_id(user_id)
    admins = auth_guard.admin_emails()
    if not admins:
        return False
    return norm_uid in admins


def authorize_adc_mode(user_id: Optional[str]) -> str:
    """Validates that `user_id` is authorized to activate or execute under server ADC; raises `PermissionError` otherwise."""
    norm_uid = normalize_user_id(user_id)
    if not is_adc_authorized_user(norm_uid):
        raise PermissionError(
            "ADC_UNAUTHORIZED: Forbidden: Server Service Account (ADC) mode is restricted to server-authorized "
            "administrators (PQC_ADMIN_EMAILS). External and non-administrative users must use delegated OAuth 2.0 credentials."
        )
    return norm_uid


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

# Trusted absolute installation paths for the `gcloud` CLI executable (never resolved from PATH or ~)
TRUSTED_GCLOUD_PATHS: Tuple[str, ...] = (
    "/usr/bin/gcloud",
    "/usr/local/bin/gcloud",
    "/google-cloud-sdk/bin/gcloud",
    "/opt/google-cloud-sdk/bin/gcloud",
    "/usr/lib/google-cloud-sdk/bin/gcloud",
    "/snap/google-cloud-cli/current/bin/gcloud",
    "/opt/homebrew/bin/gcloud",
)

TRUSTED_GCLOUD_REALPATH_PREFIXES: Tuple[str, ...] = (
    "/usr/bin/",
    "/usr/local/",
    "/usr/lib/google-cloud-sdk/",
    "/usr/share/google-cloud-sdk/",
    "/google-cloud-sdk/",
    "/opt/google-cloud-sdk/",
    "/snap/google-cloud-cli/",
    "/opt/homebrew/",
)

TRUSTED_SUBPROCESS_PATH = (
    "/usr/bin:/bin:/usr/local/bin:/google-cloud-sdk/bin:/opt/google-cloud-sdk/bin:/opt/homebrew/bin"
)

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
    "--billing-project",
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

# Embedded resource hierarchy extractors for independent scope enforcement
_EMBEDDED_PROJECT_RE = re.compile(r"(?:^|/)projects/((?:[a-z0-9.-]+:)?[a-zA-Z0-9_-]+)")
_EMBEDDED_ORG_RE = re.compile(r"(?:^|/)organizations/([0-9]+)")
_EMBEDDED_FOLDER_RE = re.compile(r"(?:^|/)folders/([0-9]+)")
_EMBEDDED_SA_PROJECT_RE = re.compile(r"[a-zA-Z0-9._-]+@([a-zA-Z0-9.-]+)\.iam\.gserviceaccount\.com")

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


@dataclass(frozen=True)
class AuthorizedTenantScope:
    """Authorized GCP resource hierarchy boundaries for a specific authenticated tenant caller."""

    user_id: str
    projects: FrozenSet[str]
    organizations: FrozenSet[str]
    folders: FrozenSet[str]


@dataclass(frozen=True)
class _ServerScopePolicy:
    has_project_restriction: bool
    projects: FrozenSet[str]
    has_org_restriction: bool
    organizations: FrozenSet[str]
    has_folder_restriction: bool
    folders: FrozenSet[str]

    @property
    def has_any_restriction(self) -> bool:
        return bool(self.has_project_restriction or self.has_org_restriction or self.has_folder_restriction)


def _check_common_arg_safety(value: str) -> Optional[str]:
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
    if _URL_SCHEME_IN_VALUE_RE.search(value):
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

# Service groups whose commands are inherently project-scoped when `--project` is omitted
_PROJECT_SCOPED_GROUPS: FrozenSet[str] = frozenset(
    {"kms", "compute", "privateca", "certificate-manager", "iam", "run", "container", "sql", "storage"}
)


def _build_command_policies() -> Dict[Tuple[str, ...], _CommandPolicy]:
    policies: List[_CommandPolicy] = [
        # Local binary version diagnostic
        _CommandPolicy(("version",), frozenset({"--format", "--quiet"}), 0),
        # Cloud KMS
        _CommandPolicy(("kms", "keyrings", "list"), _COMMON_LIST_FLAGS | {"--project", "--location"}, 0),
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
        _CommandPolicy(("kms", "keys", "list"), _COMMON_LIST_FLAGS | {"--project", "--location", "--keyring"}, 0),
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
        _CommandPolicy(("compute", "instances", "list"), _COMMON_LIST_FLAGS | {"--project", "--zone"}, 0),
        _CommandPolicy(
            ("compute", "instances", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--zone"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(("compute", "disks", "list"), _COMMON_LIST_FLAGS | {"--project", "--zone", "--region"}, 0),
        _CommandPolicy(
            ("compute", "disks", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--zone", "--region"},
            1,
            _validate_resource_ref_value,
        ),
        # Certificate Authority Service (Private CA)
        _CommandPolicy(("privateca", "pools", "list"), _COMMON_LIST_FLAGS | {"--project", "--location"}, 0),
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
        _CommandPolicy(("privateca", "templates", "list"), _COMMON_LIST_FLAGS | {"--project", "--location"}, 0),
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
        # Scoped Resource Hierarchy Inspection (`projects list` and `organizations list` intentionally excluded: unscoped!)
        _CommandPolicy(("projects", "describe"), _COMMON_DESCRIBE_FLAGS, 1, _validate_project_value),
        _CommandPolicy(("projects", "get-iam-policy"), _COMMON_IAM_FLAGS, 1, _validate_project_value),
        _CommandPolicy(("projects", "get-ancestors"), _COMMON_DESCRIBE_FLAGS, 1, _validate_project_value),
        _CommandPolicy(("folders", "list"), _COMMON_LIST_FLAGS | {"--organization", "--folder"}, 0),
        _CommandPolicy(("folders", "describe"), _COMMON_DESCRIBE_FLAGS, 1, _validate_numeric_id_value),
        _CommandPolicy(("folders", "get-iam-policy"), _COMMON_IAM_FLAGS, 1, _validate_numeric_id_value),
        _CommandPolicy(("organizations", "describe"), _COMMON_DESCRIBE_FLAGS, 1, _validate_numeric_id_value),
        _CommandPolicy(("organizations", "get-iam-policy"), _COMMON_IAM_FLAGS, 1, _validate_numeric_id_value),
        # Workload verification groups (`storage buckets describe` excluded: global bucket namespace bypasses --project!)
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
        _CommandPolicy(("run", "services", "list"), _COMMON_LIST_FLAGS | {"--project", "--region"}, 0),
        _CommandPolicy(
            ("run", "services", "describe"),
            _COMMON_DESCRIBE_FLAGS | {"--project", "--region"},
            1,
            _validate_resource_ref_value,
        ),
        _CommandPolicy(("run", "jobs", "list"), _COMMON_LIST_FLAGS | {"--project", "--region"}, 0),
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
    ]
    return {p.command_path: p for p in policies}


_COMMAND_POLICIES: Dict[Tuple[str, ...], _CommandPolicy] = _build_command_policies()
ALLOWED_GCLOUD_GROUPS: FrozenSet[str] = frozenset(path[0] for path in _COMMAND_POLICIES)

# Safe OS/Cloud Run environment variables preserved across sanitized gcloud subprocess invocations
_SAFE_BASE_ENV_VARS: Tuple[str, ...] = (
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


def _principal_matches_rule(user_id: Optional[str], principal_pattern: str) -> bool:
    if principal_pattern == "*":
        return True
    if not _is_authenticated_email_identity(user_id):
        return False
    norm_uid = normalize_user_id(user_id)
    pat = principal_pattern.strip().lower()
    if pat.startswith("@"):
        return norm_uid.endswith(pat)
    return norm_uid == pat


def _parse_scoped_allowlist_env(env_var_name: str, user_id: Optional[str]) -> Tuple[bool, FrozenSet[str]]:
    """Parses comma-separated global or `principal=value` allowlist entries from a server environment variable."""
    raw = (os.getenv(env_var_name) or "").strip()
    if not raw:
        return False, frozenset()
    matched: Set[str] = set()
    for item in raw.split(","):
        token = item.strip()
        if not token:
            continue
        if "=" in token:
            principal_pat, _, val = token.partition("=")
            clean_val = val.strip()
            if clean_val and _principal_matches_rule(user_id, principal_pat):
                matched.add(clean_val)
        else:
            matched.add(token)
    return True, frozenset(matched)


def _load_server_scope_policy(user_id: Optional[str]) -> _ServerScopePolicy:
    """Loads non-spoofable server-side project/organization/folder authorization rules for `user_id`."""
    has_proj, projs_set = _parse_scoped_allowlist_env("PQC_ALLOWED_PROJECTS", user_id)
    has_org, orgs_set = _parse_scoped_allowlist_env("PQC_ALLOWED_ORGANIZATIONS", user_id)
    has_fld, flds_set = _parse_scoped_allowlist_env("PQC_ALLOWED_FOLDERS", user_id)

    projs = {p.replace("projects/", "") for p in projs_set}
    orgs = {o.replace("organizations/", "") for o in orgs_set}
    flds = {f.replace("folders/", "") for f in flds_set}

    raw_json = (os.getenv("PQC_TENANT_SCOPE_POLICY") or "").strip()
    if raw_json:
        has_proj = True
        has_org = True
        has_fld = True
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, Mapping):
                for key, spec in parsed.items():
                    if _principal_matches_rule(user_id, str(key)) and isinstance(spec, Mapping):
                        for p in spec.get("projects") or []:
                            if str(p).strip():
                                projs.add(str(p).strip().replace("projects/", ""))
                        for o in spec.get("organizations") or []:
                            if str(o).strip():
                                orgs.add(str(o).strip().replace("organizations/", ""))
                        for fl in spec.get("folders") or []:
                            if str(fl).strip():
                                flds.add(str(fl).strip().replace("folders/", ""))
        except Exception as exc:
            logger.error("Invalid PQC_TENANT_SCOPE_POLICY JSON configuration; failing closed: %s", type(exc).__name__)
            return _ServerScopePolicy(True, frozenset(), True, frozenset(), True, frozenset())

    return _ServerScopePolicy(
        has_project_restriction=has_proj,
        projects=frozenset(projs),
        has_org_restriction=has_org,
        organizations=frozenset(orgs),
        has_folder_restriction=has_fld,
        folders=frozenset(flds),
    )


def resolve_server_bound_defaults(user_id: Optional[str]) -> Tuple[str, str, str]:
    """Returns unambiguous `(org_id, project_id, active_scope_uri)` derived strictly from server scope policy."""
    if not _is_authenticated_email_identity(user_id):
        return "", "", ""
    policy = _load_server_scope_policy(user_id)
    if not policy.has_any_restriction:
        return "", "", ""

    valid_orgs = sorted(o for o in policy.organizations if _validate_numeric_id_value(o) is None)
    valid_projs = sorted(p for p in policy.projects if _validate_project_value(p) is None)
    valid_folders = sorted(f for f in policy.folders if _validate_numeric_id_value(f) is None)

    default_org = valid_orgs[0] if len(valid_orgs) == 1 else ""
    default_proj = valid_projs[0] if len(valid_projs) == 1 else ""
    default_folder = valid_folders[0] if len(valid_folders) == 1 else ""

    if default_org:
        active_uri = f"organizations/{default_org}"
    elif default_proj:
        active_uri = f"projects/{default_proj}"
    elif default_folder:
        active_uri = f"folders/{default_folder}"
    else:
        active_uri = ""
    return default_org, default_proj, active_uri


def _default_connection_template(user_id: Optional[str] = None) -> Dict[str, Any]:
    """Returns default connection state: ADC + server scope ONLY for ADC-authorized admins; `access_token` + server-bound scope (or empty) for all others."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    policy = _load_server_scope_policy(user_id) if _is_authenticated_email_identity(user_id) else None
    srv_org, srv_proj, _ = resolve_server_bound_defaults(user_id)
    if is_adc_authorized_user(user_id):
        raw_env_mode = (os.getenv("PQC_CONNECTION_MODE") or "adc").strip()
        try:
            resolved_mode = normalize_connection_mode(raw_env_mode)
        except ValueError:
            resolved_mode = "adc"
        if policy is not None and policy.has_any_restriction:
            env_org = os.getenv("GCP_ORGANIZATION_ID", "31564119954").strip().replace("organizations/", "")
            env_proj = os.getenv("GOOGLE_CLOUD_PROJECT", "pqc-inventory-agent-cd06").strip().replace("projects/", "")
            admin_org = env_org if env_org in policy.organizations else srv_org
            admin_proj = env_proj if env_proj in policy.projects else srv_proj
        else:
            admin_org = os.getenv("GCP_ORGANIZATION_ID", "31564119954")
            admin_proj = os.getenv("GOOGLE_CLOUD_PROJECT", "pqc-inventory-agent-cd06")
        return {
            "mode": resolved_mode,
            "organization_id": admin_org,
            "project_id": admin_proj,
            "location": os.getenv("PQC_DEFAULT_LOCATION", "all"),
            "impersonated_service_account": "",
            "updated_at": now_iso,
        }
    return {
        "mode": "access_token",
        "organization_id": srv_org,
        "project_id": srv_proj,
        "location": os.getenv("PQC_DEFAULT_LOCATION", "all"),
        "impersonated_service_account": "",
        "updated_at": now_iso,
    }


def _extract_sa_project(sa_email: str) -> str:
    m = _EMBEDDED_SA_PROJECT_RE.fullmatch(sa_email.strip())
    return m.group(1) if m else ""


def validate_impersonated_service_account(sa_email: str, *, user_id: Optional[str] = None) -> str:
    """Validates a target GCP Service Account email and enforces default-deny `PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS`."""
    clean = str(sa_email or "").strip()
    if not clean:
        return ""
    if not _SA_EMAIL_PATTERN.match(clean):
        raise ValueError(
            f"Invalid GCP service account principal '{clean}'. Expected '<name>@<project>.iam.gserviceaccount.com'."
        )
    allowlist_raw = (os.getenv("PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS") or "").strip()
    if not allowlist_raw:
        raise PermissionError(
            "Forbidden: Service account impersonation requires PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS "
            "to be explicitly configured on the server."
        )

    effective_uid = user_id if user_id is not None else get_current_tenant_user()
    low = clean.lower()
    permitted = False
    for raw_entry in allowlist_raw.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        if "=" in entry:
            principal_pat, _, sa_rule_raw = entry.partition("=")
            sa_rule = sa_rule_raw.strip().lower()
            if not sa_rule or not _principal_matches_rule(effective_uid, principal_pat):
                continue
            if low == sa_rule or (sa_rule.startswith("@") and low.endswith(sa_rule)):
                permitted = True
                break
        else:
            sa_rule = entry.lower()
            if low == sa_rule or (sa_rule.startswith("@") and low.endswith(sa_rule)):
                permitted = True
                break

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
    """Normalizes a non-empty connection mode string to ('adc', 'impersonation', 'access_token').

    Fails closed with ``ValueError`` if empty or unrecognized, never defaulting untrusted input to ``adc``.
    """
    if raw_mode is None:
        raise ValueError("Connection mode is required.")
    cleaned = str(raw_mode).strip().lower()
    if not cleaned:
        raise ValueError("Connection mode cannot be empty.")
    resolved = _MODE_ALIASES.get(cleaned)
    if resolved is None:
        raise ValueError(
            f"Unsupported GCP connection mode '{raw_mode}'. Allowed modes: adc, impersonation, access_token."
        )
    return resolved


def _validate_delegated_access_token_syntax(token: str) -> Optional[str]:
    if not token:
        return None
    if len(token) < 6 or not token.isascii() or _CONTROL_CHARS_RE.search(token) or any(ch.isspace() for ch in token):
        return "ACCESS_TOKEN_INVALID: Delegated OAuth access token is malformed."
    return None


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
    """Updates a tenant's GCP connection configuration after enforcing ADC, impersonation, and scope authorization.

    Fails closed with ``PermissionError`` or ``ValueError`` BEFORE any database write if unauthorized.
    """
    from pqc_agent import auth_guard, auth_store, credential_service

    active_ctx_uid = get_current_tenant_user()
    uid = normalize_user_id(user_id or active_ctx_uid)
    if _is_authenticated_email_identity(active_ctx_uid) and uid != active_ctx_uid:
        raise PermissionError(
            f"Forbidden: authenticated caller '{active_ctx_uid}' cannot modify connection settings for '{uid}'."
        )

    norm_mode = normalize_connection_mode(mode) if mode is not None else None
    store = auth_store.get_active_auth_store()
    existing_row = store.get_user_connection(uid)
    defaults = _default_connection_template(uid)

    target_mode = norm_mode or (existing_row.get("mode") if existing_row else None) or defaults["mode"]
    if target_mode == "adc":
        authorize_adc_mode(uid)

    clean_sa: Optional[str] = None
    if impersonated_service_account is not None:
        raw_sa = str(impersonated_service_account).strip()
        if raw_sa:
            if not _is_authenticated_email_identity(uid):
                raise PermissionError("Forbidden: Service account impersonation requires an authenticated user identity.")
            clean_sa = validate_impersonated_service_account(raw_sa, user_id=uid)
        else:
            clean_sa = ""

    if target_mode == "impersonation":
        if not _is_authenticated_email_identity(uid):
            raise PermissionError("Forbidden: Service account impersonation requires an authenticated user identity.")
        effective_sa = (
            clean_sa
            if clean_sa is not None
            else str((existing_row or {}).get("impersonated_service_account") or "").strip()
        )
        if not effective_sa:
            raise ValueError("impersonated_service_account is required when connection mode is 'impersonation'.")
        validate_impersonated_service_account(effective_sa, user_id=uid)

    server_scope = _load_server_scope_policy(uid)
    adc_admin = is_adc_authorized_user(uid)
    in_prod = auth_guard.is_production_environment()
    existing_org = str((existing_row or {}).get("organization_id") or "").strip().replace("organizations/", "")
    existing_proj = str((existing_row or {}).get("project_id") or "").strip().replace("projects/", "")

    clean_org: Optional[str] = None
    if organization_id is not None and str(organization_id).strip():
        candidate_org = str(organization_id).strip().replace("organizations/", "")
        org_err = _validate_numeric_id_value(candidate_org)
        if org_err:
            raise ValueError(org_err)
        if server_scope.has_any_restriction:
            if candidate_org not in server_scope.organizations:
                raise PermissionError(
                    f"UNAUTHORIZED_RESOURCE_SCOPE: Organization '{candidate_org}' is outside the server-authorized scope for '{uid}'."
                )
        elif not adc_admin:
            if in_prod:
                raise PermissionError(
                    f"UNAUTHORIZED_RESOURCE_SCOPE (MISSING_AUTHORIZED_SCOPE): Tenant '{uid}' cannot self-bind "
                    "organization scope in production without a server-side tenant scope policy "
                    "(PQC_TENANT_SCOPE_POLICY or PQC_ALLOWED_ORGANIZATIONS)."
                )
            if existing_org and candidate_org != existing_org:
                raise PermissionError(
                    f"UNAUTHORIZED_RESOURCE_SCOPE: Tenant '{uid}' cannot change its bound organization "
                    f"from '{existing_org}' to '{candidate_org}' via request payload."
                )
            if not existing_org and existing_proj:
                raise PermissionError(
                    f"UNAUTHORIZED_RESOURCE_SCOPE: Tenant '{uid}' is bound to project '{existing_proj}' and cannot "
                    f"self-bind organization '{candidate_org}' without a server-side tenant scope policy."
                )
        clean_org = candidate_org

    clean_proj: Optional[str] = None
    if project_id is not None and str(project_id).strip():
        candidate_proj = str(project_id).strip().replace("projects/", "")
        proj_err = _validate_project_value(candidate_proj)
        if proj_err:
            raise ValueError(proj_err)
        if server_scope.has_any_restriction:
            if candidate_proj not in server_scope.projects:
                raise PermissionError(
                    f"UNAUTHORIZED_RESOURCE_SCOPE: Project '{candidate_proj}' is outside the server-authorized scope for '{uid}'."
                )
        elif not adc_admin:
            if in_prod:
                raise PermissionError(
                    f"UNAUTHORIZED_RESOURCE_SCOPE (MISSING_AUTHORIZED_SCOPE): Tenant '{uid}' cannot self-bind "
                    "project scope in production without a server-side tenant scope policy "
                    "(PQC_TENANT_SCOPE_POLICY or PQC_ALLOWED_PROJECTS)."
                )
            if existing_proj and candidate_proj != existing_proj:
                raise PermissionError(
                    f"UNAUTHORIZED_RESOURCE_SCOPE: Tenant '{uid}' cannot change its bound project "
                    f"from '{existing_proj}' to '{candidate_proj}' via request payload."
                )
            if not existing_proj and existing_org:
                raise PermissionError(
                    f"UNAUTHORIZED_RESOURCE_SCOPE: Tenant '{uid}' is bound to organization '{existing_org}' and cannot "
                    f"self-bind project '{candidate_proj}' without a server-side tenant scope policy."
                )
        clean_proj = candidate_proj
    elif target_mode == "impersonation" and not existing_proj:
        sa_for_proj = clean_sa or str((existing_row or {}).get("impersonated_service_account") or "")
        derived_proj = _extract_sa_project(sa_for_proj)
        if derived_proj and _validate_project_value(derived_proj) is None:
            if not server_scope.has_any_restriction or derived_proj in server_scope.projects:
                clean_proj = derived_proj

    # Server-side scope auto-binding: when server policy unambiguously defines a single org/project for this tenant,
    # bind it server-side so delegated tokens work seamlessly without requiring client-supplied scope parameters.
    if server_scope.has_any_restriction:
        srv_org, srv_proj, _ = resolve_server_bound_defaults(uid)
        if clean_org is None and srv_org:
            clean_org = srv_org
        if clean_proj is None and srv_proj:
            clean_proj = srv_proj

    # Validate delegated token syntax & TTL BEFORE writing connection state to the database.
    validated_token: Optional[str] = None
    if access_token is not None:
        tok = str(access_token).strip()
        if tok.lower().startswith("bearer "):
            tok = tok[7:].strip()
        if tok:
            tok_err = _validate_delegated_access_token_syntax(tok)
            if tok_err:
                raise ValueError(tok_err)
            if access_token_expires_in is not None:
                try:
                    ttl_val = float(access_token_expires_in)
                except (TypeError, ValueError) as exc:
                    raise ValueError("Invalid delegated OAuth access token expiration.") from exc
                if ttl_val <= 0:
                    raise ValueError("ACCESS_TOKEN_EXPIRED: Delegated OAuth access token is already expired.")
        validated_token = tok

    clean_loc: Optional[str] = None
    if location is not None and str(location).strip():
        clean_loc = str(location).strip()

    store.upsert_user_connection(
        user_id=uid,
        mode=norm_mode,
        organization_id=clean_org,
        project_id=clean_proj,
        location=clean_loc,
        impersonated_service_account=clean_sa,
        defaults=defaults,
    )

    if validated_token is not None:
        cred_svc = credential_service.get_active_credential_service()
        if validated_token:
            cred_svc.store_delegated_token(
                user_id=uid,
                access_token=validated_token,
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
    """Returns the current GCP connection state (never reporting unauthorized `adc` or unauthorized scopes as active)."""
    from pqc_agent import auth_guard, auth_store, credential_service

    uid = normalize_user_id(user_id or get_current_tenant_user())
    stored = auth_store.get_active_auth_store().get_user_connection(uid)
    defaults = _default_connection_template(uid)
    state = stored if stored is not None else defaults

    raw_token = ""
    token_expires_at: Optional[float] = None
    has_refresh_token = False
    kek_provider: Optional[str] = None

    is_auth_email = _is_authenticated_email_identity(uid)
    if is_auth_email or stored is not None:
        loaded_cred = credential_service.get_active_credential_service().load_delegated_token(
            user_id=uid,
            caller_user_id=uid,
        )
        if loaded_cred is not None:
            raw_token = loaded_cred.access_token
            token_expires_at = loaded_cred.expires_at
            has_refresh_token = loaded_cred.has_refresh_token
            kek_provider = loaded_cred.kek_provider

    adc_allowed = is_adc_authorized_user(uid)
    raw_stored_mode = state.get("mode")
    try:
        mode = normalize_connection_mode(raw_stored_mode) if raw_stored_mode else defaults["mode"]
    except ValueError:
        mode = "access_token"

    if mode == "adc" and not adc_allowed:
        mode = "access_token"

    effective_org = str(state.get("organization_id") or "").strip().replace("organizations/", "")
    effective_proj = str(state.get("project_id") or "").strip().replace("projects/", "")
    server_policy = _load_server_scope_policy(uid) if is_auth_email else _ServerScopePolicy(
        False, frozenset(), False, frozenset(), False, frozenset()
    )
    authorized_orgs: List[str] = []
    authorized_projs: List[str] = []
    authorized_folders: List[str] = []

    if is_auth_email:
        if server_policy.has_any_restriction:
            srv_org, srv_proj, _ = resolve_server_bound_defaults(uid)
            if effective_org not in server_policy.organizations:
                effective_org = srv_org
            if effective_proj not in server_policy.projects:
                effective_proj = srv_proj
        elif auth_guard.is_production_environment() and not adc_allowed:
            effective_org = ""
            effective_proj = ""

        authz_scope = resolve_authorized_tenant_scope(
            uid,
            {
                **state,
                "mode": mode,
                "organization_id": effective_org,
                "project_id": effective_proj,
            },
        )
        authorized_orgs = sorted(authz_scope.organizations)
        authorized_projs = sorted(authz_scope.projects)
        authorized_folders = sorted(authz_scope.folders)

    if effective_org:
        active_scope_uri = f"organizations/{effective_org}"
    elif effective_proj:
        active_scope_uri = f"projects/{effective_proj}"
    elif len(authorized_orgs) == 1:
        active_scope_uri = f"organizations/{authorized_orgs[0]}"
    elif len(authorized_projs) == 1:
        active_scope_uri = f"projects/{authorized_projs[0]}"
    elif len(authorized_folders) == 1:
        active_scope_uri = f"folders/{authorized_folders[0]}"
    else:
        active_scope_uri = ""

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
        "mode_label": CONNECTION_MODES.get(mode, CONNECTION_MODES["access_token"]),
        "adc_authorized": adc_allowed,
        "auth_flow": "oauth2_3lo" if mode == "access_token" else mode,
        "oauth_consent_required": bool(mode == "access_token" and not has_token),
        "organization_id": effective_org,
        "project_id": effective_proj,
        "active_scope_uri": active_scope_uri,
        "scope_bound_by_server": bool(server_policy.has_any_restriction),
        "authorized_scope": {
            "organizations": authorized_orgs,
            "projects": authorized_projs,
            "folders": authorized_folders,
        },
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
    """Returns google.auth credentials matching the authorized tenant user's connection mode.

    Fails closed with ``PermissionError`` if caller is unauthenticated, if ``mode == 'adc'`` is unauthorized,
    if ``mode == 'access_token'`` lacks a valid unexpired delegated token, or if ``mode == 'impersonation'`` is unauthorized.
    """
    from pqc_agent import auth_store, credential_service

    active_ctx_uid = get_current_tenant_user()
    uid = normalize_user_id(user_id or active_ctx_uid)
    if _is_authenticated_email_identity(active_ctx_uid) and uid != active_ctx_uid:
        raise PermissionError("Forbidden: cross-tenant credential resolution denied.")
    if not _is_authenticated_email_identity(uid):
        raise PermissionError(
            "UNAUTHENTICATED_EXECUTION_CONTEXT: An authenticated tenant user identity is required to resolve GCP credentials."
        )

    raw_row = auth_store.get_active_auth_store().get_user_connection(uid)
    if raw_row is not None and str(raw_row.get("mode") or "").strip().lower() == "adc":
        authorize_adc_mode(uid)

    conn = get_gcp_connection_config(mask_token=False, user_id=uid)
    mode = normalize_connection_mode(conn.get("mode"))
    impersonated_sa = (conn.get("impersonated_service_account") or "").strip()
    quota_project = (conn.get("project_id") or "").strip() or None

    if mode == "access_token":
        loaded_cred = credential_service.get_active_credential_service().load_delegated_token(
            user_id=uid,
            caller_user_id=uid,
        )
        access_token = (loaded_cred.access_token if loaded_cred is not None else "").strip()
        if not access_token:
            raise PermissionError(
                "ACCESS_TOKEN_REQUIRED: Delegated OAuth access token is missing, revoked, or expired for mode 'access_token'."
            )
        tok_err = _validate_delegated_access_token_syntax(access_token)
        if tok_err:
            raise PermissionError(tok_err)
        expiry_dt = (
            datetime.datetime.fromtimestamp(loaded_cred.expires_at, tz=datetime.timezone.utc).replace(tzinfo=None)
            if (loaded_cred is not None and loaded_cred.expires_at)
            else None
        )
        from google.oauth2 import credentials as oauth2_credentials

        return oauth2_credentials.Credentials(
            token=access_token,
            expiry=expiry_dt,
            quota_project_id=quota_project,
        )

    if mode == "impersonation":
        if not impersonated_sa:
            raise PermissionError(
                "IMPERSONATION_TARGET_REQUIRED: No impersonated service account configured for mode 'impersonation'."
            )
        validated_sa = validate_impersonated_service_account(impersonated_sa, user_id=uid)
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

    authorize_adc_mode(uid)
    return None


def validate_gcloud_executable_path(candidate: str, *, check_filesystem: bool = True) -> str:
    """Validates that a `gcloud` binary path is in `TRUSTED_GCLOUD_PATHS` and resolves inside controlled system dirs.

    Rejects relative paths, unexpected paths, symlinks pointing into untrusted/writable directories (e.g. `/tmp`,
    `/var/tmp`, `/Users`, `/home`), and world-writable binaries or parent directories.
    """
    if not isinstance(candidate, str) or not candidate.strip():
        raise PermissionError("Untrusted gcloud executable: empty path.")
    clean = candidate.strip()
    if _CONTROL_CHARS_RE.search(clean) or not clean.startswith("/") or ".." in clean:
        raise PermissionError(f"Untrusted gcloud executable path '{clean}': absolute canonical path required.")
    allowed_candidates = set(TRUSTED_GCLOUD_PATHS)
    if check_filesystem:
        for p in TRUSTED_GCLOUD_PATHS:
            if os.path.lexists(p):
                allowed_candidates.add(os.path.realpath(p))
    if clean not in allowed_candidates:
        raise PermissionError(
            f"Untrusted gcloud executable path '{clean}': not in approved system installation paths."
        )

    if not check_filesystem:
        return clean

    if not os.path.isfile(clean) or not os.access(clean, os.X_OK):
        raise PermissionError(f"Trusted gcloud candidate '{clean}' is not an executable file.")

    real = os.path.realpath(clean)
    if os.path.basename(real) != "gcloud":
        raise PermissionError(f"Untrusted gcloud realpath target '{real}': unexpected binary basename.")
    if not any(real.startswith(prefix) for prefix in TRUSTED_GCLOUD_REALPATH_PREFIXES):
        raise PermissionError(
            f"Untrusted gcloud symlink target '{real}': resolves outside controlled installation directories."
        )
    if not os.path.isfile(real) or not os.access(real, os.X_OK):
        raise PermissionError(f"Resolved gcloud target '{real}' is not an executable regular file.")

    file_stat = os.stat(real)
    if bool(file_stat.st_mode & stat.S_IWOTH):
        raise PermissionError(f"Untrusted gcloud executable '{real}': binary is world-writable.")
    parent_dir = os.path.dirname(real)
    if parent_dir:
        dir_stat = os.stat(parent_dir)
        if bool(dir_stat.st_mode & stat.S_IWOTH):
            raise PermissionError(f"Untrusted gcloud directory '{parent_dir}': directory is world-writable.")

    return real


def resolve_trusted_gcloud_binary(
    candidate_paths: Optional[Sequence[str]] = None,
) -> Optional[str]:
    """Resolves `gcloud` strictly from trusted system installation paths (never inspects `PATH` or `~`)."""
    paths = candidate_paths if candidate_paths is not None else TRUSTED_GCLOUD_PATHS
    for candidate in paths:
        try:
            return validate_gcloud_executable_path(candidate, check_filesystem=True)
        except PermissionError:
            continue
        except OSError:
            continue
    return None


def _resolve_gcloud_binary() -> Optional[str]:
    return resolve_trusted_gcloud_binary()


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
    seen_flags: Set[str] = set()

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
            "Blocked unapproved gcloud subcommand or verb; command is not in the safely scoped read-only PQC grammar.",
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


def resolve_authorized_tenant_scope(
    user_id: str,
    conn_cfg: Mapping[str, Any],
) -> AuthorizedTenantScope:
    """Computes the caller's authorized `(projects, organizations, folders)` boundaries.

    Security invariants:
    1. Whenever ANY server-side scope policy env var (`PQC_ALLOWED_PROJECTS`, `PQC_ALLOWED_ORGANIZATIONS`,
       `PQC_ALLOWED_FOLDERS`, or `PQC_TENANT_SCOPE_POLICY`) is configured, the server policy is the SOLE
       authoritative boundary across ALL scope dimensions (unmentioned dimensions fail closed to empty sets).
    2. In production (`K_SERVICE` / `PQC_PRODUCTION_MODE=true` / `PQC_ENV=production`), non-admin delegated-token
       tenants never obtain scope from client-supplied connection payloads when no server scope policy is configured.
    3. Folders are default-deny unless explicitly granted by server policy.
    """
    from pqc_agent import auth_guard

    norm_uid = normalize_user_id(user_id)
    if not _is_authenticated_email_identity(norm_uid):
        raise PermissionError("Unauthenticated identity has no authorized GCP resource scope.")

    server_policy = _load_server_scope_policy(norm_uid)

    if server_policy.has_any_restriction:
        return AuthorizedTenantScope(
            user_id=norm_uid,
            projects=frozenset(p for p in server_policy.projects if _validate_project_value(p) is None),
            organizations=frozenset(o for o in server_policy.organizations if _validate_numeric_id_value(o) is None),
            folders=frozenset(f for f in server_policy.folders if _validate_numeric_id_value(f) is None),
        )

    if auth_guard.is_production_environment() and not is_adc_authorized_user(norm_uid):
        return AuthorizedTenantScope(
            user_id=norm_uid,
            projects=frozenset(),
            organizations=frozenset(),
            folders=frozenset(),
        )

    conn_proj = str(conn_cfg.get("project_id") or "").strip().replace("projects/", "")
    conn_org = str(conn_cfg.get("organization_id") or "").strip().replace("organizations/", "")
    mode = str(conn_cfg.get("mode") or "access_token").strip().lower()
    sa_email = str(conn_cfg.get("impersonated_service_account") or "").strip()

    if mode == "impersonation" and not conn_proj and sa_email:
        conn_proj = _extract_sa_project(sa_email)

    allowed_projects = {conn_proj} if (conn_proj and _validate_project_value(conn_proj) is None) else set()
    allowed_orgs = {conn_org} if (conn_org and _validate_numeric_id_value(conn_org) is None) else set()

    return AuthorizedTenantScope(
        user_id=norm_uid,
        projects=frozenset(allowed_projects),
        organizations=frozenset(allowed_orgs),
        folders=frozenset(),
    )


def authorize_gcp_scope(
    scope_uri: str,
    *,
    user_id: Optional[str] = None,
    conn_cfg: Optional[Mapping[str, Any]] = None,
) -> str:
    """Validates that `scope_uri` (`organizations/<id>`, `folders/<id>`, or `projects/<id>`) is authorized for the caller.

    Reuses the canonical tenant scope boundary (`resolve_authorized_tenant_scope`) and deny-by-default ADC
    authorization (`authorize_adc_mode`) so Python SDK and Cloud Asset Inventory collectors enforce the same
    multi-tenant isolation rules as `authorize_gcloud_command_scope`.
    """
    from pqc_agent import auth_store

    active_ctx_uid = get_current_tenant_user()
    uid = normalize_user_id(user_id or active_ctx_uid)
    if _is_authenticated_email_identity(active_ctx_uid) and uid != active_ctx_uid:
        raise PermissionError("Forbidden: cross-tenant scope authorization denied.")
    if not _is_authenticated_email_identity(uid):
        raise PermissionError(
            "UNAUTHENTICATED_EXECUTION_CONTEXT: An authenticated tenant user identity is required to query GCP scopes."
        )

    raw_row = auth_store.get_active_auth_store().get_user_connection(uid)
    if raw_row is not None and str(raw_row.get("mode") or "").strip().lower() == "adc":
        authorize_adc_mode(uid)

    effective_conn = conn_cfg if conn_cfg is not None else get_gcp_connection_config(mask_token=True, user_id=uid)
    if str(effective_conn.get("mode") or "").strip().lower() == "adc":
        authorize_adc_mode(uid)

    authorized = resolve_authorized_tenant_scope(uid, effective_conn)
    clean_scope = str(scope_uri or "").strip()

    if not clean_scope:
        if not (authorized.organizations or authorized.projects or authorized.folders):
            raise PermissionError(
                f"UNAUTHORIZED_RESOURCE_SCOPE (MISSING_AUTHORIZED_SCOPE): No authorized GCP organization, project, "
                f"or folder scope is bound for tenant '{uid}'. Configure a server-side tenant scope policy "
                "(PQC_TENANT_SCOPE_POLICY, PQC_ALLOWED_ORGANIZATIONS, or PQC_ALLOWED_PROJECTS) before running live scans."
            )
        raise PermissionError(
            f"UNAUTHORIZED_RESOURCE_SCOPE (MISSING_AUTHORIZED_SCOPE): Explicit GCP scope is required for tenant '{uid}'."
        )

    scope_err = _validate_scope_value(clean_scope)
    if scope_err is not None:
        raise PermissionError(f"UNAUTHORIZED_RESOURCE_SCOPE: {scope_err}")

    if not (authorized.organizations or authorized.projects or authorized.folders):
        raise PermissionError(
            f"UNAUTHORIZED_RESOURCE_SCOPE (MISSING_AUTHORIZED_SCOPE): No authorized GCP organization, project, "
            f"or folder scope is bound for tenant '{uid}'. Configure a server-side tenant scope policy "
            "(PQC_TENANT_SCOPE_POLICY, PQC_ALLOWED_ORGANIZATIONS, or PQC_ALLOWED_PROJECTS) before running live scans."
        )

    kind, _, identifier = clean_scope.partition("/")

    if kind == "organizations":
        if identifier not in authorized.organizations:
            raise PermissionError(
                f"UNAUTHORIZED_RESOURCE_SCOPE: Organization '{identifier}' is outside tenant '{uid}' authorized scope."
            )
    elif kind == "folders":
        if identifier not in authorized.folders:
            raise PermissionError(
                f"UNAUTHORIZED_RESOURCE_SCOPE: Folder '{identifier}' is outside tenant '{uid}' authorized scope."
            )
    elif kind == "projects":
        if identifier not in authorized.projects:
            raise PermissionError(
                f"UNAUTHORIZED_RESOURCE_SCOPE: Project '{identifier}' is outside tenant '{uid}' authorized scope."
            )
    else:
        raise PermissionError(f"UNAUTHORIZED_RESOURCE_SCOPE: Unrecognized GCP scope '{clean_scope}'.")

    return clean_scope


def authorize_gcloud_command_scope(
    raw_command: str,
    *,
    user_id: str,
    conn_cfg: Mapping[str, Any],
) -> Optional[str]:
    """Independently validates that `raw_command` accesses ONLY resources within `user_id`'s authorized scope.

    Returns an optional implicit `--project` value to inject when a project-scoped command omitted `--project`,
    or raises ``PermissionError`` if any referenced project, organization, folder, service account, or unscoped
    operation violates the caller's tenant boundary.
    """
    if not _is_authenticated_email_identity(user_id):
        raise PermissionError("UNAUTHENTICATED_EXECUTION_CONTEXT: Authenticated tenant user required.")

    authorized = resolve_authorized_tenant_scope(user_id, conn_cfg)

    try:
        raw_tokens = shlex.split(str(raw_command or "").strip(), posix=True)
    except ValueError as exc:
        raise PermissionError(f"Malformed command in scope authorization check: {exc}") from exc

    if not raw_tokens or raw_tokens[0] != "gcloud":
        raise PermissionError("Executable must be 'gcloud' in scope authorization check.")

    rest = raw_tokens[1:]
    referenced_projects: Set[str] = set()
    referenced_orgs: Set[str] = set()
    referenced_folders: Set[str] = set()
    non_flags: List[str] = []
    explicit_project_flag = False
    explicit_scope_flag = False

    def _collect_embedded_hierarchy_refs(token_val: str) -> None:
        for pm in _EMBEDDED_PROJECT_RE.finditer(token_val):
            referenced_projects.add(pm.group(1))
        for om in _EMBEDDED_ORG_RE.finditer(token_val):
            referenced_orgs.add(om.group(1))
        for fm in _EMBEDDED_FOLDER_RE.finditer(token_val):
            referenced_folders.add(fm.group(1))
        for sam in _EMBEDDED_SA_PROJECT_RE.finditer(token_val):
            referenced_projects.add(sam.group(1))

    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok.startswith("-"):
            flag_name, has_eq, inline_val = tok.partition("=")
            canon = flag_name.lower().replace("_", "-")
            if _is_blocked_flag_name(canon):
                raise PermissionError(f"Forbidden privilege/scope flag '{flag_name}'.")

            spec = _FLAG_SPECS.get(canon)
            takes_val = spec.takes_value if spec is not None else has_eq
            val: Optional[str] = None
            if takes_val:
                if has_eq:
                    val = inline_val
                    i += 1
                elif i + 1 < len(rest):
                    val = rest[i + 1]
                    i += 2
                else:
                    raise PermissionError(f"Missing value for flag '{flag_name}'.")
            else:
                i += 1

            if val is not None:
                _collect_embedded_hierarchy_refs(val)
                if canon == "--project":
                    explicit_project_flag = True
                    referenced_projects.add(val.strip().replace("projects/", ""))
                elif canon == "--organization":
                    referenced_orgs.add(val.strip().replace("organizations/", ""))
                elif canon == "--folder":
                    referenced_folders.add(val.strip().replace("folders/", ""))
                elif canon == "--scope":
                    explicit_scope_flag = True
                    sval = val.strip()
                    if sval.startswith("projects/"):
                        referenced_projects.add(sval[len("projects/"):])
                    elif sval.startswith("organizations/"):
                        referenced_orgs.add(sval[len("organizations/"):])
                    elif sval.startswith("folders/"):
                        referenced_folders.add(sval[len("folders/"):])
                    else:
                        raise PermissionError(f"Unrecognized '--scope' hierarchy '{sval}'.")
            continue

        _collect_embedded_hierarchy_refs(tok)
        non_flags.append(tok)
        i += 1

    # Local `gcloud version` / `gcloud --version` accesses zero GCP resources.
    if (not non_flags and "--version" in rest) or non_flags == ["version"]:
        if referenced_projects or referenced_orgs or referenced_folders:
            raise PermissionError("Unexpected resource scope arguments on 'gcloud version'.")
        return None

    if not non_flags:
        raise PermissionError("Command has no target service group for scope verification.")

    top_group = non_flags[0].lower()

    # Explicitly reject unscoped global commands even if command parser were ever bypassed.
    if tuple(t.lower() for t in non_flags[:2]) in (
        ("projects", "list"),
        ("organizations", "list"),
    ) or tuple(t.lower() for t in non_flags[:3]) == ("storage", "buckets", "describe"):
        raise PermissionError(
            f"Forbidden unscoped or globally addressed command 'gcloud {' '.join(non_flags[:3])}'."
        )

    if top_group == "projects" and len(non_flags) >= 3:
        referenced_projects.add(non_flags[2].strip().replace("projects/", ""))
    elif top_group == "organizations" and len(non_flags) >= 3:
        referenced_orgs.add(non_flags[2].strip().replace("organizations/", ""))
    elif top_group == "folders":
        if len(non_flags) >= 2 and non_flags[1].lower() == "list":
            if not referenced_orgs and not referenced_folders:
                raise PermissionError("'gcloud folders list' requires an authorized '--organization' or '--folder'.")
        elif len(non_flags) >= 3:
            referenced_folders.add(non_flags[2].strip().replace("folders/", ""))
    elif top_group == "asset":
        sub = non_flags[1].lower() if len(non_flags) >= 2 else ""
        if sub in ("search-all-resources", "search-all-iam-policies") and not explicit_scope_flag:
            raise PermissionError(f"'gcloud asset {sub}' requires an explicit authorized '--scope' flag.")
        if sub == "list" and not (referenced_projects or referenced_orgs or referenced_folders):
            raise PermissionError(
                "'gcloud asset list' requires an explicit authorized '--project', '--organization', or '--folder'."
            )

    injected_project: Optional[str] = None
    if top_group in _PROJECT_SCOPED_GROUPS and not explicit_project_flag:
        conn_proj = str(conn_cfg.get("project_id") or "").strip().replace("projects/", "")
        default_proj = conn_proj if conn_proj else (next(iter(authorized.projects)) if len(authorized.projects) == 1 else "")
        if not default_proj:
            raise PermissionError(
                f"No authorized GCP project is bound for tenant '{user_id}'; specify an authorized '--project'."
            )
        referenced_projects.add(default_proj)
        injected_project = default_proj

    if not (referenced_projects or referenced_orgs or referenced_folders):
        raise PermissionError("Command does not specify a safely enforceable GCP project, organization, or folder scope.")

    unauthorized_projects = sorted(p for p in referenced_projects if p not in authorized.projects)
    if unauthorized_projects:
        raise PermissionError(
            f"UNAUTHORIZED_RESOURCE_SCOPE: Project(s) {unauthorized_projects} are outside tenant '{user_id}' authorized scope."
        )

    unauthorized_orgs = sorted(o for o in referenced_orgs if o not in authorized.organizations)
    if unauthorized_orgs:
        raise PermissionError(
            f"UNAUTHORIZED_RESOURCE_SCOPE: Organization(s) {unauthorized_orgs} are outside tenant '{user_id}' authorized scope."
        )

    unauthorized_folders = sorted(f for f in referenced_folders if f not in authorized.folders)
    if unauthorized_folders:
        raise PermissionError(
            f"UNAUTHORIZED_RESOURCE_SCOPE: Folder(s) {unauthorized_folders} are outside tenant '{user_id}' authorized scope."
        )

    return injected_project


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
    user_id: Optional[str] = None,
    project_id: Optional[str] = None,
    has_explicit_project_flag: bool = False,
    access_token: Optional[str] = None,
    impersonated_service_account: Optional[str] = None,
    source_env: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    """Constructs a sanitized subprocess environment with pinned system `PATH` and verified mode authorization."""
    effective_uid = normalize_user_id(user_id or get_current_tenant_user())
    if not _is_authenticated_email_identity(effective_uid):
        raise PermissionError("UNAUTHENTICATED_EXECUTION_CONTEXT: Authenticated tenant user required.")

    src = source_env if source_env is not None else os.environ
    env: Dict[str, str] = {"PATH": TRUSTED_SUBPROCESS_PATH}

    for key in _SAFE_BASE_ENV_VARS:
        val = src.get(key)
        if val and not _CONTROL_CHARS_RE.search(val):
            env[key] = val

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
        env["CLOUDSDK_CONFIG"] = _ensure_isolated_gcloud_config_dir("token-isolated")
        env["CLOUDSDK_AUTH_ACCESS_TOKEN"] = clean_tok
    elif canonical_mode == "impersonation":
        clean_sa = validate_impersonated_service_account(impersonated_service_account or "", user_id=effective_uid)
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
        authorize_adc_mode(effective_uid)
        gac = src.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        if gac and os.path.isfile(gac):
            env["GOOGLE_APPLICATION_CREDENTIALS"] = gac
        src_cfg = src.get("CLOUDSDK_CONFIG", "").strip()
        if src_cfg and os.path.isdir(src_cfg) and _check_common_arg_safety(src_cfg) is None:
            env["CLOUDSDK_CONFIG"] = src_cfg

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
    from pqc_agent import egress_guard

    cleaned = egress_guard.redact_sensitive_text(text or "")
    for secret in secret_values:
        s = (secret or "").strip()
        if len(s) >= 8 and s in cleaned:
            cleaned = cleaned.replace(s, "[REDACTED]")
    return cleaned


def execute_gcloud_command(command: str) -> str:
    """Executes a strictly validated, scope-authorized read-only `gcloud` command for the authenticated tenant."""
    from pqc_agent import auth_store

    start_ts = time.time()
    uid = get_current_tenant_user()
    is_valid, tokens, validation_msg = validate_gcloud_command(command)
    conn_cfg = get_gcp_connection_config(mask_token=False, user_id=uid)
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

    # 1. Require authenticated tenant identity and verify raw stored ADC/impersonation authorization BEFORE scope/exec
    try:
        if not _is_authenticated_email_identity(uid):
            raise PermissionError(
                "UNAUTHENTICATED_EXECUTION_CONTEXT: execute_gcloud_command requires an authenticated tenant identity."
            )
        raw_stored_row = auth_store.get_active_auth_store().get_user_connection(uid)
        if raw_stored_row is not None and str(raw_stored_row.get("mode") or "").strip().lower() == "adc":
            authorize_adc_mode(uid)
        if mode == "adc":
            authorize_adc_mode(uid)
        injected_project = authorize_gcloud_command_scope(command, user_id=uid, conn_cfg=conn_cfg)
    except PermissionError as authz_err:
        err_str = str(authz_err)
        if "UNAUTHORIZED_RESOURCE_SCOPE" in err_str:
            err_code = "UNAUTHORIZED_RESOURCE_SCOPE"
        elif "UNAUTHENTICATED_EXECUTION_CONTEXT" in err_str:
            err_code = "UNAUTHENTICATED_EXECUTION_CONTEXT"
        else:
            err_code = "ADC_UNAUTHORIZED"
        denied_scope_payload = {
            "status": "COMMAND_ERROR",
            "error_code": err_code,
            "command_executed": display_cmd,
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "exit_code": 126,
            "stdout": "",
            "stderr": _scrub_output(err_str, secret_values=(raw_token,)),
            "duration_ms": round((time.time() - start_ts) * 1000, 2),
        }
        _record_gcloud_trace(denied_scope_payload)
        return json.dumps(denied_scope_payload, ensure_ascii=False)

    effective_tokens = list(tokens)
    if injected_project and not any(t == "--project" or t.startswith("--project=") for t in effective_tokens):
        effective_tokens.append(f"--project={injected_project}")
        display_cmd = "gcloud " + " ".join(shlex.quote(t) for t in effective_tokens)

    # 2. Build sanitized subprocess environment & enforce mode-specific credential requirements
    try:
        has_project_flag = any(t == "--project" or t.startswith("--project=") for t in effective_tokens)
        env = build_sanitized_gcloud_env(
            mode=mode,
            user_id=uid,
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
            else ("IMPERSONATION_ERROR" if mode == "impersonation" else "ADC_UNAUTHORIZED")
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

    # 3. Resolve & validate trusted gcloud executable path (never via PATH / shutil.which)
    gcloud_bin = _resolve_gcloud_binary()
    if not gcloud_bin:
        missing_payload = {
            "status": "GCLOUD_BINARY_NOT_FOUND",
            "command_requested": _scrub_output(command, secret_values=(raw_token,)),
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "exit_code": 127,
            "stdout": "",
            "stderr": "No trusted 'gcloud' CLI binary found in approved system installation directories.",
            "duration_ms": round((time.time() - start_ts) * 1000, 2),
        }
        _record_gcloud_trace(missing_payload)
        return json.dumps(missing_payload, ensure_ascii=False)

    try:
        # Validate path policy even if `_resolve_gcloud_binary` was monkeypatched; check filesystem if path exists.
        fs_check = os.path.lexists(gcloud_bin)
        validated_bin = validate_gcloud_executable_path(gcloud_bin, check_filesystem=fs_check)
    except PermissionError as bin_err:
        untrusted_bin_payload = {
            "status": "COMMAND_ERROR",
            "error_code": "GCLOUD_UNTRUSTED_EXECUTABLE",
            "command_executed": display_cmd,
            "connection_mode": mode,
            "connection_mode_label": mode_label,
            "exit_code": 126,
            "stdout": "",
            "stderr": _scrub_output(str(bin_err), secret_values=(raw_token,)),
            "duration_ms": round((time.time() - start_ts) * 1000, 2),
        }
        _record_gcloud_trace(untrusted_bin_payload)
        return json.dumps(untrusted_bin_payload, ensure_ascii=False)

    exec_tokens = [validated_bin] + list(effective_tokens)
    if "--quiet" not in effective_tokens:
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

        duration_ms = round((time.time() - start_ts) * 1000, 2)
        result_payload = {
            "status": "SUCCESS" if proc.returncode == 0 else "COMMAND_ERROR",
            "command_executed": display_cmd,
            "executable_path": validated_bin,
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
