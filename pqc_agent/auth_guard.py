"""Reusable authentication hardening for a FastAPI + Google ADK portal deployed on Cloud Run.

This module only depends on FastAPI/Starlette and ``google-auth`` so it can be copied into a sibling project. To port
it, rename the ``ENV_*`` constants (``PQC_`` prefix), ``AUTH_SECRET_FILENAME`` and the session header names passed to
:class:`IdentityResolver`; nothing else is project specific.

Threat model: the service is reachable from the internet (``--allow-unauthenticated``) and holds org-wide read
credentials, so every request is hostile until proven otherwise.

=====  =========================================  =================================================================
ID     Vulnerability                              Control provided here
=====  =========================================  =================================================================
S2     ``user_id`` taken from headers/params       :func:`bind_user_id` - the authenticated identity is the ONLY
                                                  source of the user id (explicit ids must match it, else 403).
S3     Plain ``X-Goog-Authenticated-User-Email``   :func:`verify_iap_jwt` - IAP is trusted only through a verified,
       header trusted                             signed ``X-Goog-IAP-JWT-Assertion`` (issuer + optional audience).
S4     ADK REST routes without auth               :class:`AdkRouteGuardMiddleware` - every non-portal route is
                                                  ADK-native: 404 unless enabled, then identity + user binding.
S5     ADK DevServer (builder/save, deploy) on     :func:`adk_dev_ui_enabled` - off on Cloud Run (``K_SERVICE``)
       Cloud Run                                  unless explicitly enabled.
S6     Constant HMAC fallback key                 :func:`load_or_create_hmac_secret` - env > persisted file >
                                                  ephemeral random key (never a constant).
S8     ``allow_origins=["*"]``                    :func:`allowed_cors_origins` - explicit allowlist, never ``*``.
=====  =========================================  =================================================================

(S1 "email-only sign-in" and S7 "OAuth tokens at rest" are fixed in the portal server and in the gcloud bridge; the
flags they use, :func:`allow_unverified_signin` and the signed-payload helpers, live here.)

Public API
----------
Flags (read at call time so tests and operators can change the environment):
    env_flag(name) -> Optional[bool]          true/1/yes -> True, false/0/no -> False, anything else -> None
    running_on_cloud_run() -> bool            ``K_SERVICE`` is set
    adk_dev_ui_enabled() -> bool              PQC_ENABLE_ADK_DEV_UI, default: enabled only when not on Cloud Run
    adk_api_enabled() -> bool                 PQC_ENABLE_ADK_API,    default: enabled only when not on Cloud Run
    allow_unverified_signin() -> bool         PQC_ALLOW_UNVERIFIED_SIGNIN, default False (dev only)
    allowed_cors_origins() -> Optional[list]  PQC_ALLOWED_ORIGINS (comma-separated http(s) origins), default None
    admin_emails() / is_admin_identity(id)    PQC_ADMIN_EMAILS; without it only local (non Cloud Run) users are admin
Secrets and signed tokens:
    load_or_create_hmac_secret(data_dir) -> bytes
    sign_payload(payload, secret) -> str      ``<base64url(json)>.<hex hmac-sha256>``
    verify_signed_payload(token, secret, expected_type=None) -> Optional[dict]   (``exp`` is mandatory)
Identity:
    verify_iap_jwt(token, audience=None) -> Optional[dict]
    AuthenticatedIdentity, IdentityResolver(...).resolve(conn) -> Optional[AuthenticatedIdentity]
    bind_user_id(identity, explicit_user_id) -> str     (401 without identity, 403 on mismatch)
ADK routes:
    is_portal_path(path, dev_ui_static=False) -> bool
    AdkRouteGuardMiddleware(app, resolver=..., api_enabled=..., ...)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, FrozenSet, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

from fastapi import HTTPException
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse
from starlette.websockets import WebSocketClose

import urllib.error
import urllib.request

from pqc_agent import egress_guard

try:  # google-auth is a transitive dependency of google-adk / google-cloud-*; keep the import failure explicit.
    from google.auth import exceptions as _google_auth_exceptions
    from google.auth import transport as _google_auth_transport
    import google.auth.transport.requests as _google_auth_requests
    from google.oauth2 import id_token as google_id_token
except Exception:  # pragma: no cover - only when google-auth[requests] is missing
    _google_auth_exceptions = None  # type: ignore[assignment]
    _google_auth_transport = None  # type: ignore[assignment]
    _google_auth_requests = None  # type: ignore[assignment]
    google_id_token = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# =============================================================================
# Names - rename these when copying the module into a sibling project
# =============================================================================
ENV_ALLOW_UNVERIFIED_SIGNIN = "PQC_ALLOW_UNVERIFIED_SIGNIN"
ENV_ENABLE_ADK_API = "PQC_ENABLE_ADK_API"
ENV_ENABLE_ADK_DEV_UI = "PQC_ENABLE_ADK_DEV_UI"
ENV_ALLOWED_ORIGINS = "PQC_ALLOWED_ORIGINS"
ENV_IAP_AUDIENCE = "PQC_IAP_AUDIENCE"
ENV_REQUIRE_IAP_AUDIENCE = "PQC_REQUIRE_IAP_AUDIENCE"
ENV_AUTH_SECRET = "PQC_AUTH_SECRET"
ENV_AUTH_SECRET_FILE = "PQC_AUTH_SECRET_FILE"
ENV_AUTH_SECRET_PREVIOUS = "PQC_AUTH_SECRET_PREVIOUS"
ENV_PRODUCTION_MODE = "PQC_PRODUCTION_MODE"
ENV_ADMIN_EMAILS = "PQC_ADMIN_EMAILS"
AUTH_SECRET_FILENAME = ".pqc_auth_secret"
CSRF_COOKIE_NAME = "pqc_csrf_token"
CSRF_HEADER_NAME = "X-PQC-CSRF-Token"

IAP_JWT_HEADER = "X-Goog-IAP-JWT-Assertion"
IAP_ISSUER = "https://cloud.google.com/iap"
IAP_CERTS_URL = "https://www.gstatic.com/iap/verify/public_key"

UNAUTHENTICATED_DETAIL = (
    "Authentication required. Sign in with a verified Google identity: use 'Sign in with Google' or paste the "
    "output of `gcloud auth print-access-token` in the portal sign-in dialog."
)
USER_MISMATCH_DETAIL = (
    "Forbidden: the requested user_id does not match the authenticated identity. Requests can only act on the "
    "signed-in user's own data."
)
CSRF_REJECTED_DETAIL = (
    "Forbidden: CSRF verification failed (missing or invalid X-PQC-CSRF-Token or untrusted cross-origin request)."
)

_TRUE_VALUES = ("true", "1", "yes")
_FALSE_VALUES = ("false", "0", "no")


# =============================================================================
# Environment flags
# =============================================================================
def env_flag(name: str) -> Optional[bool]:
    """Parses a boolean env var: ``true/1/yes`` -> True, ``false/0/no`` -> False, unset/other -> None."""
    raw = (os.getenv(name) or "").strip().lower()
    if raw in _TRUE_VALUES:
        return True
    if raw in _FALSE_VALUES:
        return False
    return None


def running_on_cloud_run() -> bool:
    """True when running on Cloud Run (the platform always sets ``K_SERVICE``)."""
    return bool(os.getenv("K_SERVICE"))


def is_production_environment() -> bool:
    """True when running on Cloud Run (``K_SERVICE``) or when ``PQC_PRODUCTION_MODE=true`` / ``PQC_ENV=production``."""
    if env_flag(ENV_PRODUCTION_MODE) is True:
        return True
    if (os.getenv("PQC_ENV") or "").strip().lower() in ("prod", "production"):
        return True
    return running_on_cloud_run()


def adk_dev_ui_enabled() -> bool:
    """Whether to mount the ADK DevServer (``/dev-ui`` + ``/dev/apps/*`` builder/eval/deploy routes).

    ``PQC_ENABLE_ADK_DEV_UI`` in (true, 1, yes) -> True; in (false, 0, no) -> False; otherwise enabled only when
    ``K_SERVICE`` is unset (local development). The DevServer can write files and run deployments with the runtime
    identity, so it must never be reachable on a public service.
    """
    flag = env_flag(ENV_ENABLE_ADK_DEV_UI)
    if flag is not None:
        return flag
    return not os.getenv("K_SERVICE")


def adk_api_enabled() -> bool:
    """Whether ADK-native REST routes (``/list-apps``, ``/apps/...``, ``/run``, ``/run_sse``...) are served at all.

    Same defaulting rule as :func:`adk_dev_ui_enabled` with ``PQC_ENABLE_ADK_API``. When enabled they still require an
    authenticated identity (see :class:`AdkRouteGuardMiddleware`).
    """
    flag = env_flag(ENV_ENABLE_ADK_API)
    if flag is not None:
        return flag
    return not os.getenv("K_SERVICE")


def allow_unverified_signin() -> bool:
    """Development-only escape hatch that re-enables email-only sign-in (``PQC_ALLOW_UNVERIFIED_SIGNIN=true``).

    Never permitted in production (Cloud Run / ``PQC_PRODUCTION_MODE=true``).
    """
    if is_production_environment():
        return False
    return env_flag(ENV_ALLOW_UNVERIFIED_SIGNIN) is True


def allowed_cors_origins() -> Optional[List[str]]:
    """Explicit CORS allowlist from ``PQC_ALLOWED_ORIGINS`` (comma-separated ``https://host[:port]`` origins).

    Returns None (no cross-origin access: same-origin portal only) when unset. Wildcards and non-http(s) entries are
    ignored because credentialed requests must never be allowed from arbitrary origins.
    """
    origins: List[str] = []
    for item in (os.getenv(ENV_ALLOWED_ORIGINS) or "").split(","):
        origin = item.strip().rstrip("/")
        if not origin:
            continue
        if "*" in origin or not origin.lower().startswith(("https://", "http://")):
            logger.warning("Ignoring unsafe CORS origin %r in %s (wildcards are not allowed).", origin, ENV_ALLOWED_ORIGINS)
            continue
        if origin not in origins:
            origins.append(origin)
    return origins or None


def admin_emails() -> FrozenSet[str]:
    """Lower-cased emails listed in ``PQC_ADMIN_EMAILS`` (comma-separated)."""
    return frozenset(e.strip().lower() for e in (os.getenv(ENV_ADMIN_EMAILS) or "").split(",") if e.strip())


# =============================================================================
# HMAC secret, key rotation, PKCE and signed payloads
# =============================================================================
def _read_secret_file(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def load_previous_hmac_secrets(env_var: str = ENV_AUTH_SECRET_PREVIOUS) -> Tuple[bytes, ...]:
    """Returns previous HMAC keys configured in ``PQC_AUTH_SECRET_PREVIOUS`` (comma-separated) for safe rotation."""
    raw = (os.getenv(env_var) or "").strip()
    if not raw:
        return ()
    keys: List[bytes] = []
    for item in raw.split(","):
        cleaned = item.strip()
        if len(cleaned) >= 32:
            keys.append(cleaned.encode("utf-8"))
        elif cleaned:
            logger.warning("Ignoring rotation secret in %s shorter than 32 characters.", env_var)
    return tuple(keys)


def load_or_create_hmac_secret(
    data_dir: Optional[str],
    *,
    env_var: str = ENV_AUTH_SECRET,
    filename: str = AUTH_SECRET_FILENAME,
    require_stable_secret: Optional[bool] = None,
) -> bytes:
    """Returns the HMAC key used to sign session tokens and OAuth state. Never returns a constant.

    * **Production (Cloud Run / ``PQC_PRODUCTION_MODE=true``):** fails closed (raises :class:`RuntimeError`) if
      ``$PQC_AUTH_SECRET`` (or ``$PQC_AUTH_SECRET_FILE``, e.g. a Secret Manager volume mount) is missing or shorter
      than 32 characters. Never generates an ephemeral or local-file secret in production.
    * **Local development:** ``$PQC_AUTH_SECRET`` > ``$PQC_AUTH_SECRET_FILE`` > ``<data_dir>/.pqc_auth_secret``
      (created with 256 random bits, mode 0600) > ephemeral ``secrets.token_hex(32)`` with a warning.
    """
    env_secret = (os.getenv(env_var) or "").strip()
    if not env_secret:
        secret_file = (os.getenv(ENV_AUTH_SECRET_FILE) or "").strip()
        if secret_file:
            env_secret = (_read_secret_file(secret_file) or "").strip()

    must_have_stable = is_production_environment() if require_stable_secret is None else bool(require_stable_secret)
    if env_secret:
        if len(env_secret) < 32:
            if must_have_stable:
                raise RuntimeError(
                    f"Production security failure: {env_var} must be at least 32 characters (256 bits) from Secret Manager."
                )
            logger.warning("%s is shorter than 32 characters; use a random 256-bit value.", env_var)
        return env_secret.encode("utf-8")

    if must_have_stable:
        raise RuntimeError(
            f"Production security failure: {env_var} is not configured. Inject a 256-bit secret from Secret Manager "
            f"(or set {ENV_AUTH_SECRET_FILE}); refusing to generate an ephemeral production HMAC secret."
        )

    if data_dir:
        path = os.path.join(data_dir, filename)
        try:
            existing = _read_secret_file(path)
            if existing is not None and len(existing) >= 32:
                return existing.encode("utf-8")
            generated = secrets.token_hex(32)
            # O_EXCL on first creation so concurrent workers cannot silently disagree on the key.
            flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if existing is not None else os.O_EXCL)
            try:
                fd = os.open(path, flags, 0o600)
            except FileExistsError:
                raced = _read_secret_file(path)
                if raced and len(raced) >= 32:
                    return raced.encode("utf-8")
                raise
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(generated)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return generated.encode("utf-8")
        except OSError as exc:
            logger.warning("Cannot read or persist the HMAC secret in %s: %s", data_dir, exc)

    logger.warning(
        "No %s and no writable secret file: using an EPHEMERAL random HMAC key (local dev only). Set %s in production.",
        env_var,
        env_var,
    )
    return secrets.token_hex(32).encode("utf-8")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def compute_pkce_challenge(code_verifier: str) -> str:
    """Computes an RFC 7636 S256 PKCE ``code_challenge`` from ``code_verifier`` (43..128 ASCII chars)."""
    if not code_verifier or not (43 <= len(code_verifier) <= 128):
        raise ValueError("RFC 7636 PKCE code_verifier must be between 43 and 128 ASCII characters.")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return _b64url_encode(digest)


def generate_pkce_pair() -> Tuple[str, str]:
    """Generates a cryptographically random RFC 7636 PKCE ``(code_verifier, code_challenge)`` pair (S256)."""
    verifier = secrets.token_urlsafe(64)
    return verifier, compute_pkce_challenge(verifier)


def derive_csrf_token(session_token: str, secret: bytes) -> str:
    """Derives a session-bound CSRF token from the active session token using HMAC-SHA256."""
    raw = (session_token or "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    return hmac.new(secret, f"pqc-csrf-v1:{raw}".encode("utf-8"), hashlib.sha256).hexdigest()


def verify_csrf_token(csrf_token: Optional[str], session_token: Optional[str], secret: bytes) -> bool:
    """Verifies that ``csrf_token`` matches the HMAC-derived CSRF token for ``session_token`` (or a rotated key)."""
    if not csrf_token or not session_token:
        return False
    candidate = str(csrf_token).strip()
    if not candidate:
        return False
    candidate_secrets: List[bytes] = [secret, *load_previous_hmac_secrets()]
    for key in candidate_secrets:
        expected = derive_csrf_token(session_token, key)
        if hmac.compare_digest(candidate.encode("utf-8"), expected.encode("ascii")):
            return True
    return False


def sign_payload(payload: Mapping[str, Any], secret: bytes) -> str:
    """Serializes ``payload`` as compact JSON and returns ``<base64url(json)>.<hex HMAC-SHA256>``."""
    raw = json.dumps(dict(payload), separators=(",", ":"), sort_keys=True).encode("utf-8")
    body = _b64url_encode(raw)
    signature = hmac.new(secret, body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def verify_signed_payload(
    token: Optional[str],
    secret: bytes,
    *,
    expected_type: Optional[str] = None,
    previous_secrets: Optional[Sequence[bytes]] = None,
) -> Optional[Dict[str, Any]]:
    """Verifies a token produced by :func:`sign_payload` (constant-time). Returns the payload or None.

    ``exp`` (unix seconds) is mandatory; when ``expected_type`` is given the payload ``typ`` must match it, which
    prevents using e.g. an OAuth ``state`` value as a session token. Supports seamless key rotation via
    ``previous_secrets`` or ``PQC_AUTH_SECRET_PREVIOUS``.
    """
    if not token:
        return None
    raw = str(token).strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    body, sep, signature = raw.partition(".")
    if not sep or not body or not signature:
        return None
    keys_to_try: List[bytes] = [secret]
    if previous_secrets is not None:
        keys_to_try.extend(previous_secrets)
    else:
        keys_to_try.extend(load_previous_hmac_secrets())
    sig_matched = False
    for key in keys_to_try:
        try:
            expected = hmac.new(key, body.encode("ascii"), hashlib.sha256).hexdigest()
        except UnicodeEncodeError:
            continue
        if hmac.compare_digest(signature.encode("utf-8"), expected.encode("ascii")):
            sig_matched = True
            break
    if not sig_matched:
        return None
    try:
        decoded = json.loads(_b64url_decode(body).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(decoded, dict):
        return None
    try:
        if int(decoded.get("exp", 0)) < int(time.time()):
            return None
    except (TypeError, ValueError):
        return None
    if expected_type is not None and decoded.get("typ") != expected_type:
        return None
    return decoded


# =============================================================================
# Cloud IAP signed-header verification
# =============================================================================
if (
    _google_auth_requests is not None
    and _google_auth_transport is not None
    and _google_auth_exceptions is not None
):

    class _SafeGoogleAuthResponse(_google_auth_transport.Response):  # type: ignore[misc,name-defined]
        """``google.auth.transport.Response`` backed by a bounded ``egress_guard.safe_urlopen`` payload."""

        def __init__(self, status: int, headers: Mapping[str, str], data: bytes) -> None:
            self._status = int(status)
            self._headers = dict(headers)
            self._data = bytes(data)

        @property
        def status(self) -> int:
            return self._status

        @property
        def headers(self) -> Mapping[str, str]:
            return self._headers

        @property
        def data(self) -> bytes:
            return self._data

    class _CertCachingRequest(_google_auth_requests.Request):  # type: ignore[misc,name-defined]
        """``google.auth.transport.requests.Request`` enforcing ``egress_guard.safe_urlopen`` for JWKS retrieval.

        Enforces HTTPS-only, explicit Google/IAP JWKS hostname allowlist (``GOOGLE_JWKS_ALLOWED_HOSTS``),
        DNS/IP destination validation, disabled HTTP redirects, verified TLS, explicit finite timeout,
        and a 64 KiB response size ceiling while caching successful ``200 OK`` public key documents.
        Never invokes the underlying ``requests.Session`` transport.
        """

        def __init__(
            self,
            ttl_seconds: float = 3600.0,
            *,
            max_bytes: int = egress_guard.DEFAULT_MAX_RESPONSE_BYTES,
            allowed_hosts: FrozenSet[str] = egress_guard.GOOGLE_JWKS_ALLOWED_HOSTS,
            dns_resolver: Optional[egress_guard.DnsResolver] = None,
            opener: Optional[urllib.request.OpenerDirector] = None,
        ) -> None:
            super().__init__()
            self._ttl_seconds = ttl_seconds
            self._max_bytes = max_bytes
            self._allowed_hosts = frozenset(allowed_hosts)
            self._dns_resolver = dns_resolver
            self._opener = opener
            self._cache: Dict[str, Tuple[float, _SafeGoogleAuthResponse]] = {}
            self._cache_lock = threading.Lock()

        def _execute_safe(
            self,
            url: str,
            *,
            method: str,
            body: Optional[bytes],
            headers: Optional[Mapping[str, str]],
            timeout: float,
        ) -> _SafeGoogleAuthResponse:
            upper_method = str(method or "GET").upper()
            if upper_method != "GET" or body is not None:
                raise _google_auth_exceptions.TransportError(
                    "JWKS certificate transport permits bodyless GET requests only."
                )
            req_headers = {"Accept": "application/json"}
            if headers:
                for k, v in headers.items():
                    req_headers[str(k)] = str(v)
            req = urllib.request.Request(url, headers=req_headers, method="GET")
            try:
                with egress_guard.safe_urlopen(
                    req,
                    timeout=float(timeout),
                    max_bytes=self._max_bytes,
                    allowed_hosts=self._allowed_hosts,
                    dns_resolver=self._dns_resolver,
                    opener=self._opener,
                ) as resp:
                    return _SafeGoogleAuthResponse(
                        status=resp.status,
                        headers=resp.headers,
                        data=resp.read(),
                    )
            except egress_guard.EgressError as exc:
                raise _google_auth_exceptions.TransportError(
                    f"Blocked JWKS HTTP request by egress policy: {egress_guard.redact_sensitive_text(exc)}"
                ) from exc
            except urllib.error.HTTPError as http_err:
                if 300 <= int(http_err.code) < 400:
                    raise _google_auth_exceptions.TransportError(
                        f"Blocked HTTP {http_err.code} redirect during JWKS retrieval."
                    ) from http_err
                hdrs = dict(http_err.headers.items()) if getattr(http_err, "headers", None) else {}
                return _SafeGoogleAuthResponse(status=int(http_err.code), headers=hdrs, data=b"")
            except Exception as exc:
                raise _google_auth_exceptions.TransportError(
                    f"JWKS retrieval transport error: {egress_guard.redact_sensitive_text(exc)}"
                ) from exc

        def __call__(self, url, method="GET", body=None, headers=None, timeout=None, **kwargs):  # type: ignore[override]
            effective_timeout = float(timeout) if timeout is not None else 10.0
            if str(method).upper() != "GET" or body is not None:
                return self._execute_safe(
                    url,
                    method=method,
                    body=body,
                    headers=headers,
                    timeout=effective_timeout,
                )
            now = time.time()
            with self._cache_lock:
                hit = self._cache.get(url)
            if hit and hit[0] > now:
                return hit[1]
            response = self._execute_safe(
                url,
                method=method,
                body=None,
                headers=headers,
                timeout=effective_timeout,
            )
            if getattr(response, "status", None) == 200:
                with self._cache_lock:
                    self._cache[url] = (now + self._ttl_seconds, response)
            return response

else:  # pragma: no cover
    _CertCachingRequest = None  # type: ignore[assignment,misc]

_IAP_TRANSPORT: Any = None
_IAP_TRANSPORT_LOCK = threading.Lock()
_IAP_AUDIENCE_WARNING_EMITTED = False


def _iap_transport() -> Any:
    global _IAP_TRANSPORT
    with _IAP_TRANSPORT_LOCK:
        if _IAP_TRANSPORT is None and _CertCachingRequest is not None:
            _IAP_TRANSPORT = _CertCachingRequest()
        return _IAP_TRANSPORT


def verify_iap_jwt(token: Optional[str], audience: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Verifies a Cloud IAP ``X-Goog-IAP-JWT-Assertion`` and returns its claims, or None if it is not valid.

    Uses ``google.oauth2.id_token.verify_token(token, google.auth.transport.requests.Request(), audience=...,
    certs_url="https://www.gstatic.com/iap/verify/public_key")`` (signature, expiry, audience) and requires
    ``iss == "https://cloud.google.com/iap"``, a valid ``email`` claim, and (in production or when configured)
    an exact match on ``aud == expected_audience``.
    The plain ``X-Goog-Authenticated-User-Email`` header is NEVER trusted: anyone can send it to a public service.
    """
    global _IAP_AUDIENCE_WARNING_EMITTED
    if not token or google_id_token is None:
        return None
    expected_audience = audience or (os.getenv(ENV_IAP_AUDIENCE) or "").strip() or None
    require_audience = is_production_environment() or (env_flag(ENV_REQUIRE_IAP_AUDIENCE) is True)
    if expected_audience is None and require_audience:
        logger.error("Rejected Cloud IAP JWT assertion: %s is required in production.", ENV_IAP_AUDIENCE)
        return None
    try:
        claims = google_id_token.verify_token(
            token,
            _iap_transport(),
            audience=expected_audience,
            certs_url=IAP_CERTS_URL,
            clock_skew_in_seconds=60,
        )
    except TypeError:
        claims = google_id_token.verify_token(
            token,
            _iap_transport(),
            audience=expected_audience,
            certs_url=IAP_CERTS_URL,
        )
    except Exception as exc:  # invalid signature, expired, wrong audience, malformed, key fetch failure...
        logger.warning("Rejected Cloud IAP JWT assertion: %s: %s", type(exc).__name__, str(exc)[:200])
        return None
    if not isinstance(claims, Mapping) or claims.get("iss") != IAP_ISSUER:
        logger.warning("Rejected Cloud IAP JWT assertion: unexpected issuer.")
        return None
    if expected_audience is not None:
        claim_aud = claims.get("aud")
        aud_matches = (
            claim_aud == expected_audience
            if isinstance(claim_aud, str)
            else (isinstance(claim_aud, (list, tuple)) and expected_audience in claim_aud)
        )
        if not aud_matches:
            logger.warning("Rejected Cloud IAP JWT assertion: audience mismatch (expected %r, got %r).", expected_audience, claim_aud)
            return None
    if "exp" in claims:
        try:
            if int(claims["exp"]) < int(time.time()) - 60:
                logger.warning("Rejected Cloud IAP JWT assertion: token is expired.")
                return None
        except (TypeError, ValueError):
            return None
    email = str(claims.get("email") or "").strip()
    if not email:
        return None
    if expected_audience is None and not _IAP_AUDIENCE_WARNING_EMITTED:
        _IAP_AUDIENCE_WARNING_EMITTED = True
        logger.warning("%s is not set: the IAP JWT audience is not checked (local dev only).", ENV_IAP_AUDIENCE)
    return dict(claims)


def verify_google_oidc_id_token(
    token: Optional[str],
    *,
    audiences: Sequence[str] = (),
    expected_nonce: Optional[str] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Cryptographically verifies a Google OpenID Connect ID token JWT (signature, iss, aud, exp, and nonce).

    Uses ``google.oauth2.id_token.verify_oauth2_token`` against Google's OIDC JWKS certs (cached in-process).
    """
    if not token or google_id_token is None:
        return None, "Google ID token verification is unavailable."
    single_audience = audiences[0] if len(audiences) == 1 else None
    try:
        claims = google_id_token.verify_oauth2_token(
            token,
            _iap_transport(),
            audience=single_audience,
            clock_skew_in_seconds=60,
        )
    except TypeError:
        try:
            claims = google_id_token.verify_oauth2_token(
                token,
                _iap_transport(),
                audience=single_audience,
            )
        except Exception as exc:
            return None, f"Google ID token signature or claim verification failed: {exc}"
    except Exception as exc:
        return None, f"Google ID token signature or claim verification failed: {exc}"

    if not isinstance(claims, Mapping):
        return None, "Google ID token payload is malformed."
    if claims.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        return None, "Google ID token has an unexpected issuer."
    if audiences:
        claim_aud = claims.get("aud")
        aud_ok = (
            claim_aud in audiences
            if isinstance(claim_aud, str)
            else (isinstance(claim_aud, (list, tuple)) and any(a in audiences for a in claim_aud))
        )
        if not aud_ok:
            return None, "Google ID token was issued for a different OAuth client (audience mismatch)."
    elif is_production_environment():
        return None, "Google ID token rejected: no allowed OAuth client audience is configured in production."
    try:
        if int(claims.get("exp", 0)) < int(time.time()):
            return None, "Google ID token has expired."
    except (TypeError, ValueError):
        return None, "Google ID token has an invalid exp claim."
    if expected_nonce is not None:
        claim_nonce = str(claims.get("nonce") or "")
        if not claim_nonce or not hmac.compare_digest(claim_nonce.encode("utf-8"), expected_nonce.encode("utf-8")):
            return None, "Google ID token nonce mismatch."
    return dict(claims), None


# =============================================================================
# Identity resolution and binding
# =============================================================================
def _default_normalize_user_id(value: str) -> str:
    cleaned = str(value or "").strip()
    if cleaned.lower().startswith("accounts.google.com:"):
        cleaned = cleaned.split(":", 1)[1].strip()
    return cleaned.lower()


@dataclass(frozen=True)
class AuthenticatedIdentity:
    """A request identity proven by a signed portal session token or by a verified Cloud IAP JWT."""

    user_id: str
    email: str
    source: str  # "session_token" | "iap"
    claims: Mapping[str, Any] = field(default_factory=dict, compare=False, hash=False, repr=False)
    auth_transport: str = field(default="header", compare=False, hash=False, repr=False)  # "iap" | "header" | "cookie"
    raw_token: str = field(default="", compare=False, hash=False, repr=False)


class IdentityResolver:
    """Resolves the authenticated identity of an HTTP/WebSocket connection. Never trusts unsigned identity hints.

    Sources, in order:
      1. ``X-Goog-IAP-JWT-Assertion`` verified by :func:`verify_iap_jwt` (email taken from the verified claims).
      2. A signed portal session token in one of ``session_token_headers`` (e.g. ``X-PQC-User-Token`` or
         ``Authorization: Bearer``) or in the ``session_cookie_name`` cookie, verified by ``verify_session_token``.
    Headers such as ``X-PQC-User-Id`` or ``X-Goog-Authenticated-User-Email`` are ignored entirely.
    """

    def __init__(
        self,
        *,
        verify_session_token: Callable[[Optional[str]], Optional[Mapping[str, Any]]],
        is_allowed_email: Callable[[str], bool],
        session_cookie_name: str,
        session_token_headers: Sequence[str] = ("X-PQC-User-Token", "Authorization"),
        normalize_user_id: Callable[[str], str] = _default_normalize_user_id,
        iap_verifier: Optional[Callable[[str], Optional[Mapping[str, Any]]]] = None,
    ) -> None:
        self._verify_session_token = verify_session_token
        self._is_allowed_email = is_allowed_email
        self._session_cookie_name = session_cookie_name
        self._session_token_headers = tuple(session_token_headers)
        self._normalize = normalize_user_id
        self._iap_verifier = iap_verifier

    def resolve(self, conn: HTTPConnection) -> Optional[AuthenticatedIdentity]:
        assertion = conn.headers.get(IAP_JWT_HEADER)
        if assertion:
            verifier = self._iap_verifier or verify_iap_jwt  # module lookup at call time (monkeypatch friendly)
            claims = verifier(assertion)
            if claims and claims.get("email"):
                email = self._normalize(str(claims["email"]))
                if self._is_allowed_email(email):
                    return AuthenticatedIdentity(
                        user_id=email,
                        email=email,
                        source="iap",
                        claims=dict(claims),
                        auth_transport="iap",
                        raw_token=assertion,
                    )

        header_candidates = [(conn.headers.get(h), "header") for h in self._session_token_headers]
        cookie_candidate = (conn.cookies.get(self._session_cookie_name), "cookie")
        for candidate, transport in [*header_candidates, cookie_candidate]:
            if not candidate:
                continue
            decoded = self._verify_session_token(candidate)
            if not decoded:
                continue
            email = self._normalize(str(decoded.get("email") or decoded.get("uid") or ""))
            if email and self._is_allowed_email(email):
                return AuthenticatedIdentity(
                    user_id=email,
                    email=email,
                    source="session_token",
                    claims=dict(decoded),
                    auth_transport=transport,
                    raw_token=str(candidate).strip(),
                )
        return None


def bind_user_id(
    identity: Optional[AuthenticatedIdentity],
    explicit_user_id: Optional[str] = None,
    *,
    normalize_user_id: Callable[[str], str] = _default_normalize_user_id,
) -> str:
    """Returns the user id a request may act on: always the authenticated identity's.

    Raises HTTP 401 when there is no authenticated identity, and HTTP 403 when the caller explicitly asked for a
    different ``user_id`` (query/form/body parameter). Blank explicit values are treated as absent.
    """
    if identity is None:
        raise HTTPException(status_code=401, detail=UNAUTHENTICATED_DETAIL, headers={"WWW-Authenticate": "Bearer"})
    if explicit_user_id is not None and str(explicit_user_id).strip():
        if normalize_user_id(str(explicit_user_id)) != identity.user_id:
            raise HTTPException(status_code=403, detail=USER_MISMATCH_DETAIL)
    return identity.user_id


def is_admin_identity(identity: Optional[AuthenticatedIdentity]) -> bool:
    """Admin = listed in ``PQC_ADMIN_EMAILS``. Without that list, any signed-in user is admin only off Cloud Run."""
    if identity is None:
        return False
    admins = admin_emails()
    if admins:
        return identity.email in admins
    return not running_on_cloud_run()


# =============================================================================
# ADK-native route guard (pure ASGI middleware)
# =============================================================================
PORTAL_EXACT_PATHS: FrozenSet[str] = frozenset({"/", "/favicon.ico", "/robots.txt"})
PORTAL_PATH_PREFIXES: Tuple[str, ...] = ("/api/", "/static/")
DEV_UI_STATIC_PREFIX = "/dev-ui"
_USER_SEGMENT_RE = re.compile(r"/users/([^/]+)")
_BODY_USER_KEYS = ("user_id", "userId")

Resolver = Callable[[HTTPConnection], Optional[AuthenticatedIdentity]]
ASGIApp = Callable[[MutableMapping[str, Any], Callable[[], Awaitable[Any]], Callable[[Any], Awaitable[None]]], Awaitable[None]]


def is_portal_path(path: str, *, dev_ui_static: bool = False) -> bool:
    """True for the portal allowlist: ``/``, ``/api/*``, static assets and (only when mounted) ``/dev-ui`` assets.

    Every other path is treated as an ADK-native route by :class:`AdkRouteGuardMiddleware`. Portal ``/api/*``
    endpoints enforce authentication themselves (public: health, models, auth/*, OAuth callbacks).
    """
    if path in PORTAL_EXACT_PATHS or path.startswith(PORTAL_PATH_PREFIXES):
        return True
    if dev_ui_static and (path == DEV_UI_STATIC_PREFIX or path.startswith(DEV_UI_STATIC_PREFIX + "/")):
        return True
    return False


class AdkRouteGuardMiddleware:
    """Guards every route outside the portal allowlist (the routes added by ADK's ``get_fast_api_app``).

    * ADK API disabled (default on Cloud Run): HTTP 404 ``{"detail": "Not Found"}`` (WebSocket: close 1008).
    * Enabled: requires an identity from ``resolver`` (401 otherwise) and binds every user id the request names to it:
      ``/users/{user_id}/`` path segments (``/apps/{app}/users/{user_id}/...``, ``/dev/apps/...``), ``user_id`` query
      parameters (``/run_live``) and top-level ``user_id``/``userId`` in JSON bodies (``/run``, ``/run_sse``, eval
      ``add_session``...). Any mismatch is HTTP 403. Cross-site WebSocket handshakes are rejected.
    * ``on_identity`` is called before the request is forwarded (e.g. to bind a per-tenant ``ContextVar``).
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        resolver: Resolver,
        api_enabled: Union[bool, Callable[[], bool]],
        dev_ui_static: bool = False,
        on_identity: Optional[Callable[[AuthenticatedIdentity], Any]] = None,
        normalize_user_id: Callable[[str], str] = _default_normalize_user_id,
        allowed_origins: Optional[Sequence[str]] = None,
        max_body_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        self.app = app
        self._resolver = resolver
        self._api_enabled = api_enabled
        self._dev_ui_static = dev_ui_static
        self._on_identity = on_identity
        self._normalize = normalize_user_id
        self._allowed_origins = tuple(o.rstrip("/") for o in (allowed_origins or ()))
        self._max_body_bytes = max_body_bytes

    def _enabled(self) -> bool:
        return bool(self._api_enabled() if callable(self._api_enabled) else self._api_enabled)

    async def __call__(self, scope: MutableMapping[str, Any], receive: Callable[[], Awaitable[Any]], send: Callable[[Any], Awaitable[None]]) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope.get("path") or "/"
        root_path = scope.get("root_path") or ""
        if root_path and path.startswith(root_path):
            path = path[len(root_path):] or "/"
        if is_portal_path(path, dev_ui_static=self._dev_ui_static):
            await self.app(scope, receive, send)
            return

        if not self._enabled():
            await self._deny(scope, receive, send, 404, "Not Found")
            return

        conn = HTTPConnection(scope)
        if scope["type"] == "websocket" and not self._websocket_origin_allowed(conn):
            await self._deny(scope, receive, send, 403, "Forbidden: cross-origin WebSocket handshake.")
            return

        identity = self._resolver(conn)
        if identity is None:
            await self._deny(scope, receive, send, 401, UNAUTHENTICATED_DETAIL)
            return

        for match in _USER_SEGMENT_RE.finditer(path):
            if self._normalize(match.group(1)) != identity.user_id:
                await self._deny(scope, receive, send, 403, USER_MISMATCH_DETAIL)
                return
        for key in _BODY_USER_KEYS:
            for value in conn.query_params.getlist(key):
                if self._normalize(value) != identity.user_id:
                    await self._deny(scope, receive, send, 403, USER_MISMATCH_DETAIL)
                    return

        if scope["type"] == "http" and str(scope.get("method", "GET")).upper() in ("POST", "PUT", "PATCH", "DELETE"):
            body = await self._read_body(receive)
            if body is None:
                await self._deny(scope, receive, send, 413, "Request body too large.")
                return
            body_user = self._body_user_ids(body)
            if any(self._normalize(u) != identity.user_id for u in body_user):
                await self._deny(scope, receive, send, 403, USER_MISMATCH_DETAIL)
                return
            receive = self._replay(body, receive)

        if self._on_identity is not None:
            self._on_identity(identity)
        await self.app(scope, receive, send)

    # ------------------------------------------------------------------ helpers
    def _websocket_origin_allowed(self, conn: HTTPConnection) -> bool:
        origin = (conn.headers.get("origin") or "").rstrip("/")
        if not origin:
            return True  # non-browser client
        if origin in self._allowed_origins:
            return True
        host = conn.headers.get("host") or ""
        proto = (conn.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
        if not proto:
            proto = "https" if conn.url.scheme in ("wss", "https") else "http"
        proto = {"wss": "https", "ws": "http"}.get(proto, proto)
        return bool(host) and origin.lower() == f"{proto}://{host}".lower()

    async def _read_body(self, receive: Callable[[], Awaitable[Any]]) -> Optional[bytes]:
        chunks: List[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"") or b""
                size += len(chunk)
                if size > self._max_body_bytes:
                    return None
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                break
        return b"".join(chunks)

    @staticmethod
    def _replay(body: bytes, receive: Callable[[], Awaitable[Any]]) -> Callable[[], Awaitable[Any]]:
        sent = False

        async def replay_receive() -> Any:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        return replay_receive

    @staticmethod
    def _body_user_ids(body: bytes) -> List[str]:
        if not body or not body.lstrip().startswith(b"{"):
            return []
        try:
            parsed = json.loads(body.decode("utf-8"))
        except Exception:
            return []
        if not isinstance(parsed, dict):
            return []
        return [str(parsed[k]) for k in _BODY_USER_KEYS if parsed.get(k) is not None]

    @staticmethod
    async def _deny(scope: MutableMapping[str, Any], receive: Any, send: Any, status: int, detail: str) -> None:
        if scope["type"] == "websocket":
            await WebSocketClose(code=1008, reason=detail[:120])(scope, receive, send)
            return
        headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
        await JSONResponse({"detail": detail}, status_code=status, headers=headers)(scope, receive, send)
