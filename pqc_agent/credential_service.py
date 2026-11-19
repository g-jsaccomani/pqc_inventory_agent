"""Distributed Envelope-Encrypted Credential Service (replaces ADK ``InMemoryCredentialService``).

Identity Architecture & Justification (Phase 2 — ID-01)
-------------------------------------------------------
1. **Preferred Production Identity Model — Service Account Impersonation & Least-Privilege ADC:**
   For enterprise Google Cloud PQC assessments, the primary model uses short-lived (<= 3600s) IAM Credentials API
   tokens via ``google.auth.impersonated_credentials.Credentials`` (``mode='impersonation'``) or the Cloud Run runtime
   service account (``mode='adc'``) restricted to read-only roles (``roles/cloudkms.viewer``, ``roles/cloudasset.viewer``,
   ``roles/resourcemanager.organizationViewer``, ``roles/compute.viewer``, ``roles/privateca.auditor``). No long-lived
   user secrets exist in these modes.

2. **Delegated User Authorization Model — KMS Envelope-Encrypted Persistent Store (``mode='access_token'`` / 3LO):**
   When inspecting external GCP organizations/projects where user-specific 3-Legged OAuth 2.0 authorization is
   genuinely required, delegated credentials (short-lived ``access_token`` and optional ``refresh_token``) are stored
   in PostgreSQL (``pqc_delegated_credentials``) using **two-tier Envelope Encryption**:
     - Each write generates a fresh CSPRNG 256-bit Data Encryption Key (DEK) and 96-bit AES-GCM nonce.
     - The credential JSON is encrypted with ``AES-256-GCM`` bound to Authenticated Associated Data (AAD) encoding
       ``app_name``, ``tenant_domain``, ``user_id``, and ``credential_key``.
     - In production, the 256-bit DEK is wrapped and unwrapped exclusively through **Google Cloud KMS**
       (``PQC_KMS_KEY_NAME``, ``KeyManagementServiceClient.encrypt`` / ``.decrypt``) with the same AAD; production
       fails closed if ``PQC_KMS_KEY_NAME`` is unconfigured when delegated credentials are used.
     - In explicitly non-production local development and isolated unit tests without Cloud KMS, the per-record DEK is
       wrapped with an RFC 5869 ``HKDF-SHA256`` 256-bit Key Encryption Key (KEK) using ``AES-256-GCM`` + AAD.
   - Refresh tokens are never exposed to the frontend, ``ToolContext`` session state, JSON APIs, or logs.
   - Expiration and revocation are enforced atomically in the shared database across all Cloud Run instances.
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import dataclasses
import hashlib
import json
import logging
import os
import secrets
import time
from typing import Any, Callable, Dict, Optional, Protocol
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from google.adk.agents.callback_context import CallbackContext
from google.adk.auth.auth_credential import AuthCredential, AuthCredentialTypes, OAuth2Auth
from google.adk.auth.auth_tool import AuthConfig
from google.adk.auth.credential_service.base_credential_service import BaseCredentialService

from pqc_agent import auth_guard, auth_store, egress_guard

logger = logging.getLogger(__name__)

ENV_KMS_KEY_NAME = "PQC_KMS_KEY_NAME"
ENV_CREDENTIAL_KEK = "PQC_CREDENTIAL_KEK"
DEFAULT_APP_NAME = "pqc_agent"
DEFAULT_GCP_CREDENTIAL_KEY = "gcp_pqc_oauth_3lo_credential"


def _b64_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _b64_decode(encoded: str) -> bytes:
    return base64.urlsafe_b64decode(encoded.encode("ascii"))


def build_credential_id(app_name: str, tenant_domain: str, user_id: str, credential_key: str) -> str:
    canonical = f"{app_name.strip()}|{tenant_domain.strip().lower()}|{user_id.strip().lower()}|{credential_key.strip()}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_credential_aad(app_name: str, tenant_domain: str, user_id: str, credential_key: str) -> bytes:
    canonical = (
        f"pqc-cred-v1|app={app_name.strip()}|tenant={tenant_domain.strip().lower()}"
        f"|user={user_id.strip().lower()}|key={credential_key.strip()}"
    )
    return canonical.encode("utf-8")


class DekKeyWrapper(Protocol):
    """Protocol for wrapping and unwrapping 256-bit Data Encryption Keys (DEKs)."""

    provider_id: str
    kms_key_name: Optional[str]

    def wrap_dek(self, dek: bytes, aad: bytes) -> bytes:
        ...

    def unwrap_dek(self, wrapped_dek: bytes, aad: bytes, kms_key_name: Optional[str] = None) -> bytes:
        ...


class CloudKmsDekWrapper:
    """Wraps and unwraps per-record 256-bit DEKs via Google Cloud KMS symmetric encryption with AAD."""

    provider_id = "gcp_kms"

    def __init__(self, kms_key_name: str, *, kms_client: Optional[Any] = None) -> None:
        clean_key = (kms_key_name or "").strip()
        if not clean_key:
            raise ValueError("Cloud KMS key resource name (PQC_KMS_KEY_NAME) is required.")
        self.kms_key_name = clean_key
        self._kms_client = kms_client

    def _client(self) -> Any:
        if self._kms_client is None:
            from google.cloud import kms_v1

            self._kms_client = kms_v1.KeyManagementServiceClient()
        return self._kms_client

    def wrap_dek(self, dek: bytes, aad: bytes) -> bytes:
        resp = self._client().encrypt(
            request={
                "name": self.kms_key_name,
                "plaintext": dek,
                "additional_authenticated_data": aad,
            }
        )
        ciphertext = getattr(resp, "ciphertext", None)
        if not isinstance(ciphertext, (bytes, bytearray)) or not ciphertext:
            raise RuntimeError("Cloud KMS encrypt returned empty ciphertext.")
        return bytes(ciphertext)

    def unwrap_dek(self, wrapped_dek: bytes, aad: bytes, kms_key_name: Optional[str] = None) -> bytes:
        target_key = (kms_key_name or self.kms_key_name or "").strip()
        if not target_key:
            raise RuntimeError("Missing Cloud KMS key name for DEK unwrap.")
        resp = self._client().decrypt(
            request={
                "name": target_key,
                "ciphertext": wrapped_dek,
                "additional_authenticated_data": aad,
            }
        )
        plaintext = getattr(resp, "plaintext", None)
        if not isinstance(plaintext, (bytes, bytearray)) or len(plaintext) != 32:
            raise RuntimeError("Cloud KMS decrypt did not return a valid 256-bit DEK.")
        return bytes(plaintext)


class LocalHkdfKekWrapper:
    """Dev/test-only AES-256-GCM DEK wrapper derived via RFC 5869 HKDF-SHA256 (never permitted in production)."""

    provider_id = "local_hkdf_kek"
    kms_key_name = None

    def __init__(self, root_material: bytes) -> None:
        if len(root_material) < 32:
            raise ValueError("Root KEK material must be at least 32 bytes.")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"pqc-credential-envelope-kek-salt-v1",
            info=b"pqc-delegated-credential-dek-wrapper",
        )
        self._kek = hkdf.derive(root_material)

    def wrap_dek(self, dek: bytes, aad: bytes) -> bytes:
        iv = secrets.token_bytes(12)
        encrypted = AESGCM(self._kek).encrypt(iv, dek, aad)
        return iv + encrypted

    def unwrap_dek(self, wrapped_dek: bytes, aad: bytes, kms_key_name: Optional[str] = None) -> bytes:
        if len(wrapped_dek) < 12 + 32 + 16:
            raise ValueError("Malformed wrapped DEK envelope.")
        iv, body = wrapped_dek[:12], wrapped_dek[12:]
        dek = AESGCM(self._kek).decrypt(iv, body, aad)
        if len(dek) != 32:
            raise ValueError("Unwrapped DEK has invalid length.")
        return dek


def resolve_dek_wrapper(*, kms_client: Optional[Any] = None) -> DekKeyWrapper:
    """Resolves the active DEK wrapper; fails closed in production if ``PQC_KMS_KEY_NAME`` is unconfigured."""
    kms_key = (os.getenv(ENV_KMS_KEY_NAME) or "").strip()
    if kms_key:
        return CloudKmsDekWrapper(kms_key, kms_client=kms_client)
    if auth_guard.is_production_environment():
        raise RuntimeError(
            f"Production credential security failure: {ENV_KMS_KEY_NAME} must be configured with a Google Cloud KMS "
            "CryptoKey resource name for envelope encryption of delegated credentials."
        )
    raw_kek = (os.getenv(ENV_CREDENTIAL_KEK) or os.getenv(auth_guard.ENV_AUTH_SECRET) or "").strip()
    if len(raw_kek) >= 32:
        material = raw_kek.encode("utf-8")
    else:
        data_dir = (os.getenv("PQC_DATA_DIR") or "data").strip()
        material = auth_guard.load_or_create_hmac_secret(data_dir, require_stable_secret=False)
    return LocalHkdfKekWrapper(material)


@dataclasses.dataclass(frozen=True)
class DecryptedDelegatedToken:
    """In-memory view of a decrypted short-lived access token (never logs or serializes secret values)."""

    user_id: str
    tenant_domain: str
    access_token: str
    expires_at: float
    has_refresh_token: bool
    kek_provider: str

    def __repr__(self) -> str:
        return (
            f"<DecryptedDelegatedToken(user_id={self.user_id!r}, tenant={self.tenant_domain!r}, "
            f"expires_at={self.expires_at:.0f}, provider={self.kek_provider!r})>"
        )


def _default_oauth_refresh_exchange(
    refresh_token: str,
    client_id: str,
    client_secret: str,
    token_uri: str,
) -> Optional[Dict[str, Any]]:
    """Exchanges a stored refresh_token server-side for a fresh short-lived access_token."""
    if not refresh_token or not client_id:
        return None
    params: Dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }
    if client_secret:
        params["client_secret"] = client_secret
    data = urllib.parse.urlencode(params).encode("utf-8")
    req = urllib.request.Request(
        token_uri or "https://oauth2.googleapis.com/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    with egress_guard.safe_urlopen(
        req,
        timeout=8.0,
        max_bytes=egress_guard.DEFAULT_MAX_RESPONSE_BYTES,
        allowed_hosts=egress_guard.GOOGLE_OAUTH_ALLOWED_HOSTS,
    ) as resp:
        parsed = json.loads(resp.read().decode("utf-8"))
    return parsed if isinstance(parsed, dict) and parsed.get("access_token") else None


class EncryptedDatabaseCredentialService(BaseCredentialService):
    """Production ADK ``BaseCredentialService`` backed by envelope-encrypted PostgreSQL records."""

    def __init__(
        self,
        *,
        store: Optional[auth_store.DistributedAuthStore] = None,
        dek_wrapper: Optional[DekKeyWrapper] = None,
        kms_client: Optional[Any] = None,
        refresh_handler: Optional[Callable[[str, str, str, str], Optional[Dict[str, Any]]]] = None,
    ) -> None:
        super().__init__()
        self._store = store
        self._explicit_wrapper = dek_wrapper
        self._kms_client = kms_client
        self._refresh_handler = refresh_handler or _default_oauth_refresh_exchange

    def _active_store(self) -> auth_store.DistributedAuthStore:
        return self._store or auth_store.get_active_auth_store()

    def _wrapper(self) -> DekKeyWrapper:
        if self._explicit_wrapper is not None:
            return self._explicit_wrapper
        return resolve_dek_wrapper(kms_client=self._kms_client)

    @staticmethod
    def _default_ttl_seconds() -> float:
        try:
            return max(60.0, min(float(os.getenv("PQC_ACCESS_TOKEN_TTL_SECONDS", "3600")), 3600.0))
        except ValueError:
            return 3600.0

    def store_delegated_token(
        self,
        *,
        user_id: str,
        access_token: str,
        refresh_token: Optional[str] = None,
        expires_in: Optional[float] = None,
        app_name: str = DEFAULT_APP_NAME,
        credential_key: str = DEFAULT_GCP_CREDENTIAL_KEY,
        client_id: str = "",
        client_secret: str = "",
        token_uri: str = "https://oauth2.googleapis.com/token",
        scopes: Optional[list[str]] = None,
        caller_user_id: Optional[str] = None,
    ) -> Optional[DecryptedDelegatedToken]:
        """Envelope-encrypts and persists a user's delegated OAuth credential in ``pqc_delegated_credentials``."""
        clean_uid = str(user_id or "").strip().lower()
        if not clean_uid:
            raise ValueError("user_id is required to store delegated credentials.")
        if caller_user_id and str(caller_user_id).strip().lower() != clean_uid:
            raise PermissionError("Forbidden: cannot store delegated credentials for a different user.")

        clean_access = str(access_token or "").strip()
        if clean_access.lower().startswith("bearer "):
            clean_access = clean_access[7:].strip()
        if not clean_access:
            self.revoke_delegated_tokens(user_id=clean_uid, credential_key=credential_key, reason="cleared")
            return None

        tenant = auth_store.extract_tenant_domain(clean_uid)
        cred_id = build_credential_id(app_name, tenant, clean_uid, credential_key)
        aad = build_credential_aad(app_name, tenant, clean_uid, credential_key)
        aad_hash = hashlib.sha256(aad).hexdigest()

        now = time.time()
        ttl = float(expires_in) if (expires_in is not None and float(expires_in) > 0) else self._default_ttl_seconds()
        expires_at = now + ttl
        clean_refresh = str(refresh_token or "").strip() or None

        envelope_payload = {
            "access_token": clean_access,
            "refresh_token": clean_refresh,
            "client_id": client_id,
            "client_secret": client_secret,
            "token_uri": token_uri,
            "scopes": list(scopes or []),
            "issued_at": now,
            "expires_at": expires_at,
        }
        plaintext_bytes = json.dumps(envelope_payload, separators=(",", ":")).encode("utf-8")

        dek_buf = bytearray(secrets.token_bytes(32))
        nonce = secrets.token_bytes(12)
        wrapper = self._wrapper()
        try:
            wrapped_dek = wrapper.wrap_dek(bytes(dek_buf), aad)
            ciphertext = AESGCM(bytes(dek_buf)).encrypt(nonce, plaintext_bytes, aad)
        finally:
            for i in range(len(dek_buf)):
                dek_buf[i] = 0

        self._active_store().upsert_encrypted_credential(
            credential_id=cred_id,
            app_name=app_name,
            tenant_domain=tenant,
            user_id=clean_uid,
            credential_key=credential_key,
            kek_provider=wrapper.provider_id,
            kms_key_name=wrapper.kms_key_name,
            wrapped_dek_b64=_b64_encode(wrapped_dek),
            payload_nonce_b64=_b64_encode(nonce),
            ciphertext_b64=_b64_encode(ciphertext),
            aad_sha256=aad_hash,
            has_refresh_token=bool(clean_refresh),
            issued_at=now,
            expires_at=expires_at,
        )
        return DecryptedDelegatedToken(
            user_id=clean_uid,
            tenant_domain=tenant,
            access_token=clean_access,
            expires_at=expires_at,
            has_refresh_token=bool(clean_refresh),
            kek_provider=wrapper.provider_id,
        )

    def load_delegated_token(
        self,
        *,
        user_id: str,
        caller_user_id: Optional[str] = None,
        caller_tenant_domain: Optional[str] = None,
        app_name: str = DEFAULT_APP_NAME,
        credential_key: str = DEFAULT_GCP_CREDENTIAL_KEY,
        now_override: Optional[float] = None,
    ) -> Optional[DecryptedDelegatedToken]:
        """Loads, validates ownership/revocation/expiry, and decrypts a delegated OAuth token."""
        clean_uid = str(user_id or "").strip().lower()
        if not clean_uid:
            return None
        expected_tenant = auth_store.extract_tenant_domain(clean_uid)

        if caller_user_id is not None and str(caller_user_id).strip().lower() != clean_uid:
            raise PermissionError(
                f"Forbidden: caller '{caller_user_id}' cannot access delegated credentials owned by '{clean_uid}'."
            )
        if caller_tenant_domain is not None and str(caller_tenant_domain).strip().lower() != expected_tenant:
            raise PermissionError(
                f"Forbidden: cross-tenant credential access ('{caller_tenant_domain}' != '{expected_tenant}')."
            )

        cred_id = build_credential_id(app_name, expected_tenant, clean_uid, credential_key)
        row = self._active_store().get_encrypted_credential_row(
            credential_id=cred_id,
            expected_user_id=clean_uid,
            expected_tenant_domain=expected_tenant,
        )
        if row is None:
            return None
        if row["revoked_at"] is not None or not row["ciphertext_b64"] or not row["wrapped_dek_b64"]:
            return None

        aad = build_credential_aad(app_name, expected_tenant, clean_uid, credential_key)
        if hashlib.sha256(aad).hexdigest() != row["aad_sha256"]:
            raise PermissionError("Credential AAD integrity mismatch.")

        wrapper = self._wrapper()
        dek_buf: Optional[bytearray] = None
        try:
            unwrapped = wrapper.unwrap_dek(
                _b64_decode(row["wrapped_dek_b64"]),
                aad,
                kms_key_name=row.get("kms_key_name"),
            )
            dek_buf = bytearray(unwrapped)
            plaintext = AESGCM(bytes(dek_buf)).decrypt(
                _b64_decode(row["payload_nonce_b64"]),
                _b64_decode(row["ciphertext_b64"]),
                aad,
            )
            payload = json.loads(plaintext.decode("utf-8"))
        except PermissionError:
            raise
        except Exception as exc:
            logger.warning(
                "Delegated credential decryption failed for user '%s' (provider=%s): %s",
                clean_uid,
                row.get("kek_provider"),
                type(exc).__name__,
            )
            raise PermissionError("Credential envelope authentication or decryption failed.") from exc
        finally:
            if dek_buf is not None:
                for i in range(len(dek_buf)):
                    dek_buf[i] = 0

        now = float(now_override if now_override is not None else time.time())
        if float(row["expires_at"]) <= now:
            stored_refresh = str(payload.get("refresh_token") or "").strip()
            if stored_refresh:
                try:
                    refreshed = self._refresh_handler(
                        stored_refresh,
                        str(payload.get("client_id") or ""),
                        str(payload.get("client_secret") or ""),
                        str(payload.get("token_uri") or "https://oauth2.googleapis.com/token"),
                    )
                    if refreshed and refreshed.get("access_token"):
                        return self.store_delegated_token(
                            user_id=clean_uid,
                            access_token=str(refreshed["access_token"]),
                            refresh_token=str(refreshed.get("refresh_token") or stored_refresh),
                            expires_in=float(refreshed.get("expires_in") or 3600),
                            app_name=app_name,
                            credential_key=credential_key,
                            client_id=str(payload.get("client_id") or ""),
                            client_secret=str(payload.get("client_secret") or ""),
                            token_uri=str(payload.get("token_uri") or "https://oauth2.googleapis.com/token"),
                            scopes=list(payload.get("scopes") or []),
                            caller_user_id=clean_uid,
                        )
                except Exception as exc:
                    logger.warning("Delegated refresh token exchange failed for '%s': %s", clean_uid, type(exc).__name__)
            # Expired with no usable refresh token -> revoke/clear and fail closed
            self.revoke_delegated_tokens(user_id=clean_uid, credential_key=credential_key, reason="expired")
            return None

        tok = str(payload.get("access_token") or "").strip()
        if not tok:
            return None
        return DecryptedDelegatedToken(
            user_id=clean_uid,
            tenant_domain=expected_tenant,
            access_token=tok,
            expires_at=float(row["expires_at"]),
            has_refresh_token=bool(payload.get("refresh_token")),
            kek_provider=str(row["kek_provider"]),
        )

    def revoke_delegated_tokens(
        self,
        *,
        user_id: str,
        credential_key: Optional[str] = None,
        reason: str = "revoked",
    ) -> int:
        clean_uid = str(user_id or "").strip().lower()
        tenant = auth_store.extract_tenant_domain(clean_uid)
        return self._active_store().revoke_encrypted_credentials(
            user_id=clean_uid,
            tenant_domain=tenant,
            credential_key=credential_key,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Envelope encryption helper for admin-stored OAuth client_secret
    # ------------------------------------------------------------------
    def encrypt_config_secret(self, secret_value: str, config_key: str = "global") -> str:
        clean = (secret_value or "").strip()
        if not clean:
            return ""
        aad = f"pqc-oauth-cfg-v1|key={config_key}".encode("utf-8")
        dek_buf = bytearray(secrets.token_bytes(32))
        nonce = secrets.token_bytes(12)
        wrapper = self._wrapper()
        try:
            wrapped_dek = wrapper.wrap_dek(bytes(dek_buf), aad)
            ct = AESGCM(bytes(dek_buf)).encrypt(nonce, clean.encode("utf-8"), aad)
        finally:
            for i in range(len(dek_buf)):
                dek_buf[i] = 0
        return json.dumps(
            {
                "v": 1,
                "provider": wrapper.provider_id,
                "kms_key": wrapper.kms_key_name,
                "dek": _b64_encode(wrapped_dek),
                "iv": _b64_encode(nonce),
                "ct": _b64_encode(ct),
            },
            separators=(",", ":"),
        )

    def decrypt_config_secret(self, encrypted_blob: Optional[str], config_key: str = "global") -> str:
        if not encrypted_blob:
            return ""
        try:
            env = json.loads(encrypted_blob)
            aad = f"pqc-oauth-cfg-v1|key={config_key}".encode("utf-8")
            wrapper = self._wrapper()
            dek_buf = bytearray(wrapper.unwrap_dek(_b64_decode(env["dek"]), aad, kms_key_name=env.get("kms_key")))
            try:
                pt = AESGCM(bytes(dek_buf)).decrypt(_b64_decode(env["iv"]), _b64_decode(env["ct"]), aad)
                return pt.decode("utf-8")
            finally:
                for i in range(len(dek_buf)):
                    dek_buf[i] = 0
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Google ADK BaseCredentialService Async Interface
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_invocation_identity(callback_context: CallbackContext) -> tuple[str, str]:
        inv_ctx = getattr(callback_context, "_invocation_context", None)
        app_name = str(getattr(inv_ctx, "app_name", None) or DEFAULT_APP_NAME).strip()
        user_id = str(getattr(inv_ctx, "user_id", None) or "").strip().lower()
        if user_id.startswith("accounts.google.com:"):
            user_id = user_id.split(":", 1)[1].strip()
        return app_name, user_id

    async def load_credential(
        self,
        auth_config: AuthConfig,
        callback_context: CallbackContext,
    ) -> Optional[AuthCredential]:
        app_name, user_id = self._extract_invocation_identity(callback_context)
        if not user_id:
            return None
        cred_key = str(auth_config.credential_key or DEFAULT_GCP_CREDENTIAL_KEY)
        tenant = auth_store.extract_tenant_domain(user_id)
        loaded = await asyncio.to_thread(
            self.load_delegated_token,
            user_id=user_id,
            caller_user_id=user_id,
            caller_tenant_domain=tenant,
            app_name=app_name,
            credential_key=cred_key,
        )
        if loaded is None:
            return None
        # Never expose refresh_token or client_secret in AuthCredential returned to ToolContext!
        raw_oauth2 = getattr(getattr(auth_config, "raw_auth_credential", None), "oauth2", None)
        oauth2_cred = OAuth2Auth(
            client_id=getattr(raw_oauth2, "client_id", None) or "pqc-workspace-3lo-client",
            auth_uri=getattr(raw_oauth2, "auth_uri", None),
            access_token=loaded.access_token,
            refresh_token=None,
        )
        return AuthCredential(
            auth_type=AuthCredentialTypes.OAUTH2,
            oauth2=oauth2_cred,
        )

    async def save_credential(
        self,
        auth_config: AuthConfig,
        callback_context: CallbackContext,
    ) -> None:
        app_name, user_id = self._extract_invocation_identity(callback_context)
        if not user_id:
            raise PermissionError("Cannot persist delegated credential without an authenticated user_id.")
        exchanged = getattr(auth_config, "exchanged_auth_credential", None) or getattr(
            auth_config, "raw_auth_credential", None
        )
        oauth2 = getattr(exchanged, "oauth2", None)
        access_tok = getattr(oauth2, "access_token", None)
        if not access_tok:
            return
        refresh_tok = getattr(oauth2, "refresh_token", None)
        cred_key = str(auth_config.credential_key or DEFAULT_GCP_CREDENTIAL_KEY)
        await asyncio.to_thread(
            self.store_delegated_token,
            user_id=user_id,
            access_token=str(access_tok),
            refresh_token=str(refresh_tok) if refresh_tok else None,
            app_name=app_name,
            credential_key=cred_key,
            client_id=str(getattr(oauth2, "client_id", None) or ""),
            client_secret=str(getattr(oauth2, "client_secret", None) or ""),
            caller_user_id=user_id,
        )


_CURRENT_CREDENTIAL_SERVICE: contextvars.ContextVar[Optional[EncryptedDatabaseCredentialService]] = (
    contextvars.ContextVar("pqc_current_credential_service", default=None)
)


def set_active_credential_service(
    svc: Optional[EncryptedDatabaseCredentialService],
) -> contextvars.Token[Optional[EncryptedDatabaseCredentialService]]:
    return _CURRENT_CREDENTIAL_SERVICE.set(svc)


def reset_active_credential_service(
    token: contextvars.Token[Optional[EncryptedDatabaseCredentialService]],
) -> None:
    _CURRENT_CREDENTIAL_SERVICE.reset(token)


def get_active_credential_service() -> EncryptedDatabaseCredentialService:
    bound = _CURRENT_CREDENTIAL_SERVICE.get()
    if bound is not None:
        return bound
    return EncryptedDatabaseCredentialService()
