"""Shared pytest configuration.

- Keeps tests offline: model verification on app startup is disabled and GCS uploads are not configured.
- Registers a fake ADK model (`fake-*`) so server plumbing (telemetry, explicit errors) can be tested without Vertex AI.
  The fake model is test-only and is never exposed by the production model registry (Gemini Pro-only candidates).
- Keeps authentication hermetic: a temp data dir (`PQC_DATA_DIR`), no Cloud Run / auth env flags inherited from the
  developer shell, and a `signin` fixture that signs users in through a monkeypatched Google token verifier (no real
  Google calls).
"""

import os
import tempfile

_TMP_DIR = tempfile.mkdtemp(prefix="pqc-tests-")
os.environ["PQC_MODEL_VERIFICATION_ON_STARTUP"] = "false"
os.environ["PQC_SIMULATION_MODE"] = "FALSE"
os.environ["PQC_CALIBRATION_STORE_PATH"] = os.path.join(_TMP_DIR, "calibration-history.jsonl")
os.environ["PQC_EXPORT_DIR"] = os.path.join(_TMP_DIR, "exports")
os.environ["PQC_ARTIFACT_BUCKET"] = ""
os.environ["PQC_DATA_DIR"] = os.path.join(_TMP_DIR, "data")
for _auth_env in (
    "K_SERVICE",
    "PQC_ALLOW_UNVERIFIED_SIGNIN",
    "PQC_ENABLE_ADK_API",
    "PQC_ENABLE_ADK_DEV_UI",
    "PQC_ALLOWED_ORIGINS",
    "PQC_IAP_AUDIENCE",
    "PQC_AUTH_SECRET",
    "PQC_ADMIN_EMAILS",
    "PQC_GOOGLE_ID_TOKEN_AUDIENCES",
    "PQC_USER_ACCESS_TOKEN",
    "GOOGLE_OAUTH_CLIENT_ID",
    "GOOGLE_OAUTH_CLIENT_SECRET",
):
    os.environ.pop(_auth_env, None)
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "pqc-inventory-agent-cd06")
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", "global")

from typing import AsyncGenerator  # noqa: E402

import pytest  # noqa: E402

from google.adk.models.base_llm import BaseLlm  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.adk.models.registry import LLMRegistry  # noqa: E402
from google.genai import types  # noqa: E402


class FakeModelForTests(BaseLlm):
    """Deterministic test double for an LLM. `fake-fail*` models raise like a Vertex AI 404."""

    model: str = "fake-ok-model"

    @classmethod
    def supported_models(cls) -> list[str]:
        return [r"fake-.*"]

    async def generate_content_async(self, llm_request, stream: bool = False) -> AsyncGenerator[LlmResponse, None]:
        if "fail" in self.model:
            raise RuntimeError(f"404 NOT_FOUND. Publisher model `{self.model}` was not found or your project does not have access to it.")
        last_text = ""
        for content in llm_request.contents or []:
            for part in content.parts or []:
                if getattr(part, "text", None):
                    last_text = part.text
        yield LlmResponse(
            content=types.Content(role="model", parts=[types.Part.from_text(text=f"Fake model answer to: {last_text[:80]}")]),
            model_version=f"{self.model}-001",
            usage_metadata=types.GenerateContentResponseUsageMetadata(
                prompt_token_count=11, candidates_token_count=7, thoughts_token_count=3, total_token_count=21
            ),
            turn_complete=True,
        )


LLMRegistry.register(FakeModelForTests)


def _fake_google_token_verifier(id_token_jwt=None, google_access_token=None):
    """Offline stand-in for `_verify_google_oauth_or_id_token`.

    Tokens look like `valid:<email>` (verified email) or `unverified:<email>` (email_verified=False); anything else
    is rejected like Google's tokeninfo would reject an invalid token.
    """
    tok = (id_token_jwt or google_access_token or "").strip()
    kind, _, email = tok.partition(":")
    if kind not in ("valid", "unverified") or "@" not in email:
        return None, "Google OAuth access token verification failed: HTTP Error 400: Bad Request"
    email = email.strip().lower()
    return {
        "email": email,
        "email_verified": kind == "valid",
        "name": email.split("@", 1)[0],
        "picture": "",
        "hd": email.split("@", 1)[-1],
        "auth_method": "google_id_token" if id_token_jwt else "google_access_token",
        "expires_in": 3599,
    }, None


@pytest.fixture
def google_verifier(monkeypatch):
    """Monkeypatches the server's Google credential verifier; returns the list of (id_token, access_token) calls."""
    from pqc_agent import workspace_server

    calls = []

    def fake(id_token_jwt=None, google_access_token=None):
        calls.append((id_token_jwt, google_access_token))
        return _fake_google_token_verifier(id_token_jwt, google_access_token)

    monkeypatch.setattr(workspace_server, "_verify_google_oauth_or_id_token", fake)
    return calls


@pytest.fixture(autouse=True)
def _dispose_fallback_auth_stores():
    yield
    from pqc_agent import auth_store

    auth_store.clear_fallback_auth_stores()


@pytest.fixture
def signin(google_verifier):
    """`signin(client, email, **extra) -> session cookie value` through POST /api/auth/google with a verified token."""

    def _signin(client, email, **extra):
        resp = client.post("/api/auth/google", json={"google_access_token": f"valid:{email}", **extra})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "token" not in body, "Session bearer token must never be serialized in JSON responses"
        cookie_tok = resp.cookies.get("pqc_session_token") or client.cookies.get("pqc_session_token")
        assert cookie_tok, "Expected HttpOnly pqc_session_token cookie to be set"
        return cookie_tok

    return _signin
