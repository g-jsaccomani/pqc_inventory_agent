"""Shared pytest configuration.

- Keeps tests offline: model verification on app startup is disabled and GCS uploads are not configured.
- Registers a fake ADK model (`fake-*`) so server plumbing (telemetry, explicit errors) can be tested without Vertex AI.
  The fake model is test-only and is never exposed by the production model registry (Gemini-only candidates).
"""

import os
import tempfile

_TMP_DIR = tempfile.mkdtemp(prefix="pqc-tests-")
os.environ["PQC_MODEL_VERIFICATION_ON_STARTUP"] = "false"
os.environ["PQC_SIMULATION_MODE"] = "FALSE"
os.environ["PQC_CALIBRATION_STORE_PATH"] = os.path.join(_TMP_DIR, "calibration-history.jsonl")
os.environ["PQC_EXPORT_DIR"] = os.path.join(_TMP_DIR, "exports")
os.environ["PQC_ARTIFACT_BUCKET"] = ""
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "pqc-inventory-agent-cd06")
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", "global")

from typing import AsyncGenerator  # noqa: E402

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
