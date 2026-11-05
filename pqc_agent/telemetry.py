"""Per-turn telemetry of every Gemini call, including calls made by specialist sub-agents.

`LlmCallTelemetryPlugin` is registered on the ADK Runner. ADK's AgentTool inherits the parent runner's plugins, so
specialist agents are captured too. Each answer in the portal can therefore show the real Vertex AI
`model_version` and token usage reported by the model API — evidence that a model (not a script) produced it.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from google.adk.plugins.base_plugin import BasePlugin

_CURRENT_LEDGER: contextvars.ContextVar[Optional[List[Dict[str, Any]]]] = contextvars.ContextVar(
    "pqc_llm_call_ledger", default=None
)


@contextmanager
def capture_llm_calls() -> Iterator[List[Dict[str, Any]]]:
    """Collects every LLM call made while the block runs (per request; safe under concurrency)."""
    ledger: List[Dict[str, Any]] = []
    token = _CURRENT_LEDGER.set(ledger)
    try:
        yield ledger
    finally:
        _CURRENT_LEDGER.reset(token)


class LlmCallTelemetryPlugin(BasePlugin):
    """Records model_version, token usage and errors of each model call into the active ledger."""

    def __init__(self) -> None:
        super().__init__(name="pqc_llm_call_telemetry")

    async def after_model_callback(self, *, callback_context: Any, llm_response: Any) -> Optional[Any]:
        ledger = _CURRENT_LEDGER.get()
        if ledger is None or getattr(llm_response, "partial", False):
            return None
        usage = getattr(llm_response, "usage_metadata", None)
        ledger.append(
            {
                "agent": getattr(callback_context, "agent_name", None),
                "model_version": getattr(llm_response, "model_version", None),
                "prompt_tokens": getattr(usage, "prompt_token_count", None) if usage else None,
                "output_tokens": getattr(usage, "candidates_token_count", None) if usage else None,
                "thinking_tokens": getattr(usage, "thoughts_token_count", None) if usage else None,
                "error_code": getattr(llm_response, "error_code", None),
                "error_message": (getattr(llm_response, "error_message", None) or None),
            }
        )
        return None

    async def on_model_error_callback(self, *, callback_context: Any, llm_request: Any, error: Exception) -> Optional[Any]:
        ledger = _CURRENT_LEDGER.get()
        if ledger is not None:
            ledger.append(
                {
                    "agent": getattr(callback_context, "agent_name", None),
                    "requested_model": getattr(llm_request, "model", None),
                    "model_version": None,
                    "error_code": type(error).__name__,
                    "error_message": str(error)[:400],
                }
            )
        return None


def summarize_llm_calls(ledger: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregates a turn's ledger into the `served_by` block shown under each answer."""
    successful = [c for c in ledger if c.get("model_version") and not c.get("error_code")]
    errors = [c for c in ledger if c.get("error_code")]

    def _sum(field: str) -> int:
        return int(sum(c.get(field) or 0 for c in successful))

    return {
        "llm_call_count": len(successful),
        "models_used": sorted({c["model_version"] for c in successful}),
        "agents_involved": sorted({c["agent"] for c in ledger if c.get("agent")}),
        "prompt_tokens": _sum("prompt_tokens"),
        "output_tokens": _sum("output_tokens"),
        "thinking_tokens": _sum("thinking_tokens"),
        "errors": errors,
        "calls": ledger,
    }
