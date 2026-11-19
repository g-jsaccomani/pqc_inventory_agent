"""Phase 3.4 (`P3-02`) Test Suite — Vertex AI Timeouts, Bounded Retries & Per-Model Circuit Breaker.

Covers all unit, integration, adversarial, and regression tests from `PHASE_03_0_AUDIT.md` & `PHASE_03_0_TEST_PLAN.md`:
- Explicit millisecond `HttpOptions.timeout` in `build_generate_content_config()` and `vertex_generate_probe()`
- `VertexCircuitBreaker` state machine (`CLOSED` -> `OPEN` -> `HALF_OPEN` -> `CLOSED`), single trial probe, non-transient exemption
- Full-jitter exponential backoff retry helper respecting turn deadline budget and zero retry on 400/404
- `POST /api/chat` recovery from transient `503 UNAVAILABLE`, fast-fail `503 MODEL_CIRCUIT_OPEN` with `Retry-After`,
  per-model isolation, and `504 MODEL_TIMEOUT` on stalled async generator streams
- `main.run_adk_agent_turn()` wall-clock timeout and circuit-breaker enforcement
"""

from __future__ import annotations

import asyncio
import random
import time
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Tuple

from fastapi.testclient import TestClient
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.models.registry import LLMRegistry
from google.genai import types
import pytest

import main
from pqc_agent import agent, auth_store, model_registry, resilience, workspace_server as ws
from pqc_agent.model_registry import ModelRegistry


@pytest.fixture(autouse=True)
def _reset_resilience_state(monkeypatch: pytest.MonkeyPatch):
    resilience.get_vertex_circuit_breaker().reset()
    for var in (
        "PQC_VERTEX_PROBE_TIMEOUT_SECONDS",
        "PQC_VERTEX_REQUEST_TIMEOUT_SECONDS",
        "PQC_AGENT_TURN_TIMEOUT_SECONDS",
        "PQC_VERTEX_MAX_ATTEMPTS",
        "PQC_VERTEX_RETRY_BASE_DELAY_SECONDS",
        "PQC_VERTEX_RETRY_MAX_DELAY_SECONDS",
        "PQC_VERTEX_CIRCUIT_FAILURE_THRESHOLD",
        "PQC_VERTEX_CIRCUIT_COOLDOWN_SECONDS",
    ):
        monkeypatch.delenv(var, raising=False)
    yield
    resilience.get_vertex_circuit_breaker().reset()


# Deterministic test-only ADK LLM doubles for resilience scenarios
_RESILIENCE_MODEL_STATE: Dict[str, Any] = {
    "flaky_calls": 0,
    "outage_calls": 0,
    "hung_calls": 0,
}


class _ResilienceTestLlm(BaseLlm):
    model: str = "resilience-flaky-model"

    @classmethod
    def supported_models(cls) -> list[str]:
        return [r"resilience-.*"]

    async def generate_content_async(self, llm_request, stream: bool = False) -> AsyncGenerator[LlmResponse, None]:
        if self.model == "resilience-flaky-model":
            _RESILIENCE_MODEL_STATE["flaky_calls"] += 1
            if _RESILIENCE_MODEL_STATE["flaky_calls"] == 1:
                raise RuntimeError("503 UNAVAILABLE: Transient Vertex AI backend overload")
            yield LlmResponse(
                content=types.Content(role="model", parts=[types.Part.from_text(text="Recovered after transient 503.")]),
                model_version="resilience-flaky-model-001",
                usage_metadata=types.GenerateContentResponseUsageMetadata(
                    prompt_token_count=10, candidates_token_count=6, thoughts_token_count=0, total_token_count=16
                ),
                turn_complete=True,
            )
            return
        if self.model == "resilience-outage-model":
            _RESILIENCE_MODEL_STATE["outage_calls"] += 1
            raise RuntimeError("503 UNAVAILABLE: Sustained Vertex AI regional brownout")
        if self.model == "resilience-hung-model":
            _RESILIENCE_MODEL_STATE["hung_calls"] += 1
            await asyncio.sleep(60.0)
            yield LlmResponse(
                content=types.Content(role="model", parts=[types.Part.from_text(text="Should never reach here")]),
                turn_complete=True,
            )


LLMRegistry.register(_ResilienceTestLlm)


def _make_resilience_registry() -> ModelRegistry:
    def _probe(model: str, _level: Any) -> Tuple[bool, Dict[str, Any]]:
        return True, {"model_version": f"{model}-001"}

    return ModelRegistry(
        candidates=[
            {"model": "fake-ok-model", "label": "Fake OK", "thinking_levels": [None]},
            {"model": "resilience-flaky-model", "label": "Resilience Flaky", "thinking_levels": [None]},
            {"model": "resilience-outage-model", "label": "Resilience Outage", "thinking_levels": [None]},
            {"model": "resilience-hung-model", "label": "Resilience Hung", "thinking_levels": [None]},
        ],
        probe=_probe,
        default_model="fake-ok-model",
        default_thinking_level="",
    )


def _create_resilience_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "p3_02_resilience.db"
    monkeypatch.setenv("SESSION_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("PQC_EXPORT_DIR", str(tmp_path / "exports"))
    monkeypatch.setenv("PQC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PQC_AUTH_SECRET", "p3-02-resilience-hmac-secret-material-at-least-32-bytes!!")
    auth_store.clear_fallback_auth_stores()
    return ws.create_workspace_app(
        session_db_url=f"sqlite:///{db_path}",
        model_registry=_make_resilience_registry(),
        verify_models_on_startup=False,
    )


def _login_user(client: TestClient, email: str) -> Dict[str, str]:
    resp = client.post("/api/auth/google", json={"google_access_token": f"valid:{email}"})
    assert resp.status_code == 200, resp.text
    csrf = resp.json()["csrf_token"]
    return {"X-PQC-CSRF-Token": csrf, "Origin": "http://testserver"}


# =============================================================================
# 2.1 UNIT TESTS
# =============================================================================


def test_p3_02_unit_generate_content_config_and_probe_set_explicit_http_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 1. Default build_generate_content_config populates HttpOptions.timeout in integer milliseconds (120s -> 120000ms)
    cfg_default = agent.build_generate_content_config("gemini-3.1-pro-preview", "MEDIUM")
    assert cfg_default.http_options is not None
    assert cfg_default.http_options.timeout == 120_000

    monkeypatch.setenv("PQC_VERTEX_REQUEST_TIMEOUT_SECONDS", "45.5")
    cfg_custom = agent.build_generate_content_config("gemini-2.5-pro", None)
    assert cfg_custom.http_options is not None
    assert cfg_custom.http_options.timeout == 45_500

    # 2. vertex_generate_probe configures client & GenerateContentConfig with millisecond probe timeout + retries transient 429
    monkeypatch.setenv("PQC_VERTEX_PROBE_TIMEOUT_SECONDS", "12")
    monkeypatch.setenv("PQC_VERTEX_RETRY_BASE_DELAY_SECONDS", "0.0")
    monkeypatch.setenv("PQC_VERTEX_MAX_ATTEMPTS", "3")

    captured_client_kwargs: List[Dict[str, Any]] = []
    captured_gen_configs: List[Any] = []
    probe_attempts = {"n": 0}

    class _FakeModels:
        def generate_content(self, *, model: str, contents: str, config: Any) -> Any:
            captured_gen_configs.append(config)
            probe_attempts["n"] += 1
            if probe_attempts["n"] == 1:
                raise RuntimeError("429 RESOURCE_EXHAUSTED: temporary burst")

            class _Resp:
                model_version = f"{model}-001"

            return _Resp()

    class _FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            captured_client_kwargs.append(kwargs)
            self.models = _FakeModels()

    import google.genai as genai_mod

    monkeypatch.setattr(genai_mod, "Client", _FakeClient)
    ok, detail = model_registry.vertex_generate_probe("gemini-3.1-pro-preview", "HIGH")
    assert ok is True
    assert detail["model_version"] == "gemini-3.1-pro-preview-001"
    assert probe_attempts["n"] == 2
    assert captured_client_kwargs[0]["http_options"].timeout == 12_000
    assert captured_gen_configs[0].http_options.timeout == 12_000


def test_p3_02_unit_circuit_breaker_state_machine() -> None:
    now = {"t": 100.0}
    breaker = resilience.VertexCircuitBreaker(
        failure_threshold=3,
        recovery_timeout_seconds=10.0,
        clock=lambda: now["t"],
    )

    # Non-transient client errors (400 / 403 / 404) MUST NOT trip the circuit breaker
    for _ in range(10):
        breaker.before_call("gemini-3.1-pro-preview")
        breaker.record_failure("gemini-3.1-pro-preview", is_transient=resilience.is_transient_vertex_error("400 INVALID_ARGUMENT"))
        breaker.record_failure("gemini-3.1-pro-preview", is_transient=resilience.is_transient_vertex_error("403 PERMISSION_DENIED"))
        breaker.record_failure("gemini-3.1-pro-preview", is_transient=resilience.is_transient_vertex_error("404 NOT_FOUND"))
    assert breaker.state_of("gemini-3.1-pro-preview") == "CLOSED"

    # 3 consecutive transient failures open the circuit for gemini-3.1-pro-preview ONLY
    for _ in range(3):
        breaker.before_call("gemini-3.1-pro-preview")
        breaker.record_failure("gemini-3.1-pro-preview", is_transient=True)
    assert breaker.state_of("gemini-3.1-pro-preview") == "OPEN"
    assert breaker.state_of("gemini-2.5-pro") == "CLOSED"

    with pytest.raises(resilience.CircuitBreakerOpenError) as exc_info:
        breaker.before_call("gemini-3.1-pro-preview")
    assert exc_info.value.retry_after_seconds == pytest.approx(10.0)

    # Advance past cooldown -> HALF_OPEN allows strictly 1 trial probe; concurrent call fails fast
    now["t"] = 111.0
    assert breaker.state_of("gemini-3.1-pro-preview") == "HALF_OPEN"
    breaker.before_call("gemini-3.1-pro-preview")
    with pytest.raises(resilience.CircuitBreakerOpenError):
        breaker.before_call("gemini-3.1-pro-preview")

    # Trial probe fails -> immediately re-opens for another cooldown window
    breaker.record_failure("gemini-3.1-pro-preview", is_transient=True)
    assert breaker.state_of("gemini-3.1-pro-preview") == "OPEN"

    # Advance past second cooldown -> trial probe succeeds -> resets cleanly to CLOSED
    now["t"] = 122.0
    breaker.before_call("gemini-3.1-pro-preview")
    breaker.record_success("gemini-3.1-pro-preview")
    assert breaker.state_of("gemini-3.1-pro-preview") == "CLOSED"


def test_p3_02_unit_exponential_backoff_retry_policy() -> None:
    rng = random.Random(42)
    slept: List[float] = []

    # 1. Transient 503 recovers on attempt 3
    calls = {"n": 0}

    def _flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("503 UNAVAILABLE")
        return "recovered"

    assert (
        resilience.call_with_retry_sync(
            _flaky,
            max_attempts=3,
            deadline_seconds=10.0,
            sleep_fn=slept.append,
            rng=rng,
        )
        == "recovered"
    )
    assert calls["n"] == 3
    assert len(slept) == 2

    # 2. Non-transient 400 fails immediately after 1 attempt with ZERO sleeps
    non_transient_calls = {"n": 0}
    slept.clear()

    def _bad_req():
        non_transient_calls["n"] += 1
        raise RuntimeError("400 INVALID_ARGUMENT: malformed content")

    with pytest.raises(RuntimeError, match="400 INVALID_ARGUMENT"):
        resilience.call_with_retry_sync(_bad_req, max_attempts=3, sleep_fn=slept.append, rng=rng)
    assert non_transient_calls["n"] == 1
    assert len(slept) == 0


# =============================================================================
# 2.2 INTEGRATION & 2.3 ADVERSARIAL TESTS
# =============================================================================


def test_p3_02_integration_chat_recovers_from_transient_vertex_503(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    _RESILIENCE_MODEL_STATE["flaky_calls"] = 0
    monkeypatch.setenv("PQC_VERTEX_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("PQC_VERTEX_RETRY_BASE_DELAY_SECONDS", "0.0")

    app = _create_resilience_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        headers = _login_user(client, "alice@google.com")
        res = client.post(
            "/api/chat",
            headers=headers,
            json={"message": "Check resilience", "model_id": "resilience-flaky-model"},
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["status"] == "OK"
        assert "Recovered after transient 503." in body["response"]
        assert _RESILIENCE_MODEL_STATE["flaky_calls"] == 2
        assert resilience.get_vertex_circuit_breaker().state_of("resilience-flaky-model") == "CLOSED"
    app.state.auth_store.close()


def test_p3_02_adversarial_stalled_llm_stream_aborts_at_turn_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    _RESILIENCE_MODEL_STATE["hung_calls"] = 0
    monkeypatch.setenv("PQC_AGENT_TURN_TIMEOUT_SECONDS", "0.25")
    monkeypatch.setenv("PQC_VERTEX_MAX_ATTEMPTS", "2")

    app = _create_resilience_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        headers = _login_user(client, "alice@google.com")
        t0 = time.monotonic()
        res = client.post(
            "/api/chat",
            headers=headers,
            json={"message": "Trigger hung stream", "model_id": "resilience-hung-model"},
        )
        elapsed = time.monotonic() - t0
        assert elapsed < 1.5, f"Hung turn did not abort promptly ({elapsed:.2f}s)"
        assert res.status_code == 504
        body = res.json()
        assert body["status"] == "MODEL_ERROR"
        assert body["error"]["code"] == "MODEL_TIMEOUT"
        assert _RESILIENCE_MODEL_STATE["hung_calls"] == 1
    app.state.auth_store.close()


def test_p3_02_adversarial_sustained_vertex_outage_trips_breaker_and_preserves_other_models(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    _RESILIENCE_MODEL_STATE["outage_calls"] = 0
    monkeypatch.setenv("PQC_VERTEX_MAX_ATTEMPTS", "1")
    monkeypatch.setenv("PQC_VERTEX_CIRCUIT_FAILURE_THRESHOLD", "3")
    monkeypatch.setenv("PQC_VERTEX_CIRCUIT_COOLDOWN_SECONDS", "60")

    app = _create_resilience_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        headers = _login_user(client, "alice@google.com")

        # 3 consecutive failing calls trip the circuit breaker on resilience-outage-model
        for _ in range(3):
            r_fail = client.post(
                "/api/chat",
                headers=headers,
                json={"message": "Outage probe", "model_id": "resilience-outage-model"},
            )
            assert r_fail.status_code == 502
        assert _RESILIENCE_MODEL_STATE["outage_calls"] == 3
        assert resilience.get_vertex_circuit_breaker().state_of("resilience-outage-model") == "OPEN"

        # Next 10 calls fast-fail immediately with HTTP 503 + Retry-After + ZERO upstream model invocations!
        t0 = time.monotonic()
        for _ in range(10):
            r_open = client.post(
                "/api/chat",
                headers=headers,
                json={"message": "Should fast-fail", "model_id": "resilience-outage-model"},
            )
            assert r_open.status_code == 503
            assert int(r_open.headers.get("Retry-After", "0")) >= 1
            assert r_open.json()["error"]["code"] == "MODEL_CIRCUIT_OPEN"
        elapsed = time.monotonic() - t0
        assert _RESILIENCE_MODEL_STATE["outage_calls"] == 3  # Strictly 0 additional upstream calls!
        assert elapsed < 1.0

        # Unaffected model (fake-ok-model) remains 100% operational!
        r_healthy = client.post(
            "/api/chat",
            headers=headers,
            json={"message": "Healthy model works", "model_id": "fake-ok-model"},
        )
        assert r_healthy.status_code == 200
        assert r_healthy.json()["status"] == "OK"
    app.state.auth_store.close()


def test_p3_02_integration_cli_ask_enforces_turn_timeout_and_circuit_breaker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PQC_AGENT_TURN_TIMEOUT_SECONDS", "0.2")
    monkeypatch.setenv("PQC_VERTEX_CIRCUIT_FAILURE_THRESHOLD", "1")
    monkeypatch.setenv("PQC_VERTEX_CIRCUIT_COOLDOWN_SECONDS", "60")
    monkeypatch.setenv("PQC_VERTEX_MAX_ATTEMPTS", "1")

    app = _create_resilience_app(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "get_workspace_app", lambda: app)

    # 1. Hung turn in CLI run_adk_agent_turn aborts at wall-clock deadline and opens breaker
    t0 = time.monotonic()
    res_timeout = asyncio.run(
        main.run_adk_agent_turn("Hung CLI prompt", model_name="resilience-hung-model", thinking_level=None)
    )
    assert time.monotonic() - t0 < 1.5
    assert res_timeout["status"] == "MODEL_ERROR"
    assert res_timeout["error"]["code"] == "MODEL_TIMEOUT"

    # 2. Subsequent CLI call hits OPEN circuit breaker immediately
    res_open = asyncio.run(
        main.run_adk_agent_turn("Fast fail CLI prompt", model_name="resilience-hung-model", thinking_level=None)
    )
    assert res_open["status"] == "MODEL_ERROR"
    assert res_open["error"]["code"] == "MODEL_CIRCUIT_OPEN"
    app.state.auth_store.close()
