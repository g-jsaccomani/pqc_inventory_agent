"""Vertex AI Timeouts, Bounded Retries & Per-Model Circuit-Breaker Resilience (`P3-02`).

Provides:
- Configurable per-probe, per-request (`google.genai.types.HttpOptions` in milliseconds), and per-turn timeouts.
- Deterministic transient error classification (`429`, `500`, `502`, `503`, `504`, `TimeoutError`, network resets)
  ensuring client/auth errors (`400`, `401`, `403`, `404`, `422`) never amplify retries or trip circuit breakers.
- Thread-safe / async-safe per-model `VertexCircuitBreaker` (`CLOSED` -> `OPEN` -> `HALF_OPEN` -> `CLOSED`).
- Full-jitter exponential backoff retry helper bounded by remaining turn deadline.
"""

from __future__ import annotations

import asyncio
import os
import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, TypeVar

T = TypeVar("T")

DEFAULT_VERTEX_PROBE_TIMEOUT_SECONDS = 15.0
DEFAULT_VERTEX_REQUEST_TIMEOUT_SECONDS = 120.0
DEFAULT_AGENT_TURN_TIMEOUT_SECONDS = 240.0
DEFAULT_VERTEX_MAX_ATTEMPTS = 3
DEFAULT_VERTEX_RETRY_BASE_DELAY_SECONDS = 0.5
DEFAULT_VERTEX_RETRY_MAX_DELAY_SECONDS = 8.0
DEFAULT_CIRCUIT_FAILURE_THRESHOLD = 5
DEFAULT_CIRCUIT_COOLDOWN_SECONDS = 30.0

TRANSIENT_HTTP_CODES = frozenset({429, 500, 502, 503, 504})
NON_TRANSIENT_HTTP_CODES = frozenset({400, 401, 403, 404, 405, 409, 413, 415, 422})

_TRANSIENT_MARKERS = (
    "429",
    "500",
    "502",
    "503",
    "504",
    "RESOURCE_EXHAUSTED",
    "UNAVAILABLE",
    "DEADLINE_EXCEEDED",
    "SERVICE_UNAVAILABLE",
    "TOO_MANY_REQUESTS",
    "GATEWAY_TIMEOUT",
    "BAD_GATEWAY",
    "INTERNAL_ERROR",
    "CONNECTION RESET",
    "TEMPORARILY UNAVAILABLE",
    "TIMED OUT",
    "TIMEOUT",
)

_NON_TRANSIENT_MARKERS = (
    "400",
    "401",
    "403",
    "404",
    "422",
    "INVALID_ARGUMENT",
    "PERMISSION_DENIED",
    "UNAUTHENTICATED",
    "NOT_FOUND",
    "MODEL_NOT_AVAILABLE",
)


def _env_float(name: str, default: float, *, minimum: float = 0.01) -> float:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return max(minimum, float(raw))
    except ValueError:
        return default


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def vertex_probe_timeout_seconds() -> float:
    return _env_float("PQC_VERTEX_PROBE_TIMEOUT_SECONDS", DEFAULT_VERTEX_PROBE_TIMEOUT_SECONDS)


def vertex_request_timeout_seconds() -> float:
    return _env_float("PQC_VERTEX_REQUEST_TIMEOUT_SECONDS", DEFAULT_VERTEX_REQUEST_TIMEOUT_SECONDS)


def agent_turn_timeout_seconds() -> float:
    return _env_float("PQC_AGENT_TURN_TIMEOUT_SECONDS", DEFAULT_AGENT_TURN_TIMEOUT_SECONDS)


def vertex_max_attempts() -> int:
    return _env_int("PQC_VERTEX_MAX_ATTEMPTS", DEFAULT_VERTEX_MAX_ATTEMPTS)


def vertex_retry_base_delay_seconds() -> float:
    return _env_float("PQC_VERTEX_RETRY_BASE_DELAY_SECONDS", DEFAULT_VERTEX_RETRY_BASE_DELAY_SECONDS, minimum=0.0)


def vertex_retry_max_delay_seconds() -> float:
    return _env_float("PQC_VERTEX_RETRY_MAX_DELAY_SECONDS", DEFAULT_VERTEX_RETRY_MAX_DELAY_SECONDS, minimum=0.0)


def vertex_circuit_failure_threshold() -> int:
    return _env_int("PQC_VERTEX_CIRCUIT_FAILURE_THRESHOLD", DEFAULT_CIRCUIT_FAILURE_THRESHOLD)


def vertex_circuit_cooldown_seconds() -> float:
    return _env_float("PQC_VERTEX_CIRCUIT_COOLDOWN_SECONDS", DEFAULT_CIRCUIT_COOLDOWN_SECONDS, minimum=0.01)


def build_vertex_http_options(timeout_seconds: Optional[float] = None) -> Any:
    """Builds `google.genai.types.HttpOptions` with explicit timeout converted to integer milliseconds."""
    from google.genai import types

    secs = timeout_seconds if timeout_seconds is not None else vertex_request_timeout_seconds()
    timeout_ms = max(1, int(round(float(secs) * 1000.0)))
    return types.HttpOptions(timeout=timeout_ms)


def is_transient_vertex_error(exc_or_code: Any) -> bool:
    """Returns True ONLY for upstream availability/quota/timeout faults (never 400/401/403/404 client errors)."""
    if exc_or_code is None:
        return False

    if isinstance(exc_or_code, (TimeoutError, asyncio.TimeoutError, ConnectionError)):
        return True
    if isinstance(exc_or_code, (ValueError, PermissionError, KeyError, TypeError)):
        return False

    # Inspect numeric HTTP status code if exposed (`genai.errors.APIError.code`, int, or dict)
    code: Optional[int] = None
    if isinstance(exc_or_code, int):
        code = exc_or_code
    elif isinstance(exc_or_code, dict):
        raw_c = exc_or_code.get("code") or exc_or_code.get("error_code")
        if isinstance(raw_c, int):
            code = raw_c
        elif isinstance(raw_c, str) and raw_c.isdigit():
            code = int(raw_c)
    else:
        raw_c = getattr(exc_or_code, "code", None) or getattr(exc_or_code, "status_code", None)
        if isinstance(raw_c, int):
            code = raw_c

    if code is not None:
        if code in NON_TRANSIENT_HTTP_CODES:
            return False
        if code in TRANSIENT_HTTP_CODES:
            return True

    text = str(exc_or_code).upper()
    if any(m in text for m in _NON_TRANSIENT_MARKERS):
        # Explicitly exclude 400/401/403/404 even if message text contains words like "timeout"
        if not any(t in text for t in ("429", "502", "503", "504", "RESOURCE_EXHAUSTED", "UNAVAILABLE", "DEADLINE_EXCEEDED")):
            return False
    return any(m in text for m in _TRANSIENT_MARKERS)


def compute_backoff_delay(
    attempt_index: int,
    *,
    base_delay: Optional[float] = None,
    max_delay: Optional[float] = None,
    remaining_budget: Optional[float] = None,
    rng: Optional[random.Random] = None,
) -> float:
    """Computes full-jitter exponential backoff bounded by `max_delay` and `remaining_budget`."""
    base = vertex_retry_base_delay_seconds() if base_delay is None else max(0.0, base_delay)
    cap = vertex_retry_max_delay_seconds() if max_delay is None else max(0.0, max_delay)
    ceiling = min(cap, base * (2 ** max(0, attempt_index)))
    generator = rng or random
    delay = generator.uniform(0.0, ceiling) if ceiling > 0 else 0.0
    if remaining_budget is not None:
        delay = min(delay, max(0.0, remaining_budget))
    return delay


class CircuitBreakerOpenError(RuntimeError):
    """Raised when a model's circuit breaker is OPEN and requests must fail fast."""

    def __init__(self, model: str, retry_after_seconds: float) -> None:
        self.model = model
        self.retry_after_seconds = max(0.0, float(retry_after_seconds))
        super().__init__(
            f"MODEL_CIRCUIT_OPEN: Model '{model}' is temporarily unavailable due to sustained upstream errors. "
            f"Retry after {self.retry_after_seconds:.1f}s."
        )


@dataclass
class _ModelCircuitState:
    state: str = "CLOSED"  # CLOSED | OPEN | HALF_OPEN
    consecutive_failures: int = 0
    opened_at: float = 0.0
    half_open_in_flight: bool = False


class VertexCircuitBreaker:
    """Thread-safe per-model circuit breaker protecting Cloud Run workers during Vertex AI outages."""

    def __init__(
        self,
        *,
        failure_threshold: Optional[int] = None,
        recovery_timeout_seconds: Optional[float] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._failure_threshold_override = failure_threshold
        self._recovery_timeout_override = recovery_timeout_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._models: Dict[str, _ModelCircuitState] = {}

    def _threshold(self) -> int:
        if self._failure_threshold_override is not None:
            return max(1, self._failure_threshold_override)
        return vertex_circuit_failure_threshold()

    def _cooldown(self) -> float:
        if self._recovery_timeout_override is not None:
            return max(0.01, self._recovery_timeout_override)
        return vertex_circuit_cooldown_seconds()

    def _entry(self, model: str) -> _ModelCircuitState:
        key = str(model or "default").strip().lower() or "default"
        st = self._models.get(key)
        if st is None:
            st = _ModelCircuitState()
            self._models[key] = st
        return st

    def state_of(self, model: str) -> str:
        with self._lock:
            st = self._entry(model)
            if st.state == "OPEN" and (self._clock() - st.opened_at) >= self._cooldown():
                return "HALF_OPEN"
            return st.state

    def before_call(self, model: str) -> None:
        """Checks whether a call to `model` may proceed; raises `CircuitBreakerOpenError` when OPEN."""
        now = self._clock()
        cooldown = self._cooldown()
        with self._lock:
            st = self._entry(model)
            if st.state == "CLOSED":
                return
            if st.state == "OPEN":
                elapsed = now - st.opened_at
                if elapsed < cooldown:
                    raise CircuitBreakerOpenError(model, cooldown - elapsed)
                st.state = "HALF_OPEN"
                st.half_open_in_flight = True
                return
            # HALF_OPEN: permit only one concurrent trial probe
            if st.half_open_in_flight:
                raise CircuitBreakerOpenError(model, max(0.5, cooldown / 2.0))
            st.half_open_in_flight = True

    def record_success(self, model: str) -> None:
        with self._lock:
            st = self._entry(model)
            st.state = "CLOSED"
            st.consecutive_failures = 0
            st.opened_at = 0.0
            st.half_open_in_flight = False

    def record_failure(self, model: str, *, is_transient: bool) -> None:
        now = self._clock()
        threshold = self._threshold()
        with self._lock:
            st = self._entry(model)
            if not is_transient:
                if st.state == "HALF_OPEN":
                    st.half_open_in_flight = False
                return
            if st.state == "HALF_OPEN":
                st.state = "OPEN"
                st.opened_at = now
                st.half_open_in_flight = False
                st.consecutive_failures = threshold
                return
            st.consecutive_failures += 1
            if st.consecutive_failures >= threshold:
                st.state = "OPEN"
                st.opened_at = now
                st.half_open_in_flight = False

    def reset(self, model: Optional[str] = None) -> None:
        with self._lock:
            if model is None:
                self._models.clear()
            else:
                self._models.pop(str(model).strip().lower(), None)


_GLOBAL_VERTEX_CIRCUIT_BREAKER = VertexCircuitBreaker()


def get_vertex_circuit_breaker() -> VertexCircuitBreaker:
    return _GLOBAL_VERTEX_CIRCUIT_BREAKER


def call_with_retry_sync(
    fn: Callable[[], T],
    *,
    max_attempts: Optional[int] = None,
    deadline_seconds: Optional[float] = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    rng: Optional[random.Random] = None,
) -> T:
    """Executes synchronous Vertex AI call `fn` with bounded exponential backoff + jitter on transient errors only."""
    attempts = max(1, max_attempts if max_attempts is not None else vertex_max_attempts())
    start = clock()
    last_exc: Optional[Exception] = None

    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if not is_transient_vertex_error(exc) or attempt + 1 >= attempts:
                raise
            remaining = None
            if deadline_seconds is not None:
                remaining = deadline_seconds - (clock() - start)
                if remaining <= 0.01:
                    raise
            delay = compute_backoff_delay(attempt, remaining_budget=remaining, rng=rng)
            if delay > 0:
                sleep_fn(delay)

    assert last_exc is not None
    raise last_exc
