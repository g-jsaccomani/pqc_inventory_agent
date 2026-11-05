"""Gemini model catalog for the Workspace Portal.

Only Gemini models that are VERIFIED to answer on Vertex AI in the configured project are offered to users.
Verification sends one tiny real request per candidate model (cached for `PQC_MODEL_VERIFICATION_TTL_SECONDS`).
Candidates can be extended without code changes via `PQC_GEMINI_MODEL_CANDIDATES` (comma-separated model IDs).
"""

from __future__ import annotations

import concurrent.futures
import datetime
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_MODEL = os.getenv("PQC_AGENT_MODEL", "gemini-3.1-pro-preview-customtools")
DEFAULT_THINKING_LEVEL = os.getenv("PQC_AGENT_THINKING_LEVEL", "MEDIUM")

# Candidate Gemini models (real Vertex AI model IDs). Only verified ones are exposed in the UI.
GEMINI_MODEL_CANDIDATES: List[Dict[str, Any]] = [
    {"model": "gemini-3.1-pro-preview-customtools", "label": "Gemini 3.1 Pro (custom tools)", "thinking_levels": ["HIGH", "MEDIUM"]},
    {"model": "gemini-3.1-pro-preview", "label": "Gemini 3.1 Pro", "thinking_levels": ["HIGH", "MEDIUM"]},
    {"model": "gemini-3-pro-preview", "label": "Gemini 3 Pro", "thinking_levels": ["HIGH", "LOW"]},
    {"model": "gemini-3-flash-preview", "label": "Gemini 3 Flash", "thinking_levels": ["MEDIUM", "LOW"]},
    {"model": "gemini-3.1-flash-lite-preview", "label": "Gemini 3.1 Flash Lite", "thinking_levels": ["LOW"]},
    {"model": "gemini-2.5-pro", "label": "Gemini 2.5 Pro", "thinking_levels": [None]},
    {"model": "gemini-2.5-flash", "label": "Gemini 2.5 Flash", "thinking_levels": [None]},
    {"model": "gemini-2.5-flash-lite", "label": "Gemini 2.5 Flash Lite", "thinking_levels": [None]},
]

ProbeResult = Tuple[bool, Dict[str, Any]]
ProbeFn = Callable[[str, Optional[str]], ProbeResult]


def ensure_vertex_location_for_gemini() -> None:
    """Gemini 3.x models are served from the global endpoint; default the location accordingly."""
    current = os.getenv("GOOGLE_CLOUD_LOCATION", "").strip()
    if not current or current == "us-central1":
        os.environ["GOOGLE_CLOUD_LOCATION"] = "global"


def _label_from_model_id(model: str) -> str:
    parts = model.replace("gemini-", "").split("-")
    return "Gemini " + " ".join(p.capitalize() if not p[0].isdigit() else p for p in parts if p)


def _extra_candidates_from_env() -> List[Dict[str, Any]]:
    raw = os.getenv("PQC_GEMINI_MODEL_CANDIDATES", "")
    extra = []
    for model in [m.strip() for m in raw.split(",") if m.strip()]:
        if model.startswith("gemini-"):
            extra.append({"model": model, "label": _label_from_model_id(model), "thinking_levels": ["MEDIUM"]})
    return extra


def vertex_generate_probe(model: str, thinking_level: Optional[str]) -> ProbeResult:
    """Sends one minimal real request to Vertex AI to verify that `model` answers in this project."""
    from google import genai
    from google.genai import errors as genai_errors
    from google.genai import types

    ensure_vertex_location_for_gemini()
    client = genai.Client(
        vertexai=True,
        project=os.getenv("GOOGLE_CLOUD_PROJECT"),
        location=os.getenv("GOOGLE_CLOUD_LOCATION", "global"),
    )
    config_kwargs: Dict[str, Any] = {"max_output_tokens": 512}
    if thinking_level:
        config_kwargs["thinking_config"] = types.ThinkingConfig(thinking_level=thinking_level)
    try:
        resp = client.models.generate_content(
            model=model,
            contents="Reply with the single word OK.",
            config=types.GenerateContentConfig(**config_kwargs),
        )
        return True, {"model_version": getattr(resp, "model_version", None)}
    except genai_errors.APIError as exc:
        return False, {"error_code": exc.code, "error_status": exc.status, "error": str(exc.message or exc)[:240]}
    except Exception as exc:  # network / auth errors
        return False, {"error": f"{type(exc).__name__}: {str(exc)[:240]}"}


class ModelRegistry:
    """Verifies candidate Gemini models and builds the portal catalog from verified models only."""

    def __init__(
        self,
        candidates: Optional[List[Dict[str, Any]]] = None,
        probe: Optional[ProbeFn] = None,
        default_model: Optional[str] = None,
        default_thinking_level: Optional[str] = None,
        ttl_seconds: Optional[float] = None,
    ) -> None:
        base = candidates if candidates is not None else GEMINI_MODEL_CANDIDATES + _extra_candidates_from_env()
        seen: Dict[str, Dict[str, Any]] = {}
        for cand in base:
            if cand["model"].startswith("gemini-") or candidates is not None:
                seen.setdefault(cand["model"], dict(cand))
        self.candidates: List[Dict[str, Any]] = list(seen.values())
        self.probe: ProbeFn = probe or vertex_generate_probe
        self.default_model = default_model or DEFAULT_MODEL
        self.default_thinking_level = default_thinking_level or DEFAULT_THINKING_LEVEL
        self.ttl_seconds = float(ttl_seconds if ttl_seconds is not None else os.getenv("PQC_MODEL_VERIFICATION_TTL_SECONDS", "21600"))
        self._results: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._verifying = False
        self._last_full_verification: Optional[float] = None

    # ----------------------------------------------------------------- verification
    def _candidate(self, model: str) -> Optional[Dict[str, Any]]:
        return next((c for c in self.candidates if c["model"] == model), None)

    def _verify_one(self, cand: Dict[str, Any]) -> Dict[str, Any]:
        levels = cand.get("thinking_levels") or [None]
        ok, detail = self.probe(cand["model"], levels[0])
        thinking_supported = True
        if not ok and levels[0] and str(detail.get("error_code")) == "400":
            ok, detail = self.probe(cand["model"], None)
            thinking_supported = not ok
        result = {
            "model": cand["model"],
            "available": ok,
            "thinking_supported": thinking_supported if ok else None,
            "detail": detail,
            "checked_at": time.time(),
        }
        with self._lock:
            self._results[cand["model"]] = result
        return result

    def verify_all(self, force: bool = False) -> None:
        with self._lock:
            if self._verifying:
                return
            fresh = self._last_full_verification and (time.time() - self._last_full_verification) < self.ttl_seconds
            if fresh and not force:
                return
            self._verifying = True
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
                list(executor.map(self._verify_one, self.candidates))
            self._last_full_verification = time.time()
            available = [m for m, r in self._results.items() if r["available"]]
            logger.info("Gemini model verification complete. Available: %s", available)
        finally:
            with self._lock:
                self._verifying = False

    def start_background_verification(self) -> None:
        threading.Thread(target=self.verify_all, name="gemini-model-verification", daemon=True).start()

    def ensure_verified(self, model: str) -> Dict[str, Any]:
        cand = self._candidate(model)
        if cand is None:
            return {"model": model, "available": False, "detail": {"error": "Not a configured Gemini candidate model."}}
        with self._lock:
            cached = self._results.get(model)
        if cached and (time.time() - cached["checked_at"]) < self.ttl_seconds:
            return cached
        return self._verify_one(cand)

    # ----------------------------------------------------------------- catalog
    def _entries_for(self, cand: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        levels = cand.get("thinking_levels") or [None]
        if not result.get("thinking_supported"):
            levels = [None]
        entries = []
        for level in levels:
            entry_id = cand["model"] if (len(levels) == 1) else f"{cand['model']}:{(level or 'default').lower()}"
            entries.append(
                {
                    "id": entry_id,
                    "model": cand["model"],
                    "label": cand["label"],
                    "tier": f"Thinking {level.capitalize()}" if level else "",
                    "thinking_level": level,
                    "verified": True,
                    "verified_at": datetime.datetime.fromtimestamp(result["checked_at"], tz=datetime.timezone.utc).isoformat(),
                    "verified_model_version": result.get("detail", {}).get("model_version"),
                }
            )
        return entries

    def verified_entries(self) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        with self._lock:
            results = dict(self._results)
        for cand in self.candidates:
            result = results.get(cand["model"])
            if result and result["available"]:
                entries.extend(self._entries_for(cand, result))
        return entries

    def default_entry(self) -> Optional[Dict[str, Any]]:
        entries = self.verified_entries()
        if not entries:
            return None
        preferred = [e for e in entries if e["model"] == self.default_model]
        if preferred:
            by_level = [e for e in preferred if (e["thinking_level"] or "") == (self.default_thinking_level or "")]
            return (by_level or preferred)[0]
        return entries[0]

    def resolve(self, requested: Optional[str]) -> Optional[Dict[str, Any]]:
        """Maps a catalog id or a candidate model ID to a verified entry, verifying on demand if needed."""
        raw = (requested or "").strip()
        if not raw:
            entry = self.default_entry()
            if entry is None:
                self.ensure_verified(self.default_model)
                entry = self.default_entry()
            return entry
        model = raw.split(":", 1)[0]
        if self._candidate(model) is None:
            return None
        self.ensure_verified(model)
        entries = [e for e in self.verified_entries() if e["model"] == model]
        if not entries:
            return None
        exact = [e for e in entries if e["id"] == raw]
        if exact:
            return exact[0]
        by_default_level = [e for e in entries if (e["thinking_level"] or "") == (self.default_thinking_level or "")]
        return (by_default_level or entries)[0]

    def catalog(self) -> Dict[str, Any]:
        with self._lock:
            results = dict(self._results)
            verifying = self._verifying
        unavailable = [
            {"model": r["model"], "reason": r.get("detail", {})}
            for r in results.values()
            if not r["available"]
        ]
        default = self.default_entry()
        return {
            "provider": "Vertex AI (Gemini only)",
            "project": os.getenv("GOOGLE_CLOUD_PROJECT"),
            "location": os.getenv("GOOGLE_CLOUD_LOCATION"),
            "default_model": default["id"] if default else None,
            "models": self.verified_entries(),
            "unavailable_candidates": unavailable,
            "verification": {
                "status": "IN_PROGRESS" if verifying else ("COMPLETE" if self._last_full_verification else "PARTIAL_OR_PENDING"),
                "candidates_checked": len(results),
                "candidates_total": len(self.candidates),
            },
        }
