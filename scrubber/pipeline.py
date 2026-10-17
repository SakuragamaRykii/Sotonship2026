"""Public API: scrub() and rehydrate().

    from scrubber import Session, scrub, rehydrate
    s = Session()
    r = scrub(text, s, mode="balanced")
    answer = call_llm(r.scrubbed_text)
    restored, warnings = rehydrate(answer, s)
"""

from __future__ import annotations

import time

from .detect import build_detectors, merge
from .models import Action, ScrubResult, Span
from .policy import Policy, default_policy
from .rehydrate import rehydrate as _rehydrate
from .segment import segment
from .transform import apply_spans
from .vault import Session


class Scrubber:
    """A configured pipeline: which detector layers run, under which policy."""

    def __init__(self, layers: list[str] | None = None, policy: Policy | None = None) -> None:
        self.policy = policy or default_policy()
        self.layers = list(layers if layers is not None else self.policy.enabled_layers)
        self.detectors = build_detectors(self.layers, self.policy)

    def detect(self, text: str) -> tuple[list[Span], list[str]]:
        """Segment + detect + merge. Returns final spans and detector warnings."""
        segments = segment(text)
        candidates: list[Span] = []
        warnings: list[str] = []
        for det in self.detectors:
            candidates.extend(det.detect(text, segments))
            warnings.extend(getattr(det, "warnings", []) or [])
        return merge(candidates, text), warnings

    def apply(
        self,
        text: str,
        spans: list[Span],
        session: Session,
        mode: str = "balanced",
        allow: frozenset[str] = frozenset(),
        warnings: list[str] | None = None,
    ) -> ScrubResult:
        """Transform with an explicit span list (used by the UI after review)."""
        spans = merge(spans, text)  # manual additions may overlap detections
        scrubbed, actions, report = apply_spans(text, spans, session, self.policy, mode, allow)
        report["warnings"] = (warnings or []) + report["warnings"]
        report["layers"] = self.layers
        # Never hand back the text of removed values (secrets etc.).
        safe = [
            sp.model_copy(update={"text": "*" * min(len(sp.text), 8)}) if a["action"] == Action.REMOVE.value else sp
            for sp, a in zip(spans, actions)
        ]
        return ScrubResult(scrubbed_text=scrubbed, spans=safe, actions=actions, session_id=session.id, report=report)

    def scrub(self, text: str, session: Session, mode: str = "balanced") -> ScrubResult:
        t0 = time.perf_counter()
        spans, warnings = self.detect(text)
        result = self.apply(text, spans, session, mode, warnings=warnings)
        elapsed = time.perf_counter() - t0
        result.report["latency_ms"] = round(elapsed * 1000, 2)
        result.report["chars"] = len(text)
        return result


_DEFAULT: dict[tuple[str, ...], Scrubber] = {}


def get_scrubber(layers: list[str] | None = None) -> Scrubber:
    key = tuple(sorted(layers)) if layers is not None else ("__default__",)
    if key not in _DEFAULT:
        _DEFAULT[key] = Scrubber(layers)
    return _DEFAULT[key]


def scrub(text: str, session: Session, mode: str = "balanced", layers: list[str] | None = None) -> ScrubResult:
    """Detect and replace personal data and secrets in `text`."""
    return get_scrubber(layers).scrub(text, session, mode)


def rehydrate(text: str, session: Session) -> tuple[str, list[str]]:
    """Map surrogates in an LLM response back to the originals. Returns (text, warnings)."""
    return _rehydrate(text, session)
