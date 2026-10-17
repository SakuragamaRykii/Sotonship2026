"""Detector protocol shared by all layers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import Segment, Span


@runtime_checkable
class Detector(Protocol):
    layer: str  # "L1".."L5"

    def detect(self, text: str, segments: list[Segment]) -> list[Span]: ...


def make_span(text: str, start: int, end: int, type_: str, source: str, confidence: float, reason: str) -> Span:
    return Span(start=start, end=end, text=text[start:end], type=type_, source=source, confidence=confidence, reason=reason)
