"""Pydantic data models shared across the pipeline."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

SegmentKind = Literal["json_value", "kv_value", "text"]

# Detector layers in merge-priority order (lower index wins on overlap).
LAYERS: tuple[str, ...] = ("L1", "L2", "L3", "L4", "L5")


class Segment(BaseModel):
    """A structural region of the input, with offsets into the original string."""

    start: int
    end: int
    kind: SegmentKind
    key: str | None = None

    def slice(self, text: str) -> str:
        return text[self.start : self.end]


class Span(BaseModel):
    """A detected sensitive region of the input."""

    start: int
    end: int
    text: str
    type: str  # e.g. "email", "person", "secret"
    source: str  # "L1".."L5", or "manual"
    confidence: float = 1.0
    reason: str = ""  # human-readable, shown in UI

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: "Span") -> bool:
        return self.start < other.end and other.start < self.end


class Action(str, Enum):
    REMOVE = "REMOVE"
    PSEUDONYMISE = "PSEUDONYMISE"
    GENERALISE = "GENERALISE"
    KEEP = "KEEP"
    SHIFT = "SHIFT"  # dates: session-constant day offset
    FLAG = "FLAG"  # keep the text, but flag the span for human review


class ScrubResult(BaseModel):
    scrubbed_text: str
    spans: list[Span]
    actions: list[dict] = Field(default_factory=list)  # span index → action, surrogate
    session_id: str
    report: dict = Field(default_factory=dict)  # counts per type, leak_fixes, warnings
