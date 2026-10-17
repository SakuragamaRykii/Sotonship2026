"""Local, reversible PII and secret scrubber for LLM prompts."""

from .models import Action, ScrubResult, Segment, Span
from .pipeline import Scrubber, rehydrate, scrub
from .vault import Session

__all__ = ["Action", "ScrubResult", "Segment", "Session", "Scrubber", "Span", "rehydrate", "scrub"]
__version__ = "0.1.0"
