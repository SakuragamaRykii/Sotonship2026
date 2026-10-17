"""Layered detectors. Each implements `Detector.detect(text, segments) -> list[Span]`."""

from __future__ import annotations

from ..policy import Policy
from .base import Detector
from .keys import KeyDetector
from .merge import merge
from .secrets import SecretsDetector
from .structured import StructuredDetector


def build_detectors(layers: list[str], policy: Policy) -> list[Detector]:
    """Instantiate the requested layers (in priority order). L4/L5 import heavy deps lazily."""
    out: list[Detector] = []
    for layer in sorted(set(layers)):
        if layer == "L1":
            out.append(SecretsDetector(policy))
        elif layer == "L2":
            out.append(StructuredDetector(policy))
        elif layer == "L3":
            out.append(KeyDetector(policy))
        elif layer == "L4":
            from .ner import NerDetector

            out.append(NerDetector(policy))
        elif layer == "L5":
            from .llm import LlmQuasiDetector

            out.append(LlmQuasiDetector(policy))
        else:
            raise ValueError(f"unknown detector layer {layer!r}")
    return out


__all__ = ["Detector", "build_detectors", "merge", "SecretsDetector", "StructuredDetector", "KeyDetector"]
