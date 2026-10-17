"""L4: contextual NER with GLiNER (PII checkpoint), run locally.

The model is downloaded once from the Hugging Face hub and cached; inference never leaves
this machine. Import of `gliner`/`torch` is deferred so L1–L3 work without them.
"""

from __future__ import annotations

import re
import threading
from functools import lru_cache

from ..models import Segment, Span
from ..policy import Policy, default_policy
from .base import make_span
from .keys import KeyDetector

_LOCK = threading.Lock()


@lru_cache(maxsize=2)
def load_model(name: str):
    import logging
    import warnings

    warnings.filterwarnings("ignore")
    logging.getLogger("transformers").setLevel(logging.ERROR)
    from gliner import GLiNER

    with _LOCK:
        model = GLiNER.from_pretrained(name)
        model.eval()
    return model


def _union(regions: list[tuple[int, int, float]]) -> list[tuple[int, int, float]]:
    out: list[tuple[int, int, float]] = []
    for s, e, t in sorted(regions):
        if out and s <= out[-1][1]:
            ps, pe, pt = out[-1]
            out[-1] = (ps, max(pe, e), min(pt, t))
        else:
            out.append((s, e, t))
    return out


def _chunks(text: str, start: int, end: int, max_chars: int) -> list[tuple[int, int]]:
    """Split [start, end) at sentence / line / space boundaries into pieces of ≤ max_chars."""
    out = []
    while end - start > max_chars:
        window = text[start : start + max_chars]
        cut = max(window.rfind(". "), window.rfind("\n"))
        if cut < max_chars // 2:
            cut = window.rfind(" ")
        cut = cut + 1 if cut > 0 else max_chars
        out.append((start, start + cut))
        start += cut
    out.append((start, end))
    return out


class NerDetector:
    layer = "L4"

    def __init__(self, policy: Policy | None = None, model=None) -> None:
        self.policy = policy or default_policy()
        self.cfg = self.policy.ner
        self._model = model
        self._keys = KeyDetector(self.policy)

    @property
    def model(self):
        if self._model is None:
            self._model = load_model(self.cfg.model)
        return self._model

    def _regions(self, text: str, segments: list[Segment]) -> list[tuple[int, int, float]]:
        regions = []
        for seg in segments:
            chunk = seg.slice(text)
            if not re.search(r"[^\W\d_]{2,}", chunk):
                continue
            if seg.kind != "text" and self._keys.key_type(seg.key) is not None and " " not in chunk.strip():
                continue  # single-token value already typed by its key (L3)
            thr = self.cfg.freetext_threshold if self._keys.is_freetext(seg.key) else self.cfg.threshold
            regions.append((seg.start, seg.end, thr))
        return _union(regions)

    def detect(self, text: str, segments: list[Segment]) -> list[Span]:
        regions = self._regions(text, segments)
        if not regions:
            return []
        pieces: list[tuple[int, int, float]] = []
        for s, e, thr in regions:
            pieces.extend((cs, ce, thr) for cs, ce in _chunks(text, s, e, self.cfg.max_chars))
        labels = list(self.cfg.labels)
        spans: list[Span] = []
        # group by threshold so each batch call uses one threshold
        for thr in sorted({p[2] for p in pieces}):
            batch = [(s, e) for s, e, t in pieces if t == thr]
            texts = [text[s:e] for s, e in batch]
            results = self._predict(texts, labels, thr)
            for (base, _), ents in zip(batch, results):
                for ent in ents:
                    type_ = self.cfg.labels.get(ent["label"])
                    if not type_:
                        continue
                    s, e = base + ent["start"], base + ent["end"]
                    s, e = self._tidy(text, s, e)
                    if e - s < 2:
                        continue
                    spans.append(
                        make_span(text, s, e, type_, self.layer, float(ent["score"]),
                                  f"GLiNER '{ent['label']}' (score {float(ent['score']):.2f})")
                    )
        return spans

    def _predict(self, texts: list[str], labels: list[str], threshold: float) -> list[list[dict]]:
        model = self.model
        if hasattr(model, "inference"):
            return model.inference(texts, labels, threshold=threshold, batch_size=8)
        return model.batch_predict_entities(texts, labels, threshold=threshold)  # older gliner

    @staticmethod
    def _tidy(text: str, s: int, e: int) -> tuple[int, int]:
        while s < e and text[s] in " \t\r\n,;:\"'([{":
            s += 1
        while e > s and text[e - 1] in " \t\r\n,;:\"')]}.":
            e -= 1
        if text[e - 2 : e] in ("'s", "’s"):  # possessive: keep the name only
            e -= 2
        return s, e
