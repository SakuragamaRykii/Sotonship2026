"""Stage 3: resolve overlapping candidate spans, and link partial person mentions."""

from __future__ import annotations

import re

from ..models import Span

# Lower number wins. Manual spans (added by a reviewer in the UI) beat every detector.
PRIORITY = {"manual": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}
# When two spans cover exactly the same text, a lower-priority span may still refine the type.
REFINEMENTS: dict[str, set[str]] = {
    "date": {"date_of_birth"},
    "user_id": {"username", "email", "person"},
}
# Whole-value layers: when they lose an overlap, keep the non-overlapping remainder (e.g. "Jane Doe <email>").
_TRIMMABLE = {"L3", "manual"}
_SEPARATORS = " \t\r\n,;:|<>()[]{}\"'/"


def _rank(s: Span) -> tuple:
    return (PRIORITY.get(s.source, 9), -s.length, -s.confidence, s.start)


def _residual(span: Span, blockers: list[Span], text: str) -> list[Span]:
    """Pieces of `span` not covered by `blockers`, trimmed of separators."""
    pieces: list[tuple[int, int]] = []
    pos = span.start
    for b in sorted(blockers, key=lambda x: x.start):
        if b.start > pos:
            pieces.append((pos, min(b.start, span.end)))
        pos = max(pos, b.end)
    if pos < span.end:
        pieces.append((pos, span.end))
    out: list[Span] = []
    for s, e in pieces:
        while s < e and text[s] in _SEPARATORS:
            s += 1
        while e > s and text[e - 1] in _SEPARATORS:
            e -= 1
        chunk = text[s:e]
        if len(re.findall(r"[A-Za-z0-9]", chunk)) >= 3 and re.search(r"[A-Za-z]", chunk):
            out.append(span.model_copy(update={"start": s, "end": e, "text": chunk, "reason": span.reason + " (trimmed)"}))
    return out


def merge(spans: list[Span], text: str) -> list[Span]:
    """Choose a non-overlapping set of spans.

    Priority L1 > L2 > L3 > L4 > L5; at equal priority the longer span, then higher confidence.
    Exceptions: an address that contains only postcode spans replaces them, and a lower-priority
    span covering exactly the same text may refine the type (date → date_of_birth).
    """
    accepted: list[Span] = []
    queue = sorted(spans, key=_rank)
    while queue:
        s = queue.pop(0)
        hits = [a for a in accepted if a.overlaps(s)]
        if not hits:
            accepted.append(s)
            continue
        if s.type == "address" and all(
            h.type == "postcode" and s.start <= h.start and h.end <= s.end and s.length > h.length for h in hits
        ):
            accepted = [a for a in accepted if a not in hits] + [s]
            continue
        for i, a in enumerate(accepted):
            if a.start == s.start and a.end == s.end and s.type in REFINEMENTS.get(a.type, set()):
                accepted[i] = a.model_copy(update={"type": s.type, "reason": f"{a.reason}; {s.reason}"})
        if s.source in _TRIMMABLE and not any(h.start <= s.start and s.end <= h.end for h in hits):
            accepted.extend(_residual(s, hits, text))
    return sorted(accepted, key=lambda x: x.start)


# ---- entity linking -------------------------------------------------------------------------

TITLES = {"mr", "mrs", "ms", "miss", "mx", "dr", "prof", "professor", "sir", "dame", "lord", "lady", "rev"}
_TITLE_PREFIX = re.compile(r"^((?:mr|mrs|ms|miss|mx|dr|prof|professor|sir|dame|lord|lady|rev)\.?\s+)", re.IGNORECASE)


def split_title(name: str) -> tuple[str, str]:
    """`Ms Doe` → (`Ms `, `Doe`)."""
    m = _TITLE_PREFIX.match(name)
    return (m.group(1), name[m.end() :]) if m else ("", name)


def name_tokens(name: str) -> frozenset[str]:
    toks = re.findall(r"[^\W\d_]+(?:['\-][^\W\d_]+)*", name.lower())
    return frozenset(t for t in toks if t not in TITLES and len(t) > 1)


def link_person(tokens: frozenset[str], known: dict[frozenset[str], str]) -> str | None:
    """Token-subset rule: return the surrogate of the unique known entity this mention belongs to.

    "Jane" or "Ms Doe" link to a known "Jane Doe"; a later "Jane Doe" links to an earlier "Jane"
    when that is the only candidate. Ambiguous mentions (two known Janes) are not linked.
    """
    if not tokens:
        return None
    if tokens in known:
        return known[tokens]
    supersets = {sur for toks, sur in known.items() if tokens < toks}
    if len(supersets) == 1:
        return supersets.pop()
    subsets = {sur for toks, sur in known.items() if toks < tokens}
    if len(subsets) == 1 and not supersets:
        return subsets.pop()
    return None
