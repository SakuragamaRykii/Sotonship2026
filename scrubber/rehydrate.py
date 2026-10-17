"""Stage 8: map surrogates in an LLM response back to the original values, locally."""

from __future__ import annotations

import re

from .vault import Session


def _boundary_pattern(key: str) -> str:
    lead = r"(?<![A-Za-z0-9_])" if key[:1].isalnum() else ""
    trail = r"(?![A-Za-z0-9_])" if key[-1:].isalnum() else ""
    return lead + re.escape(key) + trail


def rehydrate(text: str, session: Session) -> tuple[str, list[str]]:
    out, warnings, _, _ = rehydrate_detailed(text, session)
    return out, warnings


def rehydrate_detailed(text: str, session: Session) -> tuple[str, list[str], int, int]:
    """Replace every known surrogate in `text` with its original.

    Handles case variants (`PERSON_1`), possessives (`Person_1's`) and surrogates wrapped in
    punctuation or quotes. Removed values are never restored. Surrogate-shaped tokens the
    vault does not know (an invented `Person_7`, a mangled `user1@example.com`) are left as
    they are and reported as warnings.
    """
    reverse = session.vault.reverse
    warnings: list[str] = []
    replaced: list[tuple[int, int]] = []
    out = text
    if reverse:
        by_lower: dict[str, str] = {}
        for key in reverse:
            by_lower.setdefault(key.lower(), key)
        keys = sorted(reverse, key=len, reverse=True)
        rx = re.compile("|".join(_boundary_pattern(k) for k in keys), re.IGNORECASE)
        pieces: list[str] = []
        pos = 0
        for m in rx.finditer(text):
            found = m.group()
            key = found if found in reverse else by_lower[found.lower()]
            pieces.append(text[pos : m.start()])
            start = sum(len(p) for p in pieces)
            pieces.append(reverse[key])
            replaced.append((start, start + len(reverse[key])))
            pos = m.end()
        pieces.append(text[pos:])
        out = "".join(pieces)

    seen: set[str] = set()
    unmapped: list[tuple[int, int]] = []
    for pat in session.vault.surrogate_patterns():
        for m in re.finditer(pat, out, re.IGNORECASE):
            if any(m.start() < e and s < m.end() for s, e in replaced + unmapped):
                continue
            unmapped.append(m.span())
            if m.group() not in seen:
                seen.add(m.group())
                warnings.append(f"unmapped surrogate-like token {m.group()!r} left unchanged")
    return out, warnings, len(replaced), len(unmapped)


def surrogate_stats(response: str, session: Session) -> tuple[int, int]:
    """(surrogates restored, surrogate-like tokens left unmapped) in an LLM response.

    Re-hydration accuracy = restored / (restored + unmapped).
    """
    _, _, restored, unmapped = rehydrate_detailed(response, session)
    return restored, unmapped
