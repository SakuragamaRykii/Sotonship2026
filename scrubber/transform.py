"""Stages 5–6: apply policy actions to spans, then run the leak check."""

from __future__ import annotations

import re
from collections import Counter

from . import surrogates as S
from .detect.merge import TITLES, name_tokens
from .models import Action, Span
from .policy import REMOVED_PLACEHOLDER, Policy
from .vault import Session

_GENERALISED_LABEL = {
    "organisation": "[ORGANISATION]",
    "location": "[LOCATION]",
    "quasi_identifier": "[DETAIL_REDACTED]",
    "date_of_birth": "[DATE_OF_BIRTH]",
    "date": "[DATE]",
}
# Natural-language types: the leak check matches exact / Title / UPPER case variants only,
# so a name like "Will" does not clobber the word "will".
_CASED_TYPES = {"person", "address", "organisation", "location"}
# Name tokens too common as ordinary words to propagate on their own.
_NAME_STOPWORDS = {
    "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november",
    "december", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "the", "and", "will",
    "bill", "rose", "grace", "hope", "joy", "faith", "dawn", "summer", "king", "young", "white", "green", "brown",
    "black", "street", "road", "house", "mr", "mrs", "ms", "miss", "dr", "prof", "von", "van", "der", "del", "de",
}


def _generalise(span: Span, policy: Policy, mode: str) -> str:
    t = span.type
    if t == "date_of_birth":
        return S.age_band(span.text, policy.dob_band_years.get(mode, 5)) or "[DATE_OF_BIRTH]"
    if t == "postcode":
        part = S.postcode_district(span.text) if mode == "balanced" else S.postcode_area(span.text)
        return part or "[POSTCODE]"
    return _GENERALISED_LABEL.get(t, f"[{t.upper()}]")


def _removed(type_: str) -> str:
    return REMOVED_PLACEHOLDER.get(type_, f"[{type_.upper()}_REMOVED]")


def _replace_all(text: str, edits: list[tuple[int, int, str]]) -> tuple[str, list[tuple[int, int]]]:
    """Apply non-overlapping edits right-to-left; return new text and the inserted regions."""
    out = text
    for s, e, rep in sorted(edits, key=lambda x: x[0], reverse=True):
        out = out[:s] + rep + out[e:]
    regions, delta = [], 0
    for s, e, rep in sorted(edits, key=lambda x: x[0]):
        regions.append((s + delta, s + delta + len(rep)))
        delta += len(rep) - (e - s)
    return out, regions


def _variants(value: str, type_: str) -> list[str]:
    if type_ in _CASED_TYPES:
        return list(dict.fromkeys([value, value.title(), value.upper()]))
    return [value]


def _pattern(value: str, type_: str) -> re.Pattern[str]:
    parts = [re.escape(v) for v in _variants(value, type_)]
    lead = r"(?<![A-Za-z0-9])" if value[:1].isalnum() else ""
    trail = r"(?![A-Za-z0-9])" if value[-1:].isalnum() else ""
    flags = 0 if type_ in _CASED_TYPES else re.IGNORECASE
    return re.compile(lead + "(?:" + "|".join(parts) + ")" + trail, flags)


_CAP_LEFT = re.compile(r"([A-Z][a-z]+(?:['\-][A-Z]?[a-z]+)*) $")
_CAP_RIGHT = re.compile(r" ([A-Z][a-z]+(?:['\-][A-Z]?[a-z]+)*)(?![\w'])")
_NOT_NAMES = {"called", "dear", "hi", "hello", "thanks", "spoke", "contact", "customer", "regards", "from", "to",
              "with", "and", "summary", "note", "notes", "please", "ask", "tell", "email", "phone", "user", "client"}


def _extend_name(scrubbed: str, s: int, e: int, roles: set[str], rep: str, vault, text: str) -> tuple[int, int, str]:
    """If a known surname is preceded by another capitalised word (or a known first name is
    followed by one), the mention is a different full name ("Georgina Preston" when we know
    "Joshua Preston"): pseudonymise the whole name as its own person instead."""
    ns, ne = s, e
    if "last" in roles:
        m = _CAP_LEFT.search(scrubbed, max(0, s - 40), s)
        if m and m.group(1).lower() not in TITLES | _NOT_NAMES | _NAME_STOPWORDS:
            ns = m.start(1)
    if "first" in roles and ns == s:
        m = _CAP_RIGHT.match(scrubbed, e)
        if m and m.group(1).lower() not in _NOT_NAMES | _NAME_STOPWORDS:
            ne = m.end(1)
    if (ns, ne) == (s, e):
        return s, e, rep
    full = scrubbed[ns:ne]
    return ns, ne, vault.pseudonymise("person", full, text)


def apply_spans(
    text: str,
    spans: list[Span],
    session: Session,
    policy: Policy,
    mode: str,
    allow: frozenset[str] = frozenset(),
) -> tuple[str, list[dict], dict]:
    """Transform `text` given final (merged) spans. Returns scrubbed text, actions, report."""
    vault = session.vault
    vault.ensure_prefixes(text)
    keep_district = policy.address_keep_district.get(mode, True)

    removed_values: list[tuple[str, str]] = []  # (value, placeholder): local only, never stored
    generalised_values: list[tuple[str, str, str]] = []  # (value, replacement, type)
    replacements: dict[int, tuple[Action, str | None]] = {}
    warnings: list[str] = []

    # Register full person names before partial mentions so "Jane" links to "Jane Doe".
    order = sorted(
        range(len(spans)),
        key=lambda i: (spans[i].type != "person", -len(name_tokens(spans[i].text)), spans[i].start),
    )
    for i in order:
        sp = spans[i]
        action = policy.action(sp.type, mode)
        rep: str | None = None
        if action == Action.REMOVE:
            rep = _removed(sp.type)
            removed_values.append((sp.text, rep))
        elif action == Action.PSEUDONYMISE:
            rep = vault.pseudonymise(sp.type, sp.text, text, keep_district=keep_district)
        elif action == Action.GENERALISE:
            rep = _generalise(sp, policy, mode)
            generalised_values.append((sp.text, rep, sp.type))
        elif action == Action.SHIFT:
            rep = vault.shifted_date(sp.text, session.date_offset_days, text)
            if rep is None:
                action, rep = Action.GENERALISE, _GENERALISED_LABEL.get(sp.type, "[DATE]")
                generalised_values.append((sp.text, rep, sp.type))
        elif action == Action.FLAG:
            warnings.append(f"review: possible {sp.type} at {sp.start}-{sp.end} ({sp.reason})")
        replacements[i] = (action, rep)

    edits = [(spans[i].start, spans[i].end, rep) for i, (a, rep) in replacements.items() if rep is not None and rep != spans[i].text]
    scrubbed, regions = _replace_all(text, edits)

    # ---- leak check: originals still present outside replaced regions ----
    candidates: dict[str, tuple[str, str]] = {}  # value -> (replacement, type)
    for value, (type_, sur) in vault.seen.items():
        if type_ == "date" and policy.action("date", mode) != Action.SHIFT:
            continue  # shifted dates from a strict call; dates are kept in this mode
        candidates.setdefault(value, (sur, type_))
    # Entity linking in the leak check: a lone first name or surname of a known person
    # ("Called John", "Ms Doe") gets that person's surrogate.
    roles: dict[str, set[str]] = {}  # name token -> {"first", "last"}
    for value, (type_, sur) in list(vault.seen.items()):
        if type_ != "person":
            continue
        toks = re.findall(r"[^\W\d_]+(?:['\-][^\W\d_]+)*", value)
        for i, tok in enumerate(toks):
            if len(tok) >= 3 and tok[0].isupper() and tok.lower() not in _NAME_STOPWORDS:
                candidates.setdefault(tok, (sur, "person"))
                if len(toks) > 1:
                    roles.setdefault(tok, set()).add("first" if i == 0 else "last" if i == len(toks) - 1 else "mid")
    for value, rep in removed_values:
        candidates[value] = (rep, "removed")
    for value, rep, type_ in generalised_values:
        candidates.setdefault(value, (rep, type_))
    for value in allow:
        candidates.pop(value, None)

    leak_fixes: list[dict] = []
    for _ in range(3):  # a fix can expose nothing new, but be safe with overlapping values
        hits: list[tuple[int, int, str, str]] = []
        for value in sorted(candidates, key=len, reverse=True):
            if len(value.strip()) < 2:
                continue
            rep, type_ = candidates[value]
            for m in _pattern(value, type_).finditer(scrubbed):
                s, e = m.span()
                hit_rep = rep
                if value in roles:  # a lone name token: is it part of a *different* full name?
                    s, e, hit_rep = _extend_name(scrubbed, s, e, roles[value], rep, vault, text)
                if any(s < re_ and rs < e for rs, re_ in regions):
                    continue
                if any(s < he and hs < e for hs, he, _, _ in hits):
                    continue
                hits.append((s, e, hit_rep, type_))
        if not hits:
            break
        for s, e, rep, type_ in hits:
            leak_fixes.append({"type": type_, "start": s, "end": e, "replacement": rep})
        scrubbed, new_regions = _replace_all(scrubbed, [(s, e, rep) for s, e, rep, _ in hits])
        # shift old regions to the new coordinates
        shifted = []
        for rs, re_ in regions:
            delta = sum(len(rep) - (e - s) for s, e, rep, _ in hits if e <= rs)
            shifted.append((rs + delta, re_ + delta))
        regions = shifted + new_regions

    actions = [
        {"span": i, "type": spans[i].type, "action": replacements[i][0].value, "replacement": replacements[i][1]}
        for i in range(len(spans))
    ]
    report = {
        "mode": mode,
        "counts_by_type": dict(Counter(s.type for s in spans)),
        "counts_by_action": dict(Counter(a["action"] for a in actions)),
        "leak_fixes": leak_fixes,
        "warnings": warnings,
    }
    return scrubbed, actions, report
