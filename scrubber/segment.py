"""Stage 1: structural segmentation.

Splits the input into JSON values, key/value values and free-text regions,
keeping character offsets into the original string so every later stage can
work on the untouched input.
"""

from __future__ import annotations

import json
import re

from .models import Segment

# `key: value` at the start of a line (headers, YAML-ish, form dumps).
_LINE_KV = re.compile(
    r"^[ \t]*(?:[-*][ \t]+)?(?P<key>[A-Za-z][\w.\-/]*(?:[ ][\w.\-/]+){0,3})[ \t]*:[ \t]+(?P<value>\S[^\r\n]*?)[ \t]*$",
    re.MULTILINE,
)
# Inline `key=value` (log lines, query strings, env dumps).
_INLINE_KV = re.compile(
    r"""(?<![\w.\-])(?P<key>[A-Za-z_][\w.\-]{0,40})=(?:"(?P<dq>(?:[^"\\\r\n]|\\.)*)"|'(?P<sq>[^'\r\n]*)'|(?P<bare>[^\s,;&"'<>]+))"""
)
# `"key": "value"` fragments inside text that is not valid JSON (truncated logs, Python reprs).
_QUOTED_KV = re.compile(
    r"""["'](?P<key>[\w.\- ]{1,40})["']\s*:\s*(?:"(?P<dq>(?:[^"\\\r\n]|\\.)*)"|'(?P<sq>[^'\r\n]*)'|(?P<num>-?\d[\d.]*))"""
)
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?")


def normalise_key(key: str) -> str:
    """`firstName`, `First Name`, `first-name` → `first_name`."""
    key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key.strip())
    key = re.sub(r"[^A-Za-z0-9]+", "_", key).strip("_")
    return key.lower()


def _string_end(text: str, i: int) -> int:
    """Index of the closing quote for the JSON string opening at text[i]."""
    j = i + 1
    while j < len(text):
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == '"':
            return j
        j += 1
    return len(text) - 1


def _scan_json(text: str, base: int) -> list[Segment]:
    """Emit a json_value segment for every scalar string/number value.

    `text` must already be known to be valid JSON. Offsets are shifted by `base`.
    The key is the nearest enclosing object key (array items inherit it).
    """
    out: list[Segment] = []
    # stack entries: [container, current_key, expecting_key]
    stack: list[list] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "{":
            stack.append(["obj", None, True])
            i += 1
        elif c == "[":
            parent_key = stack[-1][1] if stack else None
            stack.append(["arr", parent_key, False])
            i += 1
        elif c in "}]":
            if stack:
                stack.pop()
            i += 1
        elif c == ",":
            if stack and stack[-1][0] == "obj":
                stack[-1][2] = True
            i += 1
        elif c == ":":
            if stack:
                stack[-1][2] = False
            i += 1
        elif c == '"':
            j = _string_end(text, i)
            if stack and stack[-1][0] == "obj" and stack[-1][2]:
                try:
                    stack[-1][1] = json.loads(text[i : j + 1])
                except json.JSONDecodeError:
                    stack[-1][1] = text[i + 1 : j]
            elif j > i + 1:
                key = stack[-1][1] if stack else None
                out.append(Segment(start=base + i + 1, end=base + j, kind="json_value", key=key))
            i = j + 1
        elif c == "-" or c.isdigit():
            m = _NUMBER.match(text, i)
            end = m.end() if m else i + 1
            key = stack[-1][1] if stack else None
            out.append(Segment(start=base + i, end=base + end, kind="json_value", key=key))
            i = end
        else:
            i += 1
    return out


def _try_json(fragment: str) -> bool:
    try:
        return isinstance(json.loads(fragment), (dict, list))
    except (json.JSONDecodeError, ValueError):
        return False


def _gaps(text: str, covered: list[tuple[int, int]]) -> list[Segment]:
    """Free-text segments for every region not covered by a structured value."""
    out: list[Segment] = []
    pos = 0
    for s, e in sorted(covered) + [(len(text), len(text))]:
        if s > pos:
            chunk = text[pos:s]
            if re.search(r"[A-Za-z0-9]", chunk):
                lead = len(chunk) - len(chunk.lstrip())
                trail = len(chunk) - len(chunk.rstrip())
                out.append(Segment(start=pos + lead, end=s - trail, kind="text"))
        pos = max(pos, e)
    return out


def segment(text: str) -> list[Segment]:
    """Split `text` into structural segments with offsets into `text`."""
    stripped = text.strip()
    if stripped[:1] in "{[" and _try_json(stripped):
        base = text.index(stripped[0])
        return _scan_json(stripped, base)

    segments: list[Segment] = []
    covered: list[tuple[int, int]] = []

    # JSON-lines, and log lines with an embedded JSON payload after a prefix.
    offset = 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        k = min((p for p in (body.find("{"), body.find("[")) if p >= 0), default=-1)
        if k >= 0:
            frag = body[k:].rstrip()
            if _try_json(frag):
                segments.extend(_scan_json(frag, offset + k))
                covered.append((offset + k, offset + k + len(frag)))
        offset += len(line)

    def in_json(pos: int) -> bool:
        return any(s <= pos < e for s, e in covered)

    kv: list[Segment] = []
    for m in _LINE_KV.finditer(text):
        if in_json(m.start("value")):
            continue
        kv.append(Segment(start=m.start("value"), end=m.end("value"), kind="kv_value", key=normalise_key(m.group("key"))))
    for rx in (_INLINE_KV, _QUOTED_KV):
        for m in rx.finditer(text):
            group = next(
                (g for g in ("dq", "sq", "bare", "num") if g in rx.groupindex and m.group(g) is not None), None
            )
            if group is None or in_json(m.start()):
                continue
            s, e = m.start(group), m.end(group)
            if s == e:
                continue
            kv.append(Segment(start=s, end=e, kind="kv_value", key=normalise_key(m.group("key"))))

    # Drop exact duplicates (the same value found by two patterns).
    seen: set[tuple[int, int]] = set()
    for seg in sorted(kv, key=lambda x: (x.start, -x.end)):
        if (seg.start, seg.end) in seen:
            continue
        seen.add((seg.start, seg.end))
        segments.append(seg)
        covered.append((seg.start, seg.end))

    segments.extend(_gaps(text, _union(covered)))
    segments.sort(key=lambda x: (x.start, x.end))
    return segments


def _union(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for s, e in sorted(intervals):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out
