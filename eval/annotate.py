"""Turn hand-written, inline-annotated text into the dataset JSONL format.

For the held-out split: a teammate who did NOT build the detectors writes synthetic examples
in a plain text file, marking each sensitive value inline as [[type:value]]:

    === prose
    Hi, I'm [[person:Priya Natarajan]] and my number is [[phone:07700 900123]].
    ?? What is the sender's phone number? => 07700 900123
    === json
    {"ref": "[[user_id:ACC-5521]]", "msg": "ask [[person:Tom]] to ring back"}

`=== <kind>` starts an item (kind: log | json | prose | document); an optional `?? question => answer`
line adds a utility task. Then:

    python -m eval.annotate data/heldout_handwritten.txt > data/heldout_handwritten.jsonl
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

MARK = re.compile(r"\[\[([a-z_]+):(.+?)\]\]", re.DOTALL)
TYPES = {"person", "email", "phone", "postcode", "address", "nhs_number", "ni_number", "card", "iban", "ip", "uuid",
         "date_of_birth", "date", "secret", "username", "user_id", "organisation", "location", "quasi_identifier"}


def parse(source: str, prefix: str = "heldout") -> list[dict]:
    items, current = [], None
    for line in source.splitlines(keepends=True):
        if line.startswith("=== "):
            if current:
                items.append(current)
            current = {"kind": line[4:].strip(), "raw": "", "task": None}
        elif line.startswith("?? ") and current is not None:
            q, _, a = line[3:].partition("=>")
            current["task"] = {"question": q.strip(), "answer": a.strip()}
        elif current is not None:
            current["raw"] += line
    if current:
        items.append(current)
    out = []
    for i, it in enumerate(items):
        text, spans, pos = "", [], 0
        raw = it["raw"].rstrip("\n")
        for m in MARK.finditer(raw):
            type_, value = m.group(1), m.group(2)
            if type_ not in TYPES:
                raise ValueError(f"item {i}: unknown type {type_!r}")
            text += raw[pos : m.start()]
            spans.append({"start": len(text), "end": len(text) + len(value), "type": type_})
            text += value
            pos = m.end()
        text += raw[pos:]
        out.append({"id": f"{prefix}-{i:04d}", "synthetic": True, "kind": it["kind"], "text": text,
                    "spans": spans, "task": it["task"], "tags": ["handwritten"]})
    return out


def main() -> None:
    src = Path(sys.argv[1]).read_text(encoding="utf-8")
    for row in parse(src):
        sys.stdout.write(json.dumps(row, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
