"""Evaluation metrics: span P/R/F1, leakage, utility, re-hydration accuracy, latency."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

# Types that the default (balanced) policy intentionally keeps; excluded from leakage.
NON_SENSITIVE_TYPES = {"date", "organisation", "location"}


def _prf(tp_p: int, n_pred: int, tp_g: int, n_gold: int) -> dict:
    p = tp_p / n_pred if n_pred else 0.0
    r = tp_g / n_gold if n_gold else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": p, "recall": r, "f1": f, "n_pred": n_pred, "n_gold": n_gold}


def _match(a: dict, b: dict, mode: str, typed: bool) -> bool:
    if typed and a["type"] != b["type"]:
        return False
    if mode == "exact":
        return a["start"] == b["start"] and a["end"] == b["end"]
    return a["start"] < b["end"] and b["start"] < a["end"]


def span_metrics(items: list[tuple[list[dict], list[dict]]], mode: str = "overlap") -> dict[str, dict]:
    """Per-type and micro P/R/F1 over (gold_spans, pred_spans) pairs.

    "ALL" is typed micro-average; "ANY" ignores types (did we flag the region at all?).
    """
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])  # tp_pred, n_pred, tp_gold, n_gold
    for gold, pred in items:
        for typed, key_fn in ((True, lambda s: s["type"]), (False, lambda s: "ANY")):
            for g in gold:
                hit = any(_match(g, p, mode, typed) for p in pred)
                for k in {key_fn(g), "ALL" if typed else "ANY"}:
                    counts[k][2] += hit
                    counts[k][3] += 1
            for p in pred:
                hit = any(_match(g, p, mode, typed) for g in gold)
                for k in {key_fn(p), "ALL" if typed else "ANY"}:
                    counts[k][0] += hit
                    counts[k][1] += 1
    return {k: _prf(*v) for k, v in counts.items()}


def sensitive_strings(item: dict) -> list[tuple[str, str]]:
    """(value, type) for every ground-truth span that must not reach the LLM."""
    out = []
    for s in item["spans"]:
        if s["type"] in NON_SENSITIVE_TYPES:
            continue
        out.append((item["text"][s["start"] : s["end"]], s["type"]))
    return out


def leaked(value: str, payload: str) -> bool:
    """Case-insensitive substring search (JSON-escaped values are also tried unescaped)."""
    p = payload.lower()
    v = value.lower()
    if v in p:
        return True
    try:
        unescaped = json.loads(f'"{value}"').lower()
    except json.JSONDecodeError:
        return False
    return unescaped != v and unescaped in p


def read_payloads(path: Path, run_id: str) -> dict[tuple[str, str, str], str]:
    """(system, mode, item_id) → payload, from the payload log written by the LLM client."""
    out: dict[tuple[str, str, str], str] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            meta = rec.get("meta", {})
            if meta.get("run_id") != run_id or meta.get("purpose") != "leakage":
                continue
            out[(meta["system"], meta["mode"], meta["item_id"])] = rec["payload"]
    return out


def leakage(items: list[dict], payloads: dict[str, str]) -> dict:
    """Leakage over item_id → payload. Returns overall, per type, secret leak count, per tag."""
    total = hits = secret_total = secret_hits = 0
    per_type: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    per_tag: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for item in items:
        payload = payloads.get(item["id"])
        if payload is None:
            continue
        for value, type_ in sensitive_strings(item):
            leak = leaked(value, payload)
            total += 1
            hits += leak
            per_type[type_][0] += leak
            per_type[type_][1] += 1
            for tag in item.get("tags", []):
                per_tag[tag][0] += leak
                per_tag[tag][1] += 1
            if type_ == "secret":
                secret_total += 1
                secret_hits += leak
    return {
        "leakage_rate": hits / total if total else 0.0,
        "n_strings": total,
        "n_leaked": hits,
        "secret_leaks": secret_hits,
        "n_secrets": secret_total,
        "per_type": {t: {"rate": v[0] / v[1], "n": v[1], "leaked": v[0]} for t, v in per_type.items()},
        "per_tag": {t: {"rate": v[0] / v[1], "n": v[1], "leaked": v[0]} for t, v in per_tag.items()},
    }


def _norm(s: str) -> str:
    return re.sub(r"[\s\W_]+", " ", s.lower()).strip()


def answer_correct(response: str, answer: str) -> bool:
    """Lenient containment: the gold answer (normalised) appears in the response."""
    a, r = _norm(answer), _norm(response)
    return bool(a) and (a in r or a.replace(" ", "") in r.replace(" ", ""))


def latency_per_1k(total_seconds: float, total_chars: int) -> float:
    return 1000.0 * total_seconds / max(total_chars, 1) * 1000.0  # ms per 1k chars
