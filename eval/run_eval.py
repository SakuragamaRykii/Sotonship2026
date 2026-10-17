"""Run the evaluation: systems × modes over a synthetic dataset.

    python -m eval.run_eval --dataset data/test.jsonl --systems raw,presidio,regex,full
    python -m eval.run_eval --dataset data/test.jsonl --systems raw,presidio,full --utility --limit 60

Every payload is written through the LLM client's payload log (`logs/payloads/eval_<run>.jsonl`)
and the leakage numbers are computed by reading that file back.
"""

from __future__ import annotations

import argparse
import csv
import json
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from scrubber.llm_client import PAYLOAD_DIR, LLMClient
from scrubber.models import Action
from scrubber.pipeline import Scrubber
from scrubber.policy import default_policy
from scrubber.rehydrate import rehydrate, surrogate_stats
from scrubber.vault import Session

from . import metrics as M

ROOT = Path(__file__).resolve().parent.parent
OURS = {"regex": ["L1", "L2", "L3"], "full": ["L1", "L2", "L3", "L4"], "full_l5": ["L1", "L2", "L3", "L4", "L5"]}
UTILITY_SYSTEMS = {"raw", "presidio", "full"}
PROMPT = (
    "Answer the question using only the text below. Reply with just the answer, no explanation.\n"
    "The text may contain placeholders such as Person_1, user_1@example.com, [ADDRESS_1] or <PERSON>; "
    "if the answer is a placeholder, copy it exactly as written.\n\n"
    "Question: {question}\n\nText:\n<<<\n{text}\n>>>"
)


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for r in rows:
        assert r.get("synthetic") is True, f"{path}: item {r.get('id')} is not marked synthetic"
    return rows


def run(dataset: Path, systems: list[str], modes: list[str], utility: bool, limit: int | None,
        l5: bool, run_id: str) -> dict:
    items = load(dataset)[:limit] if limit else load(dataset)
    policy = default_policy()
    log_path = PAYLOAD_DIR / f"eval_{run_id}.jsonl"
    audit = LLMClient(provider="dryrun", log_path=log_path)
    llm = LLMClient(log_path=log_path) if utility else None
    if llm and llm.provider == "dryrun":
        print("  ! --utility needs LLM_PROVIDER (anthropic/openai/ollama) in .env; skipping utility")
        llm = None

    results: dict = {"dataset": str(dataset.relative_to(ROOT) if dataset.is_relative_to(ROOT) else dataset),
                     "n_items": len(items), "systems": {}}
    for system in systems:
        print(f"  system={system} ({len(items)} items)")
        sys_modes = modes if system in OURS else ["-"]
        scrubber = None
        if system in OURS:
            layers = OURS[system] + (["L5"] if l5 and system == "full" else [])
            scrubber = Scrubber(layers, policy)
        presidio = None
        if system == "presidio":
            from .baselines.presidio_baseline import PresidioBaseline

            presidio = PresidioBaseline()
        stats = {m: defaultdict(float) for m in sys_modes}
        pairs: dict[str, list] = {m: [] for m in sys_modes}
        util: dict[str, list] = {m: [] for m in sys_modes}

        for k, item in enumerate(items):
            text = item["text"]
            pred: list[dict] = []
            det_s = 0.0
            if scrubber:
                t0 = time.perf_counter()
                spans, _ = scrubber.detect(text)
                det_s = time.perf_counter() - t0
                pred = [{"start": s.start, "end": s.end, "type": s.type} for s in spans]
            for mode in sys_modes:
                session = Session()
                t0 = time.perf_counter()
                if system == "raw":
                    payload = text
                elif presidio:
                    payload, pred = presidio.scrub(text)
                else:
                    payload = scrubber.apply(text, spans, session, mode).scrubbed_text
                elapsed = det_s + (time.perf_counter() - t0)
                st = stats[mode]
                st["seconds"] += elapsed
                st["chars"] += len(text)
                pairs[mode].append((item["spans"], pred))
                audit.log_payload(payload, {"run_id": run_id, "purpose": "leakage", "system": system,
                                            "mode": mode, "item_id": item["id"]})
                # echo re-hydration fidelity: protected pseudonymised values come back on rehydrate
                if scrubber:
                    back, _ = rehydrate(payload, session)
                    for value, type_ in M.sensitive_strings(item):
                        if policy.action(type_, mode) in (Action.PSEUDONYMISE, Action.SHIFT) and not M.leaked(value, payload):
                            st["echo_total"] += 1
                            st["echo_ok"] += M.leaked(value, back)
                if llm and item.get("task") and system in UTILITY_SYSTEMS and mode in ("-", "balanced"):
                    q = item["task"]
                    try:
                        response = llm.send_with_retry(PROMPT.format(question=q["question"], text=payload),
                                                       {"run_id": run_id, "purpose": "utility", "system": system,
                                                        "mode": mode, "item_id": item["id"]})
                    except Exception as exc:  # noqa: BLE001
                        print(f"    LLM error on {item['id']}: {type(exc).__name__}")
                        continue
                    final = response
                    if scrubber:
                        restored, unmapped = surrogate_stats(response, session)
                        st["rh_restored"] += restored
                        st["rh_unmapped"] += unmapped
                        final, _ = rehydrate(response, session)
                    util[mode].append(M.answer_correct(final, q["answer"]))
            if (k + 1) % 50 == 0:
                print(f"    {k + 1}/{len(items)}")

        payloads = M.read_payloads(log_path, run_id)
        for mode in sys_modes:
            st = stats[mode]
            item_payloads = {iid: p for (s, m, iid), p in payloads.items() if s == system and m == mode}
            results["systems"][f"{system}|{mode}"] = {
                "system": system,
                "mode": mode,
                "leakage": M.leakage(items, item_payloads),
                "spans_overlap": M.span_metrics(pairs[mode], "overlap"),
                "spans_exact": M.span_metrics(pairs[mode], "exact"),
                "latency_ms_per_1k": M.latency_per_1k(st["seconds"], int(st["chars"])),
                "echo_rehydration": (st["echo_ok"] / st["echo_total"]) if st["echo_total"] else None,
                "echo_n": int(st["echo_total"]),
                "utility": (sum(util[mode]) / len(util[mode])) if util[mode] else None,
                "utility_n": len(util[mode]),
                "rehydration_acc": (st["rh_restored"] / (st["rh_restored"] + st["rh_unmapped"]))
                if (st["rh_restored"] + st["rh_unmapped"]) else None,
                "rehydration_n": int(st["rh_restored"] + st["rh_unmapped"]),
            }
    return results


# ---- reporting -------------------------------------------------------------------------------

def _pct(x: float | None) -> str:
    return "—" if x is None else f"{100 * x:.1f}%"


def _f(x: float | None) -> str:
    return "—" if x is None else f"{x:.3f}"


def write_report(all_results: list[dict], out_dir: Path, run_id: str, provider: str | None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Evaluation results",
        "",
        f"Run `{run_id}`. All data is synthetic (Faker `en_GB` templates; see `eval/generate.py`).",
        "Leakage = fraction of ground-truth sensitive strings found (case-insensitive substring) in the payload",
        "actually logged to `logs/payloads/`. Dates, organisations and locations are kept by the balanced policy",
        "and excluded from leakage (they are still scored in the span tables).",
        "",
    ]
    csv_rows: list[dict] = []
    for res in all_results:
        lines += [f"## Dataset `{res['dataset']}` (n = {res['n_items']} items)", ""]
        if res["n_items"] == 0:
            lines += ["_No items yet: this split is written by hand (see `data/HELDOUT_README.md`)._", ""]
            continue
        rows = list(res["systems"].values())
        lines += [
            "### Leakage, secrets, latency",
            "",
            f"Sensitive strings per system: n = {rows[0]['leakage']['n_strings']}; secrets: n = {rows[0]['leakage']['n_secrets']}.",
            "",
            "| system | mode | leakage rate | leaked / n | secret leaks | latency (ms / 1k chars) | echo re-hydration (n) |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in rows:
            lk = r["leakage"]
            lines.append(
                f"| {r['system']} | {r['mode']} | {_pct(lk['leakage_rate'])} | {lk['n_leaked']} / {lk['n_strings']} | "
                f"**{lk['secret_leaks']}** / {lk['n_secrets']} | {r['latency_ms_per_1k']:.1f} | "
                f"{_pct(r['echo_rehydration'])} ({r['echo_n']}) |"
            )
        lines += ["", "### Detection (micro-averaged)", "",
                  "Typed = span and type must match; ANY = type-agnostic. Overlap match unless stated.", "",
                  "| system | mode | typed P | typed R | typed F1 | ANY P | ANY R | ANY F1 | exact typed F1 | n gold | n pred |",
                  "|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in rows:
            if r["system"] == "raw":
                continue
            o, e = r["spans_overlap"], r["spans_exact"]
            a, y = o.get("ALL", {}), o.get("ANY", {})
            lines.append(
                f"| {r['system']} | {r['mode']} | {_f(a.get('precision'))} | {_f(a.get('recall'))} | {_f(a.get('f1'))} | "
                f"{_f(y.get('precision'))} | {_f(y.get('recall'))} | {_f(y.get('f1'))} | {_f(e.get('ALL', {}).get('f1'))} | "
                f"{a.get('n_gold', 0)} | {a.get('n_pred', 0)} |"
            )
        gold_types = sorted({t for r in rows for t, v in r["spans_overlap"].items()
                             if t not in ("ALL", "ANY") and v["n_gold"] > 0})
        det_rows = [r for r in rows if r["system"] != "raw" and r["mode"] in ("-", "balanced")]
        lines += ["", "### Recall by type (overlap, typed)", "",
                  "| type | n gold | " + " | ".join(r["system"] for r in det_rows) + " |",
                  "|---|---|" + "---|" * len(det_rows)]
        for t in gold_types:
            n = det_rows[0]["spans_overlap"].get(t, {}).get("n_gold", 0) if det_rows else 0
            lines.append(f"| {t} | {n} | " + " | ".join(_f(r["spans_overlap"].get(t, {}).get("recall")) for r in det_rows) + " |")
        leak_types = sorted({t for r in rows for t in r["leakage"]["per_type"]})
        lines += ["", "### Leakage by type", "",
                  "| type | n | " + " | ".join(f"{r['system']} ({r['mode']})" for r in rows) + " |",
                  "|---|---|" + "---|" * len(rows)]
        for t in leak_types:
            n = rows[0]["leakage"]["per_type"].get(t, {}).get("n", 0)
            lines.append(f"| {t} | {n} | " + " | ".join(_pct(r["leakage"]["per_type"].get(t, {}).get("rate")) for r in rows) + " |")
        tags = sorted({t for r in rows for t in r["leakage"]["per_tag"]})
        if tags:
            lines += ["", "### Leakage on hard cases (by item tag)", "",
                      "| tag | n strings | " + " | ".join(f"{r['system']} ({r['mode']})" for r in rows) + " |",
                      "|---|---|" + "---|" * len(rows)]
            for t in tags:
                n = rows[0]["leakage"]["per_tag"].get(t, {}).get("n", 0)
                lines.append(f"| {t} | {n} | " + " | ".join(_pct(r["leakage"]["per_tag"].get(t, {}).get("rate")) for r in rows) + " |")
        util_rows = [r for r in rows if r["utility_n"]]
        lines += ["", "### Utility (LLM answers over items with a task)", ""]
        if util_rows:
            lines += [f"Provider: `{provider}`. Our systems' answers are re-hydrated before scoring.", "",
                      "| system | mode | answer accuracy | n tasks | re-hydration accuracy | n surrogates |",
                      "|---|---|---|---|---|---|"]
            for r in util_rows:
                lines.append(f"| {r['system']} | {r['mode']} | {_pct(r['utility'])} | {r['utility_n']} | "
                             f"{_pct(r['rehydration_acc'])} | {r['rehydration_n']} |")
        else:
            lines += ["_Not run (needs `--utility` and an LLM provider in `.env`)._"]
        modes_ours = [r for r in rows if r["system"] in OURS]
        if {r["mode"] for r in modes_ours} >= {"balanced", "strict"}:
            lines += ["", "### Strict vs balanced trade-off", "",
                      "| system | balanced leakage | strict leakage | balanced echo re-hydration | strict echo re-hydration |",
                      "|---|---|---|---|---|"]
            for s in sorted({r["system"] for r in modes_ours}):
                b = res["systems"].get(f"{s}|balanced")
                st = res["systems"].get(f"{s}|strict")
                if b and st:
                    lines.append(f"| {s} | {_pct(b['leakage']['leakage_rate'])} | {_pct(st['leakage']['leakage_rate'])} | "
                                 f"{_pct(b['echo_rehydration'])} | {_pct(st['echo_rehydration'])} |")
        lines.append("")
        for r in rows:
            base = {"dataset": res["dataset"], "system": r["system"], "mode": r["mode"]}
            csv_rows.append({**base, "metric": "leakage_rate", "type": "ALL", "value": r["leakage"]["leakage_rate"], "n": r["leakage"]["n_strings"]})
            csv_rows.append({**base, "metric": "secret_leaks", "type": "secret", "value": r["leakage"]["secret_leaks"], "n": r["leakage"]["n_secrets"]})
            csv_rows.append({**base, "metric": "latency_ms_per_1k", "type": "ALL", "value": r["latency_ms_per_1k"], "n": res["n_items"]})
            for t, v in r["leakage"]["per_type"].items():
                csv_rows.append({**base, "metric": "leakage_rate", "type": t, "value": v["rate"], "n": v["n"]})
            for match in ("overlap", "exact"):
                for t, v in r[f"spans_{match}"].items():
                    for k in ("precision", "recall", "f1"):
                        csv_rows.append({**base, "metric": f"{k}_{match}", "type": t, "value": v[k], "n": v["n_gold"]})
            for k in ("echo_rehydration", "utility", "rehydration_acc"):
                if r[k] is not None:
                    n = r["echo_n"] if k == "echo_rehydration" else (r["utility_n"] if k == "utility" else r["rehydration_n"])
                    csv_rows.append({**base, "metric": k, "type": "ALL", "value": r[k], "n": n})
    md = out_dir / "results.md"
    md.write_text("\n".join(lines), encoding="utf-8")
    with open(out_dir / "results.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["dataset", "system", "mode", "metric", "type", "value", "n"])
        w.writeheader()
        w.writerows(csv_rows)
    return md


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", action="append", type=Path,
                    help="JSONL dataset; repeat for several (default: test + heldout_handwritten)")
    ap.add_argument("--systems", default="raw,presidio,regex,full")
    ap.add_argument("--modes", default="balanced,strict")
    ap.add_argument("--utility", action="store_true", help="also send tasks to the LLM (costs API calls)")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--l5", action="store_true", help="add the L5 local-LLM layer to `full`")
    ap.add_argument("--out", type=Path, default=ROOT / "eval" / "results")
    a = ap.parse_args(argv)
    datasets = a.dataset or [ROOT / "data" / "test.jsonl", ROOT / "data" / "heldout_handwritten.jsonl"]
    systems = [s.strip() for s in a.systems.split(",") if s.strip()]
    modes = [m.strip() for m in a.modes.split(",") if m.strip()]
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    all_results = []
    for ds in datasets:
        ds = ds if ds.is_absolute() else (Path.cwd() / ds).resolve()
        print(f"dataset {ds}")
        all_results.append(run(ds, systems, modes, a.utility, a.limit, a.l5, run_id))
    provider = LLMClient().provider if a.utility else None
    md = write_report(all_results, a.out, run_id, provider)
    (a.out / "results.json").write_text(json.dumps(all_results, indent=1), encoding="utf-8")
    print(f"wrote {md}")


if __name__ == "__main__":
    main()
