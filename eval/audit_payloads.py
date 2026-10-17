"""Leakage audit over what actually left the machine: `logs/payloads/*.jsonl`.

Re-scans every logged payload with the high-risk detectors (L1 secrets + checksum-validated
card / IBAN / NHS / NI numbers). A non-zero count means a payload contained something that
should have been removed. Ground-truth leakage per dataset item is computed by `run_eval`.

    python -m eval.audit_payloads                 # all logs
    python -m eval.audit_payloads --purpose app   # only payloads sent from the app
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from scrubber.detect.merge import merge
from scrubber.detect.secrets import SecretsDetector
from scrubber.detect.structured import StructuredDetector
from scrubber.llm_client import PAYLOAD_DIR
from scrubber.segment import segment

HIGH_RISK = {"secret", "card", "iban", "nhs_number", "ni_number"}


def audit(paths: list[Path], purpose: str | None = None, system: str | None = None) -> dict:
    secrets, structured = SecretsDetector(), StructuredDetector()
    n_payloads, by_type, flagged = 0, Counter(), []
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            meta = rec.get("meta", {})
            if purpose and meta.get("purpose") != purpose:
                continue
            if system and meta.get("system") != system:
                continue
            if meta.get("system") == "raw":
                continue  # the unscrubbed baseline is expected to contain everything
            n_payloads += 1
            text = rec["payload"]
            segs = segment(text)
            hits = [s for s in merge(secrets.detect(text, segs) + structured.detect(text, segs), text) if s.type in HIGH_RISK]
            for h in hits:
                by_type[h.type] += 1
            if hits:
                flagged.append({"file": path.name, "meta": meta, "types": sorted({h.type for h in hits})})
    return {"n_payloads": n_payloads, "high_risk_hits": dict(by_type), "flagged": flagged}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", type=Path, default=PAYLOAD_DIR)
    ap.add_argument("--purpose", help="leakage | utility | app")
    ap.add_argument("--system", help="e.g. full, presidio")
    a = ap.parse_args(argv)
    paths = sorted(a.dir.glob("*.jsonl"))
    res = audit(paths, a.purpose, a.system)
    print(f"audited {res['n_payloads']} payloads in {len(paths)} file(s) (raw baseline excluded)")
    print(f"high-risk values found: {res['high_risk_hits'] or 'none'}")
    by_system = Counter(f.get("meta", {}).get("system", "?") for f in res["flagged"])
    if by_system:
        print(f"flagged payloads by system: {dict(by_system)}")


if __name__ == "__main__":
    main()
