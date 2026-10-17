# Held-out hand-written split

`heldout_handwritten.jsonl` must be written by a teammate **who did not build the detectors**, so it
measures generalisation rather than what the templates were tuned on. It is reported separately.

Rules:
- **Synthetic only.** Invent every name, number and address. Use reserved ranges where they exist:
  phones `07700 900000`–`07700 900999`, IPs `192.0.2.x` / `198.51.100.x` / `203.0.113.x`, emails at
  `example.com` / `example.org`, and checksum-valid but made-up NHS / card / IBAN numbers.
- Mix kinds (log, json, prose, document) and include awkward cases: nicknames, initials, names in
  free text inside JSON, unusual key names, IDs in odd formats, secrets inside URLs, indirect
  identifiers ("the only Welsh-speaking nurse on the ward").
- Do not look at the detector code or `config/policy.yaml` while writing.

How:
1. Write `data/heldout_handwritten.txt` using inline markup (see `eval/annotate.py` for the format).
2. `python -m eval.annotate data/heldout_handwritten.txt > data/heldout_handwritten.jsonl`
3. `python -m eval.run_eval` (it evaluates `test.jsonl` and this file by default).
