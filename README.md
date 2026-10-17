# Local reversible PII scrubber for LLM prompts

Detect personal data and secrets in text (prose, logs, JSON, key=value, documents), replace them
with **consistent, format-preserving surrogates** (or remove them), send only the scrubbed text to an
LLM, then **re-hydrate** the answer back to real values, all locally. Includes a CLI, a Streamlit
review app and an evaluation harness against a Presidio baseline.

> **Pseudonymised data is still personal data.** This tool reduces risk; it does not make data
> anonymous or compliant. See [Known limits](#known-limits).

```
text ─► segment ─► detect (L1 secrets · L2 structured · L3 key-aware · L4 GLiNER · L5 local LLM)
     ─► merge ─► policy (REMOVE / PSEUDONYMISE / GENERALISE / SHIFT / KEEP) ─► transform (vault)
     ─► leak check ─► scrubbed prompt ─► [LLM, payload logged] ─► rehydrate ─► answer with real values
```

The full specification is in [SPEC.md](SPEC.md).

## Setup (reproducible)

Requires **Python 3.11**. Everything is pinned in [requirements.lock.txt](requirements.lock.txt)
(CPU-only PyTorch, spaCy `en_core_web_lg` wheel included).

Windows (PowerShell):

```bash
powershell -ExecutionPolicy Bypass -File scripts/setup.ps1
```

macOS / Linux / Git Bash:

```bash
bash scripts/setup.sh
```

Both scripts create `.venv`, install the lock file, install this package in editable mode, download
the GLiNER PII model once (~1.2 GB, cached under `~/.cache/huggingface`; inference runs locally),
and copy `.env.example` to `.env`. Manual equivalent:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock.txt
.venv/bin/python -m pip install -e . --no-deps
.venv/bin/python scripts/download_models.py
```

On Windows, keep the checkout at a short path (e.g. `C:\Users\you\Sotonship2026`): PyTorch's
nested header files can exceed the 260-character path limit inside deep folders, which shows up as a
`No such file or directory` error during install.

Then run the tests (about 15 s; one test loads the real GLiNER model):

```bash
.venv/bin/python -m pytest -q
```

Optional: a local [Ollama](https://ollama.com) with `ollama pull qwen3:8b` for the L5
quasi-identifier layer and for running the utility eval without any cloud API.

## Use it

### Python

```python
from scrubber import Session, scrub, rehydrate

session = Session()                        # holds the vault, in memory
r = scrub(text, session, mode="balanced")  # or mode="strict"
r.scrubbed_text                            # what the model may see
r.spans, r.actions, r.report               # what was found, what was done, leak-check fixes, warnings

answer = my_llm(r.scrubbed_text)
restored, warnings = rehydrate(answer, session)
```

Example (balanced):

```
in : Hi, I'm Jane Doe (jane.doe+shop@gmail.com, 07911 123456). Ms Doe's NHS number is 943 476 5919.
     2024-05-01 WARN auth failed user=jdoe92 src=10.0.0.12 token=sk-proj-Q1w2…
     {"customer": "Jane Doe", "dob": "03/05/1988", "address": "12 High Street, Southampton SO17 1BJ"}
out: Hi, I'm Person_1 (user_1+shop@example.com, 07700 900001). Ms Person_1's NHS number is [NHS_NUMBER_REMOVED].
     2024-05-01 WARN auth failed user=username_1 src=198.51.100.12 token=[SECRET_REMOVED]
     {"customer": "Person_1", "dob": "[AGE 35-39]", "address": "[ADDRESS_1], SO17"}
```

### CLI

```bash
python cli.py scrub --mode balanced < in.txt > out.txt
```

The report (types, offsets, reasons; never the original values) goes to stderr, or to a file with
`--report report.json`. The session id is printed to stderr. Then:

```bash
python cli.py rehydrate --session <ID> < llm_answer.txt > restored.txt
```

```bash
python cli.py eval --dataset data/test.jsonl --systems presidio,regex,full
```

```bash
python cli.py audit
```

`--layers L1,L2,L3` limits the detectors (fast, no model). `audit` re-scans every logged payload for
secrets and checksum-valid identifiers.

Because `scrub` and `rehydrate` are separate processes, the CLI saves the session's pseudonym
mappings to `.sessions/<id>.json` (local, gitignored, never sent anywhere; secrets and other removed
values are never in it). Pass `--no-save` to keep them in memory only. The Python API and the app
never write the vault to disk.

### Streamlit app

```bash
streamlit run app/streamlit_app.py
```

1. Paste text, pick a mode and detector layers.
2. Spans are highlighted by type; hover for the layer and reason.
3. Untick spans to keep them, change a type, or add a span by exact text; re-run the transform.
4. Side by side: the original and exactly what the model will see.
5. Copy the scrubbed prompt, or send it via the configured LLM client.
6. Paste (or receive) the response and get it re-hydrated, with warnings for unknown surrogates.

### LLM providers

Set in `.env` (gitignored; see [.env.example](.env.example)):

| `LLM_PROVIDER` | Notes |
|---|---|
| `dryrun` (default) | Logs the payload, sends nothing. |
| `ollama` | Local Ollama (`OLLAMA_HOST`, default model `qwen3:8b`). Nothing leaves the machine. |
| `anthropic` | Claude via the Anthropic SDK (`ANTHROPIC_API_KEY`), default model `claude-opus-5-5`, with server-side refusal fallbacks enabled. |
| `openai` | Any OpenAI-compatible endpoint (`OPENAI_API_KEY`, optional `OPENAI_BASE_URL`). |

Every call writes the **exact payload sent** to `logs/payloads/*.jsonl` (gitignored). The
leakage audit and the eval read that file, so what is measured is what actually left the machine.

## How it works

| Stage | File | Notes |
|---|---|---|
| Segment | `scrubber/segment.py` | JSON (whole input or per line, including log prefixes), `key=value`, `key: value`, `"key": "value"` fragments, free text. Offsets always point into the original string. |
| L1 secrets | `scrubber/detect/secrets.py` | `sk-`, `ghp_`, `AKIA`, `xox?-`, Stripe, Google keys, JWTs, `Authorization`/`Bearer`, `scheme://user:PASS@host` (password may contain `@`), secret-named keys, private-key blocks, high-entropy tokens (H > 4.0, len ≥ 20). |
| L2 structured | `scrubber/detect/structured.py` | Email, UK phone, postcode, NHS (mod-11), NI, card (Luhn + issuer prefix), IBAN (mod-97), IPv4/IPv6, UUID, dates (+ "DOB"/"born" context → date of birth), personal URL query params, custom regexes from config. |
| L3 key-aware | `scrubber/detect/keys.py` | Key normalisation (`firstName` → `first_name`) + lookup table in `config/policy.yaml`; ambiguous keys (`user`, `customer`, `contact`) are typed by value shape; free-text keys (`note`, `message`, …) are scanned by L4 at a lower threshold. |
| L4 NER | `scrubber/detect/ner.py` | GLiNER PII checkpoint (`urchade/gliner_multi_pii-v1`), local, batched per segment; filters log levels, lowercase "names" and retypes name-shaped "username" hits. |
| L5 quasi-ids | `scrubber/detect/llm.py` | Optional. Local Ollama only (refuses non-local hosts). JSON spans + reason. |
| Merge | `scrubber/detect/merge.py` | Priority L1 > L2 > L3 > L4 > L5, then longer, then more confident. Addresses absorb their postcode; quasi-identifier phrases absorb the organisation/place inside them; L3 whole values keep their non-overlapping remainder. |
| Policy | `scrubber/policy.py`, `config/policy.yaml` | Per-type action per mode (table below). |
| Vault + surrogates | `scrubber/vault.py`, `scrubber/surrogates.py` | Per-session forward/reverse maps; counters per type; format-preserving surrogates; prefix switch if the input already contains surrogate-shaped text. |
| Transform + leak check | `scrubber/transform.py` | Right-to-left replacement, then every vault original, removed value and lone name token is searched for again outside the replaced regions. |
| Rehydrate | `scrubber/rehydrate.py` | Longest-first, case-insensitive, boundary-aware; possessives and quotes work; unknown surrogate-shaped tokens are left and reported. |

Default policy:

| Type | balanced | strict |
|---|---|---|
| secret, card, iban, nhs_number, ni_number | REMOVE | REMOVE |
| person, email, phone, user_id, uuid, username | PSEUDONYMISE | PSEUDONYMISE |
| address | PSEUDONYMISE, keep postcode district | PSEUDONYMISE |
| postcode (on its own) | GENERALISE → district (`SO17`) | GENERALISE → area (`SO`) |
| ip | PSEUDONYMISE (TEST-NET, /24 relations kept) | REMOVE |
| date_of_birth | GENERALISE → 5-year age band | GENERALISE → 10-year band |
| other dates | KEEP | SHIFT (session-constant offset; re-hydrated) |
| organisation, location | KEEP | GENERALISE |
| quasi_identifier (L5) | FLAG for review | GENERALISE |

Surrogates: `Person_N`; `user_N@example.com` (keeps `+tag`); `07700 900NNN` in the original's
spacing style; TEST-NET IPs (same /24 → same surrogate /24, same host → same host); `00000000-0000-4000-8000-00000000000N`;
`[ADDRESS_N], SO17`; IDs keep their shape (`CUST-88231` → `CUST-00001`). Removed values become
`[SECRET_REMOVED]`, `[CARD_REMOVED]`, … and are never stored.

Entity linking: "Jane", "Ms Doe" and "Jane Doe" share one surrogate (token-subset rule, ambiguous
mentions are not linked). A lone known surname next to another capitalised name ("Georgina Preston"
when the session knows "Joshua Preston") is treated as a different person.

## Evaluation

```bash
python -m eval.generate --split test --n 300 --seed 2      # already in data/
python -m eval.run_eval                                     # test + held-out, all systems, both modes
python -m eval.run_eval --systems raw,presidio,full --modes balanced --utility --limit 90
python -m eval.run_eval --dataset data/quasi.jsonl --systems full,full_l5
```

Systems: `raw` (no scrubbing), `presidio` (AnalyzerEngine + AnonymizerEngine defaults, spaCy
`en_core_web_lg`), `regex` (L1–L3), `full` (L1–L4), `full_l5` (L1–L5). Results are written to
`eval/results/results.md` and `results.csv`; every table states its sample sizes.

RESULTS_PLACEHOLDER

Datasets (all synthetic, Faker `en_GB`, every line has `"synthetic": true`):

- `data/dev.jsonl` (120): used for tuning.
- `data/test.jsonl` (300): generated with a different seed and never tuned on.
- `data/quasi.jsonl` (40): prose and documents with injected quasi-identifier phrases (M6).
- `data/heldout_handwritten.jsonl`: **empty until a teammate who did not build the detectors writes
  it**, see [data/HELDOUT_README.md](data/HELDOUT_README.md) and `eval/annotate.py`. Reported separately.

Hard cases in the generator: PII in free text inside JSON values, unknown key names, the same person
written several ways, emails with `+tags`, secrets inside URLs.

Caveat: the generated splits come from the same templates, so test scores measure robustness to new
values rather than to new text shapes. The hand-written split is the real generalisation check.

## Known limits

- English text and UK identifier formats only.
- Quasi-identifiers in free text are only partially covered (L5 is optional and model-dependent).
- Unknown custom ID formats (e.g. `CUST-88231`) are missed unless their key name matches or a custom
  pattern is added under `custom_patterns` in `config/policy.yaml`.
- Pseudonymised data is still personal data. The tool reduces risk; it does not make data anonymous
  or compliant.
- Re-hydration restores a person's most complete known name: "Jane" in the prompt comes back as
  "Jane Doe" if the session also saw "Jane Doe".
- Name-token propagation can over-replace a capitalised word that is also someone's name (e.g. the
  surname "Hall" in "Hall B"). Common words are on a stop-list.
- L4 is slow on CPU (roughly 1 s per 1k characters); L1–L3 alone are about 200× faster.

## Repo layout

```
config/policy.yaml          policy, key tables, NER labels, custom patterns
scrubber/                   library (models, pipeline, segment, policy, vault, surrogates,
                            transform, rehydrate, llm_client, detect/{secrets,structured,keys,ner,llm,merge})
cli.py                      typer CLI
app/streamlit_app.py        review UI
eval/                       generate, metrics, run_eval, audit_payloads, annotate, baselines/presidio_baseline
data/                       synthetic datasets
scripts/                    setup.ps1, setup.sh, download_models.py
tests/                      pytest suite
logs/payloads/, .sessions/  runtime only, gitignored
```
