# SPEC — Local reversible PII scrubber for LLM prompts

## Goal
A local Python library + CLI + Streamlit app that:
1. Detects personal data and secrets in text (prose, logs, JSON, key=value, documents).
2. Replaces them with **consistent, format-preserving surrogates** (or removes them), so the text stays useful to an LLM.
3. Sends only the scrubbed text to an LLM (optional adapter).
4. **Re-hydrates** the LLM's response back to real values locally.
5. Ships an **evaluation harness** that compares against a Presidio baseline on leakage and utility.

Audience-agnostic: the engine must not assume any one domain. Domain-specific behaviour lives in config and test data only.

## Non-negotiables
- All detection runs **locally**. Raw text is never sent to any external service.
- Use **synthetic data only**. Every dataset file is marked `synthetic: true`. No real personal data in the repo.
- **Secrets are removed, never pseudonymised, and never stored in the vault.**
- The vault lives in memory per session. It is never logged and never sent anywhere.
- API keys come from `.env`; `.env` is in `.gitignore`.
- Python 3.11, type hints, pydantic models, pytest.

## Pipeline

```
input text
  → 1. segment     (detect structure: JSON / key=value / log line / prose; keep char offsets)
  → 2. detect      (layered detectors → candidate spans)
  → 3. merge       (resolve overlaps → final spans)
  → 4. policy      (per-type action: REMOVE / PSEUDONYMISE / GENERALISE / KEEP; mode = strict|balanced)
  → 5. transform   (vault lookup/creation, surrogate generation, replace right-to-left by offset)
  → 6. leak check  (re-scan output for any original value still present; fix + log)
  → ScrubResult    (scrubbed_text, spans, report, session_id)
  → [7. LLM call — optional, logs exact payload sent]
  → 8. rehydrate   (map surrogates in the LLM response back to originals)
```

### 1. Segment (`segment.py`)
- Try to parse as JSON (whole input, or per line for JSON-lines logs).
- Detect `key=value` and `key: value` pairs.
- Everything else is a free-text segment.
- Output: `list[Segment(start, end, kind: "json_value"|"kv_value"|"text", key: str|None)]`, with offsets into the original string.

### 2. Detect (`detect/`), layered. Each detector returns `list[Span]`
| Layer | File | What | Method |
|---|---|---|---|
| L1 secrets | `secrets.py` | API keys (`sk-`, `ghp_`, `AKIA`, `xox[bp]-`), JWTs (`eyJ…\.…\.…`), `Authorization:`/`Bearer` values, passwords in URLs/connection strings (`scheme://user:PASS@host`), `password=` values, high-entropy tokens (Shannon entropy > 4.0, length ≥ 20) | regex + entropy |
| L2 structured | `structured.py` | email, UK phone, UK postcode, NHS number (mod-11 checksum), NI number, payment card (Luhn), IBAN (mod-97), IPv4/IPv6, UUID, dates, URLs with personal query params | regex + validators |
| L3 key-aware | `keys.py` | values whose key matches a sensitive-key list (`name, first_name, last_name, email, phone, mobile, address, street, postcode, dob, birth, user, username, customer, contact, note, comment, message`) → typed span | key normalisation + lookup table in `config/policy.yaml` |
| L4 contextual NER | `ner.py` | person, address, location, organisation, date of birth, other free-text PII in `text` segments | GLiNER, PII checkpoint, local; label set and threshold in config |
| L5 quasi-identifiers (optional, behind flag) | `llm.py` | indirect identifiers ("the only female professor in…", rare events, family details) | local LLM via Ollama, JSON output of spans + reason |

Detectors are pluggable (`Detector` protocol: `detect(text, segments) -> list[Span]`) so each layer can be switched off for ablations.

### 3. Merge (`detect/merge.py`)
- Priority when spans overlap: L1 > L2 (validated) > L3 > L4 > L5.
- At equal priority, keep the longer span, then the higher confidence.
- Entity linking: link partial mentions to a full entity (e.g. "Jane", "Ms Doe" → "Jane Doe") so they share one surrogate. Use a simple token-subset rule within a session.

### 4. Policy (`policy.py`, `config/policy.yaml`)
Default actions:
| Type | balanced | strict |
|---|---|---|
| secret, card, iban, nhs_number, ni_number | REMOVE | REMOVE |
| person, email, phone, user_id, uuid, username | PSEUDONYMISE | PSEUDONYMISE |
| address | PSEUDONYMISE (keep postcode district) | PSEUDONYMISE (drop district) |
| ip | PSEUDONYMISE (preserve subnet relations) | REMOVE |
| date_of_birth | GENERALISE (year → 5-year age band) | GENERALISE (10-year band) |
| other dates | KEEP | SHIFT (session-constant day offset, intervals preserved) |
| organisation, location | KEEP | GENERALISE |
| quasi_identifier (L5) | flag for review | GENERALISE |

### 5. Transform (`vault.py`, `surrogates.py`, `transform.py`)
**Vault:** per session, `forward[(type, normalised_original)] -> surrogate` and `reverse[surrogate] -> original`. Normalise emails to lowercase and phones to digits only.

**Surrogates:** deterministic within a session (counter per type); format-preserving:
- person → `Person_1`, `Person_2`, …
- email → `user_N@example.com`; preserve `+tag` and the dot pattern of the local part (`jane.doe+shop@gmail.com` → `user_1+shop@example.com`)
- phone → UK drama range `07700 900NNN`, keeping the original spacing style
- ip → TEST-NET ranges (`198.51.100.x`, `203.0.113.x`). The same original /24 maps to the same surrogate /24, and the same host maps to the same host.
- uuid → deterministic valid v4-format UUID (`00000000-0000-4000-8000-00000000000N`)
- address → `[ADDRESS_N]` plus postcode district if the policy keeps it
- removed → `[SECRET_REMOVED]`, `[CARD_REMOVED]`, etc. (never stored)

**Collision check:** if a surrogate string already occurs in the input, switch to a unique prefix.

**Replacement:** apply replacements right-to-left by offset so earlier offsets stay valid.

### 6. Leak check
After transforming, search the scrubbed text for every original value in the vault, plus every removed value (held only in a local variable during this call). Any hit is replaced and recorded in `report.leak_fixes`.

### 7. LLM client (`llm_client.py`), optional
- Provider-agnostic adapter (`send(prompt: str) -> str`). Keys come from env.
- **Write the exact payload sent to `logs/payloads/*.jsonl`.** The leakage audit uses this file.

### 8. Rehydrate (`rehydrate.py`)
- Replace surrogates in the LLM response using `reverse`. Handle case variants, possessives (`Person_1's`), and surrogates inside punctuation or quotes.
- Removed items are never restored.
- Surrogate-like tokens with no mapping (e.g. the model invents `Person_7`, or mangles `user_1`) are left as they are, and a warning is added to the report.

## Data models (`models.py`)
```python
class Span(BaseModel):
    start: int; end: int; text: str
    type: str            # e.g. "email", "person", "secret"
    source: str          # "L1".."L5"
    confidence: float
    reason: str          # human-readable, shown in UI

class ScrubResult(BaseModel):
    scrubbed_text: str
    spans: list[Span]
    actions: list[dict]  # span index → action, surrogate
    session_id: str
    report: dict         # counts per type, leak_fixes, warnings
```
Public API (`pipeline.py`):
```python
scrub(text: str, session: Session, mode: str = "balanced") -> ScrubResult
rehydrate(text: str, session: Session) -> tuple[str, list[str]]  # text, warnings
```

## CLI (`cli.py`, typer)
- `scrub [--mode] < in.txt > out.txt` (writes the report to stderr or `--report path.json`)
- `rehydrate --session ID < llm_answer.txt`
- `eval --dataset data/test.jsonl --systems presidio,regex,full`

## Streamlit app (`app/streamlit_app.py`)
1. Paste text, pick a mode.
2. Highlighted spans, colour-coded by type, with the reason on hover.
3. Accept or reject each span, or add a span manually; re-run the transform.
4. Side-by-side diff (original | what the model will see).
5. Copy the scrubbed prompt, or send it via the LLM client.
6. Paste or receive the response, then show the re-hydrated output with any warnings.

## Evaluation harness (`eval/`)
**Dataset format (JSONL):** `{"id", "synthetic": true, "kind": "log|json|prose|document", "text", "spans": [{"start","end","type"}], "task": {"question","answer"} | null}`

**Generators (`eval/generate.py`):** templates of each kind with PII and secrets injected from Faker (`en_GB`), recording ground-truth offsets. Include hard cases:
- PII in free text inside JSON values;
- unknown key names;
- the same person written in several ways;
- emails with `+tags`;
- secrets inside URLs.

**Splits:**
- `dev.jsonl`: for tuning.
- `test.jsonl`: generated, never tuned on.
- `heldout_handwritten.jsonl`: written by a teammate who did not build the detectors; reported separately.

**Systems compared:**
- `raw`: no scrubbing.
- `presidio`: AnalyzerEngine + AnonymizerEngine, defaults.
- `regex`: L1–L3 only (ablation; shows what the AI layers add).
- `full`: L1–L4 (plus L5 if enabled).

**Metrics (`eval/metrics.py`):**
- Span precision, recall and F1 per type (exact match and overlap match).
- **Leakage rate:** fraction of ground-truth sensitive strings present in the payload actually sent (case-insensitive substring search over `logs/payloads`).
- **Secret leaks:** absolute count. The target is 0.
- **Utility:** for items with a `task`, send the question plus text to the LLM and score answer correctness against `answer`, across `raw / presidio / full`.
- **Re-hydration accuracy:** fraction of surrogates in the responses correctly restored.
- Latency per 1k characters.

**Output:** `eval/results/results.md` (table per system × mode) plus CSV. Every table states its sample sizes.

## Repo layout
```
scrubber/
  pyproject.toml  README.md  SPEC.md  .gitignore  .env.example
  config/policy.yaml
  scrubber/
    __init__.py models.py pipeline.py segment.py policy.py
    vault.py surrogates.py transform.py rehydrate.py llm_client.py
    detect/ __init__.py secrets.py structured.py keys.py ner.py llm.py merge.py
  cli.py
  app/streamlit_app.py
  eval/ generate.py metrics.py run_eval.py baselines/presidio_baseline.py results/
  data/ dev.jsonl test.jsonl heldout_handwritten.jsonl   # synthetic only
  logs/payloads/                                          # gitignored
  tests/
```

## Dependencies
`presidio-analyzer presidio-anonymizer spacy (en_core_web_lg for the Presidio baseline) gliner pydantic typer streamlit faker pytest python-dotenv` + optional `ollama`.

## Milestones (build in order; each must pass its tests before the next)
- **M1. Core engine:** segment, L1, L2, merge, policy, vault, surrogates, transform, leak check, rehydrate.
  - Tests:
    - **Round-trip property:** `rehydrate(scrub(x).scrubbed_text) == x` for inputs containing only PSEUDONYMISE types.
    - Secrets never appear in the output or the vault.
    - Consistency: the same email mapped twice gives the same surrogate.
    - IP subnet preservation.
    - `+tag` preservation.
- **M2. Eval harness:** generator, metrics, Presidio baseline, `run_eval.py` producing `results.md` for `raw / presidio / regex`.
- **M3. AI layers:** L3 key-aware and L4 GLiNER; rerun the eval, adding `full`.
- **M4. Streamlit app** (flow above).
- **M5. LLM client:** payload logging, leakage audit and utility eval over tasks.
- **M6 (stretch). L5 local-LLM quasi-identifiers;** strict/balanced trade-off table.

## Known limits (surface these in the UI and README)
- English and UK identifier formats only.
- Quasi-identifiers in free text are only partially covered.
- Unknown custom ID formats (e.g. `CUST-88231`) are missed unless their key name matches or a custom pattern is added in config.
- Pseudonymised data is still personal data. The tool reduces risk; it does not make data anonymous or compliant.
