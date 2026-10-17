# Evaluation results

Run `20261017-160537`. All data is synthetic (Faker `en_GB` templates; see `eval/generate.py`).
Leakage = fraction of ground-truth sensitive strings found (case-insensitive substring) in the payload
actually logged to `logs/payloads/`. Dates, organisations and locations are kept by the balanced policy
and excluded from leakage (they are still scored in the span tables).

## Dataset `data\test.jsonl` (n = 300 items)

### Leakage, secrets, latency

Sensitive strings per system: n = 3410; secrets: n = 116.

| system | mode | leakage rate | leaked / n | secret leaks | latency (ms / 1k chars) | echo re-hydration (n) |
|---|---|---|---|---|---|---|
| raw | - | 100.0% | 3410 / 3410 | **116** / 116 | 0.0 | — (0) |
| presidio | - | 21.5% | 733 / 3410 | **97** / 116 | 102.5 | — (0) |
| regex | balanced | 13.9% | 475 / 3410 | **0** / 116 | 4.3 | 100.0% (2306) |
| regex | strict | 13.9% | 473 / 3410 | **0** / 116 | 2.2 | 100.0% (1912) |
| full | balanced | 0.5% | 16 / 3410 | **0** / 116 | 847.3 | 100.0% (2765) |
| full | strict | 0.3% | 9 / 3410 | **0** / 116 | 844.1 | 100.0% (2376) |

### Detection (micro-averaged)

Typed = span and type must match; ANY = type-agnostic. Overlap match unless stated.

| system | mode | typed P | typed R | typed F1 | ANY P | ANY R | ANY F1 | exact typed F1 | n gold | n pred |
|---|---|---|---|---|---|---|---|---|---|---|
| presidio | - | 0.482 | 0.640 | 0.550 | 0.876 | 0.793 | 0.833 | 0.495 | 3898 | 5172 |
| regex | balanced | 1.000 | 0.709 | 0.829 | 1.000 | 0.709 | 0.829 | 0.829 | 3898 | 2762 |
| regex | strict | 1.000 | 0.709 | 0.829 | 1.000 | 0.709 | 0.829 | 0.829 | 3898 | 2762 |
| full | balanced | 0.953 | 0.890 | 0.921 | 0.997 | 0.921 | 0.958 | 0.879 | 3898 | 3642 |
| full | strict | 0.953 | 0.890 | 0.921 | 0.997 | 0.921 | 0.958 | 0.879 | 3898 | 3642 |

### Recall by type (overlap, typed)

| type | n gold | presidio | regex | full |
|---|---|---|---|---|
| address | 112 | 0.000 | 1.000 | 1.000 |
| card | 72 | 0.819 | 1.000 | 1.000 |
| date | 150 | 0.920 | 1.000 | 1.000 |
| date_of_birth | 194 | 0.000 | 1.000 | 1.000 |
| email | 516 | 0.942 | 1.000 | 1.000 |
| iban | 94 | 1.000 | 1.000 | 1.000 |
| ip | 396 | 1.000 | 1.000 | 1.000 |
| location | 188 | 0.431 | 0.202 | 0.543 |
| nhs_number | 40 | 1.000 | 1.000 | 1.000 |
| ni_number | 75 | 0.000 | 1.000 | 1.000 |
| organisation | 150 | 0.000 | 0.000 | 0.493 |
| person | 1024 | 0.933 | 0.184 | 0.741 |
| phone | 250 | 0.976 | 1.000 | 1.000 |
| postcode | 38 | 0.000 | 1.000 | 1.000 |
| secret | 116 | 0.000 | 1.000 | 1.000 |
| user_id | 75 | 0.000 | 1.000 | 1.000 |
| username | 332 | 0.000 | 1.000 | 1.000 |
| uuid | 76 | 0.000 | 1.000 | 1.000 |

### Leakage by type

| type | n | raw (-) | presidio (-) | regex (balanced) | regex (strict) | full (balanced) | full (strict) |
|---|---|---|---|---|---|---|---|
| address | 112 | 100.0% | 5.4% | 0.0% | 0.0% | 0.0% | 0.0% |
| card | 72 | 100.0% | 6.9% | 0.0% | 0.0% | 0.0% | 0.0% |
| date_of_birth | 194 | 100.0% | 2.6% | 0.0% | 0.0% | 0.0% | 0.0% |
| email | 516 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| iban | 94 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| ip | 396 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| nhs_number | 40 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| ni_number | 75 | 100.0% | 34.7% | 0.0% | 0.0% | 0.0% | 0.0% |
| person | 1024 | 100.0% | 12.4% | 46.4% | 46.2% | 1.6% | 0.9% |
| phone | 250 | 100.0% | 0.4% | 0.0% | 0.0% | 0.0% | 0.0% |
| postcode | 38 | 100.0% | 65.8% | 0.0% | 0.0% | 0.0% | 0.0% |
| secret | 116 | 100.0% | 83.6% | 0.0% | 0.0% | 0.0% | 0.0% |
| user_id | 75 | 100.0% | 98.7% | 0.0% | 0.0% | 0.0% | 0.0% |
| username | 332 | 100.0% | 94.9% | 0.0% | 0.0% | 0.0% | 0.0% |
| uuid | 76 | 100.0% | 68.4% | 0.0% | 0.0% | 0.0% | 0.0% |

### Leakage on hard cases (by item tag)

| tag | n strings | raw (-) | presidio (-) | regex (balanced) | regex (strict) | full (balanced) | full (strict) |
|---|---|---|---|---|---|---|---|
| email_tag | 685 | 100.0% | 28.5% | 14.9% | 14.9% | 0.4% | 0.4% |
| json_freetext | 1211 | 100.0% | 22.6% | 7.8% | 7.6% | 0.7% | 0.3% |
| name_variants | 2459 | 100.0% | 14.5% | 17.3% | 17.2% | 0.7% | 0.4% |
| unknown_key | 445 | 100.0% | 18.0% | 9.2% | 9.2% | 1.3% | 0.9% |
| url_secret | 987 | 100.0% | 37.9% | 14.6% | 14.6% | 0.2% | 0.1% |

### Utility (LLM answers over items with a task)

_Not run (needs `--utility` and an LLM provider in `.env`)._

### Strict vs balanced trade-off

| system | balanced leakage | strict leakage | balanced echo re-hydration | strict echo re-hydration |
|---|---|---|---|---|
| full | 0.5% | 0.3% | 100.0% | 100.0% |
| regex | 13.9% | 13.9% | 100.0% | 100.0% |

## Dataset `data\heldout_handwritten.jsonl` (n = 0 items)

_No items yet: this split is written by hand (see `data/HELDOUT_README.md`)._
