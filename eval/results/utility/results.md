# Evaluation results

Run `20261017-161419`. All data is synthetic (Faker `en_GB` templates; see `eval/generate.py`).
Leakage = fraction of ground-truth sensitive strings found (case-insensitive substring) in the payload
actually logged to `logs/payloads/`. Dates, organisations and locations are kept by the balanced policy
and excluded from leakage (they are still scored in the span tables).

## Dataset `data\test.jsonl` (n = 90 items)

### Leakage, secrets, latency

Sensitive strings per system: n = 1032; secrets: n = 35.

| system | mode | leakage rate | leaked / n | secret leaks | latency (ms / 1k chars) | echo re-hydration (n) |
|---|---|---|---|---|---|---|
| raw | - | 100.0% | 1032 / 1032 | **35** / 35 | 0.0 | — (0) |
| presidio | - | 20.9% | 216 / 1032 | **32** / 35 | 591.5 | — (0) |
| full | balanced | 0.2% | 2 / 1032 | **0** / 35 | 1720.2 | 100.0% (839) |

### Detection (micro-averaged)

Typed = span and type must match; ANY = type-agnostic. Overlap match unless stated.

| system | mode | typed P | typed R | typed F1 | ANY P | ANY R | ANY F1 | exact typed F1 | n gold | n pred |
|---|---|---|---|---|---|---|---|---|---|---|
| presidio | - | 0.479 | 0.639 | 0.548 | 0.876 | 0.796 | 0.834 | 0.497 | 1179 | 1573 |
| full | balanced | 0.947 | 0.890 | 0.917 | 0.996 | 0.923 | 0.958 | 0.876 | 1179 | 1108 |

### Recall by type (overlap, typed)

| type | n gold | presidio | full |
|---|---|---|---|
| address | 32 | 0.000 | 1.000 |
| card | 19 | 0.789 | 1.000 |
| date | 45 | 0.867 | 1.000 |
| date_of_birth | 59 | 0.000 | 1.000 |
| email | 154 | 0.948 | 1.000 |
| iban | 32 | 1.000 | 1.000 |
| ip | 123 | 1.000 | 1.000 |
| location | 58 | 0.379 | 0.552 |
| nhs_number | 11 | 1.000 | 1.000 |
| ni_number | 22 | 0.000 | 1.000 |
| organisation | 44 | 0.000 | 0.455 |
| person | 309 | 0.945 | 0.741 |
| phone | 77 | 0.948 | 1.000 |
| postcode | 13 | 0.000 | 1.000 |
| secret | 35 | 0.000 | 1.000 |
| user_id | 23 | 0.000 | 1.000 |
| username | 100 | 0.000 | 1.000 |
| uuid | 23 | 0.000 | 1.000 |

### Leakage by type

| type | n | raw (-) | presidio (-) | full (balanced) |
|---|---|---|---|---|
| address | 32 | 100.0% | 3.1% | 0.0% |
| card | 19 | 100.0% | 10.5% | 0.0% |
| date_of_birth | 59 | 100.0% | 3.4% | 0.0% |
| email | 154 | 100.0% | 0.0% | 0.0% |
| iban | 32 | 100.0% | 0.0% | 0.0% |
| ip | 123 | 100.0% | 0.0% | 0.0% |
| nhs_number | 11 | 100.0% | 0.0% | 0.0% |
| ni_number | 22 | 100.0% | 31.8% | 0.0% |
| person | 309 | 100.0% | 11.3% | 0.6% |
| phone | 77 | 100.0% | 0.0% | 0.0% |
| postcode | 13 | 100.0% | 76.9% | 0.0% |
| secret | 35 | 100.0% | 91.4% | 0.0% |
| user_id | 23 | 100.0% | 100.0% | 0.0% |
| username | 100 | 100.0% | 90.0% | 0.0% |
| uuid | 23 | 100.0% | 60.9% | 0.0% |

### Leakage on hard cases (by item tag)

| tag | n strings | raw (-) | presidio (-) | full (balanced) |
|---|---|---|---|---|
| email_tag | 244 | 100.0% | 29.5% | 0.0% |
| json_freetext | 407 | 100.0% | 21.9% | 0.0% |
| name_variants | 742 | 100.0% | 14.7% | 0.3% |
| unknown_key | 138 | 100.0% | 15.9% | 0.0% |
| url_secret | 280 | 100.0% | 36.4% | 0.0% |

### Utility (LLM answers over items with a task)

Provider: `ollama`. Our systems' answers are re-hydrated before scoring.

| system | mode | answer accuracy | n tasks | re-hydration accuracy | n surrogates |
|---|---|---|---|---|---|
| raw | - | 98.3% | 58 | — | 0 |
| presidio | - | 15.5% | 58 | — | 0 |
| full | balanced | 86.2% | 58 | 100.0% | 40 |
