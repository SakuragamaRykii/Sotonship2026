# Evaluation results

Run `20261017-164120`. All data is synthetic (Faker `en_GB` templates; see `eval/generate.py`).
Leakage = fraction of ground-truth sensitive strings found (case-insensitive substring) in the payload
actually logged to `logs/payloads/`. Dates, organisations and locations are kept by the balanced policy
and excluded from leakage (they are still scored in the span tables).

## Dataset `data\quasi.jsonl` (n = 40 items)

### Leakage, secrets, latency

Sensitive strings per system: n = 465; secrets: n = 8.

| system | mode | leakage rate | leaked / n | secret leaks | latency (ms / 1k chars) | echo re-hydration (n) |
|---|---|---|---|---|---|---|
| presidio | - | 9.5% | 44 / 465 | **6** / 8 | 882.2 | — (0) |
| full | balanced | 8.4% | 39 / 465 | **0** / 8 | 1149.6 | 100.0% (318) |
| full | strict | 3.7% | 17 / 465 | **0** / 8 | 1146.9 | 100.0% (299) |
| full_l5 | balanced | 8.4% | 39 / 465 | **0** / 8 | 47928.9 | 100.0% (318) |
| full_l5 | strict | 0.2% | 1 / 465 | **0** / 8 | 47924.4 | 100.0% (299) |

### Detection (micro-averaged)

Typed = span and type must match; ANY = type-agnostic. Overlap match unless stated.

| system | mode | typed P | typed R | typed F1 | ANY P | ANY R | ANY F1 | exact typed F1 | n gold | n pred |
|---|---|---|---|---|---|---|---|---|---|---|
| presidio | - | 0.504 | 0.618 | 0.555 | 1.000 | 0.875 | 0.933 | 0.510 | 545 | 671 |
| full | balanced | 0.844 | 0.793 | 0.817 | 0.992 | 0.901 | 0.944 | 0.763 | 545 | 512 |
| full | strict | 0.844 | 0.793 | 0.817 | 0.992 | 0.901 | 0.944 | 0.763 | 545 | 512 |
| full_l5 | balanced | 0.868 | 0.862 | 0.865 | 0.987 | 0.947 | 0.967 | 0.793 | 545 | 545 |
| full_l5 | strict | 0.868 | 0.862 | 0.865 | 0.987 | 0.947 | 0.967 | 0.793 | 545 | 545 |

### Recall by type (overlap, typed)

| type | n gold | presidio | full | full_l5 |
|---|---|---|---|---|
| address | 20 | 0.000 | 1.000 | 1.000 |
| card | 7 | 0.714 | 1.000 | 1.000 |
| date | 20 | 0.850 | 1.000 | 1.000 |
| date_of_birth | 40 | 0.000 | 1.000 | 1.000 |
| email | 60 | 1.000 | 1.000 | 1.000 |
| iban | 20 | 1.000 | 1.000 | 1.000 |
| ip | 20 | 1.000 | 1.000 | 1.000 |
| location | 20 | 0.550 | 0.000 | 0.000 |
| nhs_number | 10 | 1.000 | 1.000 | 1.000 |
| ni_number | 20 | 0.000 | 1.000 | 1.000 |
| organisation | 40 | 0.000 | 0.425 | 0.425 |
| person | 160 | 0.969 | 0.812 | 0.812 |
| phone | 40 | 0.975 | 1.000 | 1.000 |
| quasi_identifier | 40 | 0.000 | 0.000 | 0.950 |
| secret | 8 | 0.000 | 1.000 | 1.000 |
| username | 8 | 0.000 | 1.000 | 1.000 |
| uuid | 12 | 0.000 | 1.000 | 1.000 |

### Leakage by type

| type | n | presidio (-) | full (balanced) | full (strict) | full_l5 (balanced) | full_l5 (strict) |
|---|---|---|---|---|---|---|
| address | 20 | 10.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| card | 7 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| date_of_birth | 40 | 5.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| email | 60 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| iban | 20 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| ip | 20 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| nhs_number | 10 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| ni_number | 20 | 20.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| person | 160 | 6.9% | 1.2% | 0.6% | 1.2% | 0.6% |
| phone | 40 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| quasi_identifier | 40 | 17.5% | 92.5% | 40.0% | 92.5% | 0.0% |
| secret | 8 | 75.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| username | 8 | 87.5% | 0.0% | 0.0% | 0.0% | 0.0% |
| uuid | 12 | 41.7% | 0.0% | 0.0% | 0.0% | 0.0% |

### Leakage on hard cases (by item tag)

| tag | n strings | presidio (-) | full (balanced) | full (strict) | full_l5 (balanced) | full_l5 (strict) |
|---|---|---|---|---|---|---|
| email_tag | 50 | 14.0% | 10.0% | 6.0% | 10.0% | 0.0% |
| name_variants | 465 | 9.5% | 8.4% | 3.7% | 8.4% | 0.2% |
| quasi | 465 | 9.5% | 8.4% | 3.7% | 8.4% | 0.2% |
| url_secret | 94 | 23.4% | 8.5% | 6.4% | 8.5% | 0.0% |

### Utility (LLM answers over items with a task)

_Not run (needs `--utility` and an LLM provider in `.env`)._

### Strict vs balanced trade-off

| system | balanced leakage | strict leakage | balanced echo re-hydration | strict echo re-hydration |
|---|---|---|---|---|
| full | 8.4% | 3.7% | 100.0% | 100.0% |
| full_l5 | 8.4% | 0.2% | 100.0% | 100.0% |
