"""Presidio baseline: AnalyzerEngine + AnonymizerEngine with default settings (spaCy en_core_web_lg)."""

from __future__ import annotations

from functools import lru_cache

# Presidio entity → our type names (for per-type span metrics). Unmapped types keep a lowercase name.
TYPE_MAP = {
    "PERSON": "person",
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "LOCATION": "location",
    "DATE_TIME": "date",
    "IP_ADDRESS": "ip",
    "CREDIT_CARD": "card",
    "IBAN_CODE": "iban",
    "UK_NHS": "nhs_number",
    "UK_NINO": "ni_number",
    "NRP": "nrp",
    "URL": "url",
    "ORGANIZATION": "organisation",
    "CRYPTO": "secret",
}


@lru_cache(maxsize=1)
def _engines():
    import logging

    logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine

    return AnalyzerEngine(), AnonymizerEngine()


class PresidioBaseline:
    name = "presidio"

    def scrub(self, text: str) -> tuple[str, list[dict]]:
        analyzer, anonymizer = _engines()
        results = analyzer.analyze(text=text, language="en")
        anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
        spans = [
            {"start": r.start, "end": r.end, "type": TYPE_MAP.get(r.entity_type, r.entity_type.lower()), "score": r.score}
            for r in results
        ]
        return anonymized.text, spans
