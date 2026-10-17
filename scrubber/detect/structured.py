"""L2: structured identifiers. Regex candidates confirmed by validators/checksums."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit

from ..models import Segment, Span
from ..policy import Policy, default_policy
from ..segment import normalise_key
from .base import make_span

EMAIL = re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b")
UK_PHONE = re.compile(r"(?<![\w+])(?:\+44\s?\(0\)\s?|\+44\s?|0044\s?|\(?0)(?:\d\)?[\s\-]?){8,10}\d(?![\d])")
POSTCODE = re.compile(r"\b(?:[A-PR-UWYZ][A-HK-Y]?\d[A-Z\d]?|GIR)\s?\d[ABD-HJLNP-UW-Z]{2}\b")
NHS = re.compile(r"(?<![\d\-])\d{3}[ \-]?\d{3}[ \-]?\d{4}(?![\d\-])")
NI = re.compile(
    r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b"
)
CARD = re.compile(r"(?<![\d\-])\d(?:[ \-]?\d){12,18}(?![\d])")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")
IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)")
IPV6_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])")
UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
URL = re.compile(r"\bhttps?://[^\s<>\"'`]+", re.IGNORECASE)

_MONTHS = r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
DATE_PATTERNS = [
    re.compile(r"\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b"),
    re.compile(r"\b(?:0?[1-9]|[12]\d|3[01])[/.\-](?:0?[1-9]|1[0-2])[/.\-](?:\d{4}|\d{2})\b"),
    re.compile(rf"\b(?:0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?\s+{_MONTHS}\.?,?\s+\d{{4}}\b", re.IGNORECASE),
    re.compile(rf"\b{_MONTHS}\.?\s+(?:0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?,?\s+\d{{4}}\b", re.IGNORECASE),
]
_DOB_CONTEXT = re.compile(r"(?i)(?:\bdob\b|d\.o\.b|date\s+of\s+birth|\bborn\b|\bbirth(?:day|date)?\b)[^\n]{0,25}$")


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def nhs_ok(digits: str) -> bool:
    if len(digits) != 10 or len(set(digits)) == 1:
        return False
    total = sum(int(d) * w for d, w in zip(digits[:9], range(10, 1, -1)))
    check = 11 - total % 11
    if check == 11:
        check = 0
    return check != 10 and check == int(digits[9])


def iban_ok(iban: str) -> bool:
    s = iban.replace(" ", "").upper()
    if not 15 <= len(s) <= 34 or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in rearranged)
    return int(num) % 97 == 1


def uk_phone_ok(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    if raw.lstrip().startswith("+44") or raw.lstrip().startswith("0044"):
        digits = digits[2:] if raw.lstrip().startswith("+") else digits[4:]
        if digits.startswith("0"):  # +44 (0)7…
            digits = digits[1:]
        digits = "0" + digits
    return digits.startswith("0") and len(digits) in (10, 11) and digits[1] in "1235789"


# key names that make a URL query value personal: name → type
_URL_PARAM_TYPES = {
    "email": "email", "mail": "email", "name": "person", "first_name": "person", "last_name": "person",
    "full_name": "person", "user": "username", "username": "username", "phone": "phone", "mobile": "phone",
    "postcode": "postcode", "address": "address", "dob": "date_of_birth", "user_id": "user_id",
    "uid": "user_id", "customer_id": "user_id", "customer": "user_id", "account_id": "user_id",
}


class StructuredDetector:
    layer = "L2"

    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy or default_policy()
        self._custom = [(p, re.compile(p.pattern)) for p in self.policy.custom_patterns if p.enabled]

    def detect(self, text: str, segments: list[Segment]) -> list[Span]:
        spans: list[Span] = []

        def add(s: int, e: int, type_: str, reason: str, conf: float = 0.95) -> None:
            spans.append(make_span(text, s, e, type_, self.layer, conf, reason))

        for m in EMAIL.finditer(text):
            add(m.start(), m.end(), "email", "email address pattern")
        for m in UK_PHONE.finditer(text):
            raw = m.group().rstrip()
            if raw.startswith("(") and ")" not in raw:
                raw, start = raw[1:], m.start() + 1
            else:
                start = m.start()
            # the greedy match may swallow a following number: drop trailing groups until valid
            while raw and not uk_phone_ok(raw):
                cut = max(raw.rfind(" "), raw.rfind("-"))
                raw = raw[:cut].rstrip(" -") if cut > 0 else ""
            if raw:
                add(start, start + len(raw), "phone", "UK phone number format")
        for m in POSTCODE.finditer(text):
            add(m.start(), m.end(), "postcode", "UK postcode format", 0.9)
        for m in NHS.finditer(text):
            if nhs_ok(re.sub(r"\D", "", m.group())):
                add(m.start(), m.end(), "nhs_number", "NHS number (mod-11 checksum valid)", 0.97)
        for m in NI.finditer(text):
            add(m.start(), m.end(), "ni_number", "UK National Insurance number format", 0.95)
        for m in CARD.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            # issuer prefixes start 2-6; this also excludes millisecond timestamps (1…)
            if 13 <= len(digits) <= 19 and digits[0] in "23456" and luhn_ok(digits):
                add(m.start(), m.end(), "card", "payment card number (Luhn valid)", 0.97)
        for m in IBAN.finditer(text):
            cand = m.group()
            # trim trailing groups until the checksum passes (greedy match may run into the next word)
            while len(cand.replace(" ", "")) >= 15:
                if iban_ok(cand):
                    add(m.start(), m.start() + len(cand), "iban", "IBAN (mod-97 checksum valid)", 0.98)
                    break
                cand = cand[:-1].rstrip()
        for m in IPV4.finditer(text):
            add(m.start(), m.end(), "ip", "IPv4 address", 0.9)
        for m in IPV6_CANDIDATE.finditer(text):
            cand = m.group()
            if "::" not in cand and cand.count(":") != 7:
                continue
            try:
                ipaddress.IPv6Address(cand)
            except ValueError:
                continue
            groups = [g for g in cand.split(":") if g]
            if len(groups) >= 2 or cand == "::1":
                add(m.start(), m.end(), "ip", "IPv6 address", 0.9)
        for m in UUID.finditer(text):
            add(m.start(), m.end(), "uuid", "UUID", 0.95)
        for rx in DATE_PATTERNS:
            for m in rx.finditer(text):
                before = text[max(0, m.start() - 40) : m.start()]
                if _DOB_CONTEXT.search(before):
                    add(m.start(), m.end(), "date_of_birth", "date preceded by birth context", 0.9)
                else:
                    add(m.start(), m.end(), "date", "date pattern", 0.85)
        for m in URL.finditer(text):
            self._url_params(text, m.start(), m.group(), add)
        for pat, rx in self._custom:
            for m in rx.finditer(text):
                add(m.start(), m.end(), pat.type, f"custom pattern '{pat.name}'", 0.9)
        return spans

    @staticmethod
    def _url_params(text: str, base: int, url: str, add) -> None:
        query = urlsplit(url).query
        if not query:
            return
        qstart = url.find("?") + 1
        pos = qstart
        for part in query.split("&"):
            key, _, value = part.partition("=")
            vstart = base + pos + len(key) + 1
            pos += len(part) + 1
            if not value:
                continue
            type_ = _URL_PARAM_TYPES.get(normalise_key(key))
            if type_ and type_ != "email":  # emails are caught by the email pattern itself
                decoded = dict(parse_qsl(part)).get(key, value)
                if decoded:
                    add(vstart, vstart + len(value), type_, f"personal URL query parameter '{key}'", 0.85)
