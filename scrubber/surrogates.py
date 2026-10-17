"""Format-preserving surrogate builders and generalisers (pure functions, no state)."""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta

from .detect.structured import POSTCODE

# ---- normalisation (vault keys) ---------------------------------------------------------------


def norm_email(email: str) -> str:
    return email.strip().lower()


def split_email(email: str) -> tuple[str, str | None, str]:
    """`Jane.Doe+shop@Gmail.com` → (`jane.doe`, `shop`, `gmail.com`)."""
    local, _, domain = email.strip().rpartition("@")
    base, plus, tag = local.partition("+")
    return base.lower(), (tag if plus else None), domain.lower()


def norm_phone(phone: str) -> str:
    """Digits only, with +44 / 0044 / +44 (0) folded to a leading 0."""
    raw = phone.strip()
    digits = re.sub(r"\D", "", raw)
    if raw.startswith("+44") or raw.startswith("0044"):
        digits = digits[2:] if raw.startswith("+") else digits[4:]
        digits = digits[1:] if digits.startswith("0") else digits
        digits = "0" + digits
    return digits


def norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip()).lower()


# ---- builders ----------------------------------------------------------------------------------


def email_surrogate(prefix: str, n: int, tag: str | None) -> str:
    return f"{prefix}_{n}{'+' + tag if tag else ''}@example.com"


def phone_surrogate(original: str, n: int) -> str:
    """UK drama-range mobile 07700 900NNN, keeping the original's spacing/punctuation style."""
    national = f"07700900{n % 1000:03d}"
    raw = original.strip()
    intl = raw.startswith("+44") or raw.startswith("0044")
    if intl:
        lead = "+44" if raw.startswith("+44") else "0044"
        rest = raw[len(lead) :]
        if re.match(r"\s?\(0\)", rest):  # +44 (0)7…: keep it simple
            return f"{lead} 7700 900{n % 1000:03d}"
        target = national[1:]
        template = rest
    else:
        lead, target, template = "", national, raw
        if not norm_phone(raw).startswith("07"):  # landline: don't force a mobile into its layout
            return f"07700 900{n % 1000:03d}"
    if len(re.findall(r"\d", template)) != len(target):
        return f"{lead} 7700 900{n % 1000:03d}" if intl else f"07700 900{n % 1000:03d}"
    it = iter(target)
    return lead + "".join(next(it) if ch.isdigit() else ch for ch in template)


def uuid_surrogate(original: str, n: int) -> str:
    s = f"00000000-0000-4000-8000-{n:012x}"
    return s.upper() if original.isupper() else s


def id_surrogate(original: str, n: int) -> str:
    """Keep the shape of an identifier: `CUST-88231` → `CUST-00001`, `48213` → `90001`."""
    m = re.fullmatch(r"([A-Za-z]+[\-_]?)(\d+)", original)
    if m:
        return m.group(1) + str(n).zfill(len(m.group(2)))
    if original.isdigit():
        width = max(len(original), len(str(n)) + 1)
        return "9" + str(n).zfill(width - 1)
    return f"ID_{n}"


def postcode_district(text: str) -> str | None:
    """Outward code of the (last) postcode in `text`: `SO17 1BJ` → `SO17`."""
    hits = list(POSTCODE.finditer(text))
    if not hits:
        return None
    pc = re.sub(r"\s+", "", hits[-1].group())
    return pc[:-3]


def postcode_area(text: str) -> str | None:
    d = postcode_district(text)
    return re.match(r"[A-Z]+", d).group() if d else None


# ---- dates -------------------------------------------------------------------------------------

_DATE_FORMATS = [
    "%Y-%m-%d", "%d/%m/%Y", "%d/%m/%y", "%d-%m-%Y", "%d-%m-%y", "%d.%m.%Y", "%d.%m.%y",
    "%d %B %Y", "%d %b %Y", "%d %B, %Y", "%d %b, %Y", "%B %d, %Y", "%b %d, %Y", "%B %d %Y", "%b %d %Y",
]
_ORDINAL = re.compile(r"(?<=\d)(st|nd|rd|th)\b", re.IGNORECASE)


def parse_date(s: str) -> tuple[date, str] | None:
    """Parse a date string; returns (date, format) so it can be written back the same way."""
    clean = _ORDINAL.sub("", s.strip()).replace("Sept ", "Sep ")
    clean = re.sub(r"(?<=[A-Za-z])\.", "", clean)
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(clean, fmt).date(), fmt
        except ValueError:
            continue
    return None


def _ordinal(day: int) -> str:
    if 10 <= day % 100 <= 20:
        return "th"
    return {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")


def format_like(d: date, fmt: str, original: str) -> str:
    """Format `d` with `fmt`, copying the original's zero-padding and ordinal suffix."""
    out = d.strftime(fmt)
    orig = original.strip()
    if fmt == "%Y-%m-%d":
        return out
    if fmt[:2] == "%d" and fmt[2] in "/-.":
        sep = fmt[2]
        o_parts, n_parts = orig.split(sep), out.split(sep)
        if len(o_parts) == 3:
            for i in (0, 1):
                if len(o_parts[i]) == 1:
                    n_parts[i] = n_parts[i].lstrip("0") or "0"
        return sep.join(n_parts)
    day = re.search(r"\b(\d{1,2})(?:st|nd|rd|th)?\b", orig, re.IGNORECASE)
    if day and not day.group(1).startswith("0"):
        out = re.sub(r"\b0(\d)\b", r"\1", out, count=1)
    if _ORDINAL.search(orig):
        out = re.sub(r"\b(\d{1,2})\b", lambda m: m.group(1) + _ordinal(int(m.group(1))), out, count=1)
    return out


def shift_date(original: str, days: int) -> str | None:
    parsed = parse_date(original)
    if not parsed:
        return None
    d, fmt = parsed
    return format_like(d + timedelta(days=days), fmt, original)


def age_band(original: str, width: int, today: date | None = None) -> str | None:
    parsed = parse_date(original)
    if parsed:
        dob = parsed[0]
        today = today or date.today()
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    else:
        m = re.search(r"\b(19|20)\d{2}\b", original)
        if not m:
            return None
        year = int(m.group())
        age = (today or date.today()).year - year
    lo = (age // width) * width
    return f"[AGE {lo}-{lo + width - 1}]"
