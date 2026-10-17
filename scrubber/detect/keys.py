"""L3: key-aware detection. A value is sensitive because of the key it sits under."""

from __future__ import annotations

import ipaddress
import re

from ..models import Segment, Span
from ..policy import Policy, default_policy
from ..segment import normalise_key
from .base import make_span

_EMPTY = {"", "null", "none", "nil", "n/a", "na", "true", "false", "undefined", "-", "unknown", "redacted"}
_NAME_LIKE = re.compile(r"^[^\W\d_]+(?:['\-.][^\W\d_]+)*\.?(?:\s+[^\W\d_]+(?:['\-.][^\W\d_]+)*\.?){0,4}$")
_HANDLE = re.compile(r"^[A-Za-z][\w.\-]{2,}$")


def _infer_user_type(value: str) -> str:
    """For ambiguous keys (user / customer / contact): decide from the value's shape."""
    if "@" in value and "." in value.split("@")[-1]:
        return "email"
    if _NAME_LIKE.match(value) and (" " in value or value[:1].isupper()):
        return "person"
    if _HANDLE.match(value) and not re.search(r"\d{3,}", value):
        return "username"
    return "user_id"


class KeyDetector:
    layer = "L3"

    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy or default_policy()
        self._keys = {normalise_key(k): v for k, v in self.policy.sensitive_keys.items()}
        self._non = {normalise_key(k) for k in self.policy.non_sensitive_keys}
        self._free = {normalise_key(k) for k in self.policy.freetext_keys}
        self._name_qualifiers = {normalise_key(k) for k in self.policy.person_name_qualifiers}

    def key_type(self, key: str | None) -> str | None:
        if not key:
            return None
        key = normalise_key(key)
        if key in self._non or key in self._free:
            return None
        if key in self._keys:
            return self._keys[key]
        padded = f"_{key}_"
        toks = set(key.split("_"))
        for k, t in self._keys.items():  # config order decides between e.g. contact_phone → phone
            if f"_{k}_" not in padded:
                continue
            if t == "user" and not padded.endswith(f"_{k}_"):
                continue  # user_type, customer_segment, contact_method: not identifiers
            if k == "name" and not toks & self._name_qualifiers:
                continue  # product_name, item_name: leave to L4
            return t
        return None

    def is_freetext(self, key: str | None) -> bool:
        if not key:
            return False
        toks = set(normalise_key(key).split("_"))
        return bool(toks & self._free) and self.key_type(key) is None

    def detect(self, text: str, segments: list[Segment]) -> list[Span]:
        spans: list[Span] = []
        for seg in segments:
            if seg.kind == "text" or not seg.key:
                continue
            type_ = self.key_type(seg.key)
            if type_ is None:
                continue
            raw = seg.slice(text)
            value = raw.strip().strip("\"'")
            if value.lower() in _EMPTY or len(value) < 2:
                continue
            start = seg.start + raw.index(value)
            end = start + len(value)
            if type_ == "user":
                type_ = _infer_user_type(value)
            if not self._plausible(type_, value):
                continue
            spans.append(make_span(text, start, end, type_, self.layer, 0.85, f"value of key '{seg.key}'"))
        return spans

    @staticmethod
    def _plausible(type_: str, value: str) -> bool:
        if type_ == "email":
            return "@" in value
        if type_ == "phone":
            return len(re.sub(r"\D", "", value)) >= 7
        if type_ in ("date_of_birth",):
            return bool(re.search(r"\d", value))
        if type_ == "person":
            return bool(re.search(r"[^\W\d_]", value)) and len(value) <= 80
        if type_ == "ip":
            try:
                ipaddress.ip_address(value)
                return True
            except ValueError:
                return False
        if type_ == "postcode":
            return bool(re.search(r"\d", value)) and len(value) <= 9
        return True
