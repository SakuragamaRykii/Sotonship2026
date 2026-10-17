"""L1: secrets (API keys, tokens, passwords). Regex + Shannon entropy.

Secret spans are always REMOVEd by policy. Reasons never include the value.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..models import Segment, Span
from ..policy import Policy, default_policy
from .base import make_span

_KNOWN_KEYS: list[tuple[str, re.Pattern[str]]] = [
    ("API key (sk-…)", re.compile(r"\bsk-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_\-]{20,}")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("Stripe key", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")),
    (
        "private key block",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    ),
]

_AUTH_HEADER = re.compile(
    r"""(?i)\b(?:proxy-)?authorization\b["']?\s*[:=]\s*["']?(?:(?:bearer|basic|token|digest|apikey)\s+)?(?P<v>[^\s"',;]{6,})"""
)
_BEARER = re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9\-._~+/]{8,}=*)")
# scheme://user:PASS@host — password may itself contain '@', so take up to the last '@' in the authority.
_URL_CREDS = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://(?P<user>[^\s:/@?#]+):(?P<pw>[^\s/?#]+)@(?=[^\s@/?#]+)")
_PROSE_PASSWORD = re.compile(r"(?i)\b(?:password|passcode|passwd|pin)\s+(?:is|was|=|:)\s+[\"']?(?P<v>[^\s\"',;]{4,})")
_TOKEN_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/_\-]{20,}={0,2}(?![A-Za-z0-9+/=_\-])")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_PLACEHOLDER_VALUES = {"", "null", "none", "nil", "true", "false", "redacted", "<redacted>", "[redacted]", "***", "****",
                       "xxx", "xxxx", "changeme", "example", "bearer", "basic", "n/a", "undefined"}
_SERVICE_ACCOUNTS = {"admin", "root", "postgres", "user", "app", "service", "test", "guest", "sa", "ubuntu",
                     "ec2-user", "git", "default", "readonly", "api", "oauth2", "x-access-token", "mysql", "redis"}
_NON_SECRET_KEY_SUFFIXES = ("type", "expiry", "expires", "expires_in", "expires_at", "length", "count", "url", "uri",
                            "endpoint", "name", "policy", "hint", "reset", "required", "enabled", "set", "changed",
                            "updated_at", "created_at", "id_type")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _looks_like_path(tok: str) -> bool:
    parts = [p for p in re.split(r"[/_\-]", tok) if p]
    words = [p for p in parts if p.isalpha() and len(p) >= 3]
    return "/" in tok and len(words) >= 2


def _is_secret_key(key: str, secret_keys: list[str]) -> bool:
    if key.endswith(_NON_SECRET_KEY_SUFFIXES) and key not in secret_keys:
        return False
    padded = f"_{key}_"
    return any(f"_{sk}_" in padded for sk in secret_keys)


class SecretsDetector:
    layer = "L1"

    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy or default_policy()

    def detect(self, text: str, segments: list[Segment]) -> list[Span]:
        cfg = self.policy.secrets
        spans: list[Span] = []

        def add(s: int, e: int, reason: str, conf: float = 0.99, type_: str = "secret") -> None:
            if e > s:
                spans.append(make_span(text, s, e, type_, self.layer, conf, reason))

        for reason, rx in _KNOWN_KEYS:
            for m in rx.finditer(text):
                add(m.start(), m.end(), f"matches {reason} pattern")
        for m in _AUTH_HEADER.finditer(text):
            if m.group("v").lower() not in _PLACEHOLDER_VALUES:
                add(m.start("v"), m.end("v"), "Authorization header credential")
        for m in _BEARER.finditer(text):
            add(m.start("v"), m.end("v"), "Bearer token")
        for m in _URL_CREDS.finditer(text):
            add(m.start("pw"), m.end("pw"), "password in URL / connection string")
            if m.group("user").lower() not in _SERVICE_ACCOUNTS:
                add(m.start("user"), m.end("user"), "username in URL / connection string", 0.7, "username")
        for m in _PROSE_PASSWORD.finditer(text):
            add(m.start("v"), m.end("v"), "value stated as a password", 0.9)

        for seg in segments:
            if seg.key and _is_secret_key(seg.key, cfg.secret_keys):
                value = seg.slice(text)
                if value.strip().lower() not in _PLACEHOLDER_VALUES and not set(value) <= {"*", "x", "X", "#"}:
                    add(seg.start, seg.end, f"value of secret-like key '{seg.key}'", 0.95)

        for m in _TOKEN_CANDIDATE.finditer(text):
            tok = m.group()
            if len(tok) < cfg.entropy_min_length or _UUID.match(tok) or _looks_like_path(tok):
                continue
            has_digit = any(c.isdigit() for c in tok)
            has_upper = any(c.isupper() for c in tok)
            has_lower = any(c.islower() for c in tok)
            if not (has_digit and (has_upper or has_lower)):
                continue
            if not ((has_upper and has_lower) or len(tok) >= 32):
                continue
            ent = shannon_entropy(tok)
            if ent > cfg.entropy_threshold:
                add(m.start(), m.end(), f"high-entropy token (H={ent:.2f} bits/char, len={len(tok)})", 0.8)
        return spans
