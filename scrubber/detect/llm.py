"""L5 (optional): quasi-identifiers via a LOCAL LLM served by Ollama.

Only ever talks to the configured Ollama host (default localhost). If Ollama is not running
the detector returns no spans and records a warning instead of failing the pipeline.
"""

from __future__ import annotations

import json
import os
from urllib.parse import urlsplit

import httpx

from ..models import Segment, Span
from ..policy import Policy, default_policy
from .base import make_span

PROMPT = """You find QUASI-IDENTIFIERS in text: details that do not name a person directly but could
single them out when combined with other knowledge. Examples: a unique role ("the only female
professor in the department"), a rare event ("the man who won the lottery in Leeds last May"),
specific family details ("her twin brother who is a firefighter"), rare medical conditions, exact
ages with locations. Do NOT report names, emails, phone numbers or other direct identifiers.

Return JSON only: {{"spans": [{{"text": "<exact substring copied from the text>", "reason": "<short>"}}]}}
Return {{"spans": []}} if there are none.

TEXT:
<<<
{text}
>>>"""

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class LlmQuasiDetector:
    layer = "L5"

    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy or default_policy()
        cfg = self.policy.llm_detector
        self.model = cfg.model
        self.host = os.environ.get("OLLAMA_HOST", cfg.host).rstrip("/")
        self.timeout = cfg.timeout_s
        self.warnings: list[str] = []

    def detect(self, text: str, segments: list[Segment]) -> list[Span]:
        self.warnings = []
        host = urlsplit(self.host if "://" in self.host else f"http://{self.host}").hostname or ""
        if host not in _LOCAL_HOSTS and not os.environ.get("SCRUBBER_ALLOW_REMOTE_OLLAMA"):
            self.warnings.append(f"L5 skipped: Ollama host {host!r} is not local (raw text never leaves the machine)")
            return []
        try:
            r = httpx.post(
                f"{self.host}/api/generate",
                json={"model": self.model, "prompt": PROMPT.format(text=text), "format": "json", "stream": False,
                      "options": {"temperature": 0}},
                timeout=self.timeout,
            )
            r.raise_for_status()
            data = json.loads(r.json().get("response", "{}"))
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
            self.warnings.append(f"L5 skipped: local LLM unavailable ({type(exc).__name__})")
            return []
        spans: list[Span] = []
        for item in data.get("spans", []) if isinstance(data, dict) else []:
            frag = str(item.get("text", "")).strip()
            if len(frag) < 4:
                continue
            pos = text.find(frag)
            while pos >= 0:
                spans.append(make_span(text, pos, pos + len(frag), "quasi_identifier", self.layer, 0.6,
                                       f"local LLM: {str(item.get('reason', 'quasi-identifier'))[:120]}"))
                pos = text.find(frag, pos + len(frag))
        return spans
