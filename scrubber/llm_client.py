"""Optional LLM adapter. Sends ONLY already-scrubbed text, and logs the exact payload sent.

Every call appends one JSON line to `logs/payloads/<date>.jsonl` (gitignored). The leakage
audit reads this file, so what is measured is exactly what left the machine.

Providers (env `LLM_PROVIDER`, keys from `.env`):
  anthropic  Claude via the Anthropic SDK (default model claude-opus-5-5)
  openai     any OpenAI-compatible endpoint (OPENAI_BASE_URL optional)
  ollama     a local Ollama server
  dryrun     log the payload, send nothing, return ""
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
PAYLOAD_DIR = ROOT / "logs" / "payloads"
_FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}
DEFAULT_MODELS = {"anthropic": "claude-opus-5-5", "openai": "gpt-4o-mini", "ollama": "qwen3:8b", "dryrun": "none"}


def strip_think(text: str) -> str:
    """Drop <think>…</think> blocks some local reasoning models emit."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


class LLMClient:
    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
        log_path: Path | None = None,
        max_tokens: int = 4096,
    ) -> None:
        load_dotenv(ROOT / ".env")
        self.provider = (provider or os.environ.get("LLM_PROVIDER") or "dryrun").lower()
        if self.provider not in DEFAULT_MODELS:
            raise ValueError(f"unknown LLM provider {self.provider!r}")
        self.model = model or os.environ.get("LLM_MODEL") or DEFAULT_MODELS[self.provider]
        self.max_tokens = max_tokens
        PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)
        self.log_path = log_path or PAYLOAD_DIR / f"{datetime.now(timezone.utc):%Y-%m-%d}.jsonl"
        self._client = None

    # ---- logging -----------------------------------------------------------------------------
    def log_payload(self, prompt: str, meta: dict | None = None) -> None:
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "provider": self.provider,
            "model": self.model,
            "payload": prompt,
            "meta": meta or {},
        }
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # ---- sending -----------------------------------------------------------------------------
    def send(self, prompt: str, meta: dict | None = None) -> str:
        """Send `prompt` (already scrubbed) and return the response text."""
        self.log_payload(prompt, meta)
        if self.provider == "dryrun":
            return ""
        return getattr(self, f"_send_{self.provider}")(prompt)

    def _send_anthropic(self, prompt: str) -> str:
        import anthropic

        if self._client is None:
            self._client = anthropic.Anthropic()
        # Server-side refusal fallbacks (models that support them): on a policy decline the API
        # re-runs the request on a recommended fallback model inside the same call.
        extra = {}
        if self.model in _FALLBACK_MODELS:
            extra = {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"}
        response = self._client.beta.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            messages=[{"role": "user", "content": prompt}],
            **extra,
        )
        if response.stop_reason == "refusal":
            return ""
        return "".join(b.text for b in response.content if b.type == "text")

    def _send_openai(self, prompt: str) -> str:
        from openai import OpenAI

        if self._client is None:
            self._client = OpenAI(base_url=os.environ.get("OPENAI_BASE_URL") or None)
        r = self._client.chat.completions.create(
            model=self.model, messages=[{"role": "user", "content": prompt}], max_tokens=self.max_tokens
        )
        return r.choices[0].message.content or ""

    def _send_ollama(self, prompt: str) -> str:
        import httpx

        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        r = httpx.post(f"{host}/api/generate",
                       json={"model": self.model, "prompt": prompt, "stream": False, "think": False,
                             "options": {"temperature": 0}},
                       timeout=300)
        r.raise_for_status()
        return strip_think(r.json().get("response", ""))

    def send_with_retry(self, prompt: str, meta: dict | None = None, attempts: int = 3) -> str:
        for i in range(attempts):
            try:
                return self.send(prompt, meta if i == 0 else {**(meta or {}), "retry": i})
            except Exception:  # noqa: BLE001 - provider SDKs raise different types; surface the last one
                if i == attempts - 1:
                    raise
                time.sleep(2 ** i)
        return ""
