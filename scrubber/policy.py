"""Stage 4: per-type actions, loaded from `config/policy.yaml`."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from .models import Action

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "policy.yaml"
MODES = ("balanced", "strict")

# Types whose values are removed outright: never pseudonymised, never stored.
REMOVED_PLACEHOLDER = {
    "secret": "[SECRET_REMOVED]",
    "card": "[CARD_REMOVED]",
    "iban": "[IBAN_REMOVED]",
    "nhs_number": "[NHS_NUMBER_REMOVED]",
    "ni_number": "[NI_NUMBER_REMOVED]",
    "ip": "[IP_REMOVED]",
}


class CustomPattern(BaseModel):
    name: str
    type: str
    pattern: str
    enabled: bool = True


class SecretsConfig(BaseModel):
    entropy_threshold: float = 4.0
    entropy_min_length: int = 20
    secret_keys: list[str] = Field(default_factory=list)


class NerConfig(BaseModel):
    model: str = "urchade/gliner_multi_pii-v1"
    threshold: float = 0.5
    freetext_threshold: float = 0.35
    max_chars: int = 1200
    labels: dict[str, str] = Field(default_factory=dict)


class LlmDetectorConfig(BaseModel):
    model: str = "llama3.1:8b"
    host: str = "http://localhost:11434"
    timeout_s: float = 60


class Policy(BaseModel):
    version: int = 1
    detectors: dict[str, list[str]] = Field(default_factory=lambda: {"enabled": ["L1", "L2", "L3", "L4"]})
    modes: dict[str, dict[str, Action]]
    default_action: Action = Action.PSEUDONYMISE
    address_keep_district: dict[str, bool] = Field(default_factory=lambda: {"balanced": True, "strict": False})
    dob_band_years: dict[str, int] = Field(default_factory=lambda: {"balanced": 5, "strict": 10})
    date_shift_days: dict[str, int] = Field(default_factory=lambda: {"min": 30, "max": 365})
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    sensitive_keys: dict[str, str] = Field(default_factory=dict)
    freetext_keys: list[str] = Field(default_factory=list)
    non_sensitive_keys: list[str] = Field(default_factory=list)
    person_name_qualifiers: list[str] = Field(default_factory=list)
    custom_patterns: list[CustomPattern] = Field(default_factory=list)
    ner: NerConfig = Field(default_factory=NerConfig)
    llm_detector: LlmDetectorConfig = Field(default_factory=LlmDetectorConfig)

    def action(self, type_: str, mode: str) -> Action:
        if mode not in self.modes:
            raise ValueError(f"unknown mode {mode!r}; expected one of {sorted(self.modes)}")
        return self.modes[mode].get(type_, self.default_action)

    @property
    def enabled_layers(self) -> list[str]:
        return list(self.detectors.get("enabled", []))


def load_policy(path: str | Path | None = None) -> Policy:
    with open(path or DEFAULT_POLICY_PATH, encoding="utf-8") as f:
        return Policy.model_validate(yaml.safe_load(f))


@lru_cache(maxsize=1)
def default_policy() -> Policy:
    return load_policy()
