import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scrubber import Session, scrub  # noqa: E402

REGEX_LAYERS = ["L1", "L2", "L3"]


@pytest.fixture
def session() -> Session:
    return Session()


@pytest.fixture
def scrub_regex():
    """Deterministic pipeline (no ML model): L1–L3."""

    def _run(text: str, session: Session, mode: str = "balanced"):
        return scrub(text, session, mode=mode, layers=REGEX_LAYERS)

    return _run
