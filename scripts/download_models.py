"""Pre-download the local models so the first scrub is not slow (and works offline afterwards).

- GLiNER PII checkpoint (L4), from the Hugging Face hub, cached under ~/.cache/huggingface.
- spaCy en_core_web_lg (Presidio baseline) is installed from requirements.lock.txt.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scrubber.detect.ner import load_model  # noqa: E402
from scrubber.policy import default_policy  # noqa: E402

name = default_policy().ner.model
print(f"Fetching GLiNER model {name} ...")
load_model(name)
print("GLiNER ready.")
try:
    import spacy

    spacy.load("en_core_web_lg")
    print("spaCy en_core_web_lg ready.")
except OSError:
    print("spaCy en_core_web_lg missing: run  python -m spacy download en_core_web_lg")
