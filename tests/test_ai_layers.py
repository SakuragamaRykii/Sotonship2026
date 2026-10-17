"""M3: L3 key-aware and L4 NER layers."""

import json

import pytest

from scrubber import Session
from scrubber.detect.keys import KeyDetector
from scrubber.detect.ner import NerDetector
from scrubber.pipeline import Scrubber
from scrubber.segment import segment

LABEL_OF = {"Jane Doe": "person", "Acme Ltd": "organization", "INFO": "organization", "team": "organization",
            "Harry Potter": "person", "Geraldine": "username", "jdoe_88": "username"}


class FakeGliner:
    """Stands in for the GLiNER model: tags fixed strings wherever they occur."""

    def __init__(self):
        self.calls = []

    def inference(self, texts, labels, threshold=0.5, batch_size=8):
        self.calls.append((list(texts), threshold))
        out = []
        for t in texts:
            ents = []
            for name, label in LABEL_OF.items():
                i = t.find(name)
                if i >= 0:
                    ents.append({"start": i, "end": i + len(name), "text": name, "label": label, "score": 0.9})
            out.append(ents)
        return out


def key_spans(text):
    return {(s.type, s.text) for s in KeyDetector().detect(text, segment(text))}


def test_l3_key_types():
    text = json.dumps({"firstName": "Jane", "customer_email": "j@x.com", "contact": "Jane Doe", "user": "jdoe_88",
                       "customer_id": "CUST-1234", "dob": "1990-01-02", "product_name": "Widget",
                       "user_type": "admin", "file_name": "a.txt", "email": None, "city": "Leeds"})
    got = key_spans(text)
    assert ("person", "Jane") in got
    assert ("email", "j@x.com") in got
    assert ("person", "Jane Doe") in got  # ambiguous key resolved by value shape
    assert ("username", "jdoe_88") in got
    assert ("user_id", "CUST-1234") in got
    assert ("date_of_birth", "1990-01-02") in got
    assert ("location", "Leeds") in got
    values = {v for _, v in got}
    assert not values & {"Widget", "admin", "a.txt"}


def test_l3_kv_and_headers():
    got = key_spans("Full name: Jane Doe\nMobile: 07911 123456\nlevel=info username=jdoe_88")
    assert {("person", "Jane Doe"), ("phone", "07911 123456"), ("username", "jdoe_88")} <= got


def test_l4_offsets_filters_and_freetext_threshold():
    fake = FakeGliner()
    det = NerDetector(model=fake)
    text = '2024 INFO {"rcpt": "Harry Potter", "note": "Spoke to Jane Doe from Acme Ltd; the team agreed."}'
    spans = det.detect(text, segment(text))
    got = {(s.type, s.text) for s in spans}
    assert ("person", "Harry Potter") in got and ("person", "Jane Doe") in got
    assert ("organisation", "Acme Ltd") in got
    assert not {t for _, t in got} & {"INFO", "team"}  # log level and lowercase noun dropped
    for s in spans:
        assert text[s.start : s.end] == s.text
    assert min(thr for _, thr in fake.calls) == det.cfg.freetext_threshold  # "note" is a free-text key


def test_l4_username_label_on_a_name_becomes_person():
    det = NerDetector(model=FakeGliner())
    text = "Thanks,\nGeraldine\nP.S. login is jdoe_88"
    got = {(s.type, s.text) for s in det.detect(text, segment(text))}
    assert ("person", "Geraldine") in got and ("username", "jdoe_88") in got


def test_full_pipeline_with_fake_model_round_trips():
    sc = Scrubber(["L1", "L2", "L3"])
    sc.detectors.append(NerDetector(model=FakeGliner()))
    s = Session()
    text = '{"rcpt": "Harry Potter", "note": "Spoke to Jane Doe; Harry was fine."}'
    r = sc.scrub(text, s)
    assert "Harry" not in r.scrubbed_text and "Jane" not in r.scrubbed_text
    json.loads(r.scrubbed_text)
    from scrubber import rehydrate

    back, _ = rehydrate(r.scrubbed_text, s)
    assert "Harry Potter" in back and "Jane Doe" in back


@pytest.mark.slow
def test_real_gliner_finds_person_in_free_text():
    try:
        det = NerDetector()
        det.model  # noqa: B018 - loads the cached model
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"GLiNER model unavailable: {exc}")
    text = "Spoke to Priya Natarajan from Northwind Ltd about the refund."
    got = {(s.type, s.text) for s in det.detect(text, segment(text))}
    assert ("person", "Priya Natarajan") in got


def test_l5_quasi_identifiers_flag_in_balanced_generalise_in_strict(monkeypatch):
    import httpx

    from scrubber.detect.llm import LlmQuasiDetector

    qi = "the only female professor of marine biology"

    def fake_post(url, json=None, timeout=None):  # noqa: A002
        assert url.startswith("http://localhost")
        body = '{"spans": [{"text": "%s", "reason": "unique role"}]}' % qi
        return httpx.Response(200, json={"response": body}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    sc = Scrubber(["L1", "L2", "L3"])
    sc.detectors.append(LlmQuasiDetector())
    text = f"Our client is {qi} at the university."
    rb = sc.scrub(text, Session(), "balanced")
    assert qi in rb.scrubbed_text and any("quasi_identifier" in w for w in rb.report["warnings"])
    rs = sc.scrub(text, Session(), "strict")
    assert qi not in rs.scrubbed_text and "[DETAIL_REDACTED]" in rs.scrubbed_text


def test_l5_refuses_remote_host(monkeypatch):
    from scrubber.detect.llm import LlmQuasiDetector

    monkeypatch.setenv("OLLAMA_HOST", "http://203.0.113.9:11434")
    monkeypatch.delenv("SCRUBBER_ALLOW_REMOTE_OLLAMA", raising=False)
    det = LlmQuasiDetector()
    assert det.detect("some text", []) == [] and "not local" in det.warnings[0]
