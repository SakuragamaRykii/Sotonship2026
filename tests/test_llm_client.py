"""M5: payload logging, provider adapter, payload audit."""

import json

import httpx

from eval.audit_payloads import audit
from scrubber import Session, scrub
from scrubber.llm_client import LLMClient, strip_think


def test_dryrun_logs_exact_payload(tmp_path):
    log = tmp_path / "p.jsonl"
    c = LLMClient(provider="dryrun", log_path=log)
    assert c.send("hello Person_1", {"purpose": "test"}) == ""
    rec = json.loads(log.read_text(encoding="utf-8"))
    assert rec["payload"] == "hello Person_1" and rec["meta"] == {"purpose": "test"} and rec["provider"] == "dryrun"


def test_ollama_provider_sends_scrubbed_text_only(tmp_path, monkeypatch):
    sent = {}

    def fake_post(url, json=None, timeout=None):  # noqa: A002
        sent.update(url=url, body=json)
        return httpx.Response(200, json={"response": "<think>hmm</think>Person_1"}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    s = Session()
    r = scrub("Email jane.doe@gmail.com about Jane's order", s, layers=["L1", "L2", "L3"])
    c = LLMClient(provider="ollama", model="m", log_path=tmp_path / "p.jsonl")
    out = c.send(r.scrubbed_text)
    assert out == "Person_1"
    assert "jane.doe@gmail.com" not in json.dumps(sent["body"])
    assert sent["body"]["prompt"] == r.scrubbed_text


def test_strip_think():
    assert strip_think("<think>a\nb</think>\n answer") == "answer"


def test_audit_flags_high_risk_values(tmp_path):
    log = tmp_path / "p.jsonl"
    c = LLMClient(provider="dryrun", log_path=log)
    c.log_payload("card [CARD_REMOVED] user Person_1", {"system": "full"})
    c.log_payload("key sk-proj-Q1w2E3r4T5y6U7i8O9p0AsDfGh", {"system": "presidio"})
    c.log_payload("card 4111 1111 1111 1111", {"system": "raw"})  # the raw baseline is skipped
    res = audit([log])
    assert res["n_payloads"] == 2
    assert res["high_risk_hits"] == {"secret": 1}
    assert res["flagged"][0]["meta"]["system"] == "presidio"
