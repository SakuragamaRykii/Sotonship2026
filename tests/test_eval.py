import json
from pathlib import Path

from eval import metrics as M
from eval.annotate import parse
from eval.generate import generate

ROOT = Path(__file__).resolve().parent.parent


def test_generator_offsets_and_synthetic_flag():
    rows = generate(40, seed=123, split="t")
    kinds = {r["kind"] for r in rows}
    assert kinds == {"log", "json", "prose", "document"}
    for r in rows:
        assert r["synthetic"] is True
        for s in r["spans"]:
            assert 0 <= s["start"] < s["end"] <= len(r["text"])
            assert r["text"][s["start"] : s["end"]].strip() == r["text"][s["start"] : s["end"]]
        if r["kind"] == "json":
            json.loads(r["text"])  # JSON items stay valid JSON
    tags = {t for r in rows for t in r["tags"]}
    assert {"json_freetext", "unknown_key", "name_variants", "email_tag", "url_secret"} <= tags


def test_generator_is_deterministic():
    assert generate(5, seed=7, split="x") == generate(5, seed=7, split="x")


def test_dataset_files_are_synthetic():
    for name in ("dev.jsonl", "test.jsonl", "heldout_handwritten.jsonl"):
        for line in (ROOT / "data" / name).read_text(encoding="utf-8").splitlines():
            if line.strip():
                assert json.loads(line)["synthetic"] is True


def test_span_metrics():
    gold = [{"start": 0, "end": 5, "type": "person"}, {"start": 10, "end": 20, "type": "email"}]
    pred = [{"start": 0, "end": 4, "type": "person"}, {"start": 30, "end": 35, "type": "phone"}]
    o = M.span_metrics([(gold, pred)], "overlap")
    assert o["person"]["recall"] == 1.0 and o["email"]["recall"] == 0.0
    assert o["ALL"]["precision"] == 0.5 and o["ALL"]["recall"] == 0.5
    e = M.span_metrics([(gold, pred)], "exact")
    assert e["ALL"]["recall"] == 0.0


def test_leakage_counts_secrets_and_ignores_kept_types():
    item = {"id": "a", "text": "Jane jane@x.com sk-abc London", "tags": ["t"],
            "spans": [{"start": 0, "end": 4, "type": "person"}, {"start": 5, "end": 15, "type": "email"},
                      {"start": 16, "end": 22, "type": "secret"}, {"start": 23, "end": 29, "type": "location"}]}
    r = M.leakage([item], {"a": "JANE user_1@example.com [SECRET_REMOVED] London"})
    assert r["n_strings"] == 3 and r["n_leaked"] == 1 and r["secret_leaks"] == 0


def test_answer_correct():
    assert M.answer_correct("The email is Jane.Doe@x.com.", "jane.doe@x.com")
    assert M.answer_correct("07700 900123", "07700900123")
    assert not M.answer_correct("Person_1", "Jane Doe")


def test_annotate():
    rows = parse("=== prose\nHi [[person:Tom Hale]] at [[email:t@example.com]].\n?? email? => t@example.com\n")
    r = rows[0]
    assert r["text"] == "Hi Tom Hale at t@example.com."
    assert [r["text"][s["start"] : s["end"]] for s in r["spans"]] == ["Tom Hale", "t@example.com"]
    assert r["task"]["answer"] == "t@example.com" and r["synthetic"] is True
