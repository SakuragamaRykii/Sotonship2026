from scrubber.detect.merge import link_person, merge, name_tokens, split_title
from scrubber.models import Span


def sp(text, sub, type_, source, conf=0.9, start=None):
    s = text.index(sub) if start is None else start
    return Span(start=s, end=s + len(sub), text=sub, type=type_, source=source, confidence=conf, reason="t")


def test_priority_l1_beats_l4():
    text = "token sk-abc and more"
    out = merge([sp(text, "sk-abc and", "person", "L4"), sp(text, "sk-abc", "secret", "L1")], text)
    assert [(s.type, s.text) for s in out] == [("secret", "sk-abc")]


def test_equal_priority_longer_then_confidence():
    text = "Jane Doe Smith"
    out = merge([sp(text, "Jane Doe", "person", "L4", 0.99), sp(text, "Jane Doe Smith", "person", "L4", 0.5)], text)
    assert [s.text for s in out] == ["Jane Doe Smith"]
    out = merge([sp(text, "Jane", "person", "L4", 0.6), sp(text, "Jane", "location", "L4", 0.9)], text)
    assert [s.type for s in out] == ["location"]


def test_address_swallows_postcode():
    text = "12 High Street, Southampton SO17 1BJ"
    out = merge([sp(text, "SO17 1BJ", "postcode", "L2"), sp(text, text, "address", "L4")], text)
    assert [(s.type, s.text) for s in out] == [("address", text)]


def test_dob_refines_date():
    text = '"dob": "1988-05-03"'
    out = merge([sp(text, "1988-05-03", "date", "L2"), sp(text, "1988-05-03", "date_of_birth", "L3")], text)
    assert [s.type for s in out] == ["date_of_birth"]


def test_residual_trimming():
    text = "Jane Doe <jane@x.com>"
    out = merge([sp(text, "jane@x.com", "email", "L2"), sp(text, text, "person", "L3")], text)
    assert [(s.type, s.text) for s in out] == [("person", "Jane Doe"), ("email", "jane@x.com")]


def test_entity_linking():
    known = {name_tokens("Jane Doe"): "Person_1", name_tokens("John Smith"): "Person_2"}
    assert link_person(name_tokens("Jane"), known) == "Person_1"
    assert link_person(name_tokens("Ms Doe"), known) == "Person_1"
    assert link_person(name_tokens("Mary Jones"), known) is None
    assert split_title("Ms Doe") == ("Ms ", "Doe")
    # ambiguity is not linked
    known[name_tokens("John Doe")] = "Person_3"
    assert link_person(name_tokens("Doe"), known) is None
