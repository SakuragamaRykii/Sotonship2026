import json

from scrubber.segment import normalise_key, segment


def test_whole_json_values_and_keys():
    text = '{"name": "Jane Doe", "age": 41, "tags": ["a", "b"], "nested": {"email": "j@x.com"}}'
    segs = segment(text)
    found = {(s.key, text[s.start : s.end]) for s in segs}
    assert ("name", "Jane Doe") in found
    assert ("age", "41") in found
    assert ("tags", "a") in found and ("tags", "b") in found
    assert ("email", "j@x.com") in found
    assert all(s.kind == "json_value" for s in segs)


def test_json_escapes_keep_raw_offsets():
    text = json.dumps({"note": 'She said "hi" to Jane'})
    seg = next(s for s in segment(text) if s.key == "note")
    assert text[seg.start : seg.end] == 'She said \\"hi\\" to Jane'


def test_json_lines_with_log_prefix():
    text = '2024-01-01 INFO {"user": "jdoe", "ip": "10.0.0.1"}\n2024-01-01 WARN plain text line here'
    segs = segment(text)
    vals = {(s.key, text[s.start : s.end]) for s in segs if s.kind == "json_value"}
    assert ("user", "jdoe") in vals and ("ip", "10.0.0.1") in vals
    texts = [text[s.start : s.end] for s in segs if s.kind == "text"]
    assert any("plain text line" in t for t in texts)


def test_inline_and_line_kv():
    text = 'level=info user="Jane Doe" email=jane@x.com&ref=1\nFirst Name: Jane\nAuthorization: Bearer abc'
    segs = {(s.key, text[s.start : s.end]) for s in segment(text) if s.kind == "kv_value"}
    assert ("user", "Jane Doe") in segs
    assert ("email", "jane@x.com") in segs
    assert ("first_name", "Jane") in segs
    assert ("authorization", "Bearer abc") in segs


def test_prose_is_text():
    text = "Spoke to Jane about the refund. She was happy."
    segs = segment(text)
    assert len(segs) == 1 and segs[0].kind == "text" and text[segs[0].start : segs[0].end] == text


def test_normalise_key():
    assert normalise_key("firstName") == "first_name"
    assert normalise_key("First Name") == "first_name"
    assert normalise_key("e-mail") == "e_mail"
