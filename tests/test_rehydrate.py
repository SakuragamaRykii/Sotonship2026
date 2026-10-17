from scrubber import Session, rehydrate


def _session(scrub_regex):
    s = Session()
    scrub_regex('{"name": "Jane Doe", "email": "jane.doe@gmail.com", "username": "jdoe"}', s)
    return s


def test_possessive_case_and_punctuation(scrub_regex):
    s = _session(scrub_regex)
    text, warnings = rehydrate('PERSON_1\'s email is "user_1@example.com"; (username_1).', s)
    assert text == 'Jane Doe\'s email is "jane.doe@gmail.com"; (jdoe).'
    assert warnings == []


def test_unknown_and_mangled_surrogates_warn(scrub_regex):
    s = _session(scrub_regex)
    text, warnings = rehydrate("Person_7 wrote to user1@example.com and user_9@example.com", s)
    assert "Person_7" in text and "user_9@example.com" in text
    assert any("Person_7" in w for w in warnings)
    assert any("user_9@example.com" in w for w in warnings)


def test_no_partial_matches(scrub_regex):
    s = _session(scrub_regex)
    text, warnings = rehydrate("Person_10 and Person_1", s)
    assert text.endswith("and Jane Doe") and text.startswith("Person_10")
    assert any("Person_10" in w for w in warnings)


def test_removed_never_restored(scrub_regex):
    s = Session()
    r = scrub_regex("card 4111 1111 1111 1111 key sk-proj-Q1w2E3r4T5y6U7i8O9p0AsDf", s)
    back, _ = rehydrate(r.scrubbed_text, s)
    assert "[CARD_REMOVED]" in back and "[SECRET_REMOVED]" in back
