from scrubber.surrogates import email_surrogate, phone_surrogate, shift_date, age_band
from scrubber.vault import Session


def test_email_tag_and_consistency():
    v = Session().vault
    a = v.pseudonymise("email", "jane.doe+shop@gmail.com", "")
    assert a == "user_1+shop@example.com"
    assert v.pseudonymise("email", "Jane.Doe@GMAIL.com", "") == "user_1@example.com"
    assert v.pseudonymise("email", "jane.doe+shop@gmail.com", "") == a
    assert v.pseudonymise("email", "other@gmail.com", "") == "user_2@example.com"


def test_phone_keeps_style():
    assert phone_surrogate("07911 123456", 1) == "07700 900001"
    assert phone_surrogate("07911-123-456", 2) == "07700-900-002"
    assert phone_surrogate("+44 7911 123456", 3) == "+44 7700 900003"
    assert phone_surrogate("07911123456", 4) == "07700900004"


def test_phone_same_number_same_surrogate_number():
    v = Session().vault
    a = v.pseudonymise("phone", "07911 123456", "")
    b = v.pseudonymise("phone", "+44 7911 123456", "")
    assert a == "07700 900001" and b == "+44 7700 900001"


def test_ip_subnet_preservation():
    v = Session().vault
    a1 = v.pseudonymise("ip", "10.1.2.3", "")
    a2 = v.pseudonymise("ip", "10.1.2.99", "")
    b1 = v.pseudonymise("ip", "172.16.5.3", "")
    assert a1.rsplit(".", 1)[0] == a2.rsplit(".", 1)[0]  # same /24 -> same surrogate /24
    assert a1.rsplit(".", 1)[0] != b1.rsplit(".", 1)[0]  # different /24 -> different
    assert v.pseudonymise("ip", "10.1.2.3", "") == a1  # same host -> same host
    assert a1 != a2
    assert a1.startswith(("198.51.100.", "203.0.113.", "192.0.2."))


def test_uuid_format():
    v = Session().vault
    u = v.pseudonymise("uuid", "123e4567-e89b-42d3-a456-426614174000", "")
    assert u == "00000000-0000-4000-8000-000000000001"


def test_collision_switches_prefix():
    s = Session()
    text = "Person_1 is a placeholder; real name Jane Doe"
    s.vault.ensure_prefixes(text)
    sur = s.vault.pseudonymise("person", "Jane Doe", text)
    assert sur != "Person_1" and sur.endswith("_1") and sur not in text


def test_person_linking_and_titles():
    v = Session().vault
    full = v.pseudonymise("person", "Jane Doe", "")
    assert v.pseudonymise("person", "Jane", "") == full
    assert v.pseudonymise("person", "Ms Doe", "") == "Ms " + full
    assert v.reverse[full] == "Jane Doe"


def test_date_helpers():
    assert shift_date("2024-03-05", 10) == "2024-03-15"
    assert shift_date("5/3/2024", -5) == "29/2/2024"
    import datetime
    assert age_band("03/05/1988", 5, today=datetime.date(2026, 10, 17)) == "[AGE 35-39]"
    assert age_band("03/05/1988", 10, today=datetime.date(2026, 10, 17)) == "[AGE 30-39]"


def test_session_roundtrip(tmp_path):
    s = Session()
    s.vault.pseudonymise("email", "a@b.com", "")
    s.save(tmp_path)
    t = Session.load(s.id, tmp_path)
    assert t.vault.reverse == s.vault.reverse and t.date_offset_days == s.date_offset_days
