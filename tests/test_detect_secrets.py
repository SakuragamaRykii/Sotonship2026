import pytest

from scrubber.detect.secrets import SecretsDetector, shannon_entropy
from scrubber.segment import segment


def detect(text):
    return SecretsDetector().detect(text, segment(text))


@pytest.mark.parametrize(
    "secret",
    [
        "sk-proj-AbCdEf1234567890GhIjKlMnOp",
        "sk-ant-api03-abcdefghij1234567890KLMNOP",
        "ghp_" + "a1B2c3D4e5" * 3 + "a1B2c3",
        "AKIAIOSFODNN7EXAMPLE",
        "xoxb-1234567890-abcdefghij",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ],
)
def test_known_secret_patterns(secret):
    text = f"config value {secret} here"
    spans = [s for s in detect(text) if s.type == "secret"]
    assert any(s.text == secret for s in spans), spans


def test_authorization_and_bearer():
    text = "Authorization: Bearer abc123DEF456ghi789\nX: y"
    spans = detect(text)
    assert any(s.text == "abc123DEF456ghi789" and s.type == "secret" for s in spans)


def test_password_in_url_including_at_sign():
    text = "postgres://jane.doe:S3cr3t@P4ss@db.example.internal:5432/app"
    spans = detect(text)
    assert any(s.type == "secret" and s.text == "S3cr3t@P4ss" for s in spans)
    assert any(s.type == "username" and s.text == "jane.doe" for s in spans)


def test_password_keys():
    for text, value in [('password=hunter22', "hunter22"), ('{"db_password": "pa55word!"}', "pa55word!"),
                        ("pwd: correcthorse", "correcthorse"), ("my password is Tr0ub4dor", "Tr0ub4dor")]:
        assert any(s.type == "secret" and s.text == value for s in detect(text)), text


def test_placeholders_not_secret():
    for text in ['password=***', '{"password": null}', "token_type=bearer", "password: <redacted>"]:
        assert not [s for s in detect(text) if s.type == "secret"], text


def test_high_entropy_token():
    tok = "Zx9Qw3Lp8Rt2Yv6Nb4Mk1Hs7Df5Gj0"
    assert shannon_entropy(tok) > 4.0
    assert any(s.text == tok for s in detect(f"key {tok} end"))


def test_low_entropy_and_uuid_not_flagged():
    text = "id 123e4567-e89b-42d3-a456-426614174000 path /usr/local/lib/python3/site-packages sha 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
    assert not [s for s in detect(text) if s.type == "secret"]
