import pytest

from scrubber.detect.structured import StructuredDetector, iban_ok, luhn_ok, nhs_ok, uk_phone_ok
from scrubber.segment import segment


def types_of(text):
    return {(s.type, s.text) for s in StructuredDetector().detect(text, segment(text))}


def test_validators():
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")
    assert nhs_ok("9434765919") and not nhs_ok("9434765918")
    assert iban_ok("GB82 WEST 1234 5698 7654 32") and not iban_ok("GB82 WEST 1234 5698 7654 33")
    assert uk_phone_ok("07911 123456") and uk_phone_ok("+44 7911 123456") and uk_phone_ok("+44 (0)20 7946 0018")
    assert not uk_phone_ok("12345")


@pytest.mark.parametrize(
    "text,expected",
    [
        ("mail jane.doe+shop@gmail.com now", ("email", "jane.doe+shop@gmail.com")),
        ("call 07911 123456 today", ("phone", "07911 123456")),
        ("call +44 7911 123456.", ("phone", "+44 7911 123456")),
        ("call (020) 7946 0018", ("phone", "(020) 7946 0018")),
        ("lives in SO17 1BJ", ("postcode", "SO17 1BJ")),
        ("NHS 943 476 5919", ("nhs_number", "943 476 5919")),
        ("NI AB 12 34 56 C", ("ni_number", "AB 12 34 56 C")),
        ("card 4111-1111-1111-1111", ("card", "4111-1111-1111-1111")),
        ("iban GB82WEST12345698765432 ok", ("iban", "GB82WEST12345698765432")),
        ("from 192.168.1.20.", ("ip", "192.168.1.20")),
        ("from 2001:4860:4860::8888", ("ip", "2001:4860:4860::8888")),
        ("id 123e4567-e89b-42d3-a456-426614174000", ("uuid", "123e4567-e89b-42d3-a456-426614174000")),
        ("on 2024-03-05 we met", ("date", "2024-03-05")),
        ("DOB: 03/05/1988", ("date_of_birth", "03/05/1988")),
        ("born on 5th March 1988", ("date_of_birth", "5th March 1988")),
        ("https://x.test/p?name=Jane%20Doe&page=2", ("person", "Jane%20Doe")),
    ],
)
def test_detects(text, expected):
    assert expected in types_of(text)


@pytest.mark.parametrize(
    "text",
    [
        "NHS 943 476 5918",  # bad checksum
        "ts 1700000000123 ms",  # millisecond timestamp is not a card
        "at 10:30:00 sharp",  # time is not IPv6
        "use std::vector here",
        "version 3.11.9 released",
    ],
)
def test_negatives(text):
    assert not {t for t, _ in types_of(text)} & {"nhs_number", "card", "ip"}, types_of(text)


def test_phone_followed_by_number():
    assert ("phone", "07911 123456") in types_of("tel 07911 123456 2 attempts")
