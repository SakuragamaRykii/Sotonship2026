"""M1 acceptance tests: round-trip, secrets, consistency, IP subnets, +tags."""

import json
import random
import re
import uuid

import pytest
from faker import Faker

from scrubber import Session, rehydrate
from scrubber.detect.structured import EMAIL


def _pseudonymise_only_doc(seed: int) -> str:
    """Synthetic text containing only PSEUDONYMISE-able types (balanced mode)."""
    fake = Faker("en_GB")
    Faker.seed(seed)
    rng = random.Random(seed)
    first, last = fake.first_name(), fake.last_name()
    email = f"{first.lower()}.{last.lower()}{'+' + fake.word() if rng.random() < 0.5 else ''}@{fake.free_email_domain()}"
    phone = rng.choice(["07{} {}", "+44 7{} {}", "07{}{}"]).format(rng.randint(100, 999), rng.randint(100000, 999999))
    ip_a = fake.ipv4_private()
    ip_b = ".".join(ip_a.split(".")[:3] + [str(rng.randint(1, 254))])
    uid = str(uuid.UUID(int=rng.getrandbits(128), version=4))
    user = f"{first.lower()}{rng.randint(10, 99)}"
    record = {"name": f"{first} {last}", "username": user, "email": email, "uuid": uid}
    kind = rng.choice(["json", "log", "prose"])
    if kind == "json":
        return json.dumps(record)
    if kind == "log":
        return (f"ts=2024 level=info user={user} email={email} src={ip_a} dst={ip_b} req={uid}\n"
                f"level=warn retry from {ip_a} for {email}")
    return (f"please reach out on {email} or {phone}; request id {uid}.\n"
            f"traffic came from {ip_a} and {ip_b}, then {ip_a} again.")


@pytest.mark.parametrize("seed", range(60))
def test_round_trip_property(seed, scrub_regex):
    text = _pseudonymise_only_doc(seed)
    s = Session()
    r = scrub_regex(text, s)
    assert r.scrubbed_text != text, "nothing was scrubbed"
    assert {a["action"] for a in r.actions} <= {"PSEUDONYMISE"}, r.actions
    back, warnings = rehydrate(r.scrubbed_text, s)
    assert back == text
    assert warnings == []


SECRETS = [
    "sk-proj-Q1w2E3r4T5y6U7i8O9p0AsDfGhJk",
    "ghp_" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp9Oo8",
    "AKIAQWERTYUIOPASDFGH",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqYW5lIn0.c2lnbmF0dXJlLXZhbHVlLWhlcmU",
    "Hunter2Correct!Horse",
]


def test_secrets_never_in_output_or_vault(scrub_regex):
    s = Session()
    text = (
        f"OPENAI_API_KEY={SECRETS[0]}\nexport GH={SECRETS[1]}\naws_access_key_id = {SECRETS[2]}\n"
        f"Authorization: Bearer {SECRETS[3]}\n"
        f"db: postgres://jane:{SECRETS[4]}@db.internal/app\n"
        f'{{"password": "{SECRETS[4]}", "email": "jane@corp.test"}}'
    )
    r = scrub_regex(text, s)
    vault_dump = json.dumps(s.vault.to_dict())
    for secret in SECRETS:
        assert secret not in r.scrubbed_text
        assert secret not in vault_dump
        assert secret not in json.dumps(r.model_dump())  # report and spans are safe to print
    assert "[SECRET_REMOVED]" in r.scrubbed_text
    back, _ = rehydrate(r.scrubbed_text, s)
    for secret in SECRETS:
        assert secret not in back  # removed items are never restored


def test_same_email_same_surrogate_across_calls(scrub_regex):
    s = Session()
    r1 = scrub_regex("contact jane.doe@gmail.com please", s)
    r2 = scrub_regex('{"email": "Jane.Doe@gmail.com", "cc": "bob@gmail.com"}', s)
    sur1 = EMAIL.findall(r1.scrubbed_text)
    sur2 = EMAIL.findall(r2.scrubbed_text)
    assert sur1[0] == sur2[0] == "user_1@example.com"
    assert sur2[1] == "user_2@example.com"


def test_ip_subnet_preserved_in_text(scrub_regex):
    s = Session()
    r = scrub_regex("a=10.0.0.5 b=10.0.0.6 c=10.0.1.5 d=10.0.0.5", s)
    ips = re.findall(r"\d+\.\d+\.\d+\.\d+", r.scrubbed_text)
    net = [ip.rsplit(".", 1)[0] for ip in ips]
    assert net[0] == net[1] == net[3] and net[2] != net[0]
    assert ips[0] == ips[3] and ips[0] != ips[1]
    assert "10.0." not in r.scrubbed_text


def test_plus_tag_preserved(scrub_regex):
    s = Session()
    r = scrub_regex("jane.doe+shop@gmail.com and jane.doe@gmail.com", s)
    assert r.scrubbed_text == "user_1+shop@example.com and user_1@example.com"


def test_leak_check_catches_missed_occurrence(scrub_regex):
    s = Session()
    text = '{"name": "Jane Doe", "note": "Jane Doe asked about her order. Ms Doe was polite."}'
    r = scrub_regex(text, s)
    assert "Jane" not in r.scrubbed_text and "Doe" not in r.scrubbed_text
    assert r.report["leak_fixes"]


def test_strict_mode_shifts_dates_and_rehydrates(scrub_regex):
    s = Session()
    s.date_offset_days = 10
    text = "opened 2024-03-01, closed 2024-03-05; ip 10.0.0.1"
    r = scrub_regex(text, s, mode="strict")
    assert "2024-03-11" in r.scrubbed_text and "2024-03-15" in r.scrubbed_text  # interval kept
    assert "[IP_REMOVED]" in r.scrubbed_text
    back, _ = rehydrate(r.scrubbed_text, s)
    assert "2024-03-01" in back and "2024-03-05" in back


def test_balanced_keeps_dates_generalises_dob_and_postcode(scrub_regex):
    s = Session()
    text = '{"dob": "03/05/1988", "visit": "2024-03-01", "postcode": "SO17 1BJ"}'
    r = scrub_regex(text, s)
    assert "2024-03-01" in r.scrubbed_text
    assert "03/05/1988" not in r.scrubbed_text and "[AGE " in r.scrubbed_text
    assert '"postcode": "SO17"' in r.scrubbed_text


def test_address_keeps_district_in_balanced_only(scrub_regex):
    text = '{"address": "12 High Street, Southampton SO17 1BJ"}'
    rb = scrub_regex(text, Session())
    rs = scrub_regex(text, Session(), mode="strict")
    assert "[ADDRESS_1], SO17" in rb.scrubbed_text
    assert "SO17" not in rs.scrubbed_text and "[ADDRESS_1]" in rs.scrubbed_text


def test_report_shape(scrub_regex):
    r = scrub_regex("mail a@b.com", Session())
    assert r.report["counts_by_type"] == {"email": 1}
    assert r.actions[0]["action"] == "PSEUDONYMISE" and r.actions[0]["replacement"] == "user_1@example.com"
    assert r.spans[0].reason


def test_shared_surname_is_a_different_person(scrub_regex):
    s = Session()
    text = '{"name": "Joshua Preston", "note": "Georgina Preston and Ms Preston met. Called Joshua; Joshua Smith too."}'
    r = scrub_regex(text, s)
    for name in ("Joshua", "Preston", "Georgina", "Smith"):
        assert name not in r.scrubbed_text
    back, _ = rehydrate(r.scrubbed_text, s)
    assert "Georgina Preston" in back and "Joshua Smith" in back and "Ms Joshua Preston" in back


def test_phone_09_numbers(scrub_regex):
    r = scrub_regex("call (0909) 879 0940 or +44(0)9098790519", Session())
    assert "879" not in r.scrubbed_text and "9098790519" not in r.scrubbed_text
