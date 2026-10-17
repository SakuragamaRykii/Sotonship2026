"""Synthetic evaluation data with ground-truth spans (Faker en_GB). No real personal data.

    python -m eval.generate --split dev --n 120 --seed 1
    python -m eval.generate --split test --n 300 --seed 2

Each line: {"id", "synthetic": true, "kind", "text", "spans": [{"start","end","type"}], "task", "tags"}.
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import string
from pathlib import Path

from faker import Faker

from scrubber.detect.structured import iban_ok, luhn_ok

ROOT = Path(__file__).resolve().parent.parent
TITLES = ["Mr", "Mrs", "Ms", "Dr", "Miss"]
_NI_FIRST = "ABCEGHJKLMNOPRSTWXYZ"
_NI_SECOND = "ABCEGHJKLMNPRSTWXYZ"


class Doc:
    """Builds text left-to-right and records ground-truth spans as it goes."""

    def __init__(self) -> None:
        self.parts: list[str] = []
        self.spans: list[dict] = []
        self.pos = 0

    def lit(self, s: str) -> "Doc":
        self.parts.append(s)
        self.pos += len(s)
        return self

    def pii(self, s: str, type_: str) -> "Doc":
        self.spans.append({"start": self.pos, "end": self.pos + len(s), "type": type_})
        return self.lit(s)

    def jstr(self, s: str, type_: str | None) -> "Doc":
        """A JSON string literal; the span covers the (escaped) content, not the quotes."""
        esc = json.dumps(s)[1:-1]
        self.lit('"')
        (self.pii(esc, type_) if type_ else self.lit(esc))
        return self.lit('"')

    @property
    def text(self) -> str:
        return "".join(self.parts)


class Gen:
    def __init__(self, seed: int, quasi: bool = False) -> None:
        self.quasi = quasi  # inject quasi-identifier phrases (separate split, so other splits stay stable)
        self.rng = random.Random(seed)
        self.fake = Faker("en_GB")
        self.fake.seed_instance(seed)

    # ---- value generators ---------------------------------------------------------------------
    def person(self) -> tuple[str, str, str]:
        return self.fake.first_name(), self.fake.last_name(), self.rng.choice(TITLES)

    def email(self, first: str | None = None, last: str | None = None, tag: bool | None = None) -> str:
        r = self.rng
        if first and last:
            local = r.choice([f"{first}.{last}", f"{first[0]}{last}", f"{first}{last[:1]}{r.randint(1, 99)}"]).lower()
        else:
            local = self.fake.user_name()
        local = "".join(c for c in local if c.isalnum() or c in "._")
        if tag if tag is not None else r.random() < 0.25:
            local += "+" + r.choice(["shop", "news", "work", "spam", "amazon", "2024"])
        return f"{local}@{r.choice([self.fake.free_email_domain(), self.fake.domain_name()])}"

    def phone(self) -> str:
        r = self.rng
        a, b = r.randint(100, 999), r.randint(100000, 999999)
        return r.choice([f"07{a} {b}", f"+44 7{a} {b}", f"07{a}{b}", f"07{a}-{str(b)[:3]}-{str(b)[3:]}",
                         self.fake.phone_number()])

    def nhs(self) -> str:
        while True:
            d = [self.rng.randint(0, 9) for _ in range(9)]
            d[0] = self.rng.choice([4, 6, 7])
            check = 11 - sum(x * w for x, w in zip(d, range(10, 1, -1))) % 11
            check = 0 if check == 11 else check
            if check != 10:
                s = "".join(map(str, d)) + str(check)
                return self.rng.choice([f"{s[:3]} {s[3:6]} {s[6:]}", s])

    def ni(self) -> str:
        r = self.rng
        while True:
            pre = r.choice(_NI_FIRST) + r.choice(_NI_SECOND)
            if pre not in {"BG", "GB", "NK", "KN", "TN", "NT", "ZZ"}:
                break
        digits = "".join(str(r.randint(0, 9)) for _ in range(6))
        suf = r.choice("ABCD")
        return r.choice([f"{pre}{digits}{suf}", f"{pre} {digits[:2]} {digits[2:4]} {digits[4:]} {suf}"])

    def card(self) -> str:
        while True:
            c = self.fake.credit_card_number(card_type=self.rng.choice(["visa16", "mastercard", "amex"]))
            if luhn_ok(c) and c[0] in "2345":
                break
        if len(c) == 16 and self.rng.random() < 0.6:
            return " ".join(c[i : i + 4] for i in range(0, 16, 4))
        return c

    def iban(self) -> str:
        while True:
            i = self.fake.iban()
            if iban_ok(i):
                break
        return " ".join(i[k : k + 4] for k in range(0, len(i), 4)) if self.rng.random() < 0.5 else i

    def ip(self) -> str:
        return self.rng.choice([self.fake.ipv4_public(), self.fake.ipv4_private(), self.fake.ipv4_public()])

    def date(self, dob: bool = False) -> str:
        d = self.fake.date_of_birth(minimum_age=18, maximum_age=90) if dob else self.fake.date_between("-2y", "today")
        fmt = self.rng.choice(["%Y-%m-%d", "%d/%m/%Y", "%d %B %Y", "%d %b %Y"])
        return d.strftime(fmt)

    def address(self) -> str:
        return f"{self.fake.building_number()} {self.fake.street_name()}, {self.fake.city()} {self.fake.postcode()}"

    def secret(self) -> str:
        r = self.rng
        rand = lambda n, alphabet=string.ascii_letters + string.digits: "".join(r.choice(alphabet) for _ in range(n))  # noqa: E731
        kind = r.choice(["sk", "ghp", "akia", "jwt", "slack", "hex"])
        if kind == "sk":
            return "sk-" + r.choice(["proj-", "ant-api03-", ""]) + rand(32)
        if kind == "ghp":
            return "ghp_" + rand(36)
        if kind == "akia":
            return "AKIA" + rand(16, string.ascii_uppercase + string.digits)
        if kind == "slack":
            return f"xoxb-{r.randint(10**9, 10**10)}-{rand(24)}"
        if kind == "hex":
            return rand(40, string.ascii_letters + string.digits + "_-")
        b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
        return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'sub': rand(8), 'iat': r.randint(10**9, 2 * 10**9)})}.{rand(43, string.ascii_letters + string.digits + '_-')}"

    def quasi_phrase(self) -> str:
        r, f = self.rng, self.fake
        return r.choice([
            f"the only {r.choice(['female', 'male', 'Welsh-speaking', 'deaf'])} {r.choice(['professor', 'surgeon', 'pilot', 'nurse'])}"
            f" in the {r.choice(['marine biology', 'cardiology', 'physics', 'neonatal'])} department at {f.company()}",
            f"the person who won the {f.city()} half marathon in {r.randint(2015, 2024)}",
            f"the one whose twin {r.choice(['brother', 'sister'])} works as a {f.job().lower()} in {f.city()}",
            f"the youngest {r.choice(['headteacher', 'judge', 'councillor', 'consultant'])} ever appointed in {f.city()}",
            f"the patient with {r.choice(['Fabry disease', 'acromegaly', 'situs inversus', 'Kawasaki disease'])} on Ward {r.randint(1, 30)}",
        ])

    def password(self) -> str:
        r = self.rng
        return "".join(r.choice(string.ascii_letters + string.digits + "!$%^*") for _ in range(r.randint(10, 16)))

    # ---- document templates ----------------------------------------------------------------------
    def make(self, kind: str) -> tuple[Doc, dict | None, list[str]]:
        return getattr(self, f"_{kind}")()

    def _log(self) -> tuple[Doc, dict | None, list[str]]:
        r, d, tags = self.rng, Doc(), []
        first, last, _ = self.person()
        email = self.email(first, last)
        if "+" in email:
            tags.append("email_tag")
        user = self.fake.user_name()
        ip1, ip2 = self.ip(), self.ip()
        fails = r.randint(1, 5)
        ts = lambda: f"2024-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}T{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}Z"  # noqa: E731
        for _ in range(fails):
            d.lit(f"{ts()} WARN auth failed user=").pii(user, "username").lit(" src=").pii(ip1, "ip").lit("\n")
        d.lit(f"{ts()} INFO login ok user=").pii(user, "username").lit(" email=").pii(email, "email").lit(" src=").pii(ip1, "ip").lit("\n")
        style = r.choice(["json", "kv", "url"])
        if style == "json":
            tags.append("json_freetext")
            d.lit(f'{ts()} INFO {{"event": "support_note", "ip": ').jstr(ip2, "ip").lit(', "msg": "')
            d.lit("Customer ").pii(f"{first} {last}", "person").lit(" called from ").pii(self.phone(), "phone")
            d.lit(" about a refund; ").pii(first, "person").lit(' was polite"}\n')
        elif style == "kv":
            d.lit(f'{ts()} DEBUG db connect url=postgres://svc_app:')
            d.pii(self.password(), "secret").lit("@db.internal:5432/orders\n")
            tags.append("url_secret")
        else:
            tags.append("url_secret")
            d.lit(f"{ts()} INFO GET https://api.example-shop.test/v2/orders?api_key=").pii(self.secret(), "secret")
            d.lit("&email=").pii(email, "email").lit(" 200\n")
        if r.random() < 0.5:
            d.lit(f"{ts()} ERROR payment declined card=").pii(self.card(), "card").lit(" request_id=").pii(self.fake.uuid4(), "uuid").lit("\n")
        if r.random() < 0.4:
            d.lit(f"{ts()} DEBUG headers Authorization: Bearer ").pii(self.secret(), "secret").lit("\n")
        task = r.choice([
            {"question": "How many failed login attempts are in the log? Answer with a number.", "answer": str(fails)},
            {"question": "What email address did the user log in with?", "answer": email},
            {"question": "Which source IP address appears in the failed login lines?", "answer": ip1},
        ])
        return d, task, tags

    def _json(self) -> tuple[Doc, dict | None, list[str]]:
        r, d, tags = self.rng, Doc(), []
        first, last, title = self.person()
        email = self.email(first, last)
        if "+" in email:
            tags.append("email_tag")
        city = self.fake.city()
        order = f"ORD-{r.randint(100000, 999999)}"
        d.lit("{")
        fields: list[tuple[str, str, str | None]] = [
            ("order_id", order, None),
            ("customer_id", f"CUST-{r.randint(10000, 99999)}", "user_id"),
        ]
        if r.random() < 0.5:
            fields += [("first_name", first, "person"), ("last_name", last, "person")]
        else:
            fields += [("name", f"{first} {last}", "person")]
        fields += [("email", email, "email"), ("phone", self.phone(), "phone")]
        if r.random() < 0.6:
            fields.append(("dob", self.date(dob=True), "date_of_birth"))
        if r.random() < 0.5:
            fields.append(("shipping_address", self.address(), "address"))
        else:
            fields += [("city", city, "location"), ("postcode", self.fake.postcode(), "postcode")]
        if r.random() < 0.5:  # unknown key names: only NER / patterns can help
            tags.append("unknown_key")
            unk_first, unk_last, _ = self.person()
            fields.append((r.choice(["cust_ref_nm", "x_holder", "fld_17", "rcpt"]), f"{unk_first} {unk_last}", "person"))
            fields.append((r.choice(["alt_contact_val", "c2", "misc_1"]), self.email(unk_first, unk_last), "email"))
        if r.random() < 0.4:
            fields.append(("iban", self.iban(), "iban"))
        fields.append(("created_at", self.date(), "date"))
        r.shuffle(fields)
        for i, (k, v, t) in enumerate(fields):
            d.lit(("" if i == 0 else ", ") + json.dumps(k) + ": ").jstr(v, t)
        # free text inside a JSON value, with the same person written several ways
        tags += ["json_freetext", "name_variants"]
        d.lit(', "notes": "')
        d.lit("Spoke to ").pii(f"{first} {last}", "person").lit(" on the phone. ").lit(f"{title} ").pii(last, "person")
        d.lit(" confirmed delivery to ").pii(city, "location").lit(". ").pii(first, "person").lit(" asked us to email ")
        d.pii(email, "email").lit(' instead."}')
        task = r.choice([
            {"question": "What is the customer's email address?", "answer": email},
            {"question": "What is the order ID?", "answer": order},
            {"question": "What is the customer's surname?", "answer": last},
        ])
        return d, task, tags

    def _prose(self) -> tuple[Doc, dict | None, list[str]]:
        r, d, tags = self.rng, Doc(), ["name_variants"]
        first, last, title = self.person()
        email = self.email(first, last)
        if "+" in email:
            tags.append("email_tag")
        phone = self.phone()
        org = self.fake.company()
        d.lit("Hi team,\n\nI'm ").pii(f"{first} {last}", "person").lit(" from ").pii(org, "organisation").lit(". ")
        d.lit("My account email is ").pii(email, "email").lit(" and you can reach me on ").pii(phone, "phone").lit(". ")
        if r.random() < 0.5:
            d.lit("I was charged twice on my card ending ").lit(str(r.randint(1000, 9999))).lit(" — the full number is ")
            d.pii(self.card(), "card").lit(". ")
        if r.random() < 0.5:
            d.lit("My NHS number is ").pii(self.nhs(), "nhs_number").lit(" if that helps. ")
        colleague_f, colleague_l, _ = self.person()
        d.lit("My colleague ").pii(f"{colleague_f} {colleague_l}", "person").lit(" (").pii(self.email(colleague_f, colleague_l), "email")
        d.lit(") has the same problem.\n\n")
        if self.quasi:
            tags.append("quasi")
            d.lit("For context, I am ").pii(self.quasi_phrase(), "quasi_identifier").lit(", so please be discreet.\n\n")
        if r.random() < 0.5:
            tags.append("url_secret")
            d.lit("Our staging config still has DATABASE_URL=mysql://").pii(f"{first.lower()}{last.lower()[:1]}", "username")
            d.lit(":").pii(self.password(), "secret").lit("@").pii(self.fake.ipv4_private(), "ip").lit("/app in it, sorry.\n\n")
        d.lit("Thanks,\n").pii(first, "person").lit("\n")
        d.lit("P.S. ").lit(f"{title} ").pii(last, "person").lit(" is fine as a name on the refund.")
        task = r.choice([
            {"question": "What phone number did the sender give?", "answer": phone},
            {"question": "Which company is the sender from?", "answer": org},
            {"question": "What is the sender's first name?", "answer": first},
        ])
        return d, task, tags

    def _document(self) -> tuple[Doc, dict | None, list[str]]:
        r, d, tags = self.rng, Doc(), ["name_variants"]
        first, last, title = self.person()
        dob = self.date(dob=True)
        addr = self.address()
        employer = self.fake.company()
        d.lit("EMPLOYEE RECORD (synthetic)\n\nFull name: ").pii(f"{first} {last}", "person").lit("\n")
        d.lit("Date of birth: ").pii(dob, "date_of_birth").lit("\n")
        d.lit("Home address: ").pii(addr, "address").lit("\n")
        d.lit("NI number: ").pii(self.ni(), "ni_number").lit("\n")
        d.lit("Mobile: ").pii(self.phone(), "phone").lit("\n")
        d.lit("Bank IBAN: ").pii(self.iban(), "iban").lit("\n")
        start = self.date()
        d.lit("Start date: ").pii(start, "date").lit("\n\n")
        d.lit("Summary\n").lit(f"{title} ").pii(last, "person").lit(" joined ").pii(employer, "organisation")
        d.lit(" in the ").pii(self.fake.city(), "location").lit(" office. ").pii(first, "person")
        d.lit(" reports to ").pii(" ".join(self.person()[:2]), "person").lit(" and was born on ").pii(dob, "date_of_birth")
        d.lit(". Payroll queries should go to ").pii(self.email(first, last), "email").lit(".\n")
        if self.quasi:
            tags.append("quasi")
            d.lit("Note: the employee is ").pii(self.quasi_phrase(), "quasi_identifier").lit(".\n")
        if r.random() < 0.5:
            d.lit("Laptop asset tag: ").pii(self.fake.uuid4(), "uuid").lit(", last seen on ").pii(self.ip(), "ip").lit(".\n")
        task = r.choice([
            {"question": "In which year was the employee born? Answer with the year.", "answer": dob[-4:] if not dob[:4].isdigit() else dob[:4]},
            {"question": "What is the employee's full name?", "answer": f"{first} {last}"},
            {"question": "Which company did the employee join?", "answer": employer},
        ])
        return d, task, tags


def generate(n: int, seed: int, split: str, quasi: bool = False) -> list[dict]:
    g = Gen(seed, quasi=quasi)
    kinds = ["prose", "document"] if quasi else ["log", "json", "prose", "document"]
    out = []
    for i in range(n):
        kind = kinds[i % len(kinds)]
        doc, task, tags = g.make(kind)
        text = doc.text
        for s in doc.spans:
            assert text[s["start"] : s["end"]], s
        out.append({
            "id": f"{split}-{i:04d}", "synthetic": True, "kind": kind, "text": text,
            "spans": sorted(doc.spans, key=lambda s: s["start"]),
            "task": task if g.rng.random() < 0.6 else None, "tags": sorted(set(tags)),
        })
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--split", required=True)
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--quasi", action="store_true", help="prose/document items with quasi-identifier phrases")
    a = ap.parse_args()
    out = a.out or ROOT / "data" / f"{a.split}.jsonl"
    rows = generate(a.n, a.seed, a.split, quasi=a.quasi)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} synthetic items to {out}")


if __name__ == "__main__":
    main()
