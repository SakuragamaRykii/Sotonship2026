"""Per-session vault: original ↔ surrogate mappings.

The vault lives in memory. It is never logged and never sent anywhere. Secrets and other
REMOVEd values are never stored here. (The CLI can persist a session to a local, gitignored
`.sessions/` file so `rehydrate` can run in a later process; see `Session.save`.)
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets as _stdlib_secrets
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import surrogates as S
from .detect.merge import link_person, name_tokens, split_title

# Surrogate families that use a textual prefix; if the input already contains text of that
# shape, the session switches to a fresh prefix so rehydration stays unambiguous.
PREFIX_FAMILIES = {
    "person": ("Person", r"\b{p}_\d+\b"),
    "username": ("username", r"\b{p}_\d+\b"),
    "email": ("user", r"\b{p}_\d+(?:\+[^@\s]*)?@example\.com\b"),
    "address": ("ADDRESS", r"\[{p}_\d+\]"),
}
_IP4_POOL = ["198.51.100", "203.0.113", "192.0.2"] + [f"198.{a}.{b}" for a in (18, 19) for b in range(256)]


@dataclass
class Vault:
    # (type, normalised original) -> surrogate
    forward: dict[tuple[str, str], str] = field(default_factory=dict)
    # surrogate -> original (exact text of the first / most complete mention)
    reverse: dict[str, str] = field(default_factory=dict)
    # exact original text -> (type, surrogate); used by the leak check
    seen: dict[str, tuple[str, str]] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    prefixes: dict[str, str] = field(default_factory=lambda: {k: v[0] for k, v in PREFIX_FAMILIES.items()})
    persons: dict[frozenset[str], str] = field(default_factory=dict)  # name tokens -> surrogate
    email_bases: dict[tuple[str, str], int] = field(default_factory=dict)  # (local, domain) -> N
    ip4_nets: dict[str, str] = field(default_factory=dict)  # original /24 -> surrogate /24
    ip6_nets: dict[str, str] = field(default_factory=dict)  # original /64 -> surrogate /64

    # ---- helpers ---------------------------------------------------------------------------
    def _next(self, key: str) -> int:
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    def _record(self, type_: str, norm: str, original: str, surrogate: str, canonical: bool = True) -> str:
        self.forward.setdefault((type_, norm), surrogate)
        if canonical or surrogate not in self.reverse:
            self.reverse.setdefault(surrogate, original)
        self.seen.setdefault(original, (type_, surrogate))
        return surrogate

    def _free(self, candidate: str, text: str) -> bool:
        """A surrogate is usable if it is not already in the input or in use for another original."""
        return candidate.lower() not in text.lower() and candidate not in self.reverse and candidate not in self.seen

    def ensure_prefixes(self, text: str) -> None:
        """Collision check: switch a family's prefix if the input already contains that shape."""
        for type_, (base, pattern) in PREFIX_FAMILIES.items():
            p = self.prefixes[type_]
            used = any(sur for (t, _), sur in self.forward.items() if t == type_)
            if re.search(pattern.format(p=re.escape(p)), text, re.IGNORECASE) and not used:
                k = 0
                while re.search(pattern.format(p=re.escape(p)), text, re.IGNORECASE):
                    k += 1
                    p = f"{base}{chr(ord('A') + (k % 26))}{k // 26 or ''}"
                self.prefixes[type_] = p

    def surrogate_patterns(self) -> list[str]:
        """Regexes for every surrogate family this session can emit (for rehydration warnings)."""
        pats = [pattern.format(p=re.escape(p)) for t, (b, pattern) in PREFIX_FAMILIES.items()
                for p in {self.prefixes[t], b}]
        pats += [
            r"\b07700[\s\-]?900[\s\-]?\d{3}\b", r"\+44\s?7700[\s\-]?900[\s\-]?\d{3}\b",
            r"\b00000000-0000-4000-8000-[0-9a-fA-F]{12}\b", r"\b(?:198\.51\.100|203\.0\.113|192\.0\.2)\.\d{1,3}\b",
            r"\b2001:db8:[0-9a-f:]+",
        ]
        return pats

    # ---- pseudonymisation --------------------------------------------------------------------
    def pseudonymise(self, type_: str, original: str, text: str, keep_district: bool = True) -> str:
        handler = getattr(self, f"_p_{type_}", None)
        if handler is not None:
            return handler(original, text, keep_district) if type_ == "address" else handler(original, text)
        return self._p_generic(type_, original, text)

    def _p_person(self, original: str, text: str) -> str:
        title, name = split_title(original)
        toks = name_tokens(name)
        if not toks:
            return original
        sur = link_person(toks, self.persons)
        if sur is None:
            while True:
                sur = f"{self.prefixes['person']}_{self._next('person')}"
                if self._free(sur, text):
                    break
        elif len(toks) > max(len(t) for t, s in self.persons.items() if s == sur):
            self.reverse[sur] = name  # upgrade canonical form to the most complete mention
        self.persons.setdefault(toks, sur)
        self._record("person", " ".join(sorted(toks)), name, sur)
        return title + sur

    def _p_email(self, original: str, text: str) -> str:
        norm = S.norm_email(original)
        if ("email", norm) in self.forward:
            sur = self.forward[("email", norm)]
            self.seen.setdefault(original, ("email", sur))
            return sur
        base, tag, domain = S.split_email(original)
        n = self.email_bases.get((base, domain))
        if n is None:
            while True:
                n = self._next("email")
                if self._free(S.email_surrogate(self.prefixes["email"], n, None), text):
                    break
            self.email_bases[(base, domain)] = n
        return self._record("email", norm, original, S.email_surrogate(self.prefixes["email"], n, tag))

    def _p_phone(self, original: str, text: str) -> str:
        norm = S.norm_phone(original)
        n = self.counters.get(f"phone:{norm}")
        if n is None:
            while True:
                n = self._next("phone")
                if self._free(S.phone_surrogate("07", n), text):
                    break
            self.counters[f"phone:{norm}"] = n
        sur = S.phone_surrogate(original, n)
        self.forward.setdefault(("phone", norm), sur)
        self.reverse.setdefault(sur, original)
        self.seen.setdefault(original, ("phone", sur))
        return sur

    def _p_ip(self, original: str, text: str) -> str:
        try:
            ip = ipaddress.ip_address(original)
        except ValueError:
            return self._p_generic("ip", original, text)
        norm = ip.compressed
        if ("ip", norm) in self.forward:
            sur = self.forward[("ip", norm)]
            self.seen.setdefault(original, ("ip", sur))
            return sur
        if ip.version == 4:
            octets = norm.split(".")
            net = ".".join(octets[:3])
            if net not in self.ip4_nets:
                used = set(self.ip4_nets.values())
                self.ip4_nets[net] = next(
                    p for p in _IP4_POOL if p not in used and f"{p}." not in text and p != net
                )
            sur = f"{self.ip4_nets[net]}.{octets[3]}"
        else:
            exploded = ip.exploded.split(":")
            net = ":".join(exploded[:4])
            if net not in self.ip6_nets:
                self.ip6_nets[net] = f"2001:db8:0:{len(self.ip6_nets) + 1:x}"
            sur = f"{self.ip6_nets[net]}::{self._next('ip6:' + net):x}"
        return self._record("ip", norm, original, sur)

    def _p_uuid(self, original: str, text: str) -> str:
        norm = original.lower()
        if ("uuid", norm) in self.forward:
            sur = self.forward[("uuid", norm)]
            self.seen.setdefault(original, ("uuid", sur))
            return sur
        while True:
            sur = S.uuid_surrogate(original, self._next("uuid"))
            if self._free(sur, text):
                break
        return self._record("uuid", norm, original, sur)

    def _p_address(self, original: str, text: str, keep_district: bool) -> str:
        norm = S.norm_text(original)
        key = ("address", norm)
        if key in self.forward:
            core = self.forward[key]
        else:
            while True:
                core = f"[{self.prefixes['address']}_{self._next('address')}]"
                if self._free(core, text):
                    break
            self.forward[key] = core
            self.reverse.setdefault(core, original)
        district = S.postcode_district(original) if keep_district else None
        sur = f"{core}, {district}" if district else core
        self.reverse.setdefault(sur, original)
        self.seen.setdefault(original, ("address", sur))
        return sur

    def _p_username(self, original: str, text: str) -> str:
        return self._p_prefixed("username", original, text)

    def _p_prefixed(self, type_: str, original: str, text: str) -> str:
        norm = S.norm_text(original)
        if (type_, norm) in self.forward:
            sur = self.forward[(type_, norm)]
            self.seen.setdefault(original, (type_, sur))
            return sur
        while True:
            sur = f"{self.prefixes[type_]}_{self._next(type_)}"
            if self._free(sur, text):
                break
        return self._record(type_, norm, original, sur)

    def _p_generic(self, type_: str, original: str, text: str) -> str:
        """user_id and any custom type: keep the identifier's shape."""
        norm = S.norm_text(original)
        if (type_, norm) in self.forward:
            sur = self.forward[(type_, norm)]
            self.seen.setdefault(original, (type_, sur))
            return sur
        while True:
            sur = S.id_surrogate(original, self._next("id"))
            if self._free(sur, text) and sur != original:
                break
        return self._record(type_, norm, original, sur)

    def shifted_date(self, original: str, days: int, text: str) -> str | None:
        """SHIFT: stored like a pseudonym so the response can be shifted back."""
        if ("date", original) in self.forward:
            return self.forward[("date", original)]
        sur = S.shift_date(original, days)
        if sur is None:
            return None
        return self._record("date", original, original, sur)

    # ---- (de)serialisation, for the CLI only ------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "forward": [[t, n, s] for (t, n), s in self.forward.items()],
            "reverse": self.reverse,
            "seen": {k: list(v) for k, v in self.seen.items()},
            "counters": self.counters,
            "prefixes": self.prefixes,
            "persons": [[sorted(k), v] for k, v in self.persons.items()],
            "email_bases": [[b, d, n] for (b, d), n in self.email_bases.items()],
            "ip4_nets": self.ip4_nets,
            "ip6_nets": self.ip6_nets,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Vault":
        return cls(
            forward={(t, n): s for t, n, s in d["forward"]},
            reverse=d["reverse"],
            seen={k: tuple(v) for k, v in d["seen"].items()},
            counters=d["counters"],
            prefixes=d["prefixes"],
            persons={frozenset(k): v for k, v in d["persons"]},
            email_bases={(b, dm): n for b, dm, n in d["email_bases"]},
            ip4_nets=d["ip4_nets"],
            ip6_nets=d["ip6_nets"],
        )


def _random_offset(lo: int = 30, hi: int = 365) -> int:
    days = lo + _stdlib_secrets.randbelow(hi - lo + 1)
    return days if _stdlib_secrets.randbelow(2) else -days


@dataclass
class Session:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    vault: Vault = field(default_factory=Vault)
    date_offset_days: int = field(default_factory=_random_offset)

    SESSIONS_DIR = Path(".sessions")

    def save(self, directory: Path | None = None) -> Path:
        """Persist locally (CLI only). The file holds pseudonym mappings, never secrets."""
        d = Path(directory or self.SESSIONS_DIR)
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{self.id}.json"
        path.write_text(
            json.dumps({"id": self.id, "date_offset_days": self.date_offset_days, "vault": self.vault.to_dict()}),
            encoding="utf-8",
        )
        return path

    @classmethod
    def load(cls, session_id: str, directory: Path | None = None) -> "Session":
        if not re.fullmatch(r"[A-Za-z0-9_\-]+", session_id):
            raise ValueError("invalid session id")
        path = Path(directory or cls.SESSIONS_DIR) / f"{session_id}.json"
        d = json.loads(path.read_text(encoding="utf-8"))
        return cls(id=d["id"], vault=Vault.from_dict(d["vault"]), date_offset_days=d["date_offset_days"])
