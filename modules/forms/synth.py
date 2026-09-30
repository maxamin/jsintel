"""Synthesize realistic, spec-valid values for form fields.

The goal is data that passes both HTML5 client-side validation *and* typical
server-side "does this look like a real X" checks, so an automated submission is
not bounced before it ever reaches the interesting code paths. This mirrors ZAP's
*Form Handler* value generation, but constraint-aware: every generated value
honours the field's ``type``, ``pattern``, ``min``/``max``, ``minlength``/
``maxlength``, ``step`` and ``<option>`` set.

Determinism: a :class:`Synthesizer` seeded with a fixed value produces the same
data across runs, which keeps report diffs and tests stable. Callers that want
fresh data each run simply omit the seed.
"""
from __future__ import annotations

import random
import string
from datetime import date, timedelta

from .models import Field

_FIRST = ("James", "Mary", "Robert", "Linda", "Michael", "Sarah", "David", "Emma",
          "Omar", "Yuki", "Ingrid", "Diego", "Aisha", "Noah", "Priya", "Lucas")
_LAST = ("Smith", "Johnson", "Nguyen", "Garcia", "Muller", "Kowalski", "Rossi",
         "Okafor", "Sato", "Andersson", "Silva", "Haddad", "Novak", "Patel")
_CITY = ("Springfield", "Riverton", "Aurora", "Fairview", "Kingston", "Lakewood",
         "Ashford", "Bridgewater", "Clearwater", "Northgate")
_COMPANY = ("Acme LLC", "Globex Corp", "Initech", "Umbrella Co", "Hooli Inc",
            "Stark Industries", "Wayne Enterprises", "Wonka Ltd")
_STREETS = ("Main St", "Oak Ave", "Maple Dr", "Elm St", "Cedar Ln", "Park Blvd")
_WORDS = ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "harbor",
          "meadow", "quartz", "summit", "willow", "zephyr")


class Synthesizer:
    def __init__(self, seed: int | str | None = None):
        self._rng = random.Random(seed)

    # -- small helpers ---------------------------------------------------------
    def _pick(self, seq):
        return self._rng.choice(seq)

    def _digits(self, n: int) -> str:
        return "".join(self._rng.choice(string.digits) for _ in range(n))

    def _words(self, n: int) -> str:
        return " ".join(self._pick(_WORDS) for _ in range(n)).capitalize()

    def _clamp_len(self, s: str, fld: Field) -> str:
        """Honour minlength/maxlength once a value is otherwise chosen."""
        if fld.maxlength is not None and fld.maxlength >= 0 and len(s) > fld.maxlength:
            s = s[: fld.maxlength]
        if fld.minlength is not None and len(s) < fld.minlength:
            pad = fld.minlength - len(s)
            s = s + "".join(self._rng.choice(string.ascii_lowercase) for _ in range(pad))
        return s

    # -- semantic-driven values ------------------------------------------------
    def _email(self) -> str:
        return f"{self._pick(_FIRST).lower()}.{self._pick(_LAST).lower()}{self._rng.randint(1, 999)}@example.com"

    def _phone(self) -> str:
        # E.164-ish, widely accepted by tel validators.
        return f"+1{self._rng.randint(2, 9)}{self._digits(9)}"

    def _url(self) -> str:
        return f"https://{self._pick(_WORDS)}{self._rng.randint(1, 99)}.example.com/"

    def _password(self) -> str:
        # Meets common complexity policies: upper, lower, digit, symbol, length >= 12.
        base = (self._pick(_FIRST) + self._pick(_LAST)
                + str(self._rng.randint(10, 99)) + self._pick("!@#$%^&*"))
        return base + "aZ"  # guarantee both cases even for short name picks

    def _card(self) -> str:
        # A Luhn-valid Visa TEST number (4111 1111 1111 1111). Test data only; the
        # deny-list blocks submission of payment forms, so this is for field-shape
        # validation on non-payment forms that merely look card-ish.
        return "4111111111111111"

    def _by_semantic(self, sem: str, fld: Field) -> str | None:
        if sem == "email":
            return self._email()
        if sem == "firstname":
            return self._pick(_FIRST)
        if sem == "lastname":
            return self._pick(_LAST)
        if sem == "fullname":
            return f"{self._pick(_FIRST)} {self._pick(_LAST)}"
        if sem == "username":
            return f"{self._pick(_FIRST).lower()}{self._rng.randint(100, 9999)}"
        if sem == "password":
            return self._password()
        if sem == "phone":
            return self._phone()
        if sem == "url":
            return self._url()
        if sem == "zip":
            return self._digits(5)
        if sem == "city":
            return self._pick(_CITY)
        if sem == "state":
            return self._pick(("CA", "NY", "TX", "WA", "IL", "MA"))
        if sem == "country":
            return self._pick(("US", "GB", "DE", "FR", "JP", "BR"))
        if sem == "street":
            return f"{self._rng.randint(1, 9999)} {self._pick(_STREETS)}"
        if sem == "company":
            return self._pick(_COMPANY)
        if sem == "card":
            return self._card()
        if sem == "cvv":
            return self._digits(3)
        if sem == "expiry":
            return f"{self._rng.randint(1, 12):02d}/{(date.today().year + self._rng.randint(1, 5)) % 100:02d}"
        if sem == "otp":
            return self._digits(6)
        if sem == "age":
            return str(self._rng.randint(18, 80))
        if sem == "quantity":
            return str(self._rng.randint(1, 5))
        if sem == "search":
            return self._pick(_WORDS)
        if sem == "subject":
            return self._words(3)
        if sem == "message":
            return self._words(8) + "."
        if sem == "date":
            return self._date_value(fld)
        return None

    # -- type-driven values ----------------------------------------------------
    def _number_value(self, fld: Field) -> str:
        lo_s, hi_s, step_s = fld.min, fld.max, fld.step
        try:
            lo = float(lo_s) if lo_s not in (None, "") else 0.0
        except ValueError:
            lo = 0.0
        try:
            hi = float(hi_s) if hi_s not in (None, "") else lo + 100.0
        except ValueError:
            hi = lo + 100.0
        if hi < lo:
            lo, hi = hi, lo
        # HTML number/range inputs default to step=1 (integers only); only an explicit
        # step="any" permits non-integer values. Honour that so a plain <input
        # type=number min=18 max=99> never yields a rejected float like 47.62.
        if step_s == "any":
            step = None
        elif step_s in (None, ""):
            step = 1.0
        else:
            try:
                step = float(step_s)
            except ValueError:
                step = 1.0
        if step and step > 0:
            n_steps = int((hi - lo) / step)
            val = lo + step * self._rng.randint(0, max(0, n_steps))
        else:
            val = self._rng.uniform(lo, hi)
        # Present integers without a trailing ".0".
        return str(int(val)) if val == int(val) else f"{val:.2f}"

    def _date_value(self, fld: Field) -> str:
        base = date.today()
        lo = _parse_date(fld.min) or (base - timedelta(days=365 * 30))
        hi = _parse_date(fld.max) or base
        if hi < lo:
            lo, hi = hi, lo
        span = (hi - lo).days or 1
        return (lo + timedelta(days=self._rng.randint(0, span))).isoformat()

    # -- pattern support -------------------------------------------------------
    def _pattern_value(self, pattern: str, fld: Field) -> str | None:
        val = sample_pattern(pattern, self._rng, fld.minlength or 1)
        if val is None:
            return None
        return self._clamp_len(val, fld)

    # -- main entry point ------------------------------------------------------
    def value_for(self, fld: Field) -> str:
        """Return a single spec-valid value string for ``fld``.

        For checkbox/radio the return is the value to submit when checked; for
        select it is one of the valid options; ``value_for`` never decides whether
        an optional control is *included* — the engine does that.
        """
        t = fld.type

        # Controls with an enumerated set: always pick from it (never invent).
        if fld.tag == "select":
            return self._pick(fld.options) if fld.options else ""
        if t in ("radio", "checkbox"):
            return fld.value or "on"
        if fld.options:  # <input list=datalist> — a hint, not a hard constraint
            if self._rng.random() < 0.75:
                return self._pick(fld.options)

        # A pattern is the strongest textual constraint: satisfy it first.
        if fld.pattern:
            pv = self._pattern_value(fld.pattern, fld)
            if pv is not None:
                return pv

        # Typed inputs the browser validates structurally.
        if t == "email":
            return self._email()
        if t == "tel":
            return self._phone()
        if t == "url":
            return self._url()
        if t == "number" or t == "range":
            return self._number_value(fld)
        if t == "date":
            return self._date_value(fld)
        if t == "datetime-local":
            return self._date_value(fld) + "T12:30"
        if t == "month":
            return self._date_value(fld)[:7]
        if t == "week":
            return f"{date.today().year}-W{self._rng.randint(1, 52):02d}"
        if t == "time":
            return f"{self._rng.randint(0, 23):02d}:{self._rng.randint(0, 59):02d}"
        if t == "color":
            return "#%06x" % self._rng.randint(0, 0xFFFFFF)
        if t == "password":
            return self._clamp_len(self._password(), fld)
        if t == "hidden":
            # Preserve server-provided hidden values (CSRF tokens, flow ids, …).
            return fld.value

        # Otherwise use the inferred semantic, then fall back to generic text.
        sem = fld.semantic
        by_sem = self._by_semantic(sem, fld) if sem else None
        if by_sem is not None:
            return self._clamp_len(by_sem, fld)

        base = fld.value or self._words(2)
        return self._clamp_len(base, fld)


# =============================================================================
# A tiny, ReDoS-safe regex sampler: generate a string that the (browser-anchored)
# HTML5 ``pattern`` would accept. It supports the constructs that appear in real
# form patterns; anything it cannot model returns None so the caller falls back to
# a type/semantic value. It is bounded (never backtracks, caps repetition) so a
# pathological pattern can never hang or blow up memory.
# =============================================================================
_MAX_REPEAT = 8            # cap for *, +, {n,} so unbounded quantifiers stay finite
_MAX_OUTPUT = 256          # hard ceiling on generated length


def sample_pattern(pattern: str, rng: random.Random, min_len: int = 1) -> str | None:
    """Produce a string matching ``pattern`` (HTML5 semantics: fully anchored).

    Returns ``None`` for constructs the sampler does not model. Never raises; the
    bounds above guarantee it terminates quickly on any input.
    """
    if not pattern or len(pattern) > 2000:
        return None
    src = pattern
    i = 0
    out: list[str] = []

    def emit(s: str) -> bool:
        if sum(len(x) for x in out) + len(s) > _MAX_OUTPUT:
            return False
        out.append(s)
        return True

    def atom_chars(j: int):
        """Parse one atom at position j; return (generator_of_one_char_str, next_j) or (None, j)."""
        ch = src[j]
        if ch == "[":
            k = j + 1
            negate = False
            if k < len(src) and src[k] == "^":
                negate = True
                k += 1
            members: list[str] = []
            ranges: list[tuple[str, str]] = []
            while k < len(src) and src[k] != "]":
                if src[k] == "\\" and k + 1 < len(src):
                    members.extend(_class_escape(src[k + 1]))
                    k += 2
                    continue
                if k + 2 < len(src) and src[k + 1] == "-" and src[k + 2] != "]":
                    ranges.append((src[k], src[k + 2]))
                    k += 3
                    continue
                members.append(src[k])
                k += 1
            if k >= len(src):
                return None, j
            k += 1  # skip ']'
            pool = list(members)
            for a, b in ranges:
                if ord(a) <= ord(b) and ord(b) - ord(a) < 200:
                    pool.extend(chr(c) for c in range(ord(a), ord(b) + 1))
            if negate:
                allowed = [c for c in (string.ascii_letters + string.digits) if c not in pool]
                pool = allowed or ["x"]
            pool = [c for c in pool if c.isprintable() and c not in "\n\r"]
            if not pool:
                return None, j
            return (lambda: rng.choice(pool)), k
        if ch == "\\" and j + 1 < len(src):
            pool = _class_escape(src[j + 1])
            if not pool:
                return None, j
            return (lambda p=pool: rng.choice(p)), j + 2
        if ch == ".":
            return (lambda: rng.choice(string.ascii_lowercase + string.digits)), j + 1
        if ch in "()|":
            return None, j  # groups/alternation handled below, not as an atom
        # A literal character.
        return (lambda c=ch: c), j + 1

    # Handle a single top-level alternation by picking one branch up front.
    if "|" in src and src.count("(") == 0:
        src = rng.choice(src.split("|"))

    while i < len(src):
        ch = src[i]
        if ch in "^$":
            i += 1
            continue
        if ch == "(":
            # Grab the group body up to the matching ')', pick a branch, recurse.
            depth, k = 1, i + 1
            while k < len(src) and depth:
                if src[k] == "(":
                    depth += 1
                elif src[k] == ")":
                    depth -= 1
                k += 1
            if depth:
                return None
            body = src[i + 1:k - 1]
            body = body[2:] if body.startswith("?:") else body
            branch = rng.choice(body.split("|")) if "|" in body else body
            sub = sample_pattern("^" + branch + "$", rng, 0)
            if sub is None:
                return None
            # Apply a following quantifier to the whole group.
            reps, k = _read_quant(src, k, rng)
            for _ in range(reps):
                if not emit(sub):
                    break
            i = k
            continue
        gen, j = atom_chars(i)
        if gen is None:
            return None
        reps, j = _read_quant(src, j, rng, default=1)
        for _ in range(reps):
            if not emit(gen()):
                break
        i = j

    result = "".join(out)
    # Top up to any minimum the pattern hinted at via minlength.
    while len(result) < min_len and len(result) < _MAX_OUTPUT:
        result += rng.choice(string.ascii_lowercase)
    return result


def _class_escape(c: str) -> list[str]:
    if c == "d":
        return list(string.digits)
    if c == "w":
        return list(string.ascii_letters + string.digits + "_")
    if c == "s":
        return [" "]
    if c == "D":
        return list(string.ascii_letters)
    if c == "W":
        return [" ", "-"]
    if c == "S":
        return list(string.ascii_lowercase)
    return [c]  # an escaped literal (\. \+ \/ …)


def _read_quant(src: str, j: int, rng: random.Random, default: int = 1) -> tuple[int, int]:
    """Read a quantifier at position j; return (repeat_count, next_index)."""
    if j >= len(src):
        return default, j
    ch = src[j]
    if ch == "*":
        return rng.randint(0, _MAX_REPEAT), j + 1
    if ch == "+":
        return rng.randint(1, _MAX_REPEAT), j + 1
    if ch == "?":
        return rng.randint(0, 1), j + 1
    if ch == "{":
        end = src.find("}", j)
        if end == -1:
            return default, j
        spec = src[j + 1:end]
        try:
            if "," in spec:
                lo_s, hi_s = spec.split(",", 1)
                lo = int(lo_s) if lo_s else 0
                hi = int(hi_s) if hi_s else lo + _MAX_REPEAT
            else:
                lo = hi = int(spec)
        except ValueError:
            return default, j
        lo = max(0, min(lo, _MAX_OUTPUT))
        hi = max(lo, min(hi, lo + _MAX_REPEAT))
        return rng.randint(lo, hi), end + 1
    return default, j


def _parse_date(s: str | None):
    if not s:
        return None
    try:
        return date.fromisoformat(s[:10])
    except ValueError:
        return None
