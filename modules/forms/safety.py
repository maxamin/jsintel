"""Guard-rails for the active form stage.

Submission is on by default, but firing synthesized data at a payment, trading,
withdrawal or session-ending endpoint can cause real, irreversible side effects on
an authenticated target. This module holds a conservative deny-list, matched
against the form's resolved action URL (and its owning page), that skips such
targets unless the operator explicitly overrides it.

The list is intentionally broad and cheap to extend; a false "skip" only costs one
un-exercised form, whereas a false "submit" against, say, ``/swap/execute`` under a
live session is unrecoverable.
"""
from __future__ import annotations

import re

# Substrings/patterns that mark an endpoint as too dangerous to auto-submit to.
_DESTRUCTIVE = (
    r"check\s*out", r"checkout", r"payment", r"\bpay\b", r"billing", r"invoice",
    r"purchase", r"\border\b", r"subscribe", r"\bdonat",           # commerce
    r"swap", r"trade", r"exchange", r"bridge", r"withdraw", r"deposit",
    r"transfer", r"send(funds|money|token|eth|btc)?", r"stake", r"unstake",
    r"mint", r"burn", r"claim", r"defi", r"wallet", r"redeem",     # crypto / finance
    r"delete", r"remove", r"destroy", r"deactivate", r"close[-_]?account",
    r"cancel", r"reset", r"wipe", r"purge",                         # destructive state
    r"logout", r"log[-_]?off", r"signout", r"sign[-_]?out",         # session-ending
)
_DENY_RE = re.compile("|".join(_DESTRUCTIVE), re.IGNORECASE)


def is_destructive(url: str, extra_denylist: list[str] | None = None) -> str | None:
    """Return the matched danger token if ``url`` looks destructive, else ``None``."""
    if not url:
        return None
    m = _DENY_RE.search(url)
    if m:
        return m.group(0)
    for term in (extra_denylist or ()):
        if term and term.lower() in url.lower():
            return term
    return None


# Request methods that mutate server state. GET/HEAD are treated as safe to fire.
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def masked_fields(fields: dict[str, str]) -> dict[str, str]:
    """Mask likely-secret values (passwords, tokens, card data) for reporting."""
    secret = re.compile(r"pass|pwd|token|secret|cvv|cvc|card|cc[-_]?num|\bpan\b|ssn|otp|auth|api[-_]?key",
                        re.IGNORECASE)
    out: dict[str, str] = {}
    for k, v in fields.items():
        if secret.search(k):
            out[k] = f"<{len(v)} chars>"
        else:
            out[k] = v
    return out
