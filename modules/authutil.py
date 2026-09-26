"""Shared authenticated-session helpers.

JSIntel can drive a target as an authenticated user by supplying a session cookie
(`--cookie`) and/or a bearer/JWT token (`--jwt`) on `jsintel.sh`. Those are exported
as environment variables that every request-making stage reads through this module:

    JSINTEL_AUTH_COOKIE   raw Cookie header value, e.g. "PHPSESSID=abc; security=low"
    JSINTEL_AUTH_BEARER   a token sent as "Authorization: Bearer <token>"

The auth headers are sent only to the hosts a stage contacts, which are constrained
to the operator-supplied authorized scope (the crawl scope is anchored and the
fuzzer is scope-gated), so a supplied session is never sent off-scope.
"""
from __future__ import annotations

import os


def auth_headers(env: dict | None = None) -> dict[str, str]:
    """Build the auth header dict from the environment (empty when none set)."""
    e = os.environ if env is None else env
    headers: dict[str, str] = {}
    cookie = (e.get("JSINTEL_AUTH_COOKIE") or "").strip()
    bearer = (e.get("JSINTEL_AUTH_BEARER") or "").strip()
    if cookie:
        headers["Cookie"] = cookie
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    return headers


def bearer_token(env: dict | None = None) -> str:
    """The raw bearer/JWT token, if one was supplied (else empty string)."""
    e = os.environ if env is None else env
    return (e.get("JSINTEL_AUTH_BEARER") or "").strip()


def is_authenticated(env: dict | None = None) -> bool:
    return bool(auth_headers(env))


def mask(value: str, keep: int = 4) -> str:
    """Mask a secret for logging: keep the first/last few chars only."""
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}…{value[-keep:]} (len {len(value)})"


def describe(env: dict | None = None) -> str:
    """A short, masked description of the active auth for logging."""
    e = os.environ if env is None else env
    parts = []
    if (e.get("JSINTEL_AUTH_COOKIE") or "").strip():
        parts.append(f"cookie={mask(e['JSINTEL_AUTH_COOKIE'].strip())}")
    if (e.get("JSINTEL_AUTH_BEARER") or "").strip():
        parts.append(f"bearer={mask(e['JSINTEL_AUTH_BEARER'].strip())}")
    return ", ".join(parts) if parts else "none"


if __name__ == "__main__":
    import sys
    if "--describe" in sys.argv:
        print(describe())

