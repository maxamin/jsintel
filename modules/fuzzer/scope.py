"""Authorization scope: the set of hosts the fuzzer may send requests to.

Fuzzing sends live requests, so it must only ever touch hosts the operator is
authorized to assess. JavaScript routinely references third-party CDNs, analytics
and social hosts; those show up as findings but must never be probed. The scope
is an explicit allowlist -- an empty scope allows nothing -- and every candidate
is checked against it right before a request is sent, independently of any
earlier filtering.
"""
from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit


def _host_of(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return ""
    if value.startswith("//"):
        value = "https:" + value
    if "://" in value:
        host = urlsplit(value).hostname or ""
    else:
        # Bare "example.com" or "example.com/path" or "example.com:8443".
        host = value.split("/", 1)[0]
    host = host.split("@")[-1]
    host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return host.strip(".")


class Scope:
    """An allowlist of hosts (each also matching its subdomains)."""

    def __init__(self, entries: Iterable[str] = ()) -> None:
        self._hosts: set[str] = set()
        for entry in entries:
            host = _host_of(entry)
            if host:
                self._hosts.add(host)

    @classmethod
    def parse(cls, raw: str | Iterable[str]) -> Scope:
        """Build a scope from a comma/space/newline string or an iterable."""
        if isinstance(raw, str):
            values = raw.replace(",", " ").split()
        else:
            values = list(raw)
        return cls(values)

    @property
    def hosts(self) -> frozenset[str]:
        return frozenset(self._hosts)

    def allows(self, url: str) -> bool:
        """True if ``url``'s host is in scope or a subdomain of an in-scope host."""
        host = _host_of(url)
        if not host or not self._hosts:
            return False
        if host in self._hosts:
            return True
        return any(host.endswith("." + allowed) for allowed in self._hosts)

    def __bool__(self) -> bool:
        return bool(self._hosts)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Scope({sorted(self._hosts)!r})"
