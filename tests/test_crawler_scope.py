"""Scope-derivation tests for the crawler's `reg_dom` shell helper.

`modules/crawler.sh` runs top-to-bottom (not sourceable), so we extract just the
`reg_dom()` definition and evaluate it in a bash subshell. This guards the
scope-safety property that an IP target scopes to the exact address rather than a
bogus eTLD+1 (regression: 127.0.0.9 -> "0.9" would have admitted any x.0.9 host).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

CRAWLER_SH = Path(__file__).resolve().parents[1] / "modules" / "crawler.sh"


def _extract_reg_dom() -> str:
    text = CRAWLER_SH.read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("reg_dom()"):
            return line
    raise AssertionError("reg_dom() definition not found in crawler.sh")


def _reg_dom(host: str) -> str:
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    script = f"{_extract_reg_dom()}\nprintf '%s\\n' \"$1\" | reg_dom\n"
    out = subprocess.run(
        ["bash", "-c", script, "bash", host],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


@pytest.mark.parametrize(
    "host,expected",
    [
        # IPv4 literals scope to the exact address, not a fake registered domain
        ("127.0.0.9", "127.0.0.9"),
        ("10.20.0.9", "10.20.0.9"),
        ("192.168.1.1", "192.168.1.1"),
        # IPv6 literals pass through as well
        ("::1", "::1"),
        ("fe80::1", "fe80::1"),
        # real domains still collapse to eTLD+1
        ("app.example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("a.b.c.gala.games", "gala.games"),
        # a bare single-label host is returned as-is
        ("localhost", "localhost"),
    ],
)
def test_reg_dom(host: str, expected: str) -> None:
    assert _reg_dom(host) == expected


def test_ip_does_not_collapse_to_octets() -> None:
    """The specific regression: an IP must never become a 2-octet 'domain'."""
    assert _reg_dom("127.0.0.9") != "0.9"
    # and two unrelated IPs sharing the last two octets must not share a scope key
    assert _reg_dom("127.0.0.9") != _reg_dom("10.20.0.9")
