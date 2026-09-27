"""URL parsing helpers that tolerate the malformed strings recon produces.

Discovered "URLs" are frequently not URLs at all -- regex fragments, template
literals and minifier artifacts pulled out of JavaScript (e.g. ``//i],[[d,``,
``https://(?:[A-Za-z0-9-]+``). Python's :func:`urllib.parse.urlsplit` raises
``ValueError`` ("Invalid IPv6 URL") on some of these, which would otherwise abort
the whole fuzz run. :func:`safe_urlsplit` returns an empty result instead so the
caller can simply skip the entry.
"""
from __future__ import annotations

from urllib.parse import SplitResult, urlsplit

_EMPTY = SplitResult("", "", "", "", "")


def safe_urlsplit(value: str) -> SplitResult:
    """Like :func:`urllib.parse.urlsplit` but returns an empty result on error."""
    try:
        return urlsplit(value)
    except ValueError:
        return _EMPTY
