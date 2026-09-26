"""Classify a discovered path so the matching wordlist can be chosen.

``classify_path`` is a pure function over a path or URL string. It decides which
:class:`~modules.fuzzer.models.Category` a find belongs to, which in turn selects
the Assetnote wordlist used to extend it. Ordering matters: the most specific,
highest-signal cues win first (GraphQL, then JavaScript by extension, then API
markers), falling back to file/parameter/directory and finally the generic list.
"""
from __future__ import annotations

import re
from .urlutil import safe_urlsplit

from .models import Category

_GRAPHQL_RE = re.compile(r"(^|/)(graphql|graphiql|gql)(/|$|\b)", re.IGNORECASE)
_API_RE = re.compile(
    r"(^|/)(api|apis|rest|restapi|v[0-9]+|service|services|internal|gateway|graph)(/|$)",
    re.IGNORECASE,
)
_JS_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".map")
_FILE_EXT = (
    ".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".cgi", ".pl",
    ".html", ".htm", ".xml", ".json", ".yaml", ".yml", ".ini", ".conf",
    ".config", ".env", ".txt", ".log", ".bak", ".old", ".backup", ".swp",
    ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".sql", ".db", ".sqlite",
    ".pem", ".key", ".crt", ".p12", ".pfx", ".wasm", ".wat",
)


def _split(value: str) -> tuple[str, str]:
    """Return ``(path, query)`` for a path or (protocol-relative) URL."""
    value = value.strip()
    if value.startswith("//"):
        value = "https:" + value
    if "://" in value:
        parts = safe_urlsplit(value)
        return (parts.path or "/"), parts.query
    body = value.split("#", 1)[0]
    path, _, query = body.partition("?")
    return path, query


def _last_segment(path: str) -> str:
    stem = path.rstrip("/")
    return stem.rsplit("/", 1)[-1].lower() if stem else ""


def classify_path(value: str) -> Category:
    """Map a discovered path or URL to its wordlist category."""
    path, query = _split(value)
    lowered = path.lower()
    segment = _last_segment(path)

    if _GRAPHQL_RE.search(lowered):
        return Category.GRAPHQL
    if segment.endswith(_JS_EXT):
        return Category.JS
    if _API_RE.search(lowered):
        return Category.API
    if "." in segment and segment.endswith(_FILE_EXT):
        return Category.FILE
    if query:
        return Category.PARAMETER
    if lowered.endswith("/"):
        return Category.DIRECTORY
    if "." not in segment and segment:
        return Category.DIRECTORY
    return Category.GENERIC
