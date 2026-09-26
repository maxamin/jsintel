"""Turn discovered paths plus a wordlist into concrete URLs to probe.

The hit-rate strategy is to extend *known-good prefixes*. A discovered
``/api/v1/users`` tells us ``/api/v1/`` and ``/api/`` are real directories on the
target, so appending high-frequency API words there is far more productive than
brute-forcing from ``/``. :func:`directory_contexts` derives those prefixes and
:func:`candidates_for` expands each with the wordlist, de-duplicated and bounded.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator
from urllib.parse import urlunsplit

from .urlutil import safe_urlsplit

from .models import Candidate, Category


def base_and_path(origin: str, fallback_base: str = "") -> tuple[str, str]:
    """Return ``(scheme://host[:port], path)`` for a finding.

    ``origin`` may be an absolute URL, a protocol-relative ``//host/x`` URL, or a
    root-relative ``/path``. Relative paths borrow their host from
    ``fallback_base`` (the asset the path was discovered in).
    """
    value = origin.strip()
    if value.startswith("//"):
        value = "https:" + value
    if "://" in value:
        parts = safe_urlsplit(value)
        base = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        path = parts.path or "/"
        return base, path
    # Root-relative or bare path: needs a host from the discovering asset.
    if fallback_base:
        fb = safe_urlsplit(fallback_base if "://" in fallback_base else "https://" + fallback_base)
        base = urlunsplit((fb.scheme or "https", fb.netloc, "", "", ""))
    else:
        base = ""
    path = value.split("#", 1)[0].split("?", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    return base, path


def directory_contexts(path: str, depth: int = 2) -> list[str]:
    """Return up to ``depth`` directory prefixes, deepest first.

    ``/api/v1/users`` -> ``['/api/v1/', '/api/']``; ``/`` -> ``['/']``.
    """
    path = path.split("#", 1)[0].split("?", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    directory = path if path.endswith("/") else path.rsplit("/", 1)[0] + "/"
    contexts: list[str] = []
    current = directory or "/"
    while True:
        if current not in contexts:
            contexts.append(current)
        if current == "/" or len(contexts) >= depth:
            break
        current = current[:-1].rsplit("/", 1)[0] + "/"
    return contexts


# Characters that, inside a wordlist entry, would corrupt the URL structure
# rather than name a path segment: whitespace, a query/fragment introducer, or a
# backslash. Some SecLists/Assetnote lists carry stray operator tokens ("?:",
# "&&", "==", bare "#"); appended to a base they yield junk URLs like
# "https://host/?:" (a query, not a path) that a permissive origin answers 200/403
# to, inflating the "interesting" count. These are dropped before probing.
_BAD_WORD_CHARS = frozenset(" \t\r\n?#\\")


def _clean_word(word: str) -> str:
    cleaned = word.strip().lstrip("/")
    if not cleaned:
        return ""
    if any(ch in _BAD_WORD_CHARS or ord(ch) < 0x20 for ch in cleaned):
        return ""
    return cleaned


def candidates_for(
    origin: str,
    base: str,
    category: Category,
    words: Iterable[str],
    *,
    depth: int = 2,
    extensions: tuple[str, ...] = (),
    seen: set[str] | None = None,
) -> Iterator[Candidate]:
    """Yield de-duplicated :class:`Candidate` URLs for one discovered path."""
    resolved_base, path = base_and_path(origin, base)
    if not resolved_base:
        return
    tracker = seen if seen is not None else set()
    for context in directory_contexts(path, depth=depth):
        for raw in words:
            word = _clean_word(raw)
            if not word:
                continue
            variants = [word]
            for ext in extensions:
                if not word.endswith(ext):
                    variants.append(word + ext)
            for variant in variants:
                url = resolved_base + context + variant
                if url in tracker:
                    continue
                tracker.add(url)
                yield Candidate(
                    url=url,
                    word=variant,
                    category=category,
                    origin=origin,
                    base=resolved_base,
                )
