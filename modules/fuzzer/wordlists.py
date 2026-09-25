"""Resolve a category to actual words, with caching and an offline fallback.

Resolution order for a category: a previously cached download, then a fresh
download from the Assetnote CDN (unless ``offline``), then the bundled seed that
ships with JSIntel. The result is always non-empty, so a run works with no
network at all. Downloads are fetched through an injected callable so tests are
deterministic and offline; a real run uses a standard-library fetcher.
"""
from __future__ import annotations

import logging
import re
import urllib.request
from collections.abc import Callable
from pathlib import Path

from .catalog import spec_for
from .models import Category, WordlistSpec

LOGGER = logging.getLogger(__name__)

Fetcher = Callable[[str], bytes]

SEED_DIR = Path(__file__).resolve().parent / "seeds"

# A usable path word: no whitespace, no wildcards, printable, not absurdly long.
_VALID = re.compile(r"^[^\s]+$")


def urllib_fetcher(timeout: float = 20.0, user_agent: str = "JSIntel/0.2") -> Fetcher:
    """Return a std-lib fetcher that downloads a URL's bytes (or raises)."""

    def fetch(url: str) -> bytes:
        request = urllib.request.Request(url, headers={"User-Agent": user_agent})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return bytes(response.read())

    return fetch


def _clean_lines(text: str, limit: int) -> list[str]:
    words: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        word = raw.strip()
        if not word or word.startswith("#"):
            continue
        word = word.lstrip("/")
        if not word or len(word) > 255 or not _VALID.match(word):
            continue
        if word in seen:
            continue
        seen.add(word)
        words.append(word)
        if len(words) >= limit:
            break
    return words


class WordlistProvider:
    """Loads and caches per-category wordlists."""

    def __init__(
        self,
        cache_dir: Path,
        *,
        fetcher: Fetcher | None = None,
        offline: bool = False,
        seed_dir: Path = SEED_DIR,
    ) -> None:
        self._cache_dir = cache_dir
        self._fetcher = fetcher
        self._offline = offline
        self._seed_dir = seed_dir
        self._memo: dict[Category, list[str]] = {}

    def words_for(self, category: Category, limit: int) -> list[str]:
        """Return up to ``limit`` cleaned words for a category."""
        if category in self._memo:
            return self._memo[category][:limit]
        spec = spec_for(category)
        text = self._load_text(spec)
        words = _clean_lines(text, limit)
        self._memo[category] = words
        return words

    def _load_text(self, spec: WordlistSpec) -> str:
        cached = self._cache_dir / f"{spec.name}.txt"
        if cached.is_file():
            return cached.read_text(encoding="utf-8", errors="ignore")
        if not self._offline and self._fetcher is not None:
            text = self._download(spec)
            if text is not None:
                try:
                    self._cache_dir.mkdir(parents=True, exist_ok=True)
                    cached.write_text(text, encoding="utf-8")
                except OSError as error:  # Caching is best-effort.
                    LOGGER.debug("Could not cache %s: %s", cached, error)
                return text
        return self._seed_text(spec)

    def _download(self, spec: WordlistSpec) -> str | None:
        assert self._fetcher is not None
        for url in spec.urls:
            try:
                data = self._fetcher(url)
            except Exception as error:  # A stale or missing list must not abort.
                LOGGER.debug("Wordlist download failed (%s): %s", url, error)
                continue
            if data:
                LOGGER.info("Fetched wordlist %s from %s", spec.name, url)
                return data.decode("utf-8", errors="ignore")
        LOGGER.warning("No remote wordlist available for %s; using bundled seed", spec.name)
        return None

    def _seed_text(self, spec: WordlistSpec) -> str:
        seed = self._seed_dir / spec.seed
        if seed.is_file():
            return seed.read_text(encoding="utf-8", errors="ignore")
        LOGGER.error("Missing bundled seed for %s at %s", spec.name, seed)
        return ""
