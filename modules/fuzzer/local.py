"""Locally installed wordlists (SecLists and friends) as a first-class source.

Kali and most pentest images ship SecLists at ``/usr/share/seclists``. Those
lists are curated, offline, and already on disk, so when they are present the
fuzzer prefers them over downloading from the Assetnote CDN. Each category maps
to an ordered list of candidate SecLists files (relative to the Web-Content
root); the first one that exists wins. The SecLists root is configurable, and any
arbitrary local list can still be forced by dropping it in the provider's cache
directory (see :mod:`modules.fuzzer.wordlists`).
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path

from .models import Category

LOGGER = logging.getLogger(__name__)

#: Default SecLists web-content root on Kali/Debian pentest images.
SECLISTS_WEB_CONTENT = Path("/usr/share/seclists/Discovery/Web-Content")

#: Category -> ordered candidate paths, relative to a SecLists Web-Content root.
SECLISTS_MAP: dict[Category, tuple[str, ...]] = {
    Category.API: (
        "api/api-seen-in-wild.txt",
        "api/api-endpoints.txt",
        "common-api-endpoints-mazen160.txt",
        "api/objects.txt",
    ),
    Category.GRAPHQL: ("graphql.txt",),
    Category.JS: ("raft-large-files.txt", "raft-medium-files.txt"),
    Category.FILE: ("raft-large-files.txt", "raft-medium-files.txt"),
    Category.PARAMETER: ("burp-parameter-names.txt",),
    Category.DIRECTORY: ("raft-large-directories.txt", "raft-medium-directories.txt"),
    Category.GENERIC: ("raft-large-words.txt", "common.txt"),
}


class LocalWordlistSource:
    """Resolve a category to an installed SecLists file, if one is present."""

    def __init__(
        self,
        roots: Sequence[Path] = (SECLISTS_WEB_CONTENT,),
        overrides: dict[Category, Path] | None = None,
    ) -> None:
        self._roots = tuple(Path(root) for root in roots)
        self._overrides = dict(overrides or {})

    @classmethod
    def autodetect(cls, seclists: Path | None = None) -> LocalWordlistSource | None:
        """Return a source rooted at an existing SecLists install, or ``None``."""
        roots: list[Path] = []
        if seclists is not None:
            candidate = Path(seclists)
            # Accept either the SecLists root or its Web-Content directory.
            web = candidate / "Discovery" / "Web-Content"
            roots.append(web if web.is_dir() else candidate)
        roots.append(SECLISTS_WEB_CONTENT)
        for root in roots:
            if root.is_dir():
                return cls(roots=(root,))
        return None

    @property
    def available(self) -> bool:
        return any(root.is_dir() for root in self._roots)

    def resolve(self, category: Category) -> Path | None:
        """Return the first existing wordlist file for a category, or ``None``."""
        override = self._overrides.get(category)
        if override is not None and override.is_file():
            return override
        for relative in SECLISTS_MAP.get(category, ()):
            for root in self._roots:
                candidate = root / relative
                if candidate.is_file():
                    return candidate
        return None
