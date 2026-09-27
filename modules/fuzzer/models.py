"""Typed inputs and outputs for the content-discovery fuzzer.

The fuzzer takes paths JSIntel already discovered inside JavaScript assets and
extends them with high-signal wordlists, then verifies which extensions exist on
the live, in-scope target. Everything here is plain data so the classification,
candidate-generation, and probing stages stay independently testable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Category(str, Enum):
    """A class of discovered path, used to pick the matching wordlist.

    The value doubles as the serialized label and as the wordlist catalog key,
    so a discovered ``/api/v1/users`` maps to :data:`API` which maps to an API
    route wordlist -- the core "right wordlist for the right find" behaviour.
    """

    API = "api"
    GRAPHQL = "graphql"
    JS = "js"
    FILE = "file"
    PARAMETER = "parameter"
    DIRECTORY = "directory"
    GENERIC = "generic"


@dataclass(frozen=True, slots=True)
class WordlistSpec:
    """Where a category's wordlist comes from.

    ``urls`` are tried in order against the Assetnote CDN; a stale or missing
    remote list falls back to the bundled ``seed`` so the fuzzer always has
    words to work with, online or offline.
    """

    category: Category
    name: str
    seed: str
    urls: tuple[str, ...]
    description: str


@dataclass(frozen=True, slots=True)
class Candidate:
    """One URL to probe, plus the context that produced it."""

    url: str
    word: str
    category: Category
    origin: str
    base: str

    def to_record(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "word": self.word,
            "category": self.category.value,
            "origin": self.origin,
            "base": self.base,
        }


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """The outcome of requesting one candidate URL."""

    url: str
    category: str
    origin: str
    word: str
    status: int = 0
    length: int = 0
    words: int = 0
    redirect: str = ""
    error: str = ""
    interesting: bool = False
    note: str = ""

    def to_record(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "category": self.category,
            "origin": self.origin,
            "word": self.word,
            "status": self.status,
            "length": self.length,
            "words": self.words,
            "redirect": self.redirect,
            "error": self.error,
            "interesting": self.interesting,
            "note": self.note,
        }


# Response classes worth surfacing as "the extension probably exists here".
DEFAULT_MATCH_STATUS: frozenset[int] = frozenset(
    {200, 201, 202, 203, 204, 206, 301, 302, 307, 308, 401, 403, 405, 500}
)
# Never interesting on their own -- the canonical "not found" family.
DEFAULT_FILTER_STATUS: frozenset[int] = frozenset({404, 400, 410})


@dataclass(frozen=True, slots=True)
class FuzzConfig:
    """Runtime knobs for a fuzzing run.

    Defaults are deliberately conservative: bounded concurrency, a bounded slice
    of each wordlist, and a shallow directory context. ``dry_run`` plans
    candidates without sending a single request, which is what the test-suite and
    the ``--dry-run`` preview use.
    """

    concurrency: int = 20
    delay: float = 0.0
    timeout: float = 10.0
    max_words_per_category: int = 1500
    context_depth: int = 2
    methods: tuple[str, ...] = ("GET",)
    user_agent: str = "JSIntel/0.2 (+authorized-recon; https://github.com/)"
    # Extra request headers (e.g. an authenticated Cookie / Authorization) sent with
    # every probe. Only reaches in-scope hosts (the fuzzer is scope-gated).
    extra_headers: dict[str, str] = field(default_factory=dict)
    match_status: frozenset[int] = DEFAULT_MATCH_STATUS
    filter_status: frozenset[int] = DEFAULT_FILTER_STATUS
    extensions: tuple[str, ...] = ()
    follow_redirects: bool = False
    dry_run: bool = False
    offline: bool = False
    max_candidates: int = 20000
    calibrate: bool = True
    use_local: bool = True
    seclists_dir: str = ""

    def __post_init__(self) -> None:
        if self.concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if self.max_words_per_category < 1:
            raise ValueError("max_words_per_category must be >= 1")
        if self.context_depth < 1:
            raise ValueError("context_depth must be >= 1")
        if self.timeout <= 0:
            raise ValueError("timeout must be > 0")
        if self.delay < 0:
            raise ValueError("delay must be >= 0")


@dataclass(frozen=True, slots=True)
class FuzzSummary:
    """Aggregate counts returned from a run and echoed to the operator."""

    findings_read: int = 0
    in_scope_origins: int = 0
    candidates: int = 0
    requested: int = 0
    interesting: int = 0
    errors: int = 0
    by_category: dict[str, int] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "findings_read": self.findings_read,
            "in_scope_origins": self.in_scope_origins,
            "candidates": self.candidates,
            "requested": self.requested,
            "interesting": self.interesting,
            "errors": self.errors,
            "by_category": dict(self.by_category),
        }
