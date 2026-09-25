"""Content-discovery fuzzing for JSIntel.

This package extends paths JSIntel discovers inside JavaScript assets into live,
verified content on an authorized target. It classifies each discovered path,
selects the matching Assetnote wordlist (https://wordlists.assetnote.io/),
generates candidate URLs by extending known-good prefixes, and probes only hosts
inside an explicit authorization scope.

Public API:
    * :func:`~modules.fuzzer.engine.run` -- execute a run over an output dir.
    * :class:`~modules.fuzzer.scope.Scope` -- the host allowlist / auth gate.
    * :class:`~modules.fuzzer.models.FuzzConfig` -- runtime configuration.
    * :func:`~modules.fuzzer.classify.classify_path` -- path -> category.
"""
from __future__ import annotations

from .classify import classify_path
from .engine import run
from .models import Candidate, Category, FuzzConfig, FuzzSummary, ProbeResult, WordlistSpec
from .scope import Scope

__all__ = [
    "Candidate",
    "Category",
    "FuzzConfig",
    "FuzzSummary",
    "ProbeResult",
    "Scope",
    "WordlistSpec",
    "classify_path",
    "run",
]
