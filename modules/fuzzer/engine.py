"""Orchestrate a fuzzing run over one JSIntel output directory.

The engine reads the paths JSIntel already extracted (``endpoints.json`` and
``urls.json`` under ``<output>/reports/``), classifies each into a wordlist
category, generates candidate URLs by extending in-scope prefixes with the
category's Assetnote wordlist, probes them, and writes ``fuzz.json``. It owns no
I/O policy of its own: the transport, wordlist provider and scope are all passed
in, which keeps the whole pipeline testable offline.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

from .candidates import base_and_path, candidates_for
from .classify import classify_path
from .models import Candidate, Category, FuzzConfig, FuzzSummary, ProbeResult
from .prober import Prober
from .scope import Scope
from .transport import Transport, UrllibTransport
from .wordlists import WordlistProvider

LOGGER = logging.getLogger(__name__)


def _read_json_array(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        LOGGER.warning("Could not read %s: %s", path, error)
        return []
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def load_origins(reports_dir: Path) -> list[tuple[str, str]]:
    """Return ``(origin_path, discovering_asset_url)`` pairs from the reports.

    Endpoints are frequently root-relative, so each carries the ``asset_url`` it
    was found in to supply a host. URLs are already absolute.
    """
    origins: list[tuple[str, str]] = []
    for record in _read_json_array(reports_dir / "endpoints.json"):
        endpoint = str(record.get("endpoint", "")).strip()
        if endpoint:
            origins.append((endpoint, str(record.get("asset_url", ""))))
    for record in _read_json_array(reports_dir / "urls.json"):
        url = str(record.get("url", "")).strip()
        if url:
            origins.append((url, str(record.get("asset_url", ""))))
    return origins


def build_candidates(
    origins: Iterable[tuple[str, str]],
    scope: Scope,
    provider: WordlistProvider,
    config: FuzzConfig,
) -> tuple[list[Candidate], dict[str, int], int]:
    """Classify origins and expand the in-scope ones into probe candidates.

    Scope is enforced whenever a scope is set, and always for a live run. The one
    case that is not filtered is a scope-less ``--dry-run`` preview: it sends no
    requests, so it may plan candidates for every discovered host.
    """
    enforce_scope = bool(scope) or not config.dry_run
    grouped: dict[Category, list[tuple[str, str]]] = defaultdict(list)
    in_scope_origins: set[str] = set()
    for origin, asset_url in origins:
        base, path = base_and_path(origin, asset_url)
        if not base:
            continue
        if enforce_scope and not scope.allows(base):
            continue
        in_scope_origins.add(base + path)
        grouped[classify_path(origin)].append((origin, asset_url))

    candidates: list[Candidate] = []
    by_category: dict[str, int] = {}
    seen: set[str] = set()
    for category, members in grouped.items():
        words = provider.words_for(category, config.max_words_per_category)
        if not words:
            continue
        before = len(candidates)
        for origin, asset_url in members:
            for candidate in candidates_for(
                origin,
                asset_url,
                category,
                words,
                depth=config.context_depth,
                extensions=config.extensions,
                seen=seen,
            ):
                candidates.append(candidate)
                if len(candidates) >= config.max_candidates:
                    LOGGER.warning("Candidate cap %d reached; truncating", config.max_candidates)
                    by_category[category.value] = len(candidates) - before
                    return candidates, by_category, len(in_scope_origins)
        by_category[category.value] = len(candidates) - before
    return candidates, by_category, len(in_scope_origins)


def write_report(reports_dir: Path, results: list[ProbeResult], summary: FuzzSummary) -> None:
    """Write ``fuzz.json`` (interesting results first) and ``fuzz_summary.json``."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    ordered = sorted(results, key=lambda r: (not r.interesting, r.category, r.url))
    (reports_dir / "fuzz.json").write_text(
        json.dumps([r.to_record() for r in ordered], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (reports_dir / "fuzz_summary.json").write_text(
        json.dumps(summary.to_record(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def run(
    output_dir: Path,
    scope: Scope,
    config: FuzzConfig,
    *,
    transport: Transport | None = None,
    provider: WordlistProvider | None = None,
) -> tuple[list[ProbeResult], FuzzSummary]:
    """Execute a full fuzzing run and persist ``fuzz.json``."""
    reports_dir = output_dir / "reports"
    if provider is None:
        from .wordlists import urllib_fetcher

        provider = WordlistProvider(
            cache_dir=output_dir / "wordlists",
            fetcher=urllib_fetcher(timeout=config.timeout, user_agent=config.user_agent),
            offline=config.offline,
        )
    if transport is None:
        transport = UrllibTransport()

    origins = load_origins(reports_dir)
    candidates, by_category, in_scope_origins = build_candidates(origins, scope, provider, config)
    prober = Prober(transport, scope, config)
    results = prober.probe_all(candidates)

    requested = sum(1 for r in results if r.note not in ("dry-run", "out-of-scope"))
    summary = FuzzSummary(
        findings_read=len(origins),
        in_scope_origins=in_scope_origins,
        candidates=len(candidates),
        requested=requested,
        interesting=sum(1 for r in results if r.interesting),
        errors=sum(1 for r in results if r.error),
        by_category=by_category,
    )
    write_report(reports_dir, results, summary)
    return results, summary
