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

    # Build one lazy candidate generator per (category, origin) and bucket them by
    # host (scheme://netloc). The candidate budget is then shared fairly across
    # hosts by round-robin, so a single origin -- e.g. a soft-404 SPA host like
    # arb.gala.com -- can no longer consume the entire cap and starve the other
    # in-scope hosts and categories (observed on a real gala.com run: 20k/20k on
    # one host). Dedup is global via the shared ``seen`` set.
    seen: set[str] = set()
    words_cache: dict[Category, list[str]] = {}
    host_buckets: dict[str, list] = {}
    for category, members in grouped.items():
        if category not in words_cache:
            words_cache[category] = provider.words_for(category, config.max_words_per_category)
        words = words_cache[category]
        if not words:
            continue
        for origin, asset_url in members:
            base, _ = base_and_path(origin, asset_url)
            generator = candidates_for(
                origin, asset_url, category, words,
                depth=config.context_depth, extensions=config.extensions, seen=seen,
            )
            host_buckets.setdefault(base, []).append(generator)

    candidates: list[Candidate] = []
    by_category: dict[str, int] = defaultdict(int)
    chunk = 25  # candidates pulled per host per round -- finer = more even spread
    active = [gens for gens in host_buckets.values()]
    while active and len(candidates) < config.max_candidates:
        next_active = []
        for gens in active:
            pulled = 0
            while gens and pulled < chunk and len(candidates) < config.max_candidates:
                try:
                    candidate = next(gens[0])
                except StopIteration:
                    gens.pop(0)  # this origin is exhausted; move to the next
                    continue
                candidates.append(candidate)
                by_category[candidate.category.value] += 1
                pulled += 1
            if gens and len(candidates) < config.max_candidates:
                next_active.append(gens)
        active = next_active
    if len(candidates) >= config.max_candidates:
        LOGGER.warning(
            "Candidate cap %d reached; spread across %d host(s)",
            config.max_candidates, len(host_buckets),
        )
    return candidates, dict(by_category), len(in_scope_origins)


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
        from .local import LocalWordlistSource
        from .wordlists import urllib_fetcher

        local = None
        if config.use_local:
            local = LocalWordlistSource.autodetect(
                Path(config.seclists_dir) if config.seclists_dir else None
            )
            if local is not None:
                LOGGER.info("Local wordlists detected (SecLists); preferring them over downloads")
        provider = WordlistProvider(
            cache_dir=output_dir / "wordlists",
            fetcher=urllib_fetcher(timeout=config.timeout, user_agent=config.user_agent),
            offline=config.offline,
            local=local,
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
