"""CLI entry point for the streaming Phase 2 extraction engine."""
from __future__ import annotations

import argparse
import json
import logging
import multiprocessing
import os
import shutil
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

from .ast_utils import clear_ast_cache, set_current_index
from .findings import ExtractionError, Finding, SecurityFinding
from .models import Asset
from .parser import parse_js, parse_jsx, parse_tsx, parse_typescript
from .registry import discover, select
from .utils import read_asset
from .writer import JSONWriter

LOGGER = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def iter_assets(manifest: Path) -> Iterator[Asset]:
    """Yield manifest assets one by one without keeping the list in memory."""
    decoder = json.JSONDecoder()
    buffer = ""
    opened = False
    finished = False
    needs_separator = False
    with manifest.open(encoding="utf-8") as handle:
        while not finished:
            chunk = handle.read(64 * 1024)
            if chunk:
                buffer += chunk
            elif not buffer:
                break
            position = 0
            while True:
                while position < len(buffer) and buffer[position].isspace():
                    position += 1
                if not opened:
                    if position == len(buffer):
                        break
                    if buffer[position] != "[":
                        raise ValueError("Asset manifest must be a JSON array")
                    opened = True
                    position += 1
                    continue
                while position < len(buffer) and buffer[position].isspace():
                    position += 1
                if needs_separator:
                    if position == len(buffer):
                        break
                    if buffer[position] == ",":
                        needs_separator = False
                        position += 1
                        continue
                    if buffer[position] == "]":
                        finished = True
                        position += 1
                        break
                    raise ValueError("Expected a comma or closing bracket in asset manifest")
                if position < len(buffer) and buffer[position] == "]":
                    finished = True
                    position += 1
                    break
                try:
                    item, end = decoder.raw_decode(buffer, position)
                except json.JSONDecodeError:
                    break
                if not isinstance(item, dict):
                    raise ValueError("Each asset manifest entry must be an object")
                yield Asset.from_manifest(item)
                position = end
                needs_separator = True
            buffer = buffer[position:]
            if not chunk:
                if not finished:
                    raise ValueError("Asset manifest ended before the JSON array was complete")
                break
    if not opened:
        raise ValueError("Asset manifest is empty")


_PAR_MIN_ASSETS = 12  # below this, sequential (MP overhead isn't worth it)


def _worker_count() -> int:
    """Extraction worker processes. JSINTEL_EXTRACT_WORKERS overrides; 1 = off."""
    env = os.environ.get("JSINTEL_EXTRACT_WORKERS")
    if env:
        try:
            return max(1, int(env))
        except ValueError:
            return 1
    return min(os.cpu_count() or 1, 8)


def _analyze_asset(asset: Asset, analyzers) -> tuple[list[Finding], list[dict]]:
    """Parse one asset and run every compatible analyzer. Returns its findings in
    write order (non-security, then security by severity) plus any error records.
    Populates the state of any stateful analyzer (e.g. cross_asset)."""
    compatible = select(analyzers, asset.asset_type)
    if asset.local_path is None or not compatible:
        return [], []
    try:
        source = read_asset(asset.local_path)
    except OSError as error:
        return [], [ExtractionError(asset.url, "reader", str(error)).to_record()]
    tree = None
    if asset.is_parseable_web_asset:
        if asset.asset_type == "typescript":
            tree = parse_typescript(source)
        elif asset.asset_type == "tsx":
            tree = parse_tsx(source)
        elif asset.asset_type == "jsx":
            tree = parse_jsx(source)
        else:
            tree = parse_js(source)
    if tree is not None:
        object.__setattr__(asset, "_tree", tree)
    set_current_index(tree)  # shared type index: analyzers look up instead of re-walking
    findings: list[Finding] = []
    errors: list[dict] = []
    for analyzer in compatible:
        try:
            findings.extend(analyzer.analyze(asset, source))
        except Exception as error:  # a plugin must not abort the scan
            LOGGER.exception("Analyzer %s failed for %s", analyzer.id, asset.url)
            errors.append(ExtractionError(asset.url, analyzer.id, str(error)).to_record())
    clear_ast_cache()  # never hold more than one file's memoized traversal
    security = [f for f in findings if isinstance(f, SecurityFinding)]
    other = [f for f in findings if not isinstance(f, SecurityFinding)]
    security.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
    return other + security, errors


# Rough per-analyzer cost weights (from profiling the 1.2 MB Juice Shop bundle) used to
# balance analyzer GROUPS when a single big bundle is split across workers. Unknown
# analyzers default to 1; exact values only affect balance, never correctness.
_ANALYZER_COST = {"cloud_storage": 13, "callgraph": 12, "secrets": 9, "frameworks": 6,
                  "cross_asset": 4, "taint": 3, "security": 3, "urls": 2, "endpoints": 2,
                  "websocket": 2, "sourcemap": 2, "imports": 1, "classes": 1, "types": 1,
                  "exports": 1, "dependencies": 1, "tech_fingerprint": 1, "pages": 1}


def _lpt_bins(items, weight, n: int):
    """Longest-processing-time bin packing: greedily place the heaviest items into the
    least-loaded of ``n`` bins. Minimizes makespan for skewed workloads."""
    bins: list[list] = [[] for _ in range(n)]
    load = [0.0] * n
    for it in sorted(items, key=lambda x: -weight(x)):
        j = min(range(n), key=lambda k: load[k])
        bins[j].append(it)
        load[j] += weight(it) + 1
    return [b for b in bins if b]


def _extract_batch(job):
    """Worker: analyze a batch, writing each finding straight to per-report JSONL
    SHARD FILES (report.<shard_id>.jsonl) rather than returning the records. Only
    tiny metadata crosses the process boundary — the shard id, the cross_asset
    module map (needed for the global finalize), and an error count — which is the
    point: the ~tens-of-thousands of finding records never travel over the pipe.

    A job may restrict which analyzers run (``analyzer_ids``): a single large bundle is
    split into several analyzer-group jobs so its heavy analyzers run in PARALLEL across
    workers (the source is re-parsed per group, which the profiling shows is ~18% of the
    per-analyzer cost, so the split still wins). Each analyzer runs in exactly one group,
    so no finding is duplicated."""
    shard_dir, shard_id, indexed_assets, analyzer_ids = job
    analyzers = discover()
    if analyzer_ids is not None:
        wanted = set(analyzer_ids)
        analyzers = [a for a in analyzers if a.id in wanted]
    for analyzer in analyzers:
        analyzer.initialize()
    cross = next((a for a in analyzers if a.id == "cross_asset"), None)
    handles: dict[str, Any] = {}
    error_count = 0

    def emit(report: str, record: dict) -> None:
        handle = handles.get(report)
        if handle is None:
            handle = (Path(shard_dir) / f"{report}.{shard_id}.jsonl").open("w", encoding="utf-8")
            handles[report] = handle
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
        handle.write("\n")

    for _idx, adict in indexed_assets:
        ordered, errs = _analyze_asset(Asset.from_manifest(adict), analyzers)
        for finding in ordered:
            emit(finding.report, finding.to_record())
        for record in errs:
            emit("errors", record)
            error_count += 1
    for handle in handles.values():
        handle.close()
    return shard_id, (getattr(cross, "_modules", {}) if cross else {}), error_count


def _asset_dict(a: Asset) -> dict:
    return {"url": a.url, "type": a.asset_type,
            "local_path": str(a.local_path) if a.local_path else None, "status": a.status}


def _run_sequential(assets: list[Asset], output: Path) -> int:
    analyzers = discover()
    writer = JSONWriter(output)
    errors = 0
    try:
        for analyzer in analyzers:
            analyzer.initialize()
        for asset in assets:
            ordered, errs = _analyze_asset(asset, analyzers)
            for finding in ordered:
                writer.write(finding)
            for record in errs:
                writer._write_record("errors", record)
                errors += 1
        for analyzer in analyzers:
            for finding in analyzer.finalize():
                writer.write(finding)
    finally:
        writer.close()
    return errors


def _asset_size(a: Asset) -> int:
    try:
        return a.local_path.stat().st_size if a.local_path else 0
    except OSError:
        return 0


def _plan_jobs(assets: list[Asset], workers: int, shard_dir: Path) -> list:
    """Build worker jobs. Assets are LPT-balanced by size across `workers` batches (each
    runs all analyzers). Analyzer-splitting a bundle across workers only helps when a FEW
    bundles dominate and workers would otherwise idle — splitting means re-parsing the
    source per analyzer-group, so blanket-splitting many bundles multiplies parse cost and
    is slower (measured 0.56x). So a bundle is split ONLY when: it is at/over
    ``JSINTEL_SPLIT_BYTES`` (default 200 KB, 0 disables) AND the number of such big bundles
    is at most half the workers (i.e. there is real spare capacity). Otherwise every asset
    is batched whole. This keeps the single-dominant-bundle win (~1.8x) without the
    over-split regression on many-medium-bundle runs."""
    try:
        split_bytes = int(os.environ.get("JSINTEL_SPLIT_BYTES", "200000") or 0)
    except ValueError:
        split_bytes = 200000
    big = [a for a in assets if split_bytes and _asset_size(a) >= split_bytes] if workers > 1 else []
    # Only split when big bundles are few enough that whole-batching would idle workers.
    if not big or len(big) > max(1, workers // 2):
        big = []
    big_ids = {id(a) for a in big}
    small = [a for a in assets if id(a) not in big_ids]
    jobs: list = []
    sid = 0
    for batch in _lpt_bins(small, _asset_size, workers):
        jobs.append((str(shard_dir), sid, list(enumerate(_asset_dict(x) for x in batch)), None))
        sid += 1
    if big:
        all_ids = [a.id for a in discover()]
        # Give the (few) big bundles the spare workers: split each into ~workers/len(big)
        # analyzer groups, at least 2, capped by the analyzer count.
        groups = max(2, min(len(all_ids), workers // len(big)))
        for a in big:
            adict = _asset_dict(a)
            for grp in _lpt_bins(all_ids, lambda i: _ANALYZER_COST.get(i, 1), groups):
                jobs.append((str(shard_dir), sid, [(0, adict)], list(grp)))
                sid += 1
    return jobs


def _run_parallel(assets: list[Asset], output: Path, workers: int) -> int:
    shard_dir = output / ".shards"
    shutil.rmtree(shard_dir, ignore_errors=True)
    shard_dir.mkdir(parents=True, exist_ok=True)
    jobs = _plan_jobs(assets, workers, shard_dir)
    shard_ids: list[int] = []
    merged_modules: dict = {}
    errors = 0
    # 'fork' explicitly: Python 3.14 defaults to 'forkserver' (re-imports the entry
    # module, fragile + slower). Single-threaded here, so fork is safe and children
    # inherit the already-imported analyzers.
    ctx = multiprocessing.get_context("fork")
    with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as executor:
        for shard_id, modules, err_count in executor.map(_extract_batch, jobs):
            shard_ids.append(shard_id)
            merged_modules.update(modules)  # asset urls are unique keys
            errors += err_count
    # Stateful cross-asset edges: finalize once over the merged module map (main),
    # grouped by target report — equivalent to a single sequential pass.
    extra: dict[str, list[dict]] = {}
    cross = next((a for a in discover() if a.id == "cross_asset"), None)
    if cross is not None:
        cross.initialize()
        cross._modules.update(merged_modules)
        for finding in cross.finalize():
            extra.setdefault(finding.report, []).append(finding.to_record())
    # Stitch shard files into each final report (streamed; no records held/piped).
    output.mkdir(parents=True, exist_ok=True)
    try:
        for report in JSONWriter.reports:
            with (output / f"{report}.json").open("w", encoding="utf-8") as out:
                out.write("[")
                first = True
                for shard_id in shard_ids:
                    shard = shard_dir / f"{report}.{shard_id}.jsonl"
                    if not shard.exists():
                        continue
                    with shard.open(encoding="utf-8") as handle:
                        for line in handle:
                            line = line.rstrip("\n")
                            if not line:
                                continue
                            out.write(line if first else "," + line)
                            first = False
                for record in extra.get(report, []):
                    payload = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                    out.write(payload if first else "," + payload)
                    first = False
                out.write("]\n")
    finally:
        shutil.rmtree(shard_dir, ignore_errors=True)
    return errors


def run(manifest: Path, output: Path) -> int:
    """Run all compatible analyzers and return the number of recoverable errors.

    Extraction is per-asset independent (only cross_asset accumulates state, and it
    is merged), so large runs are parallelized across processes — the work is
    CPU-bound Python, which the GIL would serialize on threads. Small runs and
    JSINTEL_EXTRACT_WORKERS=1 use the sequential path; parallel failures fall back."""
    assets = list(iter_assets(manifest))
    workers = _worker_count()
    if workers > 1 and len(assets) >= _PAR_MIN_ASSETS:
        try:
            return _run_parallel(assets, output, workers)
        except Exception:
            LOGGER.exception("Parallel extraction failed; falling back to sequential")
    return _run_sequential(assets, output)


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract intelligence from downloaded JavaScript assets")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    if not args.manifest.is_file():
        parser.error(f"Manifest not found: {args.manifest}")
    errors = run(args.manifest, args.output)
    LOGGER.info("Extraction completed with %d recoverable errors", errors)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
