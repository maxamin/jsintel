"""CLI entry point for the streaming Phase 2 extraction engine."""
from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Iterator
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


def run(manifest: Path, output: Path) -> int:
    """Run all compatible analyzers and return the number of recoverable errors."""
    analyzers = discover()
    writer = JSONWriter(output)
    errors = 0
    try:
        for analyzer in analyzers:
            analyzer.initialize()
        for asset in iter_assets(manifest):
            if asset.local_path is None:
                continue
            if not select(analyzers, asset.asset_type):
                continue
            try:
                source = read_asset(asset.local_path)
            except OSError as error:
                writer.write_error(ExtractionError(asset.url, "reader", str(error)))
                errors += 1
                continue
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
            # Build the shared type index once so every analyzer's _find_nodes call
            # is a lookup rather than a full re-traversal of the (huge) tree.
            set_current_index(tree)
            asset_findings: list[Finding] = []
            for analyzer in select(analyzers, asset.asset_type):
                try:
                    asset_findings.extend(analyzer.analyze(asset, source))
                except Exception as error:  # A plugin must not abort the scan.
                    LOGGER.exception("Analyzer %s failed for %s", analyzer.id, asset.url)
                    writer.write_error(ExtractionError(asset.url, analyzer.id, str(error)))
                    errors += 1
            security = [f for f in asset_findings if isinstance(f, SecurityFinding)]
            other = [f for f in asset_findings if not isinstance(f, SecurityFinding)]
            security.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
            for finding in other + security:
                writer.write(finding)
            # Release this asset's memoized AST traversal before moving on so the
            # cache never holds more than one file's nodes at a time.
            clear_ast_cache()
        for analyzer in analyzers:
            for finding in analyzer.finalize():
                writer.write(finding)
    finally:
        writer.close()
    return errors


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
