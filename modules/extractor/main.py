"""CLI entry point for the streaming Phase 2 extraction engine."""
from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .findings import ExtractionError
from .models import Asset
from .registry import discover, select
from .utils import read_asset
from .writer import JSONWriter

LOGGER = logging.getLogger(__name__)


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
            if not asset.is_downloaded_javascript or asset.local_path is None:
                continue
            try:
                source = read_asset(asset.local_path)
            except OSError as error:
                writer.write_error(ExtractionError(asset.url, "reader", str(error)))
                errors += 1
                continue
            for analyzer in select(analyzers, asset.asset_type):
                try:
                    for finding in analyzer.analyze(asset, source):
                        writer.write(finding)
                except Exception as error:  # A plugin must not abort the scan.
                    LOGGER.exception("Analyzer %s failed for %s", analyzer.id, asset.url)
                    writer.write_error(ExtractionError(asset.url, analyzer.id, str(error)))
                    errors += 1
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
