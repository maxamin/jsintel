"""Source map parser."""
from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from ..analyzer import Analyzer
from ..findings import Finding, SecurityFinding
from ..models import Asset


class SourceMapAnalyzer(Analyzer):
    id = "sourcemap"
    description = "Parse source maps to recover original source filenames"
    supported_asset_types = ("source_map",)

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        try:
            data = json.loads(source)
        except json.JSONDecodeError:
            return
        sources = data.get("sources", [])
        if not sources:
            return
        seen: set[str] = set()
        for src in sources:
            if isinstance(src, str) and src not in seen:
                seen.add(src)
                yield SecurityFinding(
                    asset_url=asset.url,
                    finding_type="source_map",
                    severity="info",
                    value=f"source: {src}",
                )
