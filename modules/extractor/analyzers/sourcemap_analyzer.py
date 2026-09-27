"""Source map parser + un-minification.

Beyond listing the original source filenames, when a ``.map`` carries
``sourcesContent`` (most production maps do) this analyzer **recovers the original,
un-minified source of each file and re-scans it** for secrets, URLs, and API
endpoints. This closes a real gap: secrets/endpoints that minification renames,
splits, or strips (e.g. ``"AKIA"+"IOSFODNN7"+"EXAMPLE"``) are invisible in the
shipped bundle but plainly present in the original source the map exposes.

Recovered findings are attributed to the ``.map`` asset (so they flow to the DB and
per-host triage) with the original source path named in the value.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from ..analyzer import Analyzer
from ..findings import EndpointFinding, Finding, SecurityFinding, URLFinding
from ..models import Asset

_URL_RE = re.compile(r"""(?:https?:)?//[^\s"'`<>\\)]+""")
_MAX_CONTENT = 1_000_000  # cap per-source re-scan to keep huge maps bounded
_PATH_RE = re.compile(r"""(?<![\w/])/(?:api|graphql|rest|v[0-9]+|internal|admin|user|users|account|auth)[A-Za-z0-9_./?=&%:\-]*""", re.I)


class SourceMapAnalyzer(Analyzer):
    id = "sourcemap"
    description = "Parse source maps and recover/re-scan the original un-minified sources"
    supported_asset_types = ("source_map",)

    def __init__(self) -> None:
        # Imported lazily so the registry's class discovery does not see
        # SecretsAnalyzer as a (duplicate) member of this module.
        from .secrets_analyzer import SecretsAnalyzer
        self._secrets = SecretsAnalyzer()

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        try:
            data = json.loads(source)
        except json.JSONDecodeError:
            return
        sources = data.get("sources", []) or []
        contents = data.get("sourcesContent", []) or []
        if not sources:
            return

        seen_src: set[str] = set()
        for i, src in enumerate(sources):
            if not isinstance(src, str) or src in seen_src:
                continue
            seen_src.add(src)
            # Always record the recovered original source path (structure/leak signal).
            yield SecurityFinding(asset_url=asset.url, finding_type="source_map",
                                  severity="info", value=f"source: {src}")

            content = contents[i] if i < len(contents) else None
            if not isinstance(content, str) or not content:
                continue  # no sourcesContent -> nothing to re-scan for this source
            if len(content) > _MAX_CONTENT:
                content = content[:_MAX_CONTENT]  # bound re-scan work per source

            # Re-scan the recovered original source. A synthetic asset with no _tree
            # drives SecretsAnalyzer's regex fallback across the full secret ruleset.
            synthetic = Asset(url=asset.url, asset_type="source_map",
                              local_path=asset.local_path, status="downloaded")
            for f in self._secrets.analyze(synthetic, content):
                # Re-emit as a SecurityFinding tagged with the original source path.
                rec = f.to_record()
                yield SecurityFinding(
                    asset_url=asset.url,
                    finding_type=rec.get("finding_type", "hardcoded_secret"),
                    severity=rec.get("severity", "medium"),
                    value=f"[{src}] {rec.get('value', '')}",
                    source=rec.get("source", ""), sink=rec.get("sink", ""),
                )

            seen_u: set[str] = set()
            for u in _URL_RE.findall(content):
                if u not in seen_u:
                    seen_u.add(u)
                    yield URLFinding(asset_url=asset.url, url=u)
            seen_e: set[str] = set()
            for ep in _PATH_RE.findall(content):
                if ep not in seen_e:
                    seen_e.add(ep)
                    yield EndpointFinding(asset_url=asset.url, endpoint=ep, kind="api")
