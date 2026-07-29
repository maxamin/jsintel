"""URL extraction analyzer."""
from __future__ import annotations

import re
from collections.abc import Iterable

from ..analyzer import Analyzer
from ..findings import Finding, URLFinding
from ..models import Asset

_URL_RE = re.compile(r'''(?:(?:https?:)?//[^\s"'`<>\\]+)''')


class URLAnalyzer(Analyzer):
    id = "urls"
    description = "Extract absolute and protocol-relative URLs"

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        for value in sorted(set(_URL_RE.findall(source))):
            yield URLFinding(asset_url=asset.url, url=value)
