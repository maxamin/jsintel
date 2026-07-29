"""API-path extraction analyzer."""
from __future__ import annotations

import re
from collections.abc import Iterable

from ..analyzer import Analyzer
from ..findings import EndpointFinding, Finding
from ..models import Asset

_PATH_RE = re.compile(r'''(?<![\w/])/(?:api|graphql|v[0-9]+|rest)[A-Za-z0-9_./?=&${}:\-]*''', re.I)


class EndpointAnalyzer(Analyzer):
    id = "endpoints"
    description = "Extract likely REST, GraphQL, and versioned API paths"

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        for value in sorted(set(_PATH_RE.findall(source))):
            yield EndpointFinding(asset_url=asset.url, endpoint=value)
