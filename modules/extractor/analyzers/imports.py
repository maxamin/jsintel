"""Module-import extraction analyzer."""
from __future__ import annotations

import re
from collections.abc import Iterable

from ..analyzer import Analyzer
from ..findings import Finding, ImportFinding
from ..models import Asset

_IMPORT_RE = re.compile(r'''(?:import\s*(?:[^'"()]*?\s+from\s*)?|require\s*\()["']([^"']+)["']''')


class ImportAnalyzer(Analyzer):
    id = "imports"
    description = "Extract ESM and CommonJS module specifiers"

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        for value in sorted(set(_IMPORT_RE.findall(source))):
            yield ImportFinding(asset_url=asset.url, module=value)
