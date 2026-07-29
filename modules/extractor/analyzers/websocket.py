"""WebSocket URL extraction analyzer."""
from __future__ import annotations

import re
from collections.abc import Iterable

from ..analyzer import Analyzer
from ..findings import Finding, WebSocketFinding
from ..models import Asset

_WEBSOCKET_RE = re.compile(r'''wss?://[^\s"'`<>\\]+''', re.I)


class WebSocketAnalyzer(Analyzer):
    id = "websocket"
    description = "Extract WebSocket URLs"

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        for value in sorted(set(_WEBSOCKET_RE.findall(source))):
            yield WebSocketFinding(asset_url=asset.url, url=value)
