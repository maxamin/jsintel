"""WebSocket URL extraction analyzer."""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _extract_string_literals
from ..findings import Finding, WebSocketFinding
from ..models import Asset

_WEBSOCKET_RE = re.compile(r'''wss?://[^\s"'`<>\\]+''', re.I)


class WebSocketAnalyzer(ASTAnalyzer):
    id = "websocket"
    description = "Extract WebSocket URLs"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        candidates: set[str] = set()
        if tree is not None:
            for text in _extract_string_literals(tree):
                candidates.update(_WEBSOCKET_RE.findall(text))
        else:
            candidates.update(_WEBSOCKET_RE.findall(source))
        for value in sorted(candidates):
            yield WebSocketFinding(asset_url=asset.url, url=value)
