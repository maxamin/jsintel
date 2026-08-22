"""URL extraction analyzer."""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _extract_string_literals, _find_nodes, _get_first_string_arg
from ..findings import Finding, URLFinding
from ..models import Asset

_URL_RE = re.compile(r'''(?:(?:https?:)?//[^\s"'`<>\\]+)''')
_HTTP_CLIENTS = {"fetch", "XMLHttpRequest", "WebSocket"}


class URLAnalyzer(ASTAnalyzer):
    id = "urls"
    description = "Extract absolute and protocol-relative URLs"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        candidates: set[str] = set()
        if tree is not None:
            for text in _extract_string_literals(tree):
                candidates.update(_URL_RE.findall(text))
            for node in _find_nodes(tree.root_node, ("call_expression",)):
                if _get_first_string_arg(node).startswith(("http://", "https://", "//")):
                    candidates.update(_URL_RE.findall(_get_first_string_arg(node)))
        else:
            candidates.update(_URL_RE.findall(source))
        for value in sorted(candidates):
            yield URLFinding(asset_url=asset.url, url=value)
