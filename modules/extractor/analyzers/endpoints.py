"""API-path extraction analyzer."""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _extract_string_literals, _find_nodes, _get_call_identifier, _get_first_string_arg
from ..findings import EndpointFinding, Finding
from ..models import Asset

_PATH_RE = re.compile(r'''(?<![\w/])/(?:api|graphql|v[0-9]+|rest)[A-Za-z0-9_./?=&${}:\-]*''', re.I)
_HTTP_METHODS = {"fetch", "ajax", "request", "get", "post", "put", "delete", "patch"}


class EndpointAnalyzer(ASTAnalyzer):
    id = "endpoints"
    description = "Extract likely REST, GraphQL, and versioned API paths"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        candidates: set[str] = set()
        if tree is not None:
            for text in _extract_string_literals(tree):
                candidates.update(_PATH_RE.findall(text))
            for node in _find_nodes(tree.root_node, ("call_expression",)):
                ident = _get_call_identifier(node)
                if ident in _HTTP_METHODS:
                    arg = _get_first_string_arg(node)
                    if arg.startswith(("/", "http://", "https://")):
                        candidates.add(arg)
        else:
            candidates.update(_PATH_RE.findall(source))
        for value in sorted(candidates):
            yield EndpointFinding(asset_url=asset.url, endpoint=value)
