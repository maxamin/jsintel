"""TypeScript type and interface extraction analyzer."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _find_nodes, _node_text
from ..findings import Finding, SecurityFinding
from ..models import Asset

_TYPE_LIKE_NAMES = {"Request", "Response", "Api", "Endpoint", "Payload", "Params", "Body", "Headers"}


def _line_of(node: Any) -> int:
    point = getattr(node, "start_point", None)
    return (point[0] + 1) if point else 0


def _is_api_like(name: str) -> bool:
    lowered = name.lower()
    return any(api.lower() in lowered for api in _TYPE_LIKE_NAMES)


class TypesAnalyzer(ASTAnalyzer):
    id = "types"
    description = "Extract TypeScript interfaces and type aliases relevant to API construction"
    supported_asset_types = ("typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        if tree is None:
            return
        seen: set[tuple[str, int]] = set()
        for node in _find_nodes(tree.root_node, ("interface_declaration", "type_alias_declaration")):
            name_node = node.child_by_field_name("name") if hasattr(node, "child_by_field_name") else None
            name = _node_text(name_node) if name_node else "anonymous"
            kind = "interface" if getattr(node, "type", None) == "interface_declaration" else "type"
            line = _line_of(node)
            key = (name, line)
            if key in seen:
                continue
            seen.add(key)
            finding_type = "api_type" if _is_api_like(name) else "type_definition"
            yield SecurityFinding(
                asset_url=asset.url,
                finding_type=finding_type,
                severity="info",
                value=f"{kind} {name} @line {line}",
            )
