"""Class declaration extraction analyzer."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _find_nodes, _node_text
from ..findings import Finding, SecurityFinding
from ..models import Asset


def _line_of(node: Any) -> int:
    point = getattr(node, "start_point", None)
    return (point[0] + 1) if point else 0


class ClassesAnalyzer(ASTAnalyzer):
    id = "classes"
    description = "Extract class declarations"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        if tree is None:
            return
        seen: set[tuple[str, int]] = set()
        for node in _find_nodes(tree.root_node, ("class_declaration", "class_expression")):
            name_node = node.child_by_field_name("name") if hasattr(node, "child_by_field_name") else None
            name = _node_text(name_node) if name_node else "anonymous"
            line = _line_of(node)
            key = (name, line)
            if key in seen:
                continue
            seen.add(key)
            yield SecurityFinding(
                asset_url=asset.url,
                finding_type="class",
                severity="info",
                value=f"class {name} @line {line}",
            )
