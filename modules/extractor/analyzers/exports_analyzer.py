"""Export extraction analyzer for JavaScript/TypeScript modules."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _find_nodes, _node_text
from ..findings import Finding, SecurityFinding
from ..models import Asset

_EXPORT_TYPES = {
    "export_statement",
    "export_clause",
    "named_exports",
    "namespace_export",
}


def _line_of(node: Any) -> int:
    point = getattr(node, "start_point", None)
    return (point[0] + 1) if point else 0


class ExportsAnalyzer(ASTAnalyzer):
    id = "exports"
    description = "Extract module export declarations"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        if tree is None:
            return
        seen: set[tuple[str, int]] = set()
        for node in _find_nodes(tree.root_node, ("export_statement",)):
            decl = node.child_by_field_name("declaration") if hasattr(node, "child_by_field_name") else None
            name = ""
            if decl is not None:
                name_node = decl.child_by_field_name("name") if hasattr(decl, "child_by_field_name") else None
                if name_node is not None:
                    name = _node_text(name_node)
            value = f"export {name}".strip() if name else "export"
            line = _line_of(node)
            key = (value, line)
            if key in seen:
                continue
            seen.add(key)
            yield SecurityFinding(
                asset_url=asset.url,
                finding_type="export",
                severity="info",
                value=f"{value} @line {line}",
            )
