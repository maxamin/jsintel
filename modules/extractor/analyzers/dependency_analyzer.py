"""Relative import dependency resolver."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urljoin, urlparse

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _find_nodes, _node_text
from ..findings import Finding, ImportFinding
from ..models import Asset


def _strip_quotes(text: str) -> str:
    return text.strip("'\"")


class DependencyAnalyzer(ASTAnalyzer):
    id = "dependencies"
    description = "Resolve relative module specifiers against the asset URL"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        if tree is None:
            return
        seen: set[str] = set()
        for node in _find_nodes(tree.root_node, ("import_statement", "import_require")):
            source_node = node.child_by_field_name("source") if hasattr(node, "child_by_field_name") else None
            specifier = ""
            if source_node is not None and getattr(source_node, "type", None) == "string":
                specifier = _strip_quotes(_node_text(source_node))
            else:
                args = node.child_by_field_name("arguments") if hasattr(node, "child_by_field_name") else None
                for child in getattr(args, "children", []) or []:
                    if getattr(child, "type", None) == "string":
                        specifier = _strip_quotes(_node_text(child))
                        break
            if specifier.startswith(("./", "../")):
                resolved = urljoin(asset.url, specifier)
                if resolved not in seen:
                    seen.add(resolved)
                    yield ImportFinding(asset_url=asset.url, module=resolved)
        for node in _find_nodes(tree.root_node, ("call_expression",)):
            func = node.child_by_field_name("function") if hasattr(node, "child_by_field_name") else None
            if func is not None and getattr(func, "type", None) == "import":
                args = node.child_by_field_name("arguments") if hasattr(node, "child_by_field_name") else None
                for child in getattr(args, "children", []) or []:
                    if getattr(child, "type", None) == "string":
                        specifier = _strip_quotes(_node_text(child))
                        if specifier.startswith(("./", "../")):
                            resolved = urljoin(asset.url, specifier)
                            if resolved not in seen:
                                seen.add(resolved)
                                yield ImportFinding(asset_url=asset.url, module=resolved)
                        break
