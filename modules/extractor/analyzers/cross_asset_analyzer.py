"""Cross-asset symbol resolution and knowledge-graph edge builder."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urljoin, urlparse

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _find_nodes, _get_call_identifier, _node_text
from ..findings import Finding, SecurityFinding
from ..models import Asset


def _line_of(node: Any) -> int:
    point = getattr(node, "start_point", None)
    return (point[0] + 1) if point else 0


def _strip_quotes(text: str) -> str:
    return text.strip("'\"")


class CrossAssetAnalyzer(ASTAnalyzer):
    id = "cross_asset"
    description = "Build cross-asset module and function dependency edges"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx", "source_map")

    def initialize(self) -> None:
        self._modules: dict[str, dict[str, Any]] = {}

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        imports: set[str] = set()
        exports: set[str] = set()
        functions: list[dict[str, Any]] = []
        calls: list[dict[str, Any]] = []
        if tree is not None:
            for node in _find_nodes(tree.root_node, ("import_statement", "import_require")):
                source_node = node.child_by_field_name("source") if hasattr(node, "child_by_field_name") else None
                if source_node is not None and getattr(source_node, "type", None) == "string":
                    imports.add(_strip_quotes(_node_text(source_node)))
                    continue
                args = node.child_by_field_name("arguments") if hasattr(node, "child_by_field_name") else None
                if args is not None:
                    for child in getattr(args, "children", []) or []:
                        if getattr(child, "type", None) == "string":
                            imports.add(_strip_quotes(_node_text(child)))
                            break
            for node in _find_nodes(tree.root_node, ("call_expression",)):
                func = node.child_by_field_name("function") if hasattr(node, "child_by_field_name") else None
                if func is not None and getattr(func, "type", None) == "import":
                    args = node.child_by_field_name("arguments") if hasattr(node, "child_by_field_name") else None
                    if args is not None:
                        for child in getattr(args, "children", []) or []:
                            if getattr(child, "type", None) == "string":
                                imports.add(_strip_quotes(_node_text(child)))
                                break
                ident = _get_call_identifier(node)
                if ident:
                    calls.append({"callee": ident, "line": _line_of(node)})
            for node in _find_nodes(tree.root_node, ("export_statement",)):
                decl = node.child_by_field_name("declaration") if hasattr(node, "child_by_field_name") else None
                if decl is not None:
                    name_node = decl.child_by_field_name("name") if hasattr(decl, "child_by_field_name") else None
                    if name_node is not None:
                        exports.add(_node_text(name_node))
            for node in _find_nodes(tree.root_node, ("function_declaration",)):
                name_node = node.child_by_field_name("name") if hasattr(node, "child_by_field_name") else None
                if name_node is not None:
                    functions.append({"name": _node_text(name_node), "line": _line_of(node)})
        self._modules[asset.url] = {
            "imports": imports,
            "exports": exports,
            "functions": functions,
            "calls": calls,
        }
        return ()

    def finalize(self) -> Iterable[Finding]:
        # Build a mapping from resolved absolute URL back to asset URL.
        url_to_asset: dict[str, str] = {}
        for url in self._modules:
            parsed = urlparse(url)
            url_to_asset[url] = url
            # Also map directory-level index resolution.
            if parsed.path.endswith("/"):
                url_to_asset[url.rstrip("/")] = url
        seen: set[tuple[str, str, str]] = set()
        for asset_url, data in self._modules.items():
            for specifier in data["imports"]:
                resolved = urljoin(asset_url, specifier)
                if resolved in url_to_asset and url_to_asset[resolved] != asset_url:
                    target = url_to_asset[resolved]
                    key = (asset_url, target, "cross_asset_dependency")
                    if key not in seen:
                        seen.add(key)
                        yield SecurityFinding(
                            asset_url=asset_url,
                            finding_type="cross_asset_dependency",
                            severity="info",
                            value=f"{asset_url} -> {target}",
                            source=asset_url,
                            sink=target,
                        )
            # Cross-asset call edges: a call whose callee matches an exported name of another module.
            for call in data["calls"]:
                for other_url, other_data in self._modules.items():
                    if other_url == asset_url:
                        continue
                    if call["callee"] in other_data["exports"]:
                        key = (asset_url, other_url, call["callee"])
                        if key not in seen:
                            seen.add(key)
                            yield SecurityFinding(
                                asset_url=asset_url,
                                finding_type="cross_asset_call",
                                severity="info",
                                value=f"{asset_url} calls {call['callee']}() from {other_url} @line {call['line']}",
                                source=asset_url,
                                sink=other_url,
                            )
