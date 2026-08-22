"""Function call-graph analyzer."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _get_call_identifier, _node_text
from ..findings import Finding, SecurityFinding
from ..models import Asset

_FUNCTION_TYPES = {"function_declaration", "function_expression", "arrow_function"}


def _function_name(node: Any) -> str:
    if hasattr(node, "child_by_field_name"):
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return _node_text(name_node)
    point = getattr(node, "start_point", None)
    line = (point[0] + 1) if point else 0
    if getattr(node, "type", None) == "arrow_function":
        return f"arrow@{line}"
    return f"anonymous@{line}"


def _line_of(node: Any) -> int:
    point = getattr(node, "start_point", None)
    return (point[0] + 1) if point else 0


class CallGraphAnalyzer(ASTAnalyzer):
    id = "callgraph"
    description = "Build function call relationships"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        if tree is None:
            return
        seen: set[tuple[str, str, int]] = set()
        # Iterative walk with a scope stack. Each stack entry is a function name.
        stack: list[tuple[Any, list[str]]] = [(tree.root_node, [])]
        while stack:
            node, scope = stack.pop()
            node_type = getattr(node, "type", None)
            if node_type in _FUNCTION_TYPES:
                new_scope = scope + [_function_name(node)]
                for child in getattr(node, "children", []) or []:
                    stack.append((child, new_scope))
                continue
            if node_type == "call_expression":
                callee = _get_call_identifier(node)
                if callee:
                    caller = scope[-1] if scope else "global"
                    line = _line_of(node)
                    key = (caller, callee, line)
                    if key not in seen:
                        seen.add(key)
                        yield SecurityFinding(
                            asset_url=asset.url,
                            finding_type="call_graph",
                            severity="info",
                            value=f"{caller} -> {callee} @line {line}",
                            source=caller,
                            sink=callee,
                        )
            for child in getattr(node, "children", []) or []:
                stack.append((child, scope))
