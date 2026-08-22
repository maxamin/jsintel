"""Structural security pattern analyzer (no taint tracking required)."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _find_nodes, _get_call_identifier, _get_first_string_arg, _get_member_chain, _node_text
from ..findings import Finding, SecurityFinding
from ..models import Asset


def _line_of(node: Any) -> int:
    point = getattr(node, "start_point", None)
    return (point[0] + 1) if point else 0


def _has_origin_check(body: Any) -> bool:
    """Heuristic: body contains a reference to 'origin'."""
    if body is None:
        return False
    for node in _find_nodes(body, ("identifier", "property_identifier")):
        if _node_text(node) == "origin":
            return True
    return False


class SecurityAnalyzer(ASTAnalyzer):
    id = "security"
    description = "Detect dangerous structural patterns"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        if tree is None:
            return
        seen: set[tuple[str, int]] = set()
        for node in _find_nodes(tree.root_node, ("call_expression",)):
            line = _line_of(node)
            ident = _get_call_identifier(node)
            if ident in ("eval", "Function"):
                key = ("dangerous_eval", line)
                if key not in seen:
                    seen.add(key)
                    yield SecurityFinding(
                        asset_url=asset.url,
                        finding_type="dangerous_eval",
                        severity="critical",
                        value=f"{ident}() @line {line}",
                        sink=ident,
                    )
            if ident in ("setTimeout", "setInterval") and _get_first_string_arg(node):
                key = ("dangerous_eval", line)
                if key not in seen:
                    seen.add(key)
                    yield SecurityFinding(
                        asset_url=asset.url,
                        finding_type="dangerous_eval",
                        severity="high",
                        value=f"{ident}(string) @line {line}",
                        sink=ident,
                    )
            chain = _get_member_chain(node.child_by_field_name("function") if hasattr(node, "child_by_field_name") else None)
            if len(chain) >= 2 and chain[0] == "window" and chain[1] == "addEventListener" and _get_first_string_arg(node) == "message":
                args = node.child_by_field_name("arguments") if hasattr(node, "child_by_field_name") else None
                handler = None
                for child in getattr(args, "children", []) or []:
                    if getattr(child, "type", None) in ("function_expression", "arrow_function", "identifier"):
                        handler = child
                        break
                body = None
                if handler is not None and hasattr(handler, "child_by_field_name"):
                    body = handler.child_by_field_name("body")
                if not _has_origin_check(body):
                    key = ("postmessage_missing_origin", line)
                    if key not in seen:
                        seen.add(key)
                        yield SecurityFinding(
                            asset_url=asset.url,
                            finding_type="postmessage_missing_origin",
                            severity="medium",
                            value=f"window.addEventListener('message') without origin check @line {line}",
                            sink="window.addEventListener",
                        )
        for node in _find_nodes(tree.root_node, ("assignment_expression",)):
            line = _line_of(node)
            left = node.child_by_field_name("left") if hasattr(node, "child_by_field_name") else None
            if getattr(left, "type", None) == "subscript_expression":
                key = ("prototype_pollution", line)
                if key not in seen:
                    seen.add(key)
                    yield SecurityFinding(
                        asset_url=asset.url,
                        finding_type="prototype_pollution",
                        severity="medium",
                        value=f"dynamic property assignment @line {line}",
                        sink="obj[key] = value",
                    )
