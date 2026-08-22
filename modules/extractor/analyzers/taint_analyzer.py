"""Intra-procedural taint analyzer."""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _find_nodes, _get_call_identifier, _get_member_chain, _node_text
from ..findings import Finding, SecurityFinding
from ..models import Asset

_TAINT_SOURCES = {
    ("location", "href"),
    ("location", "search"),
    ("location", "hash"),
    ("document", "URL"),
    ("document", "cookie"),
    ("window", "name"),
}

_SINK_SEVERITY = {
    "eval": "critical",
    "Function": "critical",
    "setTimeout": "high",
    "setInterval": "high",
    "document.write": "high",
    "innerHTML": "high",
    "outerHTML": "high",
    "src": "medium",
    "href": "medium",
    "location.replace": "medium",
    "window.open": "medium",
    "fetch": "medium",
    "XMLHttpRequest.open": "medium",
    "WebSocket": "medium",
    "JSON.parse": "low",
}


def _identifier_name(node: Any) -> str:
    if node is None:
        return ""
    if getattr(node, "type", None) == "identifier":
        return _node_text(node)
    return ""


def _is_taint_source(node: Any) -> tuple[bool, str]:
    """Return (is_source, source_name) for a node."""
    if node is None:
        return False, ""
    node_type = getattr(node, "type", None)
    if node_type == "member_expression":
        chain = _get_member_chain(node)
        if len(chain) >= 2:
            key = (chain[0], chain[-1])
            if key in _TAINT_SOURCES:
                return True, ".".join(chain)
    if node_type == "call_expression":
        ident = _get_call_identifier(node)
        if ident == "prompt":
            return True, "prompt()"
        chain = _get_member_chain(getattr(node, "child_by_field_name", lambda x: None)("function"))
        if len(chain) >= 2 and chain[0] == "localStorage" and chain[-1] == "getItem":
            return True, "localStorage.getItem()"
    return False, ""


def _is_sink_call(node: Any) -> tuple[bool, str, str]:
    """Return (is_sink, sink_name, severity) for a call_expression."""
    ident = _get_call_identifier(node)
    if ident in ("eval", "Function"):
        return True, ident, _SINK_SEVERITY[ident]
    if ident in ("setTimeout", "setInterval"):
        args = node.child_by_field_name("arguments") if hasattr(node, "child_by_field_name") else None
        first = next((c for c in (getattr(args, "children", []) or []) if getattr(c, "type", None) == "string"), None)
        if first is not None:
            return True, ident, _SINK_SEVERITY[ident]
    if ident == "fetch":
        return True, "fetch", _SINK_SEVERITY["fetch"]
    if ident == "WebSocket":
        return True, "WebSocket", _SINK_SEVERITY["WebSocket"]
    if ident == "JSON.parse":
        return True, "JSON.parse", _SINK_SEVERITY["JSON.parse"]
    chain = _get_member_chain(node.child_by_field_name("function") if hasattr(node, "child_by_field_name") else None)
    if len(chain) >= 2:
        dotted = ".".join(chain)
        if dotted == "document.write":
            return True, dotted, _SINK_SEVERITY["document.write"]
        if dotted == "location.replace":
            return True, dotted, _SINK_SEVERITY["location.replace"]
        if dotted == "window.open":
            return True, dotted, _SINK_SEVERITY["window.open"]
        if len(chain) >= 3 and chain[0] == "XMLHttpRequest" and chain[-1] == "open":
            return True, "XMLHttpRequest.open", _SINK_SEVERITY["XMLHttpRequest.open"]
    return False, "", ""


def _is_sink_assignment(node: Any) -> tuple[bool, str, str, Any]:
    """Return (is_sink, sink_name, severity, rhs) for an assignment_expression."""
    if getattr(node, "type", None) != "assignment_expression":
        return False, "", "", None
    left = node.child_by_field_name("left") if hasattr(node, "child_by_field_name") else None
    right = node.child_by_field_name("right") if hasattr(node, "child_by_field_name") else None
    if left is None:
        return False, "", "", None
    chain = _get_member_chain(left)
    if len(chain) >= 2:
        prop = chain[-1]
        if prop in ("innerHTML", "outerHTML", "src", "href"):
            return True, prop, _SINK_SEVERITY.get(prop, "medium"), right
    return False, "", "", None


def _build_taint_map(tree: Any) -> dict[str, str]:
    """Map tainted variable names to their source expression."""
    taint: dict[str, str] = {}
    for node in _find_nodes(tree.root_node, ("variable_declarator", "assignment_expression")):
        node_type = getattr(node, "type", None)
        if node_type == "variable_declarator":
            name_node = node.child_by_field_name("name") if hasattr(node, "child_by_field_name") else None
            value_node = node.child_by_field_name("value") if hasattr(node, "child_by_field_name") else None
            lhs = _identifier_name(name_node)
            rhs = value_node
        else:
            lhs_node = node.child_by_field_name("left") if hasattr(node, "child_by_field_name") else None
            lhs = _identifier_name(lhs_node)
            rhs = node.child_by_field_name("right") if hasattr(node, "child_by_field_name") else None
        if not lhs:
            continue
        is_source, source_name = _is_taint_source(rhs)
        if is_source:
            taint[lhs] = source_name
        elif rhs is not None and _identifier_name(rhs) in taint:
            taint[lhs] = taint[_identifier_name(rhs)]
    return taint


def _line_of(node: Any) -> int:
    point = getattr(node, "start_point", None)
    return (point[0] + 1) if point else 0


class TaintAnalyzer(ASTAnalyzer):
    id = "taint"
    description = "Intra-procedural source-to-sink taint tracking"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        if tree is None:
            return
        taint = _build_taint_map(tree)
        if not taint:
            return
        seen: set[tuple[str, str, int]] = set()
        for node in _find_nodes(tree.root_node, ("call_expression",)):
            is_sink, sink_name, severity = _is_sink_call(node)
            if not is_sink:
                continue
            args = node.child_by_field_name("arguments") if hasattr(node, "child_by_field_name") else None
            for child in getattr(args, "children", []) or []:
                child_type = getattr(child, "type", None)
                if child_type == "identifier" and _node_text(child) in taint:
                    src = taint[_node_text(child)]
                    key = (sink_name, src, _line_of(node))
                    if key in seen:
                        continue
                    seen.add(key)
                    yield SecurityFinding(
                        asset_url=asset.url,
                        finding_type="taint_to_sink",
                        severity=severity,
                        value=f"{src} -> {sink_name} @line {_line_of(node)}",
                        source=src,
                        sink=sink_name,
                    )
        for node in _find_nodes(tree.root_node, ("assignment_expression",)):
            is_sink, sink_name, severity, rhs = _is_sink_assignment(node)
            if not is_sink or rhs is None:
                continue
            rhs_name = _identifier_name(rhs)
            if rhs_name in taint:
                src = taint[rhs_name]
                key = (sink_name, src, _line_of(node))
                if key in seen:
                    continue
                seen.add(key)
                yield SecurityFinding(
                    asset_url=asset.url,
                    finding_type="taint_to_sink",
                    severity=severity,
                    value=f"{src} -> {sink_name} @line {_line_of(node)}",
                    source=src,
                    sink=sink_name,
                )
