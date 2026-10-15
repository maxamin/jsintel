"""Intra-procedural taint analyzer."""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import ScopeResolver, _find_nodes, _get_call_identifier, _get_member_chain, _node_text
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

# Sources whose value is the whole current URL. Feeding it to a navigation or
# request sink (``fetch(location.href)``, ``a.href = document.URL``) re-targets the
# page's own origin and is not attacker-steerable, so only code/HTML sinks count.
_WHOLE_URL_SOURCES = {"location.href", "document.URL"}
_CODE_SINKS = {"eval", "Function", "setTimeout", "setInterval", "document.write", "innerHTML", "outerHTML"}
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _effective_severity(source: str, sink: str, severity: str) -> str | None:
    """Severity for a source->sink pair, or None when the flow is not exploitable."""
    pair = ".".join(source.split(".")[-2:])
    if pair in _WHOLE_URL_SOURCES and sink not in _CODE_SINKS:
        return None
    if source.startswith("localStorage"):
        # Storage is only attacker-controlled through a second bug that writes it.
        return _SEVERITY_ORDER[max(1, _SEVERITY_ORDER.index(severity) - 1)]
    return severity


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
            # Match on the trailing pair so ``window.location.hash`` is a source but
            # ``location.href.length`` (a number) is not.
            key = (chain[-2], chain[-1])
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


TaintMap = dict[tuple[tuple[int, int], str], str]


def _build_taint_map(tree: Any) -> tuple[TaintMap, ScopeResolver | None]:
    """Map tainted ``(scope, variable)`` bindings to their source expression.

    Bindings are keyed by the declaring function scope: minifiers reuse the same
    short names in every function, so a name-only map would let one function's
    ``t = location.hash`` taint every unrelated ``t`` in the bundle.
    """
    taint: TaintMap = {}
    nodes = list(_find_nodes(tree.root_node, ("variable_declarator", "assignment_expression")))
    pairs: list[tuple[Any, str, Any]] = []
    for node in nodes:
        if node.type == "variable_declarator":
            lhs_node, rhs = node.child_by_field_name("name"), node.child_by_field_name("value")
        else:
            lhs_node, rhs = node.child_by_field_name("left"), node.child_by_field_name("right")
        lhs = _identifier_name(lhs_node)
        if lhs:
            pairs.append((lhs_node, lhs, rhs))
    if not any(_is_taint_source(rhs)[0] for _, _, rhs in pairs):
        return taint, None  # cheap exit: no source, no need to resolve scopes
    resolver = ScopeResolver(tree.root_node)
    tainted_names: set[str] = set()
    for lhs_node, lhs, rhs in pairs:
        is_source, source_name = _is_taint_source(rhs)
        if is_source:
            taint[(resolver.resolve(lhs, lhs_node), lhs)] = source_name
            tainted_names.add(lhs)
            continue
        rhs_name = _identifier_name(rhs)
        if rhs_name in tainted_names:
            src = taint.get((resolver.resolve(rhs_name, rhs), rhs_name))
            if src:
                taint[(resolver.resolve(lhs, lhs_node), lhs)] = src
                tainted_names.add(lhs)
    return taint, resolver


def _taint_of(node: Any, taint: TaintMap, resolver: ScopeResolver) -> str | None:
    name = _identifier_name(node)
    if not name:
        return None
    return taint.get((resolver.resolve(name, node), name))


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
        taint, resolver = _build_taint_map(tree)
        if not taint or resolver is None:
            return
        seen: set[tuple[str, str, int]] = set()

        def emit(src: str, sink_name: str, severity: str, node: Any) -> Iterable[Finding]:
            effective = _effective_severity(src, sink_name, severity)
            key = (sink_name, src, _line_of(node))
            if effective is None or key in seen:
                return
            seen.add(key)
            yield SecurityFinding(
                asset_url=asset.url,
                finding_type="taint_to_sink",
                severity=effective,
                value=f"{src} -> {sink_name} @line {_line_of(node)}",
                source=src,
                sink=sink_name,
            )

        for node in _find_nodes(tree.root_node, ("call_expression",)):
            is_sink, sink_name, severity = _is_sink_call(node)
            if not is_sink:
                continue
            args = node.child_by_field_name("arguments")
            for child in getattr(args, "named_children", []) or []:
                src = _taint_of(child, taint, resolver)
                if src:
                    yield from emit(src, sink_name, severity, node)
        for node in _find_nodes(tree.root_node, ("assignment_expression",)):
            is_sink, sink_name, severity, rhs = _is_sink_assignment(node)
            if not is_sink or rhs is None:
                continue
            src = _taint_of(rhs, taint, resolver)
            if src:
                yield from emit(src, sink_name, severity, node)
