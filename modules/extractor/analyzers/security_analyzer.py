"""Structural security pattern analyzer (no taint tracking required)."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import (
    _find_nodes,
    _get_first_string_arg,
    _get_member_chain,
    _node_text,
    enclosing_function,
    function_params,
    scope_key,
)
from ..findings import Finding, SecurityFinding
from ..models import Asset

# Receivers through which the global ``eval``/``Function``/timers are reached.
# ``obj.eval(x)`` on anything else is an unrelated method (math.js, redis, ...).
_GLOBAL_RECEIVERS = {"window", "self", "globalThis", "global"}
# Argument node types whose value is fixed at build time: ``Function("return this")``
# (the webpack/core-js globalThis shim) compiles constant code and is not injectable.
_CONSTANT_TYPES = {"string", "number", "true", "false", "null", "undefined"}
# Tokens whose presence in the writing function indicates a prototype-pollution guard.
_PROTO_GUARDS = ("__proto__", "constructor", "prototype", "hasOwnProperty", "hasOwn")
_LITERAL_INDEX = {"string", "number"}
_FUNCTION_VALUES = {"function_expression", "function", "arrow_function"}


def _line_of(node: Any) -> int:
    point = getattr(node, "start_point", None)
    return (point[0] + 1) if point else 0


def _global_callee(node: Any) -> str:
    """Name of a call's callee when it is a global (bare or ``window.``-qualified)."""
    func = node.child_by_field_name("function")
    if func is None:
        return ""
    if func.type == "identifier":
        return _node_text(func)
    chain = _get_member_chain(func)
    if len(chain) == 2 and chain[0] in _GLOBAL_RECEIVERS:
        return chain[1]
    return ""


def _is_constant(node: Any) -> bool:
    if node.type in _CONSTANT_TYPES:
        return True
    if node.type == "template_string":
        return not any(c.type == "template_substitution" for c in node.named_children)
    return False


def _has_dynamic_arg(node: Any) -> bool:
    args = node.child_by_field_name("arguments")
    named = [c for c in getattr(args, "named_children", []) or [] if c.type != "comment"]
    return any(not _is_constant(c) for c in named)


def _handler_function(handler: Any, root: Any) -> Any | None:
    """The function node a message handler refers to, or None if unresolvable."""
    if handler.type in _FUNCTION_VALUES:
        return handler
    if handler.type != "identifier":
        return None
    name = _node_text(handler)
    for decl in _find_nodes(root, ("function_declaration",)):
        if _node_text(decl.child_by_field_name("name")) == name:
            return decl
    for decl in _find_nodes(root, ("variable_declarator",)):
        value = decl.child_by_field_name("value")
        if value is not None and value.type in _FUNCTION_VALUES and _node_text(decl.child_by_field_name("name")) == name:
            return value
    return None


def _message_handler_is_unsafe(func: Any) -> bool:
    """True when the handler reads the message payload without checking its sender.

    A handler that never touches ``event.data`` cannot be steered by a hostile
    frame; one that compares ``event.origin`` (or ``event.source``, which pins the
    sending window) has a sender check.
    """
    body = func.child_by_field_name("body")
    if body is None:
        return False
    params = func.child_by_field_name("parameters") or func.child_by_field_name("parameter")
    first = None
    if params is not None:
        first = params if params.type == "identifier" else next(iter(params.named_children), None)
    if first is None:
        return False
    if first.type == "object_pattern":
        names = set(function_params(func))
        return "data" in names and not ({"origin", "source"} & names)
    if first.type != "identifier":
        return False
    event = _node_text(first)
    reads_data = False
    for member in _find_nodes(body, ("member_expression",)):
        obj = member.child_by_field_name("object")
        if obj is None or obj.type != "identifier" or _node_text(obj) != event:
            continue
        prop = _node_text(member.child_by_field_name("property"))
        if prop in ("origin", "source"):
            return False
        if prop == "data":
            reads_data = True
    return reads_data


class SecurityAnalyzer(ASTAnalyzer):
    id = "security"
    description = "Detect dangerous structural patterns"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        if tree is None:
            return
        root = tree.root_node
        seen: set[tuple[str, int]] = set()

        def emit(finding_type: str, severity: str, value: str, sink: str, line: int) -> Iterable[Finding]:
            if (finding_type, line) in seen:
                return
            seen.add((finding_type, line))
            yield SecurityFinding(asset_url=asset.url, finding_type=finding_type,
                                  severity=severity, value=value, sink=sink)

        for node in _find_nodes(root, ("call_expression",)):
            line = _line_of(node)
            ident = _global_callee(node)
            if ident in ("eval", "Function") and _has_dynamic_arg(node):
                yield from emit("dangerous_eval", "high", f"{ident}() @line {line}", ident, line)
            elif ident in ("setTimeout", "setInterval") and _get_first_string_arg(node):
                # A string literal is compiled as code, but its content is fixed.
                yield from emit("dangerous_eval", "low", f"{ident}(string) @line {line}", ident, line)
            chain = _get_member_chain(node.child_by_field_name("function"))
            if (len(chain) == 2 and chain[0] in _GLOBAL_RECEIVERS and chain[1] == "addEventListener"
                    and _get_first_string_arg(node) == "message"):
                args = node.child_by_field_name("arguments")
                handler = next((c for c in args.named_children if c.type != "string"), None) if args else None
                func = _handler_function(handler, root) if handler is not None else None
                if func is not None and _message_handler_is_unsafe(func):
                    yield from emit("postmessage_missing_origin", "medium",
                                    f"window.addEventListener('message') without origin check @line {line}",
                                    "window.addEventListener", line)

        guarded: dict[tuple[int, int], bool] = {}
        for node in _find_nodes(root, ("assignment_expression",)):
            left = node.child_by_field_name("left")
            if not _is_nested_computed_write(left):
                continue
            func = enclosing_function(node)
            if func is None:
                continue  # merge helpers live in functions; top-level writes are data setup
            key = scope_key(func)
            if key not in guarded:
                text = _node_text(func)
                guarded[key] = any(token in text for token in _PROTO_GUARDS)
            if guarded[key]:
                continue
            line = _line_of(node)
            yield from emit("prototype_pollution", "low",
                            f"nested dynamic property write (prototype-pollution candidate) @line {line}",
                            "obj[k1][k2] = value", line)


def _is_nested_computed_write(left: Any) -> bool:
    """``a[k1][k2] = v`` with both keys non-literal -- the deep-merge/set-path shape.

    A single ``obj[key] = value`` (array fills, maps, minified field writes) can only
    pollute when ``obj`` is itself a prototype, which needs the outer computed hop.
    """
    if left is None or left.type != "subscript_expression":
        return False
    inner = left.child_by_field_name("object")
    if inner is None or inner.type != "subscript_expression":
        return False
    for sub in (left, inner):
        index = sub.child_by_field_name("index")
        if index is None or index.type in _LITERAL_INDEX:
            return False
    return True
