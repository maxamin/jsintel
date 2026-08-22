"""Shared tree-sitter AST helpers with no hard dependency on tree-sitter."""
from __future__ import annotations
from collections.abc import Generator, Iterable
from typing import Any


def _node_text(node: Any) -> str:
    """Return decoded node text or an empty string."""
    if node is None or node.text is None:
        return ""
    text = node.text
    if isinstance(text, bytes):
        return text.decode("utf-8", errors="ignore")
    return str(text)


def _walk(node: Any) -> Generator[Any, None, None]:
    """Yield every node in the AST using an iterative stack."""
    if node is None:
        return
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        # Children are yielded in source order by prepending reversed children.
        children = getattr(current, "children", None) or []
        stack.extend(reversed(children))


def _find_nodes(node: Any, types: Iterable[str]) -> Generator[Any, None, None]:
    """Yield all nodes whose type is in *types*."""
    wanted = set(types)
    for n in _walk(node):
        if getattr(n, "type", None) in wanted:
            yield n


def _extract_string_literals(tree: Any) -> list[str]:
    """Return all string and template string literal texts from an AST."""
    return [_node_text(n) for n in _walk(getattr(tree, "root_node", None)) if getattr(n, "type", None) in ("string", "template_string")]


def _get_call_identifier(node: Any) -> str:
    """Return the identifier text for a call_expression callee."""
    func = node.child_by_field_name("function") if hasattr(node, "child_by_field_name") else None
    if func is None:
        return ""
    if getattr(func, "type", None) == "identifier":
        return _node_text(func)
    if getattr(func, "type", None) == "member_expression":
        prop = func.child_by_field_name("property") if hasattr(func, "child_by_field_name") else None
        return _node_text(prop)
    return ""


def _get_first_string_arg(node: Any) -> str:
    """Return the first string argument of a call_expression, with quotes stripped."""
    args = node.child_by_field_name("arguments") if hasattr(node, "child_by_field_name") else None
    if args is None:
        return ""
    for child in getattr(args, "children", []) or []:
        if getattr(child, "type", None) == "string":
            return _node_text(child).strip("'\"")
    return ""


def _get_member_chain(node: Any) -> list[str]:
    """Return the textual chain of a member_expression, e.g. ['location','href']."""
    chain: list[str] = []
    current = node
    while current is not None:
        node_type = getattr(current, "type", None)
        if node_type == "identifier":
            chain.insert(0, _node_text(current))
            break
        if node_type == "member_expression":
            prop = current.child_by_field_name("property") if hasattr(current, "child_by_field_name") else None
            if prop is not None:
                chain.insert(0, _node_text(prop))
            obj = current.child_by_field_name("object") if hasattr(current, "child_by_field_name") else None
            current = obj
            continue
        break
    return chain
