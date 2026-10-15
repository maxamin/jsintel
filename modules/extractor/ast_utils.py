"""Shared tree-sitter AST helpers with no hard dependency on tree-sitter."""
from __future__ import annotations
import heapq
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


# Per-asset AST index. Materializing tree-sitter nodes and reading their ``type``
# from Python is the dominant extraction cost on large minified bundles (a single
# real bundle can be ~3M nodes, ~12s per full traversal). Every analyzer queries
# the same tree by node type, often several times, so the naive approach rescans
# every node on every query -- effectively traversing each file ~30 times.
#
# Instead we do ONE pass per asset that buckets nodes by type into
# ``{type: [nodes in source order]}`` and stash it as the module-global "current"
# index; subsequent ``_find_nodes`` calls on the tree root are then dict lookups.
# This cannot be keyed by ``id(node)`` because tree-sitter hands back a fresh
# Python wrapper (new id) on every ``tree.root_node`` access. Extraction runs one
# asset at a time in a single thread, so a module-global is safe: ``main`` calls
# ``set_current_index`` after parsing and ``clear_ast_cache`` when the asset is
# done. Queries against a *sub*-node (parent is not None) index that subtree
# locally, since the global only covers the root.
_CURRENT_INDEX: dict[str, list[Any]] | None = None


def _build_index(node: Any) -> dict[str, list[Any]]:
    """One pass: return ``{node_type: [nodes in source order]}`` rooted at *node*."""
    buckets: dict[str, list[Any]] = {}
    stack = [node]
    while stack:
        current = stack.pop()
        node_type = getattr(current, "type", None)
        if node_type is not None:
            buckets.setdefault(node_type, []).append(current)
        # Children are visited in source order by prepending reversed children.
        children = getattr(current, "children", None) or []
        stack.extend(reversed(children))
    return buckets


def set_current_index(tree: Any) -> None:
    """Build and cache the type index for *tree*'s root. Call once per asset."""
    global _CURRENT_INDEX
    root = getattr(tree, "root_node", None) if tree is not None else None
    _CURRENT_INDEX = _build_index(root) if root is not None else None


def clear_ast_cache() -> None:
    """Drop the cached index. Call this once the asset is fully processed."""
    global _CURRENT_INDEX
    _CURRENT_INDEX = None


def _index_for(node: Any) -> dict[str, list[Any]]:
    """Return the type index covering *node*: the cached root index, or a local one."""
    if _CURRENT_INDEX is not None and getattr(node, "parent", None) is None:
        return _CURRENT_INDEX
    return _build_index(node)


def _walk(node: Any) -> Generator[Any, None, None]:
    """Yield every node in the AST in source order."""
    if node is None:
        return
    buckets = _index_for(node)
    # Merge the per-type buckets back into a single source-ordered stream.
    yield from heapq.merge(*buckets.values(), key=lambda n: n.start_byte)


def _find_nodes(node: Any, types: Iterable[str]) -> Generator[Any, None, None]:
    """Yield nodes whose type is in *types*, in source order."""
    if node is None:
        return
    buckets = _index_for(node)
    lists = [buckets[t] for t in types if t in buckets]
    if not lists:
        return
    if len(lists) == 1:
        yield from lists[0]
    else:
        # Each bucket is already sorted by source position; merge preserves it.
        yield from heapq.merge(*lists, key=lambda n: n.start_byte)


def _extract_string_literals(tree: Any) -> list[str]:
    """Return all string and template string literal texts from an AST."""
    root = getattr(tree, "root_node", None)
    return [_node_text(n) for n in _find_nodes(root, ("string", "template_string"))]


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


# --- Lexical scope helpers -------------------------------------------------
# Minified bundles reuse the same one-letter names (``e``, ``t``, ``n``) in every
# function, so any name-keyed analysis that ignores scope conflates unrelated
# variables across the whole file. These helpers resolve an identifier to the
# function scope that declares it (function-level granularity; block scoping of
# let/const is not modelled).
_FUNCTION_TYPES = frozenset({
    "function_declaration", "function_expression", "function", "arrow_function",
    "method_definition", "generator_function_declaration", "generator_function",
})
ROOT_SCOPE: tuple[int, int] = (-1, -1)


def scope_key(node: Any) -> tuple[int, int]:
    """Byte span identifying a function node (wrappers are not stable across accesses)."""
    return (node.start_byte, node.end_byte)


def enclosing_function(node: Any) -> Any | None:
    """Nearest ancestor function node of *node*, or None at program level."""
    current = getattr(node, "parent", None)
    while current is not None:
        if current.type in _FUNCTION_TYPES:
            return current
        current = current.parent
    return None


def _pattern_names(node: Any) -> Generator[str, None, None]:
    """Identifier names bound by a parameter/declarator pattern."""
    node_type = getattr(node, "type", None)
    if node_type in ("identifier", "shorthand_property_identifier_pattern"):
        yield _node_text(node)
    elif node_type == "assignment_pattern":
        yield from _pattern_names(node.child_by_field_name("left"))
    elif node_type in ("rest_pattern", "object_pattern", "array_pattern", "pair_pattern",
                       "object_assignment_pattern"):
        for child in node.named_children:
            if node_type == "pair_pattern" and child == node.child_by_field_name("key"):
                continue
            yield from _pattern_names(child)


def function_params(func: Any) -> list[str]:
    """Names bound by a function's parameter list."""
    params = func.child_by_field_name("parameters")
    if params is None:  # ``x => ...`` has a single ``parameter`` field
        single = func.child_by_field_name("parameter")
        return list(_pattern_names(single)) if single is not None else []
    return [name for child in params.named_children for name in _pattern_names(child)]


class ScopeResolver:
    """Resolve identifiers to their declaring function scope within one tree."""

    def __init__(self, root: Any) -> None:
        self._declared: dict[tuple[int, int], set[str]] = {}
        for func in _find_nodes(root, _FUNCTION_TYPES):
            self._declared.setdefault(scope_key(func), set()).update(function_params(func))
        for decl in _find_nodes(root, ("variable_declarator",)):
            func = enclosing_function(decl)
            key = scope_key(func) if func is not None else ROOT_SCOPE
            self._declared.setdefault(key, set()).update(_pattern_names(decl.child_by_field_name("name")))

    def resolve(self, name: str, node: Any) -> tuple[int, int]:
        """Scope that binds *name* as seen from *node* (ROOT_SCOPE for globals)."""
        func = enclosing_function(node)
        while func is not None:
            if name in self._declared.get(scope_key(func), ()):
                return scope_key(func)
            func = enclosing_function(func)
        return ROOT_SCOPE
