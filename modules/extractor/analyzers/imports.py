"""Module-import extraction analyzer."""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _find_nodes, _get_call_identifier, _node_text
from ..findings import Finding, ImportFinding
from ..models import Asset

_IMPORT_RE = re.compile(r'''(?:import\s*(?:[^'"()]*?\s+from\s*)?|require\s*\()["']([^"']+)["']''')


def _strip_quotes(text: str) -> str:
    return text.strip("'\"")


class ImportAnalyzer(ASTAnalyzer):
    id = "imports"
    description = "Extract ESM and CommonJS module specifiers"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        candidates: set[str] = set()
        if tree is not None:
            for node in _find_nodes(tree.root_node, ("import_statement", "import_require")):
                source_node = node.child_by_field_name("source") if hasattr(node, "child_by_field_name") else None
                if source_node is not None and getattr(source_node, "type", None) == "string":
                    candidates.add(_strip_quotes(_node_text(source_node)))
                    continue
                args = node.child_by_field_name("arguments") if hasattr(node, "child_by_field_name") else None
                if args is not None:
                    for child in getattr(args, "children", []) or []:
                        if getattr(child, "type", None) == "string":
                            candidates.add(_strip_quotes(_node_text(child)))
            for node in _find_nodes(tree.root_node, ("call_expression",)):
                func = node.child_by_field_name("function") if hasattr(node, "child_by_field_name") else None
                is_dynamic_import = func is not None and getattr(func, "type", None) == "import"
                is_require = _get_call_identifier(node) == "require"
                if is_dynamic_import or is_require:
                    args = node.child_by_field_name("arguments") if hasattr(node, "child_by_field_name") else None
                    if args is not None:
                        for child in getattr(args, "children", []) or []:
                            if getattr(child, "type", None) == "string":
                                candidates.add(_strip_quotes(_node_text(child)))
        else:
            candidates.update(_IMPORT_RE.findall(source))
        for value in sorted(candidates):
            yield ImportFinding(asset_url=asset.url, module=value)
