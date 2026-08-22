"""Framework signature analyzer preserving Phase 1 fingerprints."""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _find_nodes, _get_call_identifier, _node_text
from ..findings import Finding, FrameworkFinding
from ..models import Asset

_FINGERPRINTS = {
    "React": r"\b(?:React(?:DOM)?|createElement|useState)\b",
    "Vue": r"\b(?:Vue|createApp|defineComponent)\b",
    "Angular": r"\b(?:@angular|ngOnInit|NgModule)\b",
    "Next.js": r"\b(?:__NEXT_DATA__|next/router|next/dist)\b",
    "Nuxt": r"\b(?:__NUXT__|nuxt(?:\.js)?)\b",
    "Svelte": r"\b(?:SvelteComponent|svelte/internal)\b",
    "Webpack": r"\b(?:webpackJsonp|__webpack_require__)\b",
    "Vite": r"\b(?:import\.meta\.hot|/@vite/client)\b",
    "Rollup": r"\b(?:rollupPlugin|__commonJS)\b",
}

_IMPORT_FRAMEWORKS = {
    "react": "React",
    "vue": "Vue",
    "@angular/core": "Angular",
    "next": "Next.js",
    "nuxt": "Nuxt",
    "svelte": "Svelte",
}

_CALL_FRAMEWORKS = {
    "createApp": "Vue",
    "createElement": "React",
    "useState": "React",
    "defineComponent": "Vue",
    "__webpack_require__": "Webpack",
}


def _strip_quotes(text: str) -> str:
    return text.strip("'\"")


class FrameworkAnalyzer(ASTAnalyzer):
    id = "frameworks"
    description = "Detect framework and bundler signatures"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        detected: set[str] = set()
        # Regex fast-path always runs for compatibility.
        for name, pattern in _FINGERPRINTS.items():
            if re.search(pattern, source, re.I):
                detected.add(name)
        if tree is not None:
            for node in _find_nodes(tree.root_node, ("import_statement",)):
                source_node = node.child_by_field_name("source") if hasattr(node, "child_by_field_name") else None
                if source_node is not None and getattr(source_node, "type", None) == "string":
                    module = _strip_quotes(_node_text(source_node))
                    for key, framework in _IMPORT_FRAMEWORKS.items():
                        if module == key or module.startswith(key + "/"):
                            detected.add(framework)
            for node in _find_nodes(tree.root_node, ("call_expression",)):
                ident = _get_call_identifier(node)
                if ident in _CALL_FRAMEWORKS:
                    detected.add(_CALL_FRAMEWORKS[ident])
        for name in sorted(detected):
            yield FrameworkFinding(asset_url=asset.url, technology=name, evidence="signature match")
