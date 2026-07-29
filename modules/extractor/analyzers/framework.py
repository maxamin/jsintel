"""Framework signature analyzer preserving Phase 1 fingerprints."""
from __future__ import annotations

import re
from collections.abc import Iterable

from ..analyzer import Analyzer
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


class FrameworkAnalyzer(Analyzer):
    id = "frameworks"
    description = "Detect framework and bundler signatures"

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        for name, pattern in _FINGERPRINTS.items():
            if re.search(pattern, source, re.I):
                yield FrameworkFinding(asset_url=asset.url, technology=name, evidence="signature match")
