"""Dynamic discovery and validation of built-in analyzer plugins."""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections.abc import Iterable

from .analyzer import Analyzer
from .ast_analyzer import ASTAnalyzer


def discover() -> tuple[Analyzer, ...]:
    """Import built-in analyzer modules and return a deterministic plugin list."""
    package = importlib.import_module("modules.extractor.analyzers")
    found: dict[str, type[Analyzer]] = {}
    for module_info in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
        module = importlib.import_module(module_info.name)
        for _, candidate in inspect.getmembers(module, inspect.isclass):
            if candidate in (Analyzer, ASTAnalyzer) or not issubclass(candidate, Analyzer):
                continue
            analyzer_id = getattr(candidate, "id", None)
            if not analyzer_id or analyzer_id in found:
                raise ValueError(f"Duplicate or empty analyzer id: {analyzer_id!r}")
            found[analyzer_id] = candidate
    return tuple(found[key]() for key in sorted(found))


def select(analyzers: Iterable[Analyzer], asset_type: str) -> tuple[Analyzer, ...]:
    """Return analyzers that explicitly support an asset type."""
    return tuple(analyzer for analyzer in analyzers if asset_type in analyzer.supported_asset_types)
