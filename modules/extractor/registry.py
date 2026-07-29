"""Dynamic discovery and validation of built-in analyzer plugins."""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections.abc import Iterable

from .analyzer import Analyzer


def discover() -> tuple[Analyzer, ...]:
    """Import built-in analyzer modules and return a deterministic plugin list."""
    package = importlib.import_module("modules.extractor.analyzers")
    found: dict[str, type[Analyzer]] = {}
    for module_info in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
        module = importlib.import_module(module_info.name)
        for _, candidate in inspect.getmembers(module, inspect.isclass):
            if candidate is Analyzer or not issubclass(candidate, Analyzer):
                continue
            if not candidate.id or candidate.id in found:
                raise ValueError(f"Duplicate or empty analyzer id: {candidate.id!r}")
            found[candidate.id] = candidate
    return tuple(found[key]() for key in sorted(found))


def select(analyzers: Iterable[Analyzer], asset_type: str) -> tuple[Analyzer, ...]:
    """Return analyzers that explicitly support an asset type."""
    return tuple(analyzer for analyzer in analyzers if asset_type in analyzer.supported_asset_types)
