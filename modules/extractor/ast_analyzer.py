"""AST-aware analyzer base class."""
from __future__ import annotations
from abc import abstractmethod
from collections.abc import Iterable
from typing import Any

from .analyzer import Analyzer
from .findings import Finding
from .models import Asset


class ASTAnalyzer(Analyzer):
    """Analyzer that reads a pre-parsed AST from asset._tree."""

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        tree = getattr(asset, "_tree", None)
        return self.analyze_ast(asset, source, tree)

    @abstractmethod
    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        """Override in subclasses. tree may be None."""
        ...
