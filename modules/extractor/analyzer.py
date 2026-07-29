"""Analyzer plugin contract."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from .findings import Finding
from .models import Asset


class Analyzer(ABC):
    """A stateless analysis capability over one normalized asset at a time."""

    id: str
    description: str
    supported_asset_types: tuple[str, ...] = ("javascript",)

    def initialize(self) -> None:
        """Allocate optional scan-level resources."""

    @abstractmethod
    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        """Yield typed findings for one asset without retaining scan state."""

    def finalize(self) -> Iterable[Finding]:
        """Yield optional aggregate findings after all assets are processed."""
        return ()
