"""Stable contracts that isolate plugins from platform implementations."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence

from jsintel.models import Asset, Model, ScanRun


class ModelSink(Protocol):
    """The only persistence interface exposed to analysis plugins."""

    def store(self, model: Model) -> None: ...

    def relate(self, source: Model, relation: str, target: Model, evidence: str = "") -> None: ...


@dataclass(slots=True)
class PluginContext:
    """Immutable scan metadata plus narrow storage and configuration interfaces."""

    scan: ScanRun
    configuration: Mapping[str, Any]
    sink: ModelSink


@dataclass(frozen=True, slots=True)
class PluginResult:
    """Normalized records emitted by one plugin invocation."""

    records: tuple[Model, ...] = ()
    relationships: tuple[tuple[Model, str, Model, str], ...] = ()
    warnings: tuple[str, ...] = ()


class Plugin(ABC):
    """Common lifecycle for all collection and analysis capabilities.

    Implementations must use models in ``run`` and must never consume another
    plugin's temporary files. Dependency ordering is resolved by PluginRegistry.
    """

    @classmethod
    @abstractmethod
    def id(cls) -> str:
        """Return a globally unique, stable plugin identifier."""

    @classmethod
    @abstractmethod
    def version(cls) -> str:
        """Return the implementation version for scan provenance."""

    @classmethod
    def dependencies(cls) -> Sequence[str]:
        return ()

    @classmethod
    @abstractmethod
    def supported_asset_types(cls) -> Sequence[str]:
        """Return canonical AssetType values accepted by this plugin."""

    @classmethod
    def schema(cls) -> Mapping[str, Any]:
        """Return a JSON-schema-like configuration description."""
        return {"type": "object", "additionalProperties": False}

    def initialize(self, context: PluginContext) -> None:
        """Acquire per-run resources. Must be safe to call once per run."""

    @abstractmethod
    def run(self, assets: Sequence[Asset], context: PluginContext) -> PluginResult:
        """Analyze normalized assets and return normalized records."""

    def cleanup(self, context: PluginContext) -> None:
        """Release resources even when another plugin fails."""
