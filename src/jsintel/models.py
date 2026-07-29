"""Canonical, serializable domain models shared by all JSIntel plugins.

Plugins exchange these types through the platform context; plugin-specific JSON
files are deliberately not part of the plugin API.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4


def utcnow() -> datetime:
    """Return an aware UTC timestamp suitable for scan provenance."""
    return datetime.now(timezone.utc)


class AssetType(StrEnum):
    JAVASCRIPT = "javascript"
    SOURCE_MAP = "source_map"
    WEBASSEMBLY = "webassembly"
    CONFIGURATION = "configuration"
    MANIFEST = "manifest"
    WORKER = "worker"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class Model:
    """Base model with a stable serialization boundary for adapters."""

    id: UUID = field(default_factory=uuid4)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        return _serialize(value)


def _serialize(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _serialize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class ScanRun(Model):
    started_at: datetime = field(default_factory=utcnow)
    target: str = ""
    configuration_hash: str = ""
    status: str = "running"


@dataclass(frozen=True, slots=True)
class Asset(Model):
    url: str = ""
    asset_type: AssetType = AssetType.OTHER
    sha256: str | None = None
    local_path: str | None = None
    content_type: str | None = None
    size_bytes: int | None = None
    etag: str | None = None
    last_modified: str | None = None


@dataclass(frozen=True, slots=True)
class JavaScriptAsset(Asset):
    asset_type: AssetType = AssetType.JAVASCRIPT
    language: str = "javascript"
    source_map_url: str | None = None


@dataclass(frozen=True, slots=True)
class SourceMap(Asset):
    asset_type: AssetType = AssetType.SOURCE_MAP
    compiled_asset_id: UUID | None = None
    original_sources: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Endpoint(Model):
    value: str = ""
    protocol: str = "http"
    method: str | None = None
    asset_id: UUID | None = None
    confidence: int = 0


@dataclass(frozen=True, slots=True)
class GraphQLOperation(Model):
    name: str = ""
    operation_type: str = "query"
    endpoint_id: UUID | None = None
    asset_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class Dependency(Model):
    name: str = ""
    version: str | None = None
    source: str = "bundle"
    asset_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class Framework(Model):
    name: str = ""
    version: str | None = None
    evidence: str = ""
    asset_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class RuntimeRequest(Model):
    url: str = ""
    method: str = "GET"
    initiator: str | None = None
    status_code: int | None = None
    duration_ms: float | None = None
    asset_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class StorageEntry(Model):
    storage_type: str = "localStorage"
    key: str = ""
    value_hash: str | None = None
    origin: str = ""


@dataclass(frozen=True, slots=True)
class ServiceWorker(Model):
    scope: str = ""
    script_url: str = ""
    asset_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class Chunk(Model):
    name: str = ""
    bundle: str = ""
    asset_id: UUID | None = None
    lazy: bool = False


@dataclass(frozen=True, slots=True)
class Import(Model):
    specifier: str = ""
    kind: str = "static"
    asset_id: UUID | None = None
    resolved_asset_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class SecretFinding(Model):
    category: str = "unknown"
    fingerprint: str = ""
    asset_id: UUID | None = None
    confidence: int = 0
    severity: str = "info"
    evidence: str = ""


@dataclass(frozen=True, slots=True)
class Technology(Model):
    name: str = ""
    version: str | None = None
    evidence: str = ""
    asset_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class Manifest(Model):
    name: str = ""
    start_url: str | None = None
    asset_id: UUID | None = None
