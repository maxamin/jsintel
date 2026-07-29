"""Typed findings emitted by analyzers and serialized by writers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Finding:
    asset_url: str
    report: str = field(init=False)

    def to_record(self) -> dict[str, Any]:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class URLFinding(Finding):
    url: str
    kind: str = "url"
    report: str = field(init=False, default="urls")

    def to_record(self) -> dict[str, Any]:
        return {"asset_url": self.asset_url, "url": self.url, "kind": self.kind}


@dataclass(frozen=True, slots=True)
class EndpointFinding(Finding):
    endpoint: str
    kind: str = "api"
    report: str = field(init=False, default="endpoints")

    def to_record(self) -> dict[str, Any]:
        return {"asset_url": self.asset_url, "endpoint": self.endpoint, "kind": self.kind}


@dataclass(frozen=True, slots=True)
class WebSocketFinding(Finding):
    url: str
    kind: str = "websocket"
    report: str = field(init=False, default="websocket")

    def to_record(self) -> dict[str, Any]:
        return {"asset_url": self.asset_url, "url": self.url, "kind": self.kind}


@dataclass(frozen=True, slots=True)
class ImportFinding(Finding):
    module: str
    report: str = field(init=False, default="imports")

    def to_record(self) -> dict[str, Any]:
        return {"asset_url": self.asset_url, "module": self.module}


@dataclass(frozen=True, slots=True)
class FrameworkFinding(Finding):
    technology: str
    evidence: str
    report: str = field(init=False, default="frameworks")

    def to_record(self) -> dict[str, Any]:
        return {"asset_url": self.asset_url, "technology": self.technology, "evidence": self.evidence}


@dataclass(frozen=True, slots=True)
class ExtractionError:
    asset_url: str
    analyzer: str
    message: str

    def to_record(self) -> dict[str, str]:
        return {"asset_url": self.asset_url, "analyzer": self.analyzer, "message": self.message}
