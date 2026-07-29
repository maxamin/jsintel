"""Typed inputs and outputs for extractor analyzers."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class Asset:
    """A normalized downloaded asset from the Phase 1 manifest."""

    url: str
    asset_type: str
    local_path: Path | None
    status: str

    @classmethod
    def from_manifest(cls, value: Mapping[str, Any]) -> "Asset":
        path = value.get("local_path")
        return cls(
            url=str(value["url"]),
            asset_type=str(value.get("type", "other")),
            local_path=Path(path) if isinstance(path, str) and path else None,
            status=str(value.get("status", "discovered")),
        )

    @property
    def is_downloaded_javascript(self) -> bool:
        return self.asset_type == "javascript" and self.status == "downloaded"
