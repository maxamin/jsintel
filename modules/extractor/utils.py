"""Shared safe file-reading and deterministic extraction helpers."""
from __future__ import annotations

from pathlib import Path


def read_asset(path: Path) -> str:
    """Read JavaScript defensively; decoding errors never stop a scan."""
    return path.read_text(encoding="utf-8", errors="ignore")
