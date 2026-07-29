"""Streaming report writers.

Analyzers emit typed findings; only writers turn them into an external format.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from .findings import ExtractionError, Finding


class Writer(ABC):
    """Output boundary for extractor results."""

    @abstractmethod
    def write(self, finding: Finding) -> None:
        """Persist one finding without retaining the complete scan in memory."""

    @abstractmethod
    def write_error(self, error: ExtractionError) -> None:
        """Persist one recoverable extraction error."""

    @abstractmethod
    def close(self) -> None:
        """Finalize valid output even for an empty scan."""


class JSONWriter(Writer):
    """Continuously write backward-compatible JSON arrays using temp files."""

    reports = ("urls", "endpoints", "websocket", "imports", "frameworks", "errors")

    def __init__(self, output: Path) -> None:
        output.mkdir(parents=True, exist_ok=True)
        self._output = output
        self._files: dict[str, object] = {}
        self._first: dict[str, bool] = {}
        for report in self.reports:
            temporary = output / f".{report}.json.tmp"
            handle = temporary.open("w", encoding="utf-8")
            handle.write("[")
            self._files[report] = handle
            self._first[report] = True

    def write(self, finding: Finding) -> None:
        self._write_record(finding.report, finding.to_record())

    def write_error(self, error: ExtractionError) -> None:
        self._write_record("errors", error.to_record())

    def close(self) -> None:
        for report, handle in self._files.items():
            handle.write("]\n")  # type: ignore[union-attr]
            handle.close()  # type: ignore[union-attr]
            temporary = self._output / f".{report}.json.tmp"
            temporary.replace(self._output / f"{report}.json")
        self._files.clear()

    def _write_record(self, report: str, record: dict[str, object]) -> None:
        if report not in self._files:
            raise ValueError(f"Unknown report type: {report}")
        handle = self._files[report]
        if not self._first[report]:
            handle.write(",")  # type: ignore[union-attr]
        json.dump(record, handle, ensure_ascii=False, separators=(",", ":"))  # type: ignore[arg-type]
        self._first[report] = False
