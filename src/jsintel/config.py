"""Typed configuration loading shared by the platform and future plugins."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml


@dataclass(frozen=True, slots=True)
class DownloadConfig:
    timeout: int = 15
    retries: int = 3


@dataclass(frozen=True, slots=True)
class CrawlerConfig:
    depth: int = 5
    javascript: bool = True


@dataclass(frozen=True, slots=True)
class PlatformConfig:
    threads: int = 50
    crawler: CrawlerConfig = CrawlerConfig()
    download: DownloadConfig = DownloadConfig()
    database_path: str = "output/database/recon.db"

    @classmethod
    def from_yaml(cls, path: Path) -> "PlatformConfig":
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, Mapping):
            raise ValueError("Configuration root must be a mapping")
        crawler = _mapping(raw.get("crawler"), "crawler")
        download = _mapping(raw.get("download"), "download")
        database = _mapping(raw.get("database"), "database")
        threads = _positive_int(raw.get("threads", 50), "threads")
        return cls(
            threads=threads,
            crawler=CrawlerConfig(
                depth=_positive_int(crawler.get("depth", 5), "crawler.depth"),
                javascript=_bool(crawler.get("javascript", True), "crawler.javascript"),
            ),
            download=DownloadConfig(
                timeout=_positive_int(download.get("timeout", 15), "download.timeout"),
                retries=_nonnegative_int(download.get("retries", 3), "download.retries"),
            ),
            database_path=_string(database.get("path", "output/database/recon.db"), "database.path"),
        )


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    return value


def _positive_int(value: object, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _nonnegative_int(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value
