"""Cloud storage reference analyzer.

Detects references to cloud object storage (AWS S3, Google Cloud Storage, Azure
Blob, DigitalOcean Spaces) in any asset's text — JS bundles, server-rendered pages,
and recovered source maps. An exposed bucket name is high-value recon: it names
infrastructure an operator can then check for public/misconfigured access.

Regex-only and bounded (all patterns are char-class/literal, no catastrophic
backtracking; input is capped) so it is safe on adversarial/huge inputs.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

from ..analyzer import Analyzer
from ..findings import Finding, SecurityFinding
from ..models import Asset

_MAX = 2_000_000  # cap scanned text (ReDoS/extreme-input safety)

# Each: (compiled pattern, provider label). Patterns are linear (no nested quantifiers).
_PATTERNS = [
    (re.compile(r"\b[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com", re.I), "aws-s3"),
    (re.compile(r"\bs3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com/[A-Za-z0-9._\-][A-Za-z0-9._\-/]{1,120}", re.I), "aws-s3"),
    (re.compile(r"\bs3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9](?:/[^\s\"'`<>]{0,120})?", re.I), "aws-s3"),
    (re.compile(r"\b[a-z0-9\-_.]{1,80}\.storage\.googleapis\.com", re.I), "gcs"),
    (re.compile(r"\bstorage\.googleapis\.com/[A-Za-z0-9._\-][A-Za-z0-9._\-/]{1,120}", re.I), "gcs"),
    (re.compile(r"\bgs://[a-z0-9][a-z0-9.\-_]{1,80}(?:/[^\s\"'`<>]{0,120})?", re.I), "gcs"),
    (re.compile(r"\b[a-z0-9]{3,40}\.blob\.core\.windows\.net(?:/[^\s\"'`<>]{0,120})?", re.I), "azure-blob"),
    (re.compile(r"\b[a-z0-9\-_.]{1,80}\.[a-z0-9\-]{1,20}\.digitaloceanspaces\.com", re.I), "do-spaces"),
]
_CAP = 200  # max findings per asset
# Cheap gate: none of the (linear) provider regexes can match unless one of these
# markers is present, so a single lower-case substring scan skips the 8 finditer
# passes on the (vast majority of) assets that reference no cloud storage.
_HINTS = ("amazonaws", "googleapis", "windows.net", "digitaloceanspaces", "s3://", "gs://")


class CloudStorageAnalyzer(Analyzer):
    id = "cloud_storage"
    description = "Detect AWS S3 / GCS / Azure Blob / DO Spaces references"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx", "page", "source_map", "configuration")

    def analyze(self, asset: Asset, source: str) -> Iterable[Finding]:
        text = source[:_MAX] if len(source) > _MAX else source
        low = text.lower()
        if not any(h in low for h in _HINTS):
            return
        seen: set[str] = set()
        count = 0
        for pattern, provider in _PATTERNS:
            for m in pattern.finditer(text):
                ref = m.group(0)
                if ref in seen:
                    continue
                seen.add(ref)
                count += 1
                if count > _CAP:
                    return
                yield SecurityFinding(asset_url=asset.url, finding_type="cloud_bucket_reference",
                                      severity="low", value=f"{provider}: {ref[:160]}", sink=provider)
