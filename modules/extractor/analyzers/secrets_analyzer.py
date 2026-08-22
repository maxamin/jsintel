"""Hardcoded secret detector."""
from __future__ import annotations

import math
import re
from collections.abc import Iterable
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _extract_string_literals, _node_text, _walk
from ..findings import Finding, SecurityFinding
from ..models import Asset

_SECRET_PATTERNS = [
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "stripe_key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{30,}"), "github_token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.?[a-zA-Z0-9_-]*"), "jwt_token"),
]

_HEX_PATTERNS = [
    (re.compile(r"\b[0-9a-f]{32}\b"), "md5_hash_or_api_key"),
    (re.compile(r"\b[0-9a-f]{40}\b"), "sha1_hash_or_api_key"),
    (re.compile(r"\b[0-9a-f]{64}\b", re.I), "sha256_hash_or_api_key"),
]

_SECRET_LIKE_NAMES = re.compile(r"\b(password|api_key|apikey|token|secret|auth|credential|private_key)\b", re.I)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p:
            entropy -= p * math.log2(p)
    return entropy


def _mask(value: str) -> str:
    if len(value) <= 12:
        return value[:2] + "..." + value[-2:] if len(value) > 4 else "****"
    return value[:4] + "..." + value[-4:]


def _line_for_node(root_node: Any, node: Any, source: str) -> str:
    line_idx = getattr(node, "start_point", (0, 0))[0]
    lines = source.splitlines()
    if 0 <= line_idx < len(lines):
        return lines[line_idx]
    return ""


class SecretsAnalyzer(ASTAnalyzer):
    id = "secrets"
    description = "Detect hardcoded secrets in string literals"
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        seen: set[str] = set()
        literals: list[tuple[str, Any]] = []
        if tree is not None:
            for node in _walk(getattr(tree, "root_node", None)):
                if getattr(node, "type", None) in ("string", "template_string"):
                    text = _node_text(node)
                    # Strip surrounding quotes for analysis.
                    stripped = text.strip("'\"")
                    literals.append((stripped, node))
        else:
            # Fallback: scan the whole source for quoted strings.
            for match in re.finditer(r"['\"`]([^'\"`]{4,})['\"`]", source):
                literals.append((match.group(1), None))
        for text, node in literals:
            if len(text) < 4:
                continue
            # Known secret patterns.
            for pattern, name in _SECRET_PATTERNS:
                if pattern.search(text):
                    masked = _mask(text)
                    if masked not in seen:
                        seen.add(masked)
                        yield SecurityFinding(
                            asset_url=asset.url,
                            finding_type="hardcoded_secret",
                            severity="low",
                            value=f"{name}: {masked}",
                        )
                    break
            else:
                # High-entropy heuristic only near secret-like variable names.
                entropy = _shannon_entropy(text)
                if entropy >= 4.5 and len(text) >= 20:
                    line = _line_for_node(getattr(tree, "root_node", None), node, source) if node else ""
                    if _SECRET_LIKE_NAMES.search(line):
                        masked = _mask(text)
                        if masked not in seen:
                            seen.add(masked)
                            yield SecurityFinding(
                                asset_url=asset.url,
                                finding_type="hardcoded_secret",
                                severity="low",
                                value=f"high_entropy_secret: {masked}",
                            )
                            continue
                # Hex hashes with contextual secret hint.
                for pattern, name in _HEX_PATTERNS:
                    if pattern.search(text):
                        line = _line_for_node(getattr(tree, "root_node", None), node, source) if node else ""
                        if _SECRET_LIKE_NAMES.search(line):
                            masked = _mask(text)
                            if masked not in seen:
                                seen.add(masked)
                                yield SecurityFinding(
                                    asset_url=asset.url,
                                    finding_type="hardcoded_secret",
                                    severity="low",
                                    value=f"{name}: {masked}",
                                )
                        break
