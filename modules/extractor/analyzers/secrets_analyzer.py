"""Hardcoded secret detector.

The provider-specific credential patterns are loaded from the vendored
``token_patterns.json`` (a strategy-tagged, RE2-compatible set of OAuth/API
token regexes) so the ruleset is data-driven and easy to extend. On top of that
this module keeps a couple of patterns not covered by that set (credentials in
a URL) plus entropy/hex fallbacks for unlabeled secrets.

Extreme-case guarantees (verified by ``tests/test_analyzers.py``):
  * Every loaded pattern is RE2-compatible (no backreferences/lookbehind) and
    verified ReDoS-safe -- matching stays ~linear even on multi-megabyte
    minified single-line bundles.
  * The one hand-written pattern (``credentials_in_url``) bounds its scheme
    length so it cannot degrade to O(n^2) on a large colon-free blob.
"""
from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..ast_analyzer import ASTAnalyzer
from ..ast_utils import _extract_string_literals, _find_nodes, _node_text
from ..findings import Finding, SecurityFinding
from ..models import Asset

_PATTERNS_FILE = Path(__file__).with_name("token_patterns.json")

# Strategies that do not denote a secret: ``identifier`` is a public handle
# (e.g. a Twitter username) and ``encoding`` is a format validator (base64).
# Including them would flood the report with false positives.
_SKIP_STRATEGIES = {"identifier", "encoding"}

# Categories whose leak is high-impact (account takeover / infra / money).
_HIGH_CATEGORIES = {"Cloud", "Source / CI", "Payments"}

# Labels whose match is a structural *marker* carrying no secret material, so it
# is safe -- and clearer -- to show it unmasked.
_MARKER_LABELS = {"private-key-block", "gcp-service-account-key"}


def _severity_for(entry: dict[str, Any]) -> str:
    if entry["id"] == "jwt":
        return "low"
    if entry["id"] in _MARKER_LABELS:
        return "high"
    if entry.get("category") in _HIGH_CATEGORIES:
        return "high"
    return "medium"


def _load_patterns() -> list[tuple[re.Pattern[str], str, str, int]]:
    """Load and compile the vendored token patterns.

    Returns a list of ``(compiled, label, severity, group_index)``. ``group_index``
    is the capture group that holds the actual secret (keyword-gated patterns
    wrap the secret in a group so the surrounding keyword is not reported); it is
    0 when the whole match is the secret.
    """
    try:
        data = json.loads(_PATTERNS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out: list[tuple[re.Pattern[str], str, str, int]] = []
    for entry in data.get("patterns", []):
        if entry.get("strategy") in _SKIP_STRATEGIES:
            continue
        try:
            rx = re.compile(entry["regex"])
        except re.error:
            continue
        out.append((rx, entry["id"], _severity_for(entry), rx.groups))
    return out


# Provider patterns from the vendored set, plus one hand-written pattern for
# credentials embedded in a URL. The scheme length in that pattern is bounded
# ({0,14}) rather than open-ended: an unbounded run before the required ``://``
# makes the match O(n^2) on a large colon-free blob (a minified bundle), a
# denial-of-service risk. Real URL schemes are short, so 15 chars is ample.
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str, str, int]] = _load_patterns() + [
    (re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]{0,14}://[^:@/\s]+:[^:@/\s]+@[^\s/]+"),
     "credentials-in-url", "medium", 0),
]


# --- Literal anchor prefilter -------------------------------------------------
# Running ~100 regexes over every string literal is wasteful: a single huge
# minified literal would cost seconds. Instead, for each pattern we derive a
# cheap *required* literal substring (or an alternation of them). Before running
# the regex on a literal we do a fast ``in`` test; if the required literal is
# provably absent, the regex cannot match and is skipped. This is exactly how
# gitleaks/trufflehog keep large-input scans fast. Anchors are only used when we
# can PROVE the literal is required by every match, so the prefilter never drops
# a real hit -- patterns we cannot prove an anchor for simply always run.

def _match_paren(s: str) -> int | None:
    """Given ``s`` starting with ``(``, return the index of its matching ``)``."""
    depth = 0
    for i, c in enumerate(s):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def _leading_literal(t: str) -> str:
    """Longest run of literal characters at the start of ``t`` (regex source)."""
    out: list[str] = []
    i = 0
    while i < len(t):
        c = t[i]
        if c == "\\" and i + 1 < len(t):
            nxt = t[i + 1]
            if nxt in ".$/+*?()[]{}|^-_ ":
                out.append(nxt)
                i += 2
                continue
            break
        if c in ".$^*+?()[]{}|":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _anchors_for(pattern: str) -> tuple[list[str], bool]:
    """Return ``(anchors, case_insensitive)``.

    ``anchors`` is a list of literals, at least one of which must appear in any
    string the pattern matches; an empty list means "no provable anchor, always
    run". ``case_insensitive`` says whether the ``in`` test should be done
    against a lowercased haystack.
    """
    s = pattern
    ci = False
    if s.startswith("(?i)"):
        ci = True
        s = s[4:]
    if s.startswith(r"\b"):
        s = s[2:]
    if s.startswith("(?:"):
        end = _match_paren(s)
        # A trailing ? or * makes the whole group optional, so its contents are
        # not required and cannot serve as an anchor.
        if end is not None and not (end + 1 < len(s) and s[end + 1] in "?*"):
            inner = s[3:end]
            if "(" not in inner:  # flat alternation only
                lits = [_leading_literal(b) for b in inner.split("|")]
                if all(len(x) >= 2 for x in lits):
                    return [x.lower() if ci else x for x in lits], ci
        return [], ci
    lit = _leading_literal(s)
    if len(lit) >= 3:
        return [lit.lower() if ci else lit], ci
    return [], ci


# (compiled, label, severity, group, anchors, case_insensitive)
_MATCHERS: list[tuple[re.Pattern[str], str, str, int, list[str], bool]] = []
for _rx, _label, _sev, _grp in _SECRET_PATTERNS:
    _anchors, _ci = _anchors_for(_rx.pattern)
    _MATCHERS.append((_rx, _label, _sev, _grp, _anchors, _ci))

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


def _context_for_node(node: Any, source_bytes: bytes, radius: int = 80) -> str:
    """Return a small window of source around ``node`` for proximity checks.

    The high-entropy and hex-hash heuristics only fire when a secret-like
    variable name sits *next to* the literal. Using the whole physical line for
    that check is wrong for minified bundles, where the entire file is a single
    line: any occurrence of "token"/"auth"/"secret" anywhere in the bundle would
    satisfy the guard and produce a flood of false positives. Anchoring to the
    node's byte offsets keeps the proximity check meaningful regardless of
    minification.
    """
    if node is None:
        return ""
    start = getattr(node, "start_byte", None)
    end = getattr(node, "end_byte", None)
    if start is None or end is None:
        return ""
    lo = max(0, start - radius)
    hi = min(len(source_bytes), end + radius)
    return source_bytes[lo:hi].decode("utf-8", errors="ignore")


class SecretsAnalyzer(ASTAnalyzer):
    id = "secrets"
    description = "Detect hardcoded secrets in string literals"
    # 'page' is included so the regex fallback (below) also scans server-rendered
    # HTML/inline-script bodies; the JS AST path is unchanged for the JS types.
    supported_asset_types = ("javascript", "jsx", "typescript", "tsx", "page")

    def analyze_ast(self, asset: Asset, source: str, tree: Any | None) -> Iterable[Finding]:
        seen: set[str] = set()
        source_bytes = source.encode("utf-8")
        literals: list[tuple[str, Any]] = []
        if tree is not None:
            for node in _find_nodes(getattr(tree, "root_node", None), ("string", "template_string")):
                text = _node_text(node)
                # Strip surrounding quotes for analysis.
                stripped = text.strip("'\"`")
                literals.append((stripped, node))
        else:
            # Fallback: scan the whole source for quoted strings.
            for match in re.finditer(r"['\"`]([^'\"`]{4,})['\"`]", source):
                literals.append((match.group(1), None))
        for text, node in literals:
            if len(text) < 4:
                continue
            text_lower = text.lower()
            # Known provider/credential patterns (high precision, checked first).
            # The anchor prefilter skips patterns whose required literal is
            # absent, keeping large-literal scans fast (see ``_anchors_for``).
            for pattern, name, severity, group, anchors, ci in _MATCHERS:
                if anchors:
                    haystack = text_lower if ci else text
                    if not any(a in haystack for a in anchors):
                        continue
                match = pattern.search(text)
                if match:
                    # Keyword-gated patterns capture the secret in a group so the
                    # surrounding keyword is not leaked into the report.
                    token = match.group(group) if group else match.group(0)
                    if token is None:
                        token = match.group(0)
                    # A structural *marker* (PEM header, service-account type)
                    # carries no key material, so it is safe -- and clearer -- to
                    # show unmasked; everything else is masked to a few chars.
                    shown = token if name in _MARKER_LABELS else _mask(token)
                    value = f"{name}: {shown}"
                    if value not in seen:
                        seen.add(value)
                        yield SecurityFinding(
                            asset_url=asset.url,
                            finding_type="hardcoded_secret",
                            severity=severity,
                            value=value,
                        )
                    break
            else:
                # High-entropy heuristic only near secret-like variable names.
                entropy = _shannon_entropy(text)
                if entropy >= 4.5 and len(text) >= 20:
                    context = _context_for_node(node, source_bytes) if node else ""
                    if _SECRET_LIKE_NAMES.search(context):
                        value = f"high_entropy_secret: {_mask(text)}"
                        if value not in seen:
                            seen.add(value)
                            yield SecurityFinding(
                                asset_url=asset.url,
                                finding_type="hardcoded_secret",
                                severity="low",
                                value=value,
                            )
                            continue
                # Hex hashes with contextual secret hint.
                for pattern, name in _HEX_PATTERNS:
                    if pattern.search(text):
                        context = _context_for_node(node, source_bytes) if node else ""
                        if _SECRET_LIKE_NAMES.search(context):
                            value = f"{name}: {_mask(text)}"
                            if value not in seen:
                                seen.add(value)
                                yield SecurityFinding(
                                    asset_url=asset.url,
                                    finding_type="hardcoded_secret",
                                    severity="low",
                                    value=value,
                                )
                        break
