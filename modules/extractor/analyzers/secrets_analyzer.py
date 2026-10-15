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

# Identifiers that are public by design (shipped to every browser); reported for
# environment fingerprinting only, never as a leaked credential.
_PUBLIC_LABELS = {"stripe-publishable-key", "google-oauth-client-id", "braintree-tokenization-key"}


# Browser keys that must ship to the client (Firebase web config, Maps JS); they are
# only abusable when left without API/referrer restrictions, which needs a manual check.
_CLIENT_KEY_LABELS = {"google-api-key"}


def _severity_for(entry: dict[str, Any]) -> str:
    if entry["id"] in _PUBLIC_LABELS:
        return "info"
    if entry["id"] in _CLIENT_KEY_LABELS:
        return "low"
    if entry["id"] == "jwt":
        return "low"
    if entry["id"] in _MARKER_LABELS:
        return "high"
    if entry.get("category") in _HIGH_CATEGORIES:
        return "high"
    return "medium"


_KEYWORD_LABELS: set[str] = set()
# Labels whose match is a bare token (fixed prefix or keyword-gated body), as
# opposed to structural markers/URLs; these get the blob-slice checks below.
_TOKEN_LABELS: set[str] = set()


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
        if entry.get("strategy") == "keyword":
            _KEYWORD_LABELS.add(entry["id"])
        if entry.get("strategy") in ("keyword", "prefix"):
            _TOKEN_LABELS.add(entry["id"])
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


class _AhoCorasick:
    """Multi-pattern literal matcher: one linear pass over a string returns the set
    of payloads whose keyword appears in it. Replaces the old per-matcher substring
    prefilter (O(literals x patterns x anchors)) with O(literals x length).
    """
    __slots__ = ("goto", "fail", "out")

    def __init__(self, words: list[tuple[str, int]]) -> None:
        goto: list[dict[str, int]] = [{}]
        out: list[set[int]] = [set()]
        for word, payload in words:
            cur = 0
            for ch in word:
                nxt = goto[cur].get(ch)
                if nxt is None:
                    nxt = len(goto)
                    goto.append({})
                    out.append(set())
                    goto[cur][ch] = nxt
                cur = nxt
            out[cur].add(payload)
        fail = [0] * len(goto)
        from collections import deque
        queue = deque()
        for ch, s in goto[0].items():
            queue.append(s)  # depth-1 nodes fail to root (0)
        while queue:
            u = queue.popleft()
            for ch, v in goto[u].items():
                queue.append(v)
                f = fail[u]
                while f and ch not in goto[f]:
                    f = fail[f]
                fail[v] = goto[f].get(ch, 0) if f or ch in goto[0] else 0
                if fail[v] == v:
                    fail[v] = 0
                out[v] |= out[fail[v]]
        self.goto, self.fail, self.out = goto, fail, out

    def matches(self, text: str) -> set[int]:
        goto, fail, out = self.goto, self.fail, self.out
        cur = 0
        found: set[int] = set()
        for ch in text:
            while cur and ch not in goto[cur]:
                cur = fail[cur]
            cur = goto[cur].get(ch, 0)
            if out[cur]:
                found |= out[cur]
        return found


# Prefilter: matchers with a provable anchor go into the automaton (anchors are
# lower-cased so one scan of the lower-cased literal is a safe over-approximation
# for both case-sensitive and -insensitive patterns; the regex still enforces
# exact case). Matchers with no provable anchor must always run.
_ANCHORLESS_IDX: frozenset[int] = frozenset(
    i for i, m in enumerate(_MATCHERS) if not m[4]
)
_ANCHOR_AC = _AhoCorasick(
    [(anchor.lower(), i) for i, m in enumerate(_MATCHERS) for anchor in m[4]]
)

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


def _token_from(match: re.Match[str], group: int, name: str, text: str) -> str | None:
    """The secret a pattern matched, or None when the match is not a real token.

    Keyword-gated patterns (``aws...``, ``cloudflare...``) have no fixed prefix, so
    their fixed-length body also matches a slice of any longer alphanumeric run
    that follows the keyword: an identifier (``awsRegionResolver...``), a word
    list (``...LawsuitLayerLazy...``) or a base64 blob. A genuine credential is a
    standalone token, so the captured body must not be glued to further token
    characters on either side, and must not be degenerate (``AAAA...``).

    Open-ended prefix patterns (``EAA[0-9A-Za-z]{90,}``, ``IGQ...{100,}``) have the
    same weakness inside base64 data (wasm segments, Flutter tables, inlined
    fonts): the match stops at the first ``+``/``/`` while the blob carries on, and
    binary padding yields long single-character runs no real token contains.
    """
    token = match.group(group) if group else match.group(0)
    if token is None:
        return match.group(0)
    g = group if group else 0
    start, end = match.start(g), match.end(g)
    if name in _KEYWORD_LABELS and group:
        if (start > 0 and text[start - 1].isalnum()) or (end < len(text) and text[end].isalnum()):
            return None
        if _shannon_entropy(token) < 3.0:
            return None
    if name in _TOKEN_LABELS:
        if (end < len(text) and text[end] in "+/=") or (start > 0 and text[start - 1] in "+/"):
            return None  # the match is one slice of a longer base64 run
        if _REPEAT_RUN.search(token.lstrip("A")):  # leading A-run is twitter's real prefix
            return None
    if name == "credentials-in-url" and _PLACEHOLDER_CREDS.search(token):
        return None
    return token


_REPEAT_RUN = re.compile(r"(.)\1{5}")
# Documentation/sample credentials: placeholder passwords or reserved hosts.
_PLACEHOLDER_CREDS = re.compile(
    r":(?:password|passwd|pass|pwd|secret|changeme|xxx+|\*+|<[^>]*>|\$\{?\w+\}?)@"
    r"|@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|[\w.-]*example\.(?:com|org|net)|[\w.-]+\.(?:example|test|local|invalid))\b",
    re.I,
)


# Shape of an opaque credential: no whitespace, template syntax, markup or path
# separators-with-extensions. Tailwind classes (``w-[2px]``), CSS, i18n strings and
# asset paths are high-entropy too but are not secrets.
_TOKEN_SHAPE = re.compile(r"[A-Za-z0-9+/=_\-.~]{20,}")
_ASSET_SUFFIX = re.compile(r"\.(?:svg|png|jpe?g|gif|webp|ico|css|js|json|html?|woff2?|ttf|mp4|map)$", re.I)


def _looks_like_token(text: str) -> bool:
    if not _TOKEN_SHAPE.fullmatch(text) or _ASSET_SUFFIX.search(text):
        return False
    if text.startswith(("/", ".", "-")) or "//" in text:
        return False
    return any(c.isdigit() for c in text) and any(c.isalpha() for c in text)


# One quoted literal of each kind. Matching every literal (any length) and
# filtering afterwards keeps the scan aligned: requiring a minimum length in the
# regex lets a short literal's *closing* quote be taken as an opening one, so the
# code between two literals (``" + awsKey + "``) was scanned as if it were a string.
# Written as the "unrolled loop" (``[^q\\]*(?:\\.[^q\\]*)*``): the two branches start
# on disjoint characters, so it is linear and ~10x faster than ``(?:[^q\\]|\\.)*`` on
# an unterminated multi-megabyte literal.
_QUOTED_LITERAL = re.compile(
    r'"([^"\\\n]*(?:\\.[^"\\\n]*)*)"|\'([^\'\\\n]*(?:\\.[^\'\\\n]*)*)\'|`([^`\\]*(?:\\.[^`\\]*)*)`'
)


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


def scan_text(text: str, *, max_len: int = 2_000_000) -> list[tuple[str, str, str]]:
    """Scan arbitrary text for hardcoded secrets with the provider pattern matchers
    (the Aho-Corasick prefilter selects candidates; the entropy heuristic, which needs
    AST node context, is intentionally skipped). Returns ``(name, severity, masked)``
    tuples, deduped. Reusable outside the AST pipeline -- e.g. to fingerprint the secrets
    in a captured response body/headers for secret-aware anomaly comparison.

    Every pattern is the same RE2-compatible, ReDoS-safe set the analyzer uses, and the
    input is length-capped, so this stays ~linear on adversarial input.
    """
    if not text:
        return []
    text = text[:max_len]
    candidates = sorted(_ANCHORLESS_IDX | _ANCHOR_AC.matches(text.lower()))
    found: dict[str, tuple[str, str, str]] = {}
    for i in candidates:
        pattern, name, severity, group, _anchors, _ci = _MATCHERS[i]
        for match in pattern.finditer(text):
            token = _token_from(match, group, name, text)
            if token is None:
                continue
            shown = token if name in _MARKER_LABELS else _mask(token)
            found.setdefault(f"{name}: {shown}", (name, severity, shown))
    return list(found.values())


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
            for match in _QUOTED_LITERAL.finditer(source):
                literals.append((next(g for g in match.groups() if g is not None), None))
        for text, node in literals:
            if len(text) < 4:
                continue
            text_lower = text.lower()
            # Candidate matchers = the always-run (anchorless) ones plus those whose
            # keyword the automaton found in this literal, in original matcher order
            # (preserving the high-precision-first, first-match-wins semantics). One
            # linear scan replaces the old per-matcher substring prefilter.
            candidates = sorted(_ANCHORLESS_IDX | _ANCHOR_AC.matches(text_lower))
            matched = False
            for _i in candidates:
                pattern, name, severity, group, anchors, ci = _MATCHERS[_i]
                # Keyword-gated patterns capture the secret in a group so the
                # surrounding keyword is not leaked into the report.
                token = next(
                    (t for m in pattern.finditer(text) if (t := _token_from(m, group, name, text)) is not None),
                    None,
                )
                if token is not None:
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
                    matched = True
                    break
            if not matched:
                # High-entropy heuristic only near secret-like variable names.
                # Check the cheap length gate BEFORE the O(len) entropy calc, so we
                # never compute entropy for the many short literals that can't qualify.
                if len(text) >= 20 and _looks_like_token(text) and _shannon_entropy(text) >= 4.5:
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
