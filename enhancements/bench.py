#!/usr/bin/env python3
"""Enhancement candidates — benchmark + result-equivalence harness (READ-ONLY).

Proposes algorithmic replacements for hot code sections found by profiling, WITHOUT
touching the project. For each candidate it (1) asserts the alternative returns a
result identical to the current implementation on real data, and (2) times both.
Only faster-with-identical-output candidates are recommended.

Run:  python3 enhancements/bench.py   (from repo root)
"""
from __future__ import annotations

import glob
import math
import random
import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root

from modules.extractor.parser import parse_js
from modules.extractor.ast_utils import _extract_string_literals, _build_index as CUR_build_index
from modules.extractor.analyzers.secrets_analyzer import _MATCHERS, _ANCHOR_AC, _ANCHORLESS_IDX
import modules.extractor.analyzers.secrets_analyzer as SA
import modules.webshot as WS


def _best(fn, reps=5):
    fn()  # warm
    return min((lambda t0: (fn(), time.perf_counter() - t0)[1])(time.perf_counter()) for _ in range(reps))


def _all_lab_js(max_files=30):
    """Real JS assets from EVERY lab output dir (incl. mass-sweep targets), by size."""
    paths = set(glob.glob("output_*/assets/*.js")) | set(glob.glob("output_*/targets/*/assets/*.js"))
    # de-dup identical bundles across runs by (basename, size) so we span labs, not copies
    by_key: dict[tuple, str] = {}
    for p in paths:
        try:
            size = Path(p).stat().st_size
            if size > 2_000_000:  # skip multi-MB monsters (keep runtime tractable)
                continue
            by_key.setdefault((Path(p).name, size), p)
        except OSError:
            pass
    # Spread across lab output dirs (largest few per dir, round-robin) so the sample
    # spans every lab rather than just one lab's biggest bundles.
    by_dir: dict[str, list[str]] = {}
    for p in by_key.values():
        by_dir.setdefault(p.split("/")[0], []).append(p)
    for d in by_dir:
        by_dir[d].sort(key=lambda p: -Path(p).stat().st_size)
    files, i = [], 0
    while len(files) < max_files and any(len(v) > i for v in by_dir.values()):
        for d in sorted(by_dir):
            if len(by_dir[d]) > i and len(files) < max_files:
                files.append(by_dir[d][i])
        i += 1
    print(f"  sampling {len(files)} JS bundles across {len(by_dir)} lab output dirs")
    return files


def _load_literals(files, cap=20000):
    """Real JS string literals from the given bundles, stride-sampled to `cap` so the
    set stays diverse across all labs. Equivalence is checked on every sampled one."""
    lits: list[str] = []
    for p in files:
        try:
            lits.extend(l for l in _extract_string_literals(parse_js(Path(p).read_text(errors="ignore"))) if len(l) >= 4)
        except Exception:
            pass
    if len(lits) > cap:
        step = len(lits) // cap
        lits = lits[::step][:cap]
    return lits


# =====================================================================================
# Candidate 1 — Shannon entropy (secrets_analyzer._shannon_entropy, ~1.5s in profile)
# =====================================================================================
def entropy_current(text: str) -> float:          # verbatim from the project
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


def entropy_counter(text: str) -> float:           # candidate A: collections.Counter
    if not text:
        return 0.0
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in Counter(text).values())


def entropy_log_identity(text: str) -> float:      # candidate B: sum(c*log2 c)/n - log2 n
    if not text:
        return 0.0
    n = len(text)
    s = sum(c * math.log2(c) for c in Counter(text).values())
    return math.log2(n) - s / n


# =====================================================================================
# Candidate 2 — Hamming distance on hex dHashes (webshot.hamming)
# =====================================================================================
def hamming_current(a: str, b: str) -> int:        # verbatim from the project
    if not a or not b or len(a) != len(b):
        return 64
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def hamming_bitcount(a: str, b: str) -> int:       # candidate: int.bit_count() (py3.10+)
    if not a or not b or len(a) != len(b):
        return 64
    return (int(a, 16) ^ int(b, 16)).bit_count()


# =====================================================================================
# Candidate 3 — AST type index build (ast_utils._build_index, ~7.7s self in profile)
# =====================================================================================
def build_index_reverse_at_end(node):             # candidate: append forward, reverse buckets once
    buckets: dict[str, list] = {}
    stack = [node]
    while stack:
        current = stack.pop()
        t = getattr(current, "type", None)
        if t is not None:
            buckets.setdefault(t, []).append(current)
        children = getattr(current, "children", None)
        if children:
            stack.extend(children)          # forward push -> reverse source order
    # We pushed children forward, so within a parent the later children pop first;
    # the resulting per-type order is reversed relative to source. Restore it once.
    for v in buckets.values():
        v.reverse()
    return buckets


def build_index_slice(node):                      # candidate C1: children[::-1] vs reversed()
    buckets: dict[str, list] = {}
    stack = [node]
    while stack:
        current = stack.pop()
        t = getattr(current, "type", None)
        if t is not None:
            buckets.setdefault(t, []).append(current)
        children = getattr(current, "children", None) or []
        stack.extend(children[::-1])
    return buckets


def build_index_direct(node):                     # candidate C2: direct attr access (no getattr)
    # tree-sitter nodes always expose .type (str) and .children (list), so the
    # getattr/None guards are pure overhead here; pre-order is preserved exactly.
    buckets: dict[str, list] = {}
    stack = [node]
    while stack:
        current = stack.pop()
        buckets.setdefault(current.type, []).append(current)
        children = current.children
        if children:
            stack.extend(reversed(children))
    return buckets


# =====================================================================================
# Candidate 4 — secrets anchor prefilter: OLD substring loop vs alternation-regex vs AC
# =====================================================================================
# Reconstruct the pre-AC substring prefilter (what shipped two iterations ago).
def prefilter_substring(text: str) -> set[int]:
    tl = text.lower()
    out = set()
    for i, m in enumerate(_MATCHERS):
        anchors = m[4]
        if not anchors or any(a.lower() in tl for a in anchors):
            out.add(i)
    return out


# Alternation-regex prefilter: one compiled regex of all anchors.
_ANCHOR_TO_IDX: dict[str, set[int]] = {}
for _i, _m in enumerate(_MATCHERS):
    for _a in _m[4]:
        _ANCHOR_TO_IDX.setdefault(_a.lower(), set()).add(_i)
_ALT_RE = re.compile("|".join(sorted((re.escape(a) for a in _ANCHOR_TO_IDX), key=len, reverse=True))) if _ANCHOR_TO_IDX else None


def prefilter_alternation(text: str) -> set[int]:
    out = set(_ANCHORLESS_IDX)
    if _ALT_RE:
        for m in _ALT_RE.finditer(text.lower()):
            out |= _ANCHOR_TO_IDX.get(m.group(0), set())
    return out


def prefilter_ac(text: str) -> set[int]:           # current (shipped)
    return set(_ANCHORLESS_IDX) | _ANCHOR_AC.matches(text.lower())


# =====================================================================================
def main() -> int:
    print("Loading real inputs across ALL labs…")
    files = _all_lab_js()
    lits = _load_literals(files)
    print(f"  {len(lits)} string literals extracted (equivalence is checked on every one)")
    hexes = ["".join(random.choice("0123456789abcdef") for _ in range(16)) for _ in range(4000)]
    pairs = [(hexes[i], hexes[(i * 7 + 3) % len(hexes)]) for i in range(len(hexes))]
    trees = []
    for p in sorted(files, key=lambda x: -Path(x).stat().st_size)[:4]:
        try: trees.append(parse_js(Path(p).read_text(errors="ignore")).root_node)
        except Exception: pass

    rows = []  # (group, name, ms, identical: bool)

    def idx_eq(a, b):
        """Compare two {type: [nodes]} indexes by node identity + order (cheap; avoids
        tree-sitter Node.__eq__, which does an expensive subtree comparison)."""
        if a.keys() != b.keys():
            return False
        return all([id(n) for n in a[k]] == [id(n) for n in b[k]] for k in a)

    def check(inputs, base_fn, cand_fn, eq):
        """True iff cand matches base on every input (result-equivalence)."""
        try:
            return all(eq(base_fn(x), cand_fn(x)) for x in inputs)
        except Exception:
            return False

    groups = [
        ("entropy", "current (dict.get loop)", entropy_current, entropy_current, lits, lambda a, b: True),
        ("entropy", "A: Counter", entropy_current, entropy_counter, lits, lambda a, b: abs(a - b) < 1e-9),
        ("entropy", "B: sum(c*log c) identity", entropy_current, entropy_log_identity, lits, lambda a, b: abs(a - b) < 1e-9),
        ("hamming", "current bin().count('1')", lambda x: hamming_current(*x), lambda x: hamming_current(*x), pairs, lambda a, b: True),
        ("hamming", "candidate int.bit_count()", lambda x: hamming_current(*x), lambda x: hamming_bitcount(*x), pairs, lambda a, b: a == b),
        ("build_index", "current (reversed per node)", CUR_build_index, CUR_build_index, trees, idx_eq),
        ("build_index", "C0: reverse buckets once", CUR_build_index, build_index_reverse_at_end, trees, idx_eq),
        ("build_index", "C1: children[::-1] slice", CUR_build_index, build_index_slice, trees, idx_eq),
        ("build_index", "C2: direct attr (no getattr)", CUR_build_index, build_index_direct, trees, idx_eq),
        ("prefilter", "current: Aho-Corasick", prefilter_ac, prefilter_ac, lits, lambda a, b: True),
        ("prefilter", "old: per-matcher substring", prefilter_ac, prefilter_substring, lits, lambda a, b: a == b),
        ("prefilter", "A: alternation regex", prefilter_ac, prefilter_alternation, lits, lambda a, b: a == b),
    ]
    for grp, name, base_fn, cand_fn, inputs, eq in groups:
        identical = check(inputs, base_fn, cand_fn, eq)
        reps = 3 if grp == "build_index" else 5
        if grp == "hamming":
            ms = _best(lambda f=cand_fn: [f(x) for x in pairs], reps) * 1000
        else:
            ms = _best(lambda f=cand_fn: [f(x) for x in inputs], reps) * 1000
        rows.append((grp, name, ms, identical))
        flag = "identical ✓" if identical else "REJECTED — result differs ✗"
        print(f"  [{grp:11}] {name:32} {ms:8.1f} ms   {flag}")

    print("\n=== SUMMARY (only identical-result candidates qualify) ===")
    from itertools import groupby
    for grp, items in groupby(rows, key=lambda r: r[0]):
        items = list(items)
        cur = next((r for r in items if r[1].startswith(("current", "old:")) and "current" in r[1]), items[0])
        cur = next((r for r in items if "current" in r[1]), items[0])
        qualified = [r for r in items if r[3]]
        best = min(qualified, key=lambda r: r[2]) if qualified else None
        for grp2, name, ms, ident in items:
            speed = f"x{cur[2]/ms:.2f}" if ms and ident else ("REJECTED" if not ident else "")
            win = "  <== fastest valid" if best and (name == best[1]) and name != cur[1] and ms < cur[2] else ""
            print(f"  [{grp:11}] {name:32} {ms:8.1f} ms  {speed}{win}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
