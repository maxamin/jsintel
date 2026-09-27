# Algorithmic enhancement candidates (analysis only — no project code changed)

Hot code sections (from cProfile of the extractor over the 129-asset deep run) with
proposed algorithmic replacements. Each candidate is **result-gated**: the harness
(`enhancements/bench.py`) asserts it returns output identical to the current
implementation on real data before timing it. A candidate that changes any result is
**REJECTED** regardless of speed — "no result may be affected; only enhancements."

Reproduce: `python3 enhancements/bench.py` (from the repo root). Nothing here is wired
into the project; this file records the comparison so a change can be made deliberately.

## Method
- **Inputs span all labs.** 20,000 real JS string literals sampled across **30 bundles
  from 16 lab output dirs** (Juice Shop, WordPress, React, DVGA, VAmPI, WebGoat, DVWA,
  Django, the synth sweep, …); 4 large real ASTs; 4,000 hex dHash pairs.
- **Equivalence** is verified on **every** sampled input (entropy to 1e-9; hamming/
  prefilter exact; `_build_index` by node-identity+order via `id()` sequences — not
  `Node.__eq__`, which does an expensive subtree compare).
- **Timing** is best-of-N `perf_counter`. Sub-second/few-ms candidates that flip
  ranking between runs are reported as noise, not wins.

## Results (all-labs run)
| group | candidate | time | vs current | result |
|---|---|--:|--:|---|
| **build_index** | current (`reversed()` + `getattr`) | 3175 ms | 1.00× | — |
| | C0 reverse-buckets-once | 2168 ms | — | **REJECTED (reorders buckets)** |
| | C1 `children[::-1]` slice | 2764 ms | 1.15× | identical ✓ |
| | **C2 direct attr (no getattr)** | **1829 ms** | **1.74×** | **identical ✓ — APPROVED** |
| **prefilter** | current Aho-Corasick (shipped) | 444 ms | 1.00× | identical ✓ |
| | old per-matcher substring | 2113 ms | 0.21× | identical ✓ (4.8× slower — validates AC) |
| | alternation regex | 363 ms | — | **REJECTED (misses overlapping anchors, e.g. `api`⊂`apikey`)** |
| **hamming** | current `bin().count('1')` | 4.8 ms | 1.00× | — |
| | `int.bit_count()` | 3.3 ms | 1.45× | identical ✓ — approved but negligible (~1.5 ms absolute) |
| **entropy** | current (`dict.get` loop) | 212 ms | 1.00× | fastest; candidates ≤ 1.0× |
| | Counter / log-identity | 216–240 ms | 0.88–0.98× | identical ✓ but **not faster** (noise) |

---

## Candidate 1 — `_build_index` direct attribute access  ✅ APPROVED (1.74×)
`modules/extractor/ast_utils.py:36` — the #1 profile hotspot (~7.7 s self across the
deep run). It runs once per parseable asset.

**Current:**
```python
def _build_index(node):
    buckets = {}
    stack = [node]
    while stack:
        current = stack.pop()
        node_type = getattr(current, "type", None)
        if node_type is not None:
            buckets.setdefault(node_type, []).append(current)
        children = getattr(current, "children", None) or []
        stack.extend(reversed(children))
    return buckets
```
**Candidate C2 (direct attribute access):** tree-sitter nodes always expose `.type`
(str) and `.children` (list), so the `getattr(..., None)` guards + the `or []` are pure
overhead. Pre-order and bucket order are preserved exactly.
```python
def _build_index(node):
    buckets = {}
    stack = [node]
    while stack:
        current = stack.pop()
        buckets.setdefault(current.type, []).append(current)
        children = current.children
        if children:
            stack.extend(reversed(children))
    return buckets
```
**Verdict:** identical output on all sampled trees (id-sequence equal), **1.74× faster**.
Best single win here since `_build_index` is the top hotspot. (C1 `children[::-1]` is
also identical but only 1.15×; C0 reordered buckets → rejected.)

## Candidate 2 — secrets anchor prefilter  ✅ ALREADY SHIPPED / no change
`modules/extractor/analyzers/secrets_analyzer.py` — the current Aho-Corasick prefilter
is **4.8× faster** than the old per-matcher substring loop (2113 → 444 ms) with
identical candidate sets. The tempting **alternation-regex** alternative is faster
(363 ms) but **REJECTED**: `re.finditer` returns non-overlapping matches, so when one
anchor is a substring of another present at the same position (e.g. `api` inside
`apikey`) it misses the shorter one → a different candidate set → could change results.
AC finds all occurrences and is the correct algorithm. No change recommended.

## Candidate 3 — `hamming` via `int.bit_count()`  ⚠️ approved but negligible
`modules/webshot.py` (`hamming`). `(int(a,16)^int(b,16)).bit_count()` is 1.45× faster
than `bin(...).count("1")` and identical, but the whole clustering step is a few ms —
not worth a change on its own.

## Candidate 4 — `_shannon_entropy`  ❌ no viable candidate
`modules/extractor/analyzers/secrets_analyzer.py` (`_shannon_entropy`). `Counter` and
the `sum(c·log c)/n − log n` identity are result-identical but **not faster** — the
`dict.get` loop already wins, and rankings flip between runs (noise). Leave as is.

---

## Recommendation
Only **Candidate 1 (`_build_index` direct attribute access, 1.74×, identical)** is a
clear, meaningful, result-safe win — and it targets the single biggest CPU hotspot.
Candidate 3 is a valid micro-optimization with negligible impact. Candidates 2 and 4
confirm the current code is already the right algorithm. No changes made pending your
go-ahead.

---

## End-to-end validation of Candidate 1 (applied, measured, then REVERTED)

Applying the `_build_index` direct-attr change and measuring the **full sequential
extraction** of the 129-asset deep run (not the isolated micro-bench):

| | sequential extraction (best of 3) |
|---|--:|
| before C1 | 26.2 s |
| after C1  | 26.4 s |

**No measurable improvement (x0.99, within noise)** — output verified byte-identical,
356 tests pass. The isolated 1.74× did **not** translate.

**Why:** cProfile over-attributes time to functions that make many *cheap* calls
(`getattr`), because it counts every call. `_build_index`'s reported "7.7 s self" was
largely that instrumentation overhead; its real share of the ~26 s run is small, so
removing the `getattr` guards saves nothing at pipeline scale — and it drops a
defensive None-guard. **Verdict: reverted.** Lesson: rank real hot paths by
wall-clock on the actual workload, not by cProfile self-time on `getattr`-heavy code.

**Net conclusion of this enhancement pass:** no algorithmic change survives the
end-to-end bar right now. The genuinely expensive work is the analyzers themselves
(callgraph, taint, secrets — already AC-optimized) and, for wall-clock, the
already-shipped process parallelism. The remaining real lever is splitting the single
largest bundle across workers (Amdahl), not micro-optimizing `_build_index`.
