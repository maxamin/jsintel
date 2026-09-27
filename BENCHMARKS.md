# JSIntel — Benchmarks

Measured on the local vulnerable-target lab (Juice Shop, DVGA, VAmPI, WebGoat, DVWA, plus
the WordPress/Django/React/smap hosts), all bound to loopback. Reproduction scripts live in
the session scratchpad; the methodology is described per section so results can be
re-measured with `python3 -m modules.extractor.main`, `./jsintel.sh`, and `modules.listener`.

> **Environment caveat.** These runs shared an 8-core host that, during measurement, was
> also running an unrelated background extraction (~5 cores busy, load avg ~6–7). Absolute
> wall-clock times are therefore inflated and noisy; **ratios measured back-to-back under
> the same load are meaningful**, and the one clean-machine number is called out. Coverage
> metrics (asset/endpoint/finding counts) are load-independent and exact.

Test suite at time of writing: **435 passing** (`python3 -m pytest`).

---

## 1. Extraction — process parallelism + big-bundle analyzer split (#2)

Real lab JS bundles, `workers=4`, best-of-2, findings verified **byte-identical** across all
modes (per-report set equality).

### Across-asset parallelism (12 bundles, ≤1 MB each, 8.9 MB total)

| mode | wall | vs sequential |
|---|--:|--:|
| sequential (`WORKERS=1`) | 53.5–54.7 s | 1.00× |
| process-parallel (`WORKERS=4`) | 14.1–16.1 s | **3.4–3.9×** |

### Single dominant bundle — analyzer split (1.18 MB `main.js` + 11 small)

Splitting one large bundle's analyzers across idle workers (the Amdahl fix). Measured
earlier in the session under lighter load (spare cores available):

| mode | wall | vs no-split |
|---|--:|--:|
| parallel, split **off** (bundle serial in one worker) | 7.82 s | 1.00× |
| parallel, split **on** (`SPLIT_BYTES=200000`) | 4.38 s | **1.79×** |

Under full CPU saturation the same split measured ~1.0× (no idle cores to exploit) — a
**wash, never a regression**, because of the guard below.

### The over-split guard (correctness)

Splitting re-parses the source once per analyzer group, so blanket-splitting *many* bundles
multiplies parse cost. An early 200 KB threshold with 12 all-big bundles measured **0.56×
(slower)**. Fixed: a bundle is split **only when the number of over-threshold bundles is
≤ half the workers** (i.e. workers would otherwise idle). Verified structurally:

| scenario (`workers=4`) | split jobs emitted |
|---|--:|
| 12 bundles ≥ threshold | **0** (all batched whole — no re-parse blowup) |
| 1 big + 6 small | 4 (dominant bundle parallelized) |

**Parity:** sequential ≡ parallel ≡ parallel+split, byte-identical per report
(`tests/test_extract_parallel.py`).

**Knobs:** `JSINTEL_EXTRACT_WORKERS` (default = min(cpu, 8)), `JSINTEL_SPLIT_BYTES`
(default **200 000**; 0 disables the split).

---

## 2. Feedback discovery loop (#1)

Full pipeline vs Juice Shop with the shipped defaults (`JSINTEL_DISCOVER_ROUNDS=3`,
`JSINTEL_DISCOVER_LIMIT=200`). The loop fetches in-scope assets referenced by other
extracted assets that the crawler never reached, then re-extracts.

| metric | value |
|---|--:|
| assets crawled (round 0) | 39 |
| **assets after discovery** | **58 (+19, +49%)** |
| discovery rounds used | 1 effective (round 1 +19, round 2 +0 → converged) |
| endpoints (unique) | 62 |
| urls (unique) | 219 |
| findings | 22 468 (7 hardcoded secrets, 2 dangerous-eval, 6 taint-to-sink) |
| triage top host | shop.vuln.lab (risk 1057) |
| scope safety | **all 19 discovered assets on `shop.vuln.lab` — never a new host** |

The loop is bounded (stops when a round finds nothing, or at `DISCOVER_ROUNDS`), budget-capped
per round, de-duped across rounds, and only re-extracts when a round actually fetched something.

---

## 3. Listener — passive capture pipeline

All 9 lab hosts fed through the listener (`--group host`), one coalesced scan per site.

| metric | value |
|---|--:|
| captures fed | 36 across 9 hosts |
| sites created | 9 (one dir + one scan per host — no per-URI explosion) |
| feed time | 2.4 s |
| full scan-all (`/flush`) | 7.7 s |
| per-site security findings | 12–47 (e.g. graphql 47, goat 30, dvwa 19) |
| triage | every site ranked |

### Aggressive mode (per-flow dedup + anomalies), earlier all-labs run

| metric | value |
|---|--:|
| captures | 75 |
| distinct flows | 41 |
| deduped (cycle-break) | 25 |
| anomalies | 9 (one tampered response per host) |
| invariant | responses (50) = flows (41) + anomalies (9) |

**Anomaly truthfulness:** DVWA's rotating CSRF token → **0 false anomalies**; VAmPI's real
data change → true anomaly; a newly-appearing secret → **high** severity; suppressed noise
verified against real lab dynamic pages.

---

## 4. What each optimization buys

- **Across-asset parallelism:** ~3.4–3.9× over sequential on a 12-bundle run (4 workers).
- **Big-bundle analyzer split:** up to ~1.8× on a run dominated by one large bundle when
  cores are free; neutral (never worse) otherwise, thanks to the ≤half-workers guard.
- **Feedback discovery:** +49% asset coverage on Juice Shop (19 assets the crawler missed),
  scope-safe and convergent.
- **Listener:** turns already-captured proxy traffic into full triage without re-fetching;
  per-site coalescing keeps one scan per target; aggressive mode adds secret-aware,
  low-false-positive change detection.
