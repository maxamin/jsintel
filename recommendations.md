# JSIntel — Recommendations & Future Roadmap

Living list of enhancement ideas for JSIntel, grouped by area and roughly ordered
by value-to-effort within each. This is a **backlog of outstanding work**: when an
item ships it is *removed* from this file and recorded as a milestone in
`TESTING_PROGRESS.md` (so this list always reflects what is still to do).

> Scope/authorization note: every active stage (subdomain enum, port scan, fuzz,
> screenshots) only ever touches hosts inside the operator-supplied authorized
> scope. Any recommendation below inherits that constraint.

> Testing note: a repeatable, intentionally-vulnerable target lab now exists under
> `tests/lab/` (see `tests/lab/README.md`). Deploy and stress-test new features
> against it before shipping. Recommendations that name a concrete target below
> assume that lab.

---

## 1. Correlation & triage (remaining)

The unified per-host triage report (`reports/triage.{json,html,md}` with a risk
score that combines finding severity, sensitive-endpoint count and exposure) has
shipped, along with ingesting services + screenshots into the DB. What remains:

- **Bidirectional cross-links in the gallery.** The triage report lists a host's
  services (with screenshots) beside its findings; extend the *screenshot gallery*
  the other way — click a service → jump to that host's findings/endpoints, and
  flag a screenshot whose host has a critical/high finding.

## 2. Data model (remaining)

- **Per-run provenance.** Tag rows with a run id/timestamp so a shared DB can hold
  *intentional* multi-run history (ingest is already idempotent per output dir; a
  run id would let the shipped run-to-run diff — `python3 -m modules.diff <old>
  <new>` — work off one accumulating DB instead of two separate output dirs).

## 3. Discovery

- **Wildcard-DNS collapse in mass sweeps.** The 2026-10-09 sweep spent ~45 s each on
  ~8,000 phantom hosts (`*.kwenta.eth.limo`, `*.waymont.co`, `*.app.spot.cash`,
  `*.moonbeam.network`, `*.defly.app` — ~1,600 each) that only exist because the
  parent zone has wildcard DNS. Before running a target, resolve a random label under
  its parent (`<uuid>.<parent>`); if it resolves to the same address set (and, for
  HTTP, the same landing-page fingerprint), run ONE representative and record the
  rest as `wildcard` in `sweep_summary`. Do this in `sweep.sh` only between runs —
  editing a bash script that a live sweep is executing corrupts it.

- **More port-scan engines.** Support `naabu` natively (fast, hostname-aware) and
  `masscan` (resolve → scan IPs → fan out, reusing the CDN-aware mapping already
  built for nmap). Auto-pick by availability and target size.
- **Richer subdomain sources.** Add `crt.sh` (CT logs), `subfinder` config, and
  passive DNS; optional active DNS brute with a wordlist (scope-gated). Dedupe and
  liveness-probe as today. *Lab tie-in:* stand up a local authoritative resolver
  (dnsmasq) for a real `*.vuln.lab` zone so the `-s` stage and active brute can be
  exercised end-to-end against the lab (today the lab is reached via `/etc/hosts`,
  which passive/active enumeration cannot discover).
- **CDN/origin awareness.** The scanner already detects CDN fronting and collapses
  proxy-port mirrors. Next: attempt origin discovery (historical DNS, SAN certs) and
  label services `edge` vs `origin` in the report.

## 4. Fuzzer

- **WAF-wall early stop.** Repeated-response suppression now demotes a mid-scan WAF
  challenge wall after the fact, but the scan still spends its whole budget against
  it. Detect the wall live (N consecutive identical-shape responses after a clean
  baseline) and pause/back off that host instead of sending the remaining candidates.

- **Budget weighting.** Round-robin across hosts is in; add weighting by signal
  (hosts/directories with real 200s get a larger share than soft-404 SPAs).
- **Recursive discovery.** Feed confirmed directories back as new fuzz contexts
  (feroxbuster-style recursion), bounded by depth and budget.
- **Per-host rate limiting & backoff.** Politeness controls for shared infra and to
  avoid tripping WAFs (which the calibration already detects).
- **Template-param-aware fuzzing.** Endpoints now normalize `${...}` → `{}`; next,
  treat `{}` segments as path params in the fuzzer (skip brute-forcing them, fuzz
  the surrounding static prefix).

## 5. Extraction & analysis

- **Inter-procedural taint.** Taint is now lexically scoped (no cross-function name
  conflation) but stops at call boundaries: `h(location.hash)` → `function h(x){el.innerHTML=x}`
  is missed. Propagate taint through same-file function parameters (one level).
- **Source-map secret attribution.** Secrets recovered from `node_modules/` sources
  in a `.map` are vendor library code, not the target's config. Tag the finding with
  `first_party: false` (path under `node_modules/`) so triage can rank them below
  first-party sources instead of dropping them.
- **Google API key restriction check (opt-in, active).** Client keys are now `low`;
  an opt-in check could call a harmless metadata endpoint with the key to tell an
  unrestricted key (real finding) from a referrer-restricted one (no finding). Only
  against the operator's own authorized scope.

- **More analyzers.** Cloud-bucket references (S3/GCS/Azure URLs in JS) and other
  static signals. *(Shipped: live-service security-header, GraphQL-introspection,
  and JWT-algorithm analyzers — `modules/liveanalysis.py`.)*
- **Auth-flow JWT analysis.** The JWT analyzer flags tokens it observes in
  responses/headers and dangerous algorithms (`alg:none`, symmetric signing); extend
  it to drive an auth flow (e.g. VAmPI register→login) so a token is obtained and
  analyzed even when the bare service does not emit one.

## 6. Screenshots / triage UI

- **Playwright engine option.** Behind `--engine playwright`: waits for network-idle
  (better for heavy SPAs than a fixed virtual-time budget), and captures the final
  title + console errors. Chromium-headless stays the zero-dep default.
- **Gallery as a shareable Artifact.** Publish `screenshots.html` (and the triage
  report) as a private page for the operator's own authorized results.
- **Better visual clustering.** dHash clusters by layout and washes out on sparse
  text pages; add a coarse color/text-density signal so plain pages separate, and
  expose the Hamming threshold per run.

## 7. Reliability & performance

- **Resumable stages.** Skip already-downloaded assets / already-shot services on
  re-run (checkpointing). Whole-target resume exists (`JSINTEL_SWEEP_RESUME=1`); this is
  the finer, per-stage version inside one target.
- **Upgrade bash on the sweep box (5.3-3+b1 → 5.3-4 is available).** The 2026-10-09
  sweep lost 44 targets to sporadic bash segfaults (rc=139) inside `crawler.sh` (43,
  right after katana returned) and `portscan.sh` (1), with no kernel trace and no
  correlation with OOM kills. `sweep.sh` now retries those once. If they persist after
  the upgrade, capture a core (`ulimit -c unlimited`, `coredumpctl`) and report upstream.
- **katana memory with `-jsl`.** With the scope now passed (`-cs`), re-measure peak
  katana RSS over a sweep slice. If it still nears the 8 GB cap, consider dropping
  `-jsl` for very large sites or adding `-ct` (crawl duration).
- **Structured run manifest.** One `run.json` capturing flags, scope, tool versions,
  timings per stage — useful for debugging and for annotating run-to-run diffs.

## 8. Testing harness (remaining)

The repeatable target lab shipped (`tests/lab/`): Juice Shop, WebGoat + WebWolf,
and DVWA run loopback-only on a distinct-IP `/etc/hosts` subdomain tree on
non-standard ports, with an `assert_loopback` safety gate. What remains:

- **More target apps.** Add bWAPP, NodeGoat, crAPI, Mutillidae to broaden stack
  coverage. Prefer ones that run natively or via the `docker export` + chroot path
  now used for VAmPI/DVGA; this sandbox cannot bridge-network (see
  `TESTING_PROGRESS.md`).
- **CI regression assertions.** Wire the lab into pytest/CI: bring the estate up,
  run the full chain, and assert on the expected triage outcome (e.g.
  `shop.vuln.lab` ranks critical with the known Juice Shop sensitive endpoints and
  eval/taint findings). Turns "it ran" into a guarded regression.
- **Real minified-bundle fixtures.** Add a Juice Shop `main.js` (and a `.map`) as
  extractor fixtures for offline analyzer regression.

## 9. Safety & scope ergonomics

- **Scope config file.** A single `scope.yaml` (allow domains, deny hosts, ports,
  rate limits) consumed by every stage, instead of repeating `-s/-p/-f` scope args.

---

_This file is a backlog, not a commitment. With triage/services correlation, the
run-to-run diff, and the target lab now shipped, the next compounding wins are §8
(VAmPI/DVGA + CI regression) and §5 (GraphQL/JWT/security-header analyzers) —
together they turn the lab into a guarded, multi-vuln-class regression suite._
