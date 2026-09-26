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

- **Sourcemap-driven un-minification.** When `.map` files are present (the crawler
  already collects them), reconstruct original sources for far better endpoint/secret
  extraction and accurate line numbers.
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
  re-run (checkpointing), so large sweeps recover from interruption.
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
