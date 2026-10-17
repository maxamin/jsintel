---
name: jsintel
description: Complete working knowledge of the JSIntel recon framework (bash pipeline + Python modules for crawling, JS/page extraction, secrets/taint analysis, port scan, fuzzing, forms/AJAX-spider, listener daemon, triage). Load before reading, changing, testing, or extending anything in this repository.
---

# JSIntel — project skill

JSIntel is a JavaScript-aware **asset-intelligence and recon framework for authorized
security testing**. Give it seed URLs in an authorized scope and it can enumerate
subdomains, find web services on non-standard ports, crawl, download assets, extract
intelligence (URLs, endpoints, secrets, taint flows, frameworks), fuzz, fill forms,
take screenshots, and roll everything into SQLite plus a ranked per-host **triage**
report.

Owner: a single operator (GitHub `maxamin/jsintel`) running Kali/Debian as root. The
main branch is `main`. Work goes on `feat/*` or `fix/*` branches.

## Read these files in order

| File | Read it when |
|---|---|
| [architecture.md](architecture.md) | Always first: pipeline order, data flow, output tree, invariants |
| [modules.md](modules.md) | Before touching any file: one entry per source file with its purpose and key functions |
| [extractor.md](extractor.md) | When working on analyzers, secrets, taint, false positives, or extraction performance |
| [active-stages.md](active-stages.md) | When working on portscan, fuzzer, forms, webshot, liveanalysis, discover, subdomains, or sweep |
| [listener.md](listener.md) | When working on the capture daemon, mitmproxy addon, or anomaly engine |
| [data-and-reports.md](data-and-reports.md) | When working on report JSON shapes, the DB schema, triage scoring, diff, or sweep aggregation |
| [configuration.md](configuration.md) | For CLI flags, `JSINTEL_*` env vars, and `config.yaml` |
| [testing-and-lab.md](testing-and-lab.md) | Before claiming anything works: the test suite, the vulnerable lab, and validation rules |
| [workflow.md](workflow.md) | **Mandatory.** Operator rules, the backlog loop, commit conventions, and safety boundaries |
| [known-gaps.md](known-gaps.md) | When picking work: verified gaps, doc drift, and where the roadmap lives |
| [history.md](history.md) | For context on how the project evolved (git + shell history) |
| [docs-index.md](docs-index.md) | Map of every `.md` file in the repo, with symlinks in `project-docs/` |

## Non-negotiable rules (summary of workflow.md)

1. **Scope is a security control.** Every active stage only touches hosts inside the
   operator-supplied scope. Off-scope redirects never widen it. Auth headers
   (`--cookie`/`--jwt`) only go to in-scope hosts. Never weaken a scope check.
2. **Never delete seed or result files** (`domains.txt`, `urls`, `seeds.txt`, `output_*/`,
   `sweep_*/`, `ether_fi_runs/`, any `reports/`, `assets/`, or DB). Use a new output dir.
3. **Do not run active stages against third parties.** Validate against the local lab
   (`tests/lab/`, loopback only). Give the operator ready-to-run commands for their own
   authorized targets.
4. **Track progress in markdown.** Log milestones in `TESTING_PROGRESS.md`. Treat
   `recommendations.md` as a live backlog: remove shipped items and add new ideas.
5. **Regexes must be ReDoS-safe.** Bound every quantifier and time each pattern on
   multi-MB single-line input. Secret patterns need positive, negative, and boundary tests.
6. **Findings must be true.** False-positive reduction is a first-class goal. Fix the
   root cause in the detector, add a regression test from the real sample, and measure
   the effect on real sweep data.
7. Validate features in **unauthenticated, cookie, and JWT** modes. Wire new stages
   through every applicable entry point: `jsintel.sh`, the listener, and the standalone CLI.

## Fast orientation commands

```bash
python3 -m pytest -q                         # whole suite (~570 tests, offline)
./jsintel.sh -h                              # every flag
./jsintel.sh -i http://127.0.0.1:8099/ -o output_scratch_$(date +%s) -v   # local smoke run
python3 -m modules.extractor.main --manifest OUT/reports/assets.json --output OUT/reports
python3 modules/database.py --output OUT query "SELECT finding_type,severity,COUNT(*) FROM findings GROUP BY 1,2"
python3 -m modules.diff OLD_OUT NEW_OUT
git log --oneline; sed -n '/^## /p' TESTING_PROGRESS.md | tail -20
```

## Mental model in one paragraph

`jsintel.sh` is a thin bash orchestrator. Each stage is a script in `modules/` that
reads files in `$OUTPUT_DIR`, writes new files there, and communicates **only through
those files** (`assets/*.txt` and `reports/*.json`). `reports/assets.json` is the
manifest that every stage enriches. The extractor is a typed Python package with
auto-discovered analyzer plugins that stream findings to JSON arrays. `database.py`
rebuilds `recon.db` from the reports on every run. The reports are the source of
truth; the DB is derived from them. `reporter.py` and `triage.py` read the DB. Active
stages (portscan, fuzzer, forms, webshot, liveanalysis, discover) are opt-in and
scope-gated. The listener daemon runs the same pipeline on captured traffic
instead of crawling. `src/jsintel/` is a typed "Phase 2" platform API that only tests
use so far. The live pipeline does not run through it.
