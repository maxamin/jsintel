# Project history

## Timeline (git + TESTING_PROGRESS milestones)

| Date | What happened |
|---|---|
| 2026-07-29 / 08-22 | `first commit`, `last`: Phase 1 shell pipeline. The extractor was rebuilt per the v4/v5 workflow docs (tree-sitter parser, AST analyzers, taint, code intelligence). |
| 2026-09-25 | E2E testing begins against a local mock (third-party live runs blocked). Fixed verbose-crawl and katana stdin-hang bugs. Secrets detector overhaul (vendored `token_patterns.json`, ReDoS proofs, Aho-Corasick). Fuzzer: category-aware Assetnote wordlists, then local SecLists preferred. |
| 2026-09-26 | Mass sweep (`-m`) + port scan (`-p`) + ether.fi fuzzer soft-404 fix. Loopback vulnerable lab (Juice Shop, WebGoat, DVWA, then VAmPI and DVGA via docker-export chroot, then 8 apps). Live-service analyzers. Authenticated mode `--cookie`/`--jwt`. Multi-technology page crawl. Source-map un-minification. False-negative feature batch (API spec ingest, sensitive files, debug pages, CSRF/param candidates, cloud buckets). ReDoS stress tests. Synthetic multi-host sweep. |
| 2026-09-27 | Algorithmic performance work. Parallel extraction (process pool, JSONL shards, LPT, big-bundle analyzer split with an over-split guard). Capture **listener** daemon (per-site grouping, whole-stream mining, opt-in fuzz, `--aggressive` flow recorder, volatile-noise normalization, persistent ledger, secret-aware anomaly engine). mitmproxy addon. Feedback discovery loop. Benchmarks (`BENCHMARKS.md`). Coverage push. |
| 2026-09-30 | Downloader hard bounds (streaming endpoints wedged the pipeline). **Forms / AJAX-spider** stage + `--proxychains`. labs-index discovery target on a random port 80-10443. Port scan survives non-HTTP banners. `reg_dom` IP pass-through. |
| 2026-10-09 → | Huge real mass sweep (`sweep_2026-10-09/`, about 10.2k of 58.5k targets done when analysed). A second sweep over `../YABFF/Merged_uniqued_subdomains_list.txt` was still running on 2026-10-15. |
| 2026-10-15 | False-positive reduction pass on the sweep corpus: taint scoping, eval/prototype/postMessage precision, secret blob-slice rejection, public-key severities, same-site param candidates, cloud bucket host fix, fuzzer repeated-response suppression. Branch `fix/false-positive-reduction` had uncommitted work: a `credentials-in-url` escaped-JSON-LD fix + test, and backlog additions. |
| 2026-10-17 | Sweep stopped at 13,784 of 58.5k targets. Output analysis found: katana never got the scope and crawled whole registered domains (one wordpress.com target hit 4,736 hosts); 485 katana OOM kills (12-34 GB), which silently truncated 474 "ok" targets; 44 targets lost to bash segfaults. Fixed with katana `-cs` scope, a `ulimit -v` cap, a crash-signal retry, and `JSINTEL_SWEEP_RESUME`. |
| 2026-10-17 (b) | Full log sweep (13,070 targets). Upgrades: proxychains fixed end to end (nmap scanned `224.0.0.1`, so 0 services anywhere; chromium aborted, so 0 screenshots; katana bypassed the proxy entirely), dead/wildcard pre-filter, chunk-URL artifact drop (56% of failed downloads), downloader 403 breaker, `--reanalyze` + fuzzer `--rescore`, `code_intel.json`, CSRF same-site plus a form-attribute bug (identical bodies got the first form's action), katana `-ct`, target hygiene/deny-list, stage telemetry + sweep health check. Suite 675 → 701. |

## Operator context (from shell history)
- Kali/Debian box, root, full Kali toolset installed (nmap, ffuf, feroxbuster, amass,
  assetfinder, hakrawler, httpx, katana, seclists, mitmproxy, proxychains4, chromium).
- Typical runs: `./jsintel.sh -i https://<target> -o <dir> -s <dom> -f <dom> -v`, often
  under `proxychains` (Tor at 127.0.0.1:9050). Real targets recorded include gala.com and
  ether.fi. Mass sweeps over `domains.txt` and merged subdomain lists, run in `screen`.
- Claude Code runs in `screen -S claude`. A `caveman` MCP and hooks are installed (they
  compress tool output and sometimes elide lines from `cat`. Use the Read tool, which
  returns the full file).
- The operator also works on a feroxbuster fork with an ML loop (`--ml-loop --ml-model`)
  fed from `domains.txt`, and on `~/blockchain-security-labs` (anvil on 31000, linked
  from labs_index).
- Local LLMs: Ollama with `qwen3-coder` (18 GB) and `opencode` installed. The box has
  no GPU. With 8 cores and about 9 GB free RAM, qwen3-coder is far too slow for bulk
  file analysis (no token returned after 3.5 min on 2026-10-15). Use it only for small,
  non-urgent prompts.
