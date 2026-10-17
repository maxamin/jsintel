# Testing and the vulnerable lab

## Unit and integration suite
- `python3 -m pytest -q`: 47 files, **706 tests**. Offline and deterministic. Network
  is replaced by injected transports, local `http.server` fixtures, and crafted output
  dirs. `tests/conftest.py` puts both the repo root and `src/` on `sys.path`.
- The operator's coverage goal is every changed line:
  `python3 -m pytest --cov=modules --cov=src --cov-report=term-missing`.
- Timing-bound ReDoS tests (`test_forms.py::test_pattern_sampler_is_redos_safe_and_bounded`
  and `test_analyzers.py::TestSecretPatterns::test_no_catastrophic_backtracking_on_large_input`)
  use wall-clock limits. On 2026-10-15 both failed by a hair (5.1 s vs 5.0 s) while a
  58k-target sweep held the load average at 27 on 8 cores. If they fail, check `uptime`
  before suspecting a regression, and re-run them in isolation when the box is quiet.
- Shell logic gets tested by extracting the function from the script and running it in
  bash (see `tests/test_crawler_scope.py`, which exercises `reg_dom`).
- Test map: `test_analyzers.py` (taint, security, secrets, patterns, FP regressions),
  `test_secrets_prefilter.py`, `test_more_analyzers.py`, `test_cloud_analyzer.py`,
  `test_page_analyzer.py`, `test_sourcemap.py`, `test_url_filter.py`, `test_parser.py`,
  `test_extractor_*`/`test_extract_parallel.py` (manifest streaming, sharding, split
  plan), `test_fuzzer_*` (one per fuzzer module), `test_forms*.py` (parser, synth,
  driver, main), `test_listener.py` (classify, mining, flow recorder, anomalies),
  `test_mitm_addon.py`, `test_portscan.py`, `test_liveanalysis.py`, `test_webshot.py`,
  `test_downloader.py` (streaming-endpoint bound), `test_discover.py`,
  `test_database_ingest.py`, `test_reporter.py`, `test_triage.py`, `test_diff.py`,
  `test_sweep_aggregate.py`, `test_authutil.py`, `test_proxyutil.py`,
  `test_labs_index.py`, plus Phase 2 tests in `test_{models,plugins,storage,config}.py`.

## The lab (`tests/lab/`): loopback only and deliberately vulnerable
- `tests/lab/lab.sh up|down|status [ids]`, `hosts install|remove` (sudo, `/etc/hosts`
  block), `seeds`, `scope`. Ids: `juice vampi dvga webgoat dvwa`. App sources and
  runtime go in the git-ignored `tests/lab/runtime/` (about 3.5 GB).
- Estate: `shop.vuln.lab` 127.0.0.1:3000 (Juice Shop), `goat.vuln.lab` 127.0.0.2:8082/9090
  (WebGoat/WebWolf), `dvwa.vuln.lab` 127.0.0.3:8081 (DVWA + repo-local MariaDB),
  `api.vuln.lab` 127.0.0.4:5001 (VAmPI), `graphql.vuln.lab` 127.0.0.5:5013 (DVGA).
  Later batches added WordPress, Django, a synth multi-host server
  (`fixtures/synth/server.py`), and smap/react fixtures (see TESTING_PROGRESS
  "lab expansion"). VAmPI and DVGA run from `docker export` rootfs plus a chroot
  (`targets/rootfs.sh`), because the host Python is 3.14 and this kernel cannot create
  docker0. `assert_loopback` kills any service bound to a non-loopback address.
- `tests/lab/docker-compose.yml` + `lab-docker.sh` run the fuller estate on a normal Docker host.
- `tests/lab/labs_index.py` serves an index page on a **random free port in 80-10443**
  that links every lab (plus the blockchain labs from `~/blockchain-security-labs/ports.json`;
  anvil is on 31000). It is a discovery target that the port scan must find first:
  `JSINTEL_PORTS="80-10443" ./jsintel.sh -i <index-url> -p 127.0.0.1 -o output_ultra`.
- Seed lists: `tests/lab/seeds_*.txt` and `synth_targets.txt`.

## Validation protocol the operator expects (see also /test.md)
1. Unit tests for the possible, the probable, and the realistic-but-unlikely: malformed
   HTML or JSON, mislabeled content types, SPA behaviour, non-HTTP services, timeouts,
   ReDoS-shaped input, redirect and scope edges, and auth-header propagation.
2. A live lab run in three modes: unauthenticated, `--cookie` (DVWA:
   `PHPSESSID=<sid>; security=low` after logging in as admin/password), and `--jwt` (a
   Juice Shop token from `POST /rest/user/login`). Show the coverage difference
   (authenticated runs must find more).
3. Assert the expected outcomes: `shop.vuln.lab` is critical in triage, DVWA's `.git`
   exposure is caught, VAmPI's `/openapi.json` yields 12 endpoints including
   `/users/v1/_debug`, DVWA yields 8 reflected-param candidates and no missing-CSRF
   findings (it uses `user_token`).
4. Safety assertions: the destructive-form guard holds, no request goes out of scope,
   and no download can hang.
5. Write fresh runs to a **new** `output_<name>` dir, or to the scratchpad. Never reuse
   or delete an existing one.

## Real-data corpora (read only, no new traffic)
`sweep_2026-10-09/targets/*/reports/` (about 10.2k targets) is the FP-analysis corpus.
The `output_gala*` and `ether_fi_runs` dirs hold earlier real-target runs that the
operator ran themselves.
