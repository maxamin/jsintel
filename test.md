# Ultra-aggressive test prompt for JSIntel

Paste this to Claude Code (or run it as an agent task) to exercise **every block and
line** of the project against the local lab. It is deliberately exhaustive: it drives
the real pipeline end to end, in both unauthenticated and authenticated modes, and
demands new tests for anything a run touches that is not already covered.

> **Authorization:** local lab only (loopback `127.0.0.x` and `*.labs.local`). Never
> point any active stage (port scan, fuzz, form submit, AJAX-spider) at a third-party
> or production target. Do not authenticate as a real user to any external site.

---

## 0. Prep the discovery target
1. Start the labs index so there is one crawlable link per lab on a random port:
   `python3 tests/lab/labs_index.py` — note the printed URL (also in
   `~/blockchain-security-labs/labs_index_url.txt`). Ensure the web labs
   (Juice Shop 3000, DVWA, WebGoat, WordPress, Django) and `anvil` (31000) are up.

## 1. Full-range discovery (port scan MUST find the index)
2. Run the pipeline so the port scanner sweeps the whole range and the crawler
   reaches every lab through the index:
   `JSINTEL_PORTS="80-10443" ./jsintel.sh -i <index-url> -p 127.0.0.1 -o output_ultra`
3. Assert `output_ultra/reports/ports.json` contains the index port and
   `output_ultra/assets/services.txt` lists the index URL. A non-HTTP service in the
   range (VNC/SSH/DB/Tor) must NOT abort the scan.

## 2. Unauthenticated pass (every stage)
4. Run the whole pipeline unauthenticated against the reachable labs, enabling every
   stage: subdomain (`-s`, where applicable), port scan (`-p`), screenshots (`-w`),
   fuzz (`-f`), and the form stage (`--forms`). Confirm each stage writes its report
   (`assets.json`, `endpoints.json`, `findings.json`, `fuzz.json`, `forms.json`,
   `ports.json`, `security.json`, `triage.json`).

## 3. Authenticated pass — BOTH session styles
5. **Cookie** (DVWA): log in (admin/password), set `security=low`, then run with
   `--cookie "PHPSESSID=<sid>; security=low" --forms`. Confirm the authenticated view
   yields the real vulnerable forms (not just the login form) and that they submit.
6. **JWT** (Juice Shop): obtain a token via `POST /rest/user/login`, then run with
   `--jwt <token> --forms JSINTEL_FORMS_ARGS="--browser --settle 6"`. Confirm the
   AJAX-spider captures authenticated XHR/fetch/WebSocket endpoints and feeds them
   back into `assets/crawled_urls.txt`.
7. Diff the unauthenticated vs authenticated reports and confirm auth strictly
   increases coverage (more endpoints/forms/findings).

## 4. proxychains
8. Re-run one lab pass with `--proxychains` and confirm the run still completes and
   traffic is routed (a Tor SOCKS proxy is on 127.0.0.1:9050). Repeat for the listener
   (`python3 -m modules.listener --proxychains --forms`).

## 5. Coverage — touch every block and line
9. Run the suite under coverage and fail on any uncovered line in changed/added code:
   `python3 -m pytest --cov=modules --cov=src --cov-report=term-missing`
10. For **every** module the pipeline executed above, if coverage shows an uncovered
    branch or line, WRITE A NEW TEST that reaches it — including error paths, empty
    inputs, malformed HTML/JSON, non-HTTP services, timeouts, ReDoS-shaped patterns,
    redirect/scope edges, and auth-header propagation. Cover the possible, the
    probable, and the realistic-but-unlikely (a form posting JSON via `fetch`, a
    trickle/streaming endpoint, a select with an empty option value, a label after its
    input, a radio group, a required checkbox, a `form=`-linked control, an orphan
    control with no `<form>`).
11. Re-run until the suite is green and coverage of touched code is complete. Record
    what was added in `TESTING_PROGRESS.md`.

## 6. Safety assertions (must hold)
- The destructive-endpoint guard skips payment/swap/withdraw/delete/logout unless
  explicitly overridden.
- No active stage ever contacts an out-of-scope host.
- The download stage bounds every asset (no single URL can hang the pipeline).
