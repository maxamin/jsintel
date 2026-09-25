# Content-Discovery Fuzzing

JSIntel's fuzzer turns the paths it already discovers inside JavaScript into
live, verified content on an **authorized** target. It is a focused,
category-aware content-discovery step in the spirit of `ffuf`, `feroxbuster`, and
`dirsearch`, wired directly to the paths JSIntel extracts and to the public
[Assetnote wordlists](https://wordlists.assetnote.io/).

> **Authorized testing only.** Fuzzing sends real HTTP requests. Run it only
> against hosts you are explicitly permitted to assess. The tool enforces this
> with a mandatory authorization scope (see [Safety model](#safety-model)); it
> will not send a single request without one.

## Why the hit rate is high

Two design choices make reported hits likely to be real rather than lucky:

1. **The right wordlist for the right find.** Every discovered path is classified
   and matched to the Assetnote list built for that class. An API route is fuzzed
   with an API-route list, a GraphQL endpoint with a GraphQL list, a `.js` file
   with a JavaScript-filename list, and so on. Assetnote's `httparchive_*` lists
   are ranked by how often each entry occurs across the web, so the
   category-appropriate list front-loads the entries most likely to exist.

2. **Known-good prefix extension.** A discovered `/api/v1/users` proves that
   `/api/v1/` and `/api/` are real directories on the target. The fuzzer appends
   wordlist entries to *those* prefixes rather than brute-forcing from `/`, which
   is where most of the productive surface actually is.

Precision is then protected by **per-directory calibration**: before fuzzing a
directory the tool requests a random, almost-certainly-absent path and records
the "not found" fingerprint (status code and body length). Servers that answer
unknown paths with a soft `200`/`302` page are detected, and a candidate is only
reported as *interesting* when its response is both in the match set and
different from that baseline — the same auto-filter idea `ffuf` uses.

## Category → wordlist map

| Category   | Triggered by (examples)                         | Assetnote list (online)                         | Bundled seed         |
|------------|-------------------------------------------------|-------------------------------------------------|----------------------|
| `api`      | `/api/...`, `/rest/...`, `/v1/...`, `/service/` | `automated/httparchive_apiroutes_*.txt`         | `seeds/api.txt`      |
| `graphql`  | `/graphql`, `/graphiql`, `/gql`                 | `manual/graphql.txt`                            | `seeds/graphql.txt`  |
| `js`       | `*.js`, `*.mjs`, `*.ts`, `*.map`                | `automated/httparchive_js_*.txt`                | `seeds/js.txt`       |
| `file`     | `*.json`, `*.env`, `*.bak`, `*.zip`, ...        | `manual/raft-large-files.txt`                   | `seeds/files.txt`    |
| `parameter`| path carried a `?query=...`                     | `automated/httparchive_parameters_*.txt`        | `seeds/parameters.txt`|
| `directory`| trailing `/`, or an extension-less segment      | `manual/raft-large-directories.txt`             | `seeds/directories.txt`|
| `generic`  | anything else                                   | `manual/raft-large-words.txt`                   | `seeds/generic.txt`  |

Ordering resolves overlaps deterministically: GraphQL wins over generic API
markers, and a JavaScript extension wins over an `/api` prefix (a bundle under
`/api` is still a bundle). The full mapping lives in
[`modules/fuzzer/catalog.py`](../modules/fuzzer/catalog.py) and the classifier in
[`modules/fuzzer/classify.py`](../modules/fuzzer/classify.py).

### Wordlist resolution and caching

For each category the provider resolves words in this order:

1. a previously cached/override file under `<output>/wordlists/` (named
   `<list>.txt`, e.g. `assetnote-raft-directories.txt`) — drop any list here to
   force it for a category;
2. a **locally installed SecLists** file, when SecLists is present (used even
   with `--offline`, since it is on disk, not remote);
3. a fresh download from the Assetnote CDN (unless `--offline`), cached for reuse;
4. the **bundled seed** that ships with JSIntel.

The result is always non-empty, so the fuzzer works with no network at all. Only
the top `--max-words` entries per category are used (default 1500); because the
lists are frequency-ranked, that slice keeps request volume bounded while
retaining the highest-probability terms. Assetnote's dated `automated/` filenames
rotate over time — if a listed snapshot 404s, the next candidate URL and finally
the seed are used, so a stale filename degrades gracefully instead of failing.

The provenance actually used for each category is logged (`Using local wordlist
… for api`) and available programmatically as `WordlistProvider.sources`.

### Using locally installed SecLists

On Kali/Debian pentest images SecLists lives at `/usr/share/seclists`. When it is
present the fuzzer prefers it automatically. Each category maps to a curated
SecLists file:

| Category   | SecLists file (under `Discovery/Web-Content/`)          |
|------------|---------------------------------------------------------|
| `api`      | `api/api-seen-in-wild.txt` → `api/api-endpoints.txt`     |
| `graphql`  | `graphql.txt`                                           |
| `js`/`file`| `raft-large-files.txt`                                  |
| `parameter`| `burp-parameter-names.txt`                              |
| `directory`| `raft-large-directories.txt`                            |
| `generic`  | `raft-large-words.txt` → `common.txt`                   |

Options: `--seclists <dir>` points at a non-standard SecLists install (its root
or its `Discovery/Web-Content` directory); `--no-local` disables the local source
and uses the CDN/seed path instead. To use a **different** local collection
(ProjectDiscovery, OneListForAll, a custom list), copy the file into
`<output>/wordlists/<list>.txt` for the category you want to override — step 1
above picks it up before anything else.

## Usage

### As part of the pipeline

```bash
./jsintel.sh -i scope.txt -o target_output -f app.example.test
```

`-f` enables fuzzing against the given authorized scope (a domain, or several
separated by commas/spaces; subdomains are included). Extra fuzzer options can be
passed through the `JSINTEL_FUZZ_ARGS` environment variable:

```bash
JSINTEL_FUZZ_ARGS="--delay 0.2 --max-words 800" \
  ./jsintel.sh -i scope.txt -o target_output -f example.test
```

### Standalone

Run it against an existing output directory that already contains
`reports/endpoints.json` and `reports/urls.json`:

```bash
# Live run, limited to an authorized scope:
python3 -m modules.fuzzer --output target_output --scope example.test

# Plan candidates without sending any requests (no scope required):
python3 -m modules.fuzzer --output target_output --dry-run

# Fully offline, using only the bundled seed wordlists:
python3 -m modules.fuzzer --output target_output --scope example.test --offline
```

Key options:

| Option              | Meaning                                                        |
|---------------------|----------------------------------------------------------------|
| `--scope`           | Authorized host/domain (repeatable). **Required for live runs.**|
| `--dry-run`         | Plan and write candidates without sending requests.            |
| `--offline`         | Use only bundled seeds; never download.                        |
| `--concurrency N`   | Max concurrent requests (default 20).                          |
| `--delay S`         | Sleep S seconds before each request (throttle).                |
| `--timeout S`       | Per-request timeout (default 10).                              |
| `--max-words N`     | Max wordlist entries per category (default 1500).              |
| `--context-depth N` | Directory prefixes to fuzz per path (default 2).               |
| `--max-candidates N`| Hard cap on total candidate URLs (default 20000).             |
| `--extensions`      | Extra extensions to also try, e.g. `.json,.bak`.               |
| `--match-status`    | Override matched status codes.                                 |
| `--filter-status`   | Override filtered status codes.                                |
| `--no-calibrate`    | Disable per-directory soft-404 calibration.                    |
| `--seclists DIR`    | Path to a SecLists install (root or `Discovery/Web-Content`).  |
| `--no-local`        | Ignore locally installed SecLists; use CDN/seed instead.       |

## Output

The run writes two files under `<output>/reports/`:

* `fuzz.json` — one record per candidate, interesting results first:

  ```json
  {
    "url": "https://app.example.test/api/v1/me",
    "category": "api",
    "origin": "/api/v1/users",
    "word": "me",
    "status": 200,
    "length": 1234,
    "words": 210,
    "redirect": "",
    "error": "",
    "interesting": true,
    "note": "match"
  }
  ```

  The `note` field explains the verdict: `match`, `filtered-status`,
  `unmatched-status`, `matches-soft-404-baseline`, `dry-run`, or `out-of-scope`.

* `fuzz_summary.json` — aggregate counts, including candidates per category.

When the pipeline continues, `database.py` ingests the actually-probed rows into a
`fuzz_results` table (planning and out-of-scope rows are not stored), and
`reporter.py` adds a `fuzz_probed` / `fuzz_interesting` line to the run summary.
Query hits directly:

```bash
python3 modules/database.py --output target_output \
  query "SELECT url,status,note FROM fuzz_results WHERE interesting=1 ORDER BY status"
```

## Safety model

* **Scope is mandatory for live runs.** With no `--scope`, the CLI refuses to send
  requests and points you at `--dry-run`. An empty scope allows nothing.
* **Scope is re-checked at the last moment.** Every candidate is verified against
  the scope immediately before its request; out-of-scope URLs (third-party CDNs,
  analytics, social widgets referenced in JavaScript) are recorded as
  `out-of-scope` and never sent.
* **Bounded and throttleable.** Concurrency, per-request delay, per-category word
  count, and a hard candidate cap are all configurable, with conservative
  defaults. A recognizable `User-Agent` is sent so target operators can identify
  the traffic.
* **Read-only probing.** Only `GET` requests are issued; the fuzzer discovers
  content, it does not modify it.

## Design and testing

Every stage is a small, pure unit with its dependencies injected, so the whole
feature is tested offline with no network:

| Module                     | Responsibility                                      |
|----------------------------|-----------------------------------------------------|
| `classify.py`              | discovered path → category                          |
| `catalog.py`               | category → Assetnote `WordlistSpec`                 |
| `local.py`                 | category → installed SecLists file                  |
| `wordlists.py`             | resolve words (cache → local → download → seed)     |
| `scope.py`                 | authorization allowlist / gate                      |
| `candidates.py`            | prefix extension → candidate URLs                   |
| `transport.py`             | HTTP boundary (stdlib; a fake is injected in tests) |
| `prober.py`                | calibration, auto-filter, concurrency, scope check  |
| `engine.py`                | read reports → classify → generate → probe → write  |

The corresponding `tests/test_fuzzer_*.py` cover classification ordering, scope
matching (including the `notexample.test` sibling-domain trap), prefix
extension/de-duplication, wordlist fallback and caching, calibration-based
filtering, and full end-to-end runs through a fake transport.
