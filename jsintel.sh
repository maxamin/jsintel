#!/usr/bin/env bash
# JSIntel Phase 1 orchestration entry point.
set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$BASE_DIR/modules/utils.sh"

usage() {
  cat <<'EOF'
Usage: ./jsintel.sh -i <input_urls> [-o <output_dir>] [-t <threads>] [-s <scope>] [-p <scope>] [-f <scope>]
       ./jsintel.sh -m <targets_file> [-s] [-p] [-f] [-o <output_dir>] [-t <threads>]   (mass sweep)

  -i  File containing seed URLs (one per line), or a single URL
  -o  Output directory (default: ./output)
  -t  Concurrent download/crawl workers (default: config value or 50)
  -s  Enumerate subdomains of the given AUTHORIZED scope (a domain, comma/space
      separated domains, or a FILE of domains -- one per line, or @file) and add
      the reachable ones to the crawl as extra seeds. Only hosts that are, or are
      subdomains of, the supplied scope are ever added.
  -p  Port-scan the discovered/seed hosts within the given AUTHORIZED scope for
      web services on NON-standard ports (not just 80/443), confirm which speak
      HTTP(S), and add them to the crawl + fuzz as extra seeds. Writes
      assets/services.txt and reports/ports.json. Ports can be overridden with the
      JSINTEL_PORTS env var (e.g. JSINTEL_PORTS="80,443,8000-8100").
  -w  Screenshot the discovered web services (assets/services.txt + live subdomains)
      with headless Chromium and build a visual-triage gallery
      (reports/screenshots.html) with near-identical pages clustered. Boolean flag;
      pairs naturally with -p. Renders send a page load per service (in-scope only).
  -f  Enable content-discovery fuzzing against the given AUTHORIZED scope
      (a domain, comma/space separated domains, or a FILE of domains -- one per
      line, or @file -- that you are permitted to test).
      Extra fuzzer options may be passed via the JSINTEL_FUZZ_ARGS env var,
      e.g. JSINTEL_FUZZ_ARGS="--dry-run" or "--offline --delay 0.1".
  -m  MASS SWEEP mode: take a FILE of target domains (one per line) and run the
      full pipeline against each target independently into <output>/targets/<domain>/,
      then write an aggregate <output>/reports/sweep_summary.{json,md}. Each target is
      used as its own authorized scope. Enable per-target stages with the toggles
      below. Parallelism across targets: JSINTEL_SWEEP_PARALLEL (default 3).
      JSINTEL_SWEEP_RESUME=1 skips targets already marked ok in the same output dir
      (continue an interrupted sweep). A target whose stage dies from a crash signal
      (rc 134/135/137/139) is retried once.
  -S  (mass mode) enable subdomain enumeration per target (like -s <target>).
  -P  (mass mode) enable web-service port scanning per target (like -p <target>).
  -W  (mass mode) enable web-service screenshots per target (like -w).
  -F  (mass mode) enable content-discovery fuzzing per target (like -f <target>).
  -v  Verbose: surface crawler/tool output instead of hiding it in the log,
      and warn about silent failures (redirects off-host, empty crawls).

  --cookie <value>  Drive the target as an AUTHENTICATED user: send this Cookie
      header (e.g. "PHPSESSID=...; security=low") with every request across all
      stages (crawl, download, fuzz, live-service analysis).
  --jwt <token>     Send "Authorization: Bearer <token>" with every request. May be
      combined with --cookie. The session is only ever sent to in-scope hosts.
  --forms           Run the ACTIVE form stage after extraction: discover forms on the
      crawled pages, fill every field with realistic, spec-valid random data (so
      client/server validation does not reject it) and trigger their JavaScript and
      XHR/fetch calls (ZAP AJAX-Spider / Form-Handler style). Submits by default with
      a destructive-endpoint guard (payment/swap/withdraw/delete/logout are skipped).
      Extra options via JSINTEL_FORMS_ARGS (e.g. "--no-submit", "--browser",
      "--deny <term>", "--no-safe-denylist"). Sends live requests -> scope-gated.
  --reanalyze <dir>  Rebuild an earlier run's results OFFLINE into -o <new dir>:
      re-extract its downloaded assets with the current analyzers, re-score
      fuzz.json, rebuild the DB/reports/triage. Sends no requests; the source run
      is only read. A sweep dir (with targets/) is re-analysed per target.
  --proxychains [conf]  Route ALL outbound traffic (crawl, download, fuzz, forms and
      headless Chromium) through proxychains4 by re-exec'ing the run under it. With no
      value the default proxychains config is used; pass a path to use a specific one.
EOF
}

# --- Authenticated mode: pull the long options --cookie/--jwt out of argv first --
# getopts handles only single-char flags, so extract these (and their values) into
# env vars that every request-making stage (crawl, download, fuzz, live analysis)
# reads via modules/authutil.py. The session is only ever sent to in-scope hosts.
_pre=(); FORMS="${FORMS:-0}"; PROXYCHAINS=""; REANALYZE=""; while [[ $# -gt 0 ]]; do
  case "$1" in
    --cookie)   export JSINTEL_AUTH_COOKIE="${2:-}"; shift 2 ;;
    --cookie=*) export JSINTEL_AUTH_COOKIE="${1#*=}"; shift ;;
    --jwt)      export JSINTEL_AUTH_BEARER="${2:-}"; shift 2 ;;
    --jwt=*)    export JSINTEL_AUTH_BEARER="${1#*=}"; shift ;;
    # --proxychains [conf] routes ALL outbound traffic (crawl/download/fuzz/forms/
    # chromium) through proxychains by re-exec'ing the whole run under proxychains4;
    # every child process then inherits the proxy. Optional value is a config path.
    --proxychains)   if [[ -n "${2:-}" && "${2:0:1}" != "-" ]]; then PROXYCHAINS="$2"; shift 2; else PROXYCHAINS="1"; shift; fi ;;
    --proxychains=*) PROXYCHAINS="${1#*=}"; shift ;;
    # --forms runs the active form-filler / AJAX-spider stage after extraction
    # (submit-by-default; extra args via JSINTEL_FORMS_ARGS).
    --forms)    FORMS=1; shift ;;
    # --reanalyze <dir> rebuilds an earlier run's results offline into -o <new dir>.
    --reanalyze)   REANALYZE="${2:-}"; shift 2 ;;
    --reanalyze=*) REANALYZE="${1#*=}"; shift ;;
    --)         shift; while [[ $# -gt 0 ]]; do _pre+=("$1"); shift; done ;;
    *)          _pre+=("$1"); shift ;;
  esac
done
set -- ${_pre[@]+"${_pre[@]}"}

# Re-exec the entire run under proxychains once (guarded), so katana, curl, the
# downloader, the fuzzer, the form stage and headless Chromium all speak through the
# proxy chain. proxychains preloads its shim at process launch, so wrapping the whole
# script is the reliable way to cover in-process and child-process sockets alike.
# A run started as `proxychains4 ./jsintel.sh ...` (how the 2026-10-09 sweep was
# launched) is adopted into the same managed mode: the preload is dropped and the run
# re-exec'd under a managed config, exactly as with --proxychains.
if [[ -z "${JSINTEL_UNDER_PROXYCHAINS:-}" && "${LD_PRELOAD:-}" == *proxychains* ]]; then
  PROXYCHAINS="${PROXYCHAINS:-${PROXYCHAINS_CONF_FILE:-1}}"
  unset LD_PRELOAD
fi
if [[ -n "$PROXYCHAINS" && -z "${JSINTEL_UNDER_PROXYCHAINS:-}" ]]; then
  if command -v proxychains4 >/dev/null 2>&1; then PCBIN=proxychains4
  elif command -v proxychains >/dev/null 2>&1; then PCBIN=proxychains
  else die "--proxychains requested but proxychains4 is not installed"; fi
  # Managed config = the operator's config plus `localnet 127.0.0.0/255.0.0.0`, so
  # loopback (the forms driver's DevTools socket, lab targets) is never proxied.
  PCCONF=$(PYTHONPATH="$BASE_DIR" python3 -m modules.proxyutil managed-conf "$PROXYCHAINS") \
    || die "No proxychains config found (looked for ${PROXYCHAINS/#1/the default})"
  PCARGS=(-q -f "$PCCONF")
  export JSINTEL_UNDER_PROXYCHAINS=1 FORMS
  exec "$PCBIN" "${PCARGS[@]}" bash "$BASE_DIR/jsintel.sh" ${_pre[@]+"${_pre[@]}"}
fi
# Go tools (katana, assetfinder, subfinder, amass) make syscalls directly, so the
# preload never sees their sockets: under proxychains katana crawled from the
# operator's own address. They get the chain's proxy explicitly (JSINTEL_PROXY_URL).
# Fail closed: an unproxiable chain must not silently fall back to direct traffic.
if [[ -n "${JSINTEL_UNDER_PROXYCHAINS:-}" && -z "${JSINTEL_PROXY_URL:-}" ]]; then
  JSINTEL_PROXY_URL=$(PYTHONPATH="$BASE_DIR" python3 -m modules.proxyutil proxy-url) \
    || die "Under proxychains, but its first proxy is not socks4/socks5/http without credentials; Go tools (katana) and Chromium cannot be routed through it"
  export JSINTEL_PROXY_URL
fi
export FORMS

INPUT=""; OUTPUT_DIR="$BASE_DIR/output"; THREADS=""; FUZZ_SCOPE=""; SUB_SCOPE=""; PORT_SCOPE=""; WEBSHOT=0
MASS_TARGETS=""; MASS_SUBS=0; MASS_PORTS=0; MASS_FUZZ=0; MASS_WEBSHOT=0; VERBOSE=0
while getopts ":i:o:t:f:s:p:m:vhSPFWw" option; do
  case "$option" in
    i) INPUT="$OPTARG" ;; o) OUTPUT_DIR="$OPTARG" ;; t) THREADS="$OPTARG" ;;
    f) FUZZ_SCOPE="$OPTARG" ;;
    s) SUB_SCOPE="$OPTARG" ;;
    p) PORT_SCOPE="$OPTARG" ;;
    w) WEBSHOT=1 ;;
    m) MASS_TARGETS="$OPTARG" ;;
    S) MASS_SUBS=1 ;; P) MASS_PORTS=1 ;; F) MASS_FUZZ=1 ;; W) MASS_WEBSHOT=1 ;;
    v) VERBOSE=1 ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG needs a value" ;; *) usage; exit 2 ;;
  esac
done
[[ "$THREADS" =~ ^[1-9][0-9]*$ || -z "$THREADS" ]] || die "Threads must be a positive integer"

# --- Mass sweep mode: delegate to the sweep driver and exit -------------------
if [[ -n "$MASS_TARGETS" ]]; then
  [[ -f "$MASS_TARGETS" ]] || die "Mass targets file not found: $MASS_TARGETS"
  mkdir -p "$OUTPUT_DIR"
  OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
  export OUTPUT_DIR VERBOSE
  export SWEEP_SUBS="$MASS_SUBS" SWEEP_PORTS="$MASS_PORTS" SWEEP_FUZZ="$MASS_FUZZ" SWEEP_WEBSHOT="$MASS_WEBSHOT"
  export SWEEP_THREADS="${THREADS:-}"
  exec bash "$BASE_DIR/modules/sweep.sh" "$MASS_TARGETS"
fi

# --- Offline re-analysis: rebuild results from an earlier run, zero network -------
# Re-extracts the already-downloaded assets with the current analyzers, re-scores
# fuzz.json, and rebuilds the DB, reports and triage. Results go to a NEW -o
# directory (the source run is only read; its asset files are referenced in place),
# so false-positive fixes reach old runs without re-scanning anyone. A sweep dir
# (one with targets/) is re-analysed target by target.
if [[ -n "$REANALYZE" ]]; then
  [[ -d "$REANALYZE" ]] || die "--reanalyze: no such directory: $REANALYZE"
  SRC="$(cd "$REANALYZE" && pwd)"
  mkdir -p "$OUTPUT_DIR"; OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
  [[ "$OUTPUT_DIR" != "$SRC" && "$OUTPUT_DIR/" != "$SRC/"* ]] \
    || die "--reanalyze writes to a new directory: pass -o <dir> outside $SRC"
  if [[ -d "$SRC/targets" ]]; then
    mkdir -p "$OUTPUT_DIR/logs"; LOG_FILE="$OUTPUT_DIR/logs/jsintel.log"; export LOG_FILE
    PAR="${JSINTEL_SWEEP_PARALLEL:-3}"; [[ "$PAR" =~ ^[1-9][0-9]*$ ]] || PAR=3
    log_info "Re-analysing sweep $SRC -> $OUTPUT_DIR (offline, parallelism $PAR)"
    mapfile -t RTARGETS < <(cd "$SRC/targets" && for d in */; do [[ -f "$d/reports/assets.json" ]] && printf '%s\n' "${d%/}"; done)
    running=0
    for t in ${RTARGETS[@]+"${RTARGETS[@]}"}; do
      ( mkdir -p "$OUTPUT_DIR/targets/$t"
        if bash "$BASE_DIR/jsintel.sh" --reanalyze "$SRC/targets/$t" -o "$OUTPUT_DIR/targets/$t" \
             >"$OUTPUT_DIR/targets/$t/reanalyze.log" 2>&1; then
          cp -f "$SRC/targets/$t/.sweep_status" "$OUTPUT_DIR/targets/$t/.sweep_status" 2>/dev/null || true
        else
          printf 'failed reanalyze\n' > "$OUTPUT_DIR/targets/$t/.sweep_status"
        fi ) &
      running=$((running + 1))
      if (( running >= PAR )); then wait -n 2>/dev/null || wait; running=$((running - 1)); fi
    done
    wait
    PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" \
      python3 -m modules.sweep_aggregate --output "$OUTPUT_DIR" ${RTARGETS[@]+"${RTARGETS[@]}"}
    log_info "Sweep re-analysis complete (${#RTARGETS[@]} targets). Aggregate: $OUTPUT_DIR/reports/sweep_summary.md"
    exit 0
  fi
  [[ -f "$SRC/reports/assets.json" ]] || die "--reanalyze: $SRC has no reports/assets.json"
  [[ ! -e "$OUTPUT_DIR/reports/summary.json" ]] || die "--reanalyze: $OUTPUT_DIR already holds results; use a new directory"
  mkdir -p "$OUTPUT_DIR"/{assets,logs,database,reports}
  LOG_FILE="$OUTPUT_DIR/logs/jsintel.log"; export LOG_FILE OUTPUT_DIR
  CONFIG="$BASE_DIR/config/config.yaml"; export CONFIG
  THREADS="${THREADS:-$(config_value threads 50)}"; export THREADS
  log_info "Re-analysing $SRC -> $OUTPUT_DIR (offline; no requests are sent)"
  # Carry over everything except what extraction and reporting regenerate.
  for f in "$SRC"/reports/*.json "$SRC"/reports/.discovered.json; do
    [[ -f "$f" ]] || continue
    case "$(basename "$f")" in
      urls.json|endpoints.json|websocket.json|imports.json|frameworks.json|findings.json|code_intel.json|errors.json|summary.json|triage.json) ;;
      *) cp -f "$f" "$OUTPUT_DIR/reports/" ;;
    esac
  done
  for f in "$SRC"/assets/*.txt; do [[ -f "$f" ]] && cp -f "$f" "$OUTPUT_DIR/assets/"; done
  bash "$BASE_DIR/modules/extractor.sh" "$OUTPUT_DIR/reports/assets.json"
  if [[ -f "$OUTPUT_DIR/reports/fuzz.json" ]]; then
    PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m modules.fuzzer --output "$OUTPUT_DIR" --rescore 2>>"$LOG_FILE"
  fi
  python3 "$BASE_DIR/modules/database.py" --output "$OUTPUT_DIR" --config "$CONFIG" ingest
  python3 "$BASE_DIR/modules/reporter.py" --output "$OUTPUT_DIR" --config "$CONFIG"
  python3 "$BASE_DIR/modules/triage.py" --output "$OUTPUT_DIR" --config "$CONFIG"
  log_info "Re-analysis complete. Reports: $OUTPUT_DIR/reports"
  exit 0
fi

[[ -n "$INPUT" ]] || { usage; exit 2; }

require_command python3
mkdir -p "$OUTPUT_DIR"/{assets,logs,database} "$OUTPUT_DIR/reports"
LOG_FILE="$OUTPUT_DIR/logs/jsintel.log"; export LOG_FILE
CONFIG="$BASE_DIR/config/config.yaml"; export CONFIG
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"; export OUTPUT_DIR
THREADS="${THREADS:-$(config_value threads 50)}"; export THREADS
VERBOSE="${VERBOSE:-0}"; export VERBOSE

log_info "JSIntel Phase 1 started (workers: $THREADS)"

# Per-stage telemetry: reports/stages.tsv (name, seconds, exit code), folded into
# summary.json by the reporter and rolled up by sweep_aggregate. Recovering stage
# timings for the 2026-10-09 sweep meant parsing 13k logs, and stages that produced
# nothing on every target (ports, screenshots) went unnoticed for a week.
STAGES_TSV="$OUTPUT_DIR/reports/stages.tsv"; : > "$STAGES_TSV"
stage() {  # stage NAME CMD...: run CMD, record its time and status, return its status
  local name="$1" t0=$SECONDS rc=0; shift
  "$@" || rc=$?
  printf '%s\t%s\t%s\n' "$name" "$((SECONDS - t0))" "$rc" >> "$STAGES_TSV"
  return "$rc"
}
if [[ -n "${JSINTEL_AUTH_COOKIE:-}" || -n "${JSINTEL_AUTH_BEARER:-}" ]]; then
  log_info "Authenticated mode: $(python3 "$BASE_DIR/modules/authutil.py" --describe 2>/dev/null || echo 'session supplied')"
fi
log_info "Pipeline: Crawler -> Normalizer -> Classifier -> Downloader -> Extractor -> Database -> Reports"

CRAWL_INPUT="$INPUT"

# Anchor the crawl scope to the AUTHORIZED scope (-s/-p/-f) so off-scope redirects
# can never widen it: an authorized gala.com test must not start crawling okta.com
# just because a gala.com host redirects there. Expand any file/@file scope values
# into their domains. Honour an explicit CRAWL_SCOPE the operator already set.
if [[ -z "${CRAWL_SCOPE:-}" && ( -n "$SUB_SCOPE" || -n "$PORT_SCOPE" || -n "$FUZZ_SCOPE" ) ]]; then
  _expand_one() { local t="${1#@}"; if [[ -f "$t" ]]; then grep -vE '^\s*(#|$)' "$t"; else printf '%s\n' "$1"; fi; }
  CRAWL_SCOPE="$(
    for _grp in "$SUB_SCOPE" "$PORT_SCOPE" "$FUZZ_SCOPE"; do
      [[ -n "$_grp" ]] || continue
      # shellcheck disable=SC2086
      for _tok in ${_grp//,/ }; do _expand_one "$_tok"; done
    done | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:.*$##' | tr 'A-Z' 'a-z' \
         | grep -E '\.' | sort -u | paste -sd',' -
  )"
  export CRAWL_SCOPE
  log_info "Crawl scope anchored to authorized scope: ${CRAWL_SCOPE//,/ }"
fi

if [[ -n "$SUB_SCOPE" ]]; then
  stage subdomains bash "$BASE_DIR/modules/subdomains.sh" "$SUB_SCOPE"
fi
if [[ -n "$PORT_SCOPE" ]]; then
  # Port-scan the in-scope hosts (subdomains discovered above, plus the seeds) for
  # web services on non-standard ports; confirmed services become extra seeds.
  stage ports bash "$BASE_DIR/modules/portscan.sh" "$PORT_SCOPE" "$INPUT"
fi
if [[ -n "$SUB_SCOPE" || -n "$PORT_SCOPE" ]]; then
  # Combine the original seeds with the discovered live subdomains and any web
  # services found on non-standard ports, so the crawler visits every reachable
  # in-scope entry point -- not just the supplied ones.
  SEEDS="$OUTPUT_DIR/assets/seeds.txt"
  : > "$SEEDS"
  if [[ -f "$INPUT" ]]; then
    grep -E '^https?://' "$INPUT" >> "$SEEDS" || true
  elif [[ "$INPUT" =~ ^https?:// ]]; then
    printf '%s\n' "$INPUT" >> "$SEEDS"
  fi
  [[ -f "$OUTPUT_DIR/assets/subdomains.txt" ]] && cat "$OUTPUT_DIR/assets/subdomains.txt" >> "$SEEDS"
  [[ -f "$OUTPUT_DIR/assets/services.txt" ]] && cat "$OUTPUT_DIR/assets/services.txt" >> "$SEEDS"
  sort -u "$SEEDS" -o "$SEEDS"
  CRAWL_INPUT="$SEEDS"
  log_info "Crawling $(wc -l < "$SEEDS" | tr -d ' ') combined seeds (input + subdomains + services)"
fi

stage crawl bash "$BASE_DIR/modules/crawler.sh" "$CRAWL_INPUT"
stage classify bash "$BASE_DIR/modules/classifier.sh" "$OUTPUT_DIR/assets/crawled_urls.txt"
stage download bash "$BASE_DIR/modules/downloader.sh" "$OUTPUT_DIR/reports/assets.json"
stage extract bash "$BASE_DIR/modules/extractor.sh" "$OUTPUT_DIR/reports/assets.json"
# Feedback discovery: fetch newly-referenced in-scope assets (endpoints/URLs an extracted
# asset points at that the crawler never saw) and re-extract. Scope-safe (only new PATHS on
# hosts already fetched), budget-capped, and bounded to JSINTEL_DISCOVER_ROUNDS rounds
# (default 3; set 0 to disable). The re-extract only runs when a round found something.
DISCOVER_ROUNDS="${JSINTEL_DISCOVER_ROUNDS:-3}"
_round=1; _disc_t0=$SECONDS
while [[ "$_round" -le "$DISCOVER_ROUNDS" ]]; do
  _added=$(python3 "$BASE_DIR/modules/discover.py" --output "$OUTPUT_DIR" --config "$CONFIG" \
             --limit "${JSINTEL_DISCOVER_LIMIT:-200}" 2>>"$LOG_FILE" || echo 0)
  log_info "Discovery round $_round: fetched ${_added:-0} new in-scope asset(s)"
  [[ "${_added:-0}" -gt 0 ]] || break
  stage extract bash "$BASE_DIR/modules/extractor.sh" "$OUTPUT_DIR/reports/assets.json"
  _round=$((_round + 1))
done
printf 'discovery\t%s\t0\n' "$((SECONDS - _disc_t0))" >> "$STAGES_TSV"
# Live-service analysis (security headers, GraphQL introspection, JWTs) against the
# in-scope services discovered by the port scan. No-op if no reports/ports.json.
if [[ -s "$OUTPUT_DIR/reports/ports.json" ]]; then
  log_info "Analyzing live services (security headers / GraphQL / JWT)"
  _t0=$SECONDS
  python3 "$BASE_DIR/modules/liveanalysis.py" --output "$OUTPUT_DIR" --config "$CONFIG" \
    2>&1 | tee -a "$LOG_FILE" || log_info "Live-service analysis skipped (non-fatal)"
  printf 'live\t%s\t0\n' "$((SECONDS - _t0))" >> "$STAGES_TSV"
fi
if [[ "$WEBSHOT" == "1" ]]; then
  # After extraction so the gallery can flag services whose host yielded high findings.
  stage webshot bash "$BASE_DIR/modules/webshot.sh" "$INPUT"
fi
if [[ -n "$FUZZ_SCOPE" ]]; then
  stage fuzz bash "$BASE_DIR/modules/fuzzer.sh" "$FUZZ_SCOPE"
fi
# Active form stage (opt-in via --forms): fill discovered pages' forms with in-norm
# synthetic data and trigger their JS/XHR. Scoped to the authorized scope; submit-by-
# default with the destructive-endpoint guard. Extra args via JSINTEL_FORMS_ARGS
# (e.g. "--no-submit", "--browser", "--no-safe-denylist"). Runs before DB ingest so
# any endpoints it discovers fold into the reports/triage.
if [[ "$FORMS" == "1" ]]; then
  FORMS_SCOPE="${FUZZ_SCOPE:-${SUB_SCOPE:-$PORT_SCOPE}}"
  FORM_ARGS=(--output "$OUTPUT_DIR")
  # shellcheck disable=SC2206
  _fs=(${FORMS_SCOPE//,/ }); for _s in "${_fs[@]}"; do [[ -n "$_s" ]] && FORM_ARGS+=(--scope "$_s"); done
  # shellcheck disable=SC2206
  FORM_ARGS+=(${JSINTEL_FORMS_ARGS:-})
  log_info "Active form stage (fill + trigger JS/XHR; scope: ${FORMS_SCOPE:-<pages in output>})"
  _t0=$SECONDS
  PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m modules.forms.main "${FORM_ARGS[@]}" \
    2>&1 | tee -a "$LOG_FILE" || log_info "Form stage skipped (non-fatal)"
  printf 'forms\t%s\t0\n' "$((SECONDS - _t0))" >> "$STAGES_TSV"
fi
stage database python3 "$BASE_DIR/modules/database.py" --output "$OUTPUT_DIR" --config "$CONFIG" ingest
python3 "$BASE_DIR/modules/reporter.py" --output "$OUTPUT_DIR" --config "$CONFIG"
# Unified per-host triage view (joins services + endpoints + findings, ranked).
python3 "$BASE_DIR/modules/triage.py" --output "$OUTPUT_DIR" --config "$CONFIG"

log_info "Completed successfully. Reports: $OUTPUT_DIR/reports (see triage.html)"
