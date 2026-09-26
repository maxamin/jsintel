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
EOF
}

# --- Authenticated mode: pull the long options --cookie/--jwt out of argv first --
# getopts handles only single-char flags, so extract these (and their values) into
# env vars that every request-making stage (crawl, download, fuzz, live analysis)
# reads via modules/authutil.py. The session is only ever sent to in-scope hosts.
_pre=(); while [[ $# -gt 0 ]]; do
  case "$1" in
    --cookie)   export JSINTEL_AUTH_COOKIE="${2:-}"; shift 2 ;;
    --cookie=*) export JSINTEL_AUTH_COOKIE="${1#*=}"; shift ;;
    --jwt)      export JSINTEL_AUTH_BEARER="${2:-}"; shift 2 ;;
    --jwt=*)    export JSINTEL_AUTH_BEARER="${1#*=}"; shift ;;
    --)         shift; while [[ $# -gt 0 ]]; do _pre+=("$1"); shift; done ;;
    *)          _pre+=("$1"); shift ;;
  esac
done
set -- ${_pre[@]+"${_pre[@]}"}

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

[[ -n "$INPUT" ]] || { usage; exit 2; }

require_command python3
mkdir -p "$OUTPUT_DIR"/{assets,logs,database} "$OUTPUT_DIR/reports"
LOG_FILE="$OUTPUT_DIR/logs/jsintel.log"; export LOG_FILE
CONFIG="$BASE_DIR/config/config.yaml"; export CONFIG
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"; export OUTPUT_DIR
THREADS="${THREADS:-$(config_value threads 50)}"; export THREADS
VERBOSE="${VERBOSE:-0}"; export VERBOSE

log_info "JSIntel Phase 1 started (workers: $THREADS)"
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
  bash "$BASE_DIR/modules/subdomains.sh" "$SUB_SCOPE"
fi
if [[ -n "$PORT_SCOPE" ]]; then
  # Port-scan the in-scope hosts (subdomains discovered above, plus the seeds) for
  # web services on non-standard ports; confirmed services become extra seeds.
  bash "$BASE_DIR/modules/portscan.sh" "$PORT_SCOPE" "$INPUT"
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

bash "$BASE_DIR/modules/crawler.sh" "$CRAWL_INPUT"
bash "$BASE_DIR/modules/classifier.sh" "$OUTPUT_DIR/assets/crawled_urls.txt"
bash "$BASE_DIR/modules/downloader.sh" "$OUTPUT_DIR/reports/assets.json"
bash "$BASE_DIR/modules/extractor.sh" "$OUTPUT_DIR/reports/assets.json"
# Live-service analysis (security headers, GraphQL introspection, JWTs) against the
# in-scope services discovered by the port scan. No-op if no reports/ports.json.
if [[ -s "$OUTPUT_DIR/reports/ports.json" ]]; then
  log_info "Analyzing live services (security headers / GraphQL / JWT)"
  python3 "$BASE_DIR/modules/liveanalysis.py" --output "$OUTPUT_DIR" --config "$CONFIG" \
    2>&1 | tee -a "$LOG_FILE" || log_info "Live-service analysis skipped (non-fatal)"
fi
if [[ "$WEBSHOT" == "1" ]]; then
  # After extraction so the gallery can flag services whose host yielded high findings.
  bash "$BASE_DIR/modules/webshot.sh" "$INPUT"
fi
if [[ -n "$FUZZ_SCOPE" ]]; then
  bash "$BASE_DIR/modules/fuzzer.sh" "$FUZZ_SCOPE"
fi
python3 "$BASE_DIR/modules/database.py" --output "$OUTPUT_DIR" --config "$CONFIG" ingest
python3 "$BASE_DIR/modules/reporter.py" --output "$OUTPUT_DIR" --config "$CONFIG"
# Unified per-host triage view (joins services + endpoints + findings, ranked).
python3 "$BASE_DIR/modules/triage.py" --output "$OUTPUT_DIR" --config "$CONFIG"

log_info "Completed successfully. Reports: $OUTPUT_DIR/reports (see triage.html)"
