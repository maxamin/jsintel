#!/usr/bin/env bash
# Enumerate and liveness-check subdomains for an AUTHORIZED scope, emitting
# reachable base URLs that the crawler then treats as additional seeds.
#
# Subdomain discovery uses whichever passive tools are installed (assetfinder,
# subfinder, amass); results are constrained to the supplied scope so an
# enumerator returning an unrelated host can never widen the crawl. Liveness
# probing is done in Python with `requests` (threaded) rather than a specific
# httpx build, because the `httpx` on PATH may be the Python CLI rather than the
# ProjectDiscovery prober.
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BASE_DIR/modules/utils.sh"

SCOPE_ARG="${1:?Subdomain enumeration requires an authorized scope}"
OUT_HOSTS="$OUTPUT_DIR/assets/subdomains_hosts.txt"
OUT_URLS="$OUTPUT_DIR/assets/subdomains.txt"
VERBOSE="${VERBOSE:-0}"

# --- Resolve the scope into a list of apex/registered domains ---------------
# Accepts comma/space separated domains, a file of domains, or @file.
DOMAINS_FILE=$(mktemp); trap 'rm -f "$DOMAINS_FILE"' EXIT
expand_scope() {
  local entry token
  for entry in "$@"; do
    token="${entry#@}"
    if [[ -f "$token" ]]; then
      grep -vE '^\s*(#|$)' "$token" | sed 's/\r$//'
    else
      printf '%s\n' "$entry"
    fi
  done
}
# shellcheck disable=SC2086  # deliberate word-splitting on commas/spaces
read -r -a _scope_tokens <<<"${SCOPE_ARG//,/ }"
expand_scope "${_scope_tokens[@]}" \
  | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:.*$##' \
  | tr 'A-Z' 'a-z' | grep -E '\.' | sort -u > "$DOMAINS_FILE" || true
[[ -s "$DOMAINS_FILE" ]] || die "No valid scope domains parsed from: $SCOPE_ARG"

log_info "Subdomain enumeration for: $(paste -sd' ' "$DOMAINS_FILE")"

# --- Enumerate with whatever passive tools are available ---------------------
RAW=$(mktemp); trap 'rm -f "$DOMAINS_FILE" "$RAW"' EXIT
ENUM_TIMEOUT=$(config_value subdomain_timeout 120)
while IFS= read -r domain; do
  [[ -n "$domain" ]] || continue
  printf '%s\n' "$domain" >> "$RAW"   # always include the apex itself
  if command -v assetfinder >/dev/null 2>&1; then
    timeout "$ENUM_TIMEOUT" assetfinder --subs-only "$domain" 2>>"$LOG_FILE" >> "$RAW" || true
  fi
  if command -v subfinder >/dev/null 2>&1; then
    timeout "$ENUM_TIMEOUT" subfinder -silent -d "$domain" 2>>"$LOG_FILE" >> "$RAW" || true
  fi
  if command -v amass >/dev/null 2>&1; then
    # amass draws an animated progress bar on stderr (thousands of "0/1 [___] p/s"
    # carriage-return redraws); sending it to the log floods it, so drop stderr.
    timeout "$ENUM_TIMEOUT" amass enum -passive -norecursive -d "$domain" 2>/dev/null >> "$RAW" || true
  fi
done < "$DOMAINS_FILE"

if ! command -v assetfinder >/dev/null 2>&1 && ! command -v subfinder >/dev/null 2>&1 && ! command -v amass >/dev/null 2>&1; then
  log_warn "No subdomain enumeration tool found (assetfinder/subfinder/amass); using scope domains only"
fi

# Constrain results to the authorized scope: keep a host only if it equals, or
# is a subdomain of, one of the supplied domains. This never trusts an
# enumerator to stay in scope.
CLEAN=$(mktemp); trap 'rm -f "$DOMAINS_FILE" "$RAW" "$CLEAN"' EXIT
sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:.*$##; s#^\*\.##' "$RAW" \
  | tr 'A-Z' 'a-z' | sed 's/\r$//' | grep -E '^[a-z0-9._-]+\.[a-z]+$' | sort -u > "$CLEAN" || true

awk -v scopef="$DOMAINS_FILE" '
  BEGIN { while ((getline d < scopef) > 0) if (d != "") scope[d]=1 }
  {
    host=$0; ok=0; n=split(host, parts, ".")
    suffix=""
    for (i=n; i>=1; i--) { suffix = (suffix=="" ? parts[i] : parts[i] "." suffix); if (suffix in scope) { ok=1; break } }
    if (ok) print host
  }
' "$CLEAN" | sort -u > "$OUT_HOSTS"

HOST_COUNT=$(wc -l < "$OUT_HOSTS" | tr -d ' ')
log_info "Enumerated $HOST_COUNT in-scope hosts; probing for liveness"

# --- Liveness probe (threaded, in Python) -----------------------------------
PROBE_TIMEOUT=$(config_value download_timeout "$(config_value timeout 10)")
export OUT_HOSTS OUT_URLS THREADS PROBE_TIMEOUT VERBOSE
python3 - <<'PY'
import concurrent.futures, os, pathlib
import requests

hosts = [h.strip() for h in pathlib.Path(os.environ['OUT_HOSTS']).read_text().splitlines() if h.strip()]
timeout = float(os.environ.get('PROBE_TIMEOUT') or 10)
workers = int(os.environ.get('THREADS') or 50)
verbose = os.environ.get('VERBOSE') == '1'

def probe(host):
    # Prefer HTTPS; fall back to HTTP. Return the first scheme that answers.
    for scheme in ('https', 'http'):
        url = f'{scheme}://{host}'
        try:
            r = requests.get(url, timeout=(5, timeout), allow_redirects=True,
                             headers={'User-Agent': 'JSIntel/1.0 (+recon)'} , stream=True)
            r.close()
            return url
        except requests.RequestException:
            continue
    return None

live = []
with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, max(1, len(hosts)))) as ex:
    for result in ex.map(probe, hosts):
        if result:
            live.append(result)

live = sorted(set(live))
pathlib.Path(os.environ['OUT_URLS']).write_text('\n'.join(live) + ('\n' if live else ''))
print(f'{len(live)} live')
PY

LIVE_COUNT=$(wc -l < "$OUT_URLS" 2>/dev/null | tr -d ' ' || echo 0)
log_info "Subdomain enumeration complete: $LIVE_COUNT live hosts -> $OUT_URLS"
