#!/usr/bin/env bash
# Discover web services on non-standard ports for an AUTHORIZED scope.
#
# Port scanning sends live connections, so -- like subdomain enumeration and
# fuzzing -- it runs only against hosts that are, or are subdomains of, the
# supplied authorized scope. The host list is drawn from what the run has already
# discovered (the -s subdomain hosts) plus the seed hosts, then constrained to
# scope so an out-of-scope host can never be probed. Confirmed services are written
# to assets/services.txt for the crawler/fuzzer to pick up, and to
# reports/ports.json for the report.
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BASE_DIR/modules/utils.sh"

SCOPE_ARG="${1:?Port scanning requires an authorized scope}"
SEED_INPUT="${2:-}"   # optional: the original -i input (file or single URL)
VERBOSE="${VERBOSE:-0}"

HOSTS_FILE="$OUTPUT_DIR/assets/portscan_hosts.txt"
mkdir -p "$OUTPUT_DIR/assets" "$OUTPUT_DIR/reports"

# --- Resolve the authorized scope into apex/registered domains ---------------
DOMAINS_FILE=$(mktemp); RAW_HOSTS=$(mktemp)
trap 'rm -f "$DOMAINS_FILE" "$RAW_HOSTS"' EXIT
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
# shellcheck disable=SC2086
read -r -a _scope_tokens <<<"${SCOPE_ARG//,/ }"
expand_scope "${_scope_tokens[@]}" \
  | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:.*$##' \
  | tr 'A-Z' 'a-z' | grep -E '\.' | sort -u > "$DOMAINS_FILE" || true
[[ -s "$DOMAINS_FILE" ]] || die "No valid scope domains parsed from: $SCOPE_ARG"

# --- Gather candidate hosts from prior discovery + seeds ---------------------
strip_host() { sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:.*$##; s#^\*\.##; s#.*@##'; }
# Subdomain hosts discovered by -s (bare hostnames).
[[ -f "$OUTPUT_DIR/assets/subdomains_hosts.txt" ]] && cat "$OUTPUT_DIR/assets/subdomains_hosts.txt" >> "$RAW_HOSTS"
# Live subdomain base URLs (in case hosts file is absent).
[[ -f "$OUTPUT_DIR/assets/subdomains.txt" ]] && strip_host < "$OUTPUT_DIR/assets/subdomains.txt" >> "$RAW_HOSTS"
# Seed input hosts.
if [[ -n "$SEED_INPUT" ]]; then
  if [[ -f "$SEED_INPUT" ]]; then
    grep -E '^https?://|\.' "$SEED_INPUT" | strip_host >> "$RAW_HOSTS" || true
  else
    printf '%s\n' "$SEED_INPUT" | strip_host >> "$RAW_HOSTS" || true
  fi
fi
# The scope domains themselves are always in-scope candidates.
cat "$DOMAINS_FILE" >> "$RAW_HOSTS"

# --- Constrain to the authorized scope (never probe out-of-scope hosts) ------
awk -v scopef="$DOMAINS_FILE" '
  BEGIN { while ((getline d < scopef) > 0) if (d != "") scope[d]=1 }
  {
    host=tolower($0); gsub(/[[:space:]]/,"",host);
    if (host=="" || host !~ /\./) next
    ok=0; n=split(host, parts, "."); suffix=""
    for (i=n; i>=1; i--) { suffix=(suffix==""?parts[i]:parts[i]"."suffix); if (suffix in scope) { ok=1; break } }
    if (ok) print host
  }
' "$RAW_HOSTS" | sort -u > "$HOSTS_FILE"

HOST_COUNT=$(wc -l < "$HOSTS_FILE" | tr -d ' ')
if [[ "$HOST_COUNT" == "0" ]]; then
  log_warn "Port scan: no in-scope hosts to scan"
  printf '' > "$OUTPUT_DIR/assets/services.txt"
  printf '[]\n' > "$OUTPUT_DIR/reports/ports.json"
  exit 0
fi
log_info "Port scan: $HOST_COUNT in-scope host(s) for web-service discovery"

# --- Run the scanner ---------------------------------------------------------
PS_PORTS="${JSINTEL_PORTS:-}"
PS_ARGS=(--output "$OUTPUT_DIR" --hosts "$HOSTS_FILE" --workers "${THREADS:-100}")
[[ -n "$PS_PORTS" ]] && PS_ARGS+=(--ports "$PS_PORTS")
[[ "$VERBOSE" == "1" ]] && PS_ARGS+=(--verbose)
# shellcheck disable=SC2206
PS_ARGS+=(${JSINTEL_PORTSCAN_ARGS:-})

PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m modules.portscan "${PS_ARGS[@]}"

SERVICES=$(wc -l < "$OUTPUT_DIR/assets/services.txt" 2>/dev/null | tr -d ' ' || echo 0)
log_info "Port scan complete: $SERVICES web service(s) -> $OUTPUT_DIR/assets/services.txt"
