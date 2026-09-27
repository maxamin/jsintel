#!/usr/bin/env bash
# Screenshot the discovered web services for visual triage.
#
# Operates on what the run already discovered and constrained to scope: the web
# services found by the port scanner (assets/services.txt) plus the live subdomain
# base URLs (assets/subdomains.txt), falling back to the seed input. Renders each
# with headless Chromium, clusters near-identical looks, and writes a gallery to
# reports/screenshots.html. Screenshotting sends a page load per service, so it runs
# only against these already-authorized, in-scope targets.
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BASE_DIR/modules/utils.sh"

SEED_INPUT="${1:-}"
VERBOSE="${VERBOSE:-0}"
mkdir -p "$OUTPUT_DIR/assets" "$OUTPUT_DIR/reports"

URLS_FILE="$OUTPUT_DIR/assets/webshot_targets.txt"
: > "$URLS_FILE"
# Prefer the discovered services (distinct; CDN mirrors already collapsed).
[[ -f "$OUTPUT_DIR/assets/services.txt" ]] && cat "$OUTPUT_DIR/assets/services.txt" >> "$URLS_FILE"
# Plus the live subdomain base URLs, so hosts without an odd port are shot too.
[[ -f "$OUTPUT_DIR/assets/subdomains.txt" ]] && cat "$OUTPUT_DIR/assets/subdomains.txt" >> "$URLS_FILE"
# Fall back to the seed if nothing else was discovered.
if [[ ! -s "$URLS_FILE" && -n "$SEED_INPUT" ]]; then
  if [[ -f "$SEED_INPUT" ]]; then grep -E '^https?://' "$SEED_INPUT" >> "$URLS_FILE" || true
  elif [[ "$SEED_INPUT" =~ ^https?:// ]]; then printf '%s\n' "$SEED_INPUT" >> "$URLS_FILE"; fi
fi
grep -E '^https?://' "$URLS_FILE" | sort -u -o "$URLS_FILE" || true

COUNT=$(wc -l < "$URLS_FILE" | tr -d ' ')
if [[ "$COUNT" == "0" ]]; then
  log_warn "Webshot: no discovered service URLs to screenshot"
  printf '[]\n' > "$OUTPUT_DIR/reports/screenshots.json"
  exit 0
fi
log_info "Webshot: screenshotting $COUNT discovered service(s)"

WS_ARGS=(--output "$OUTPUT_DIR" --services "$URLS_FILE" --workers "${JSINTEL_WEBSHOT_WORKERS:-6}")
[[ "$VERBOSE" == "1" ]] && WS_ARGS+=(--verbose)
# shellcheck disable=SC2206
WS_ARGS+=(${JSINTEL_WEBSHOT_ARGS:-})

PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m modules.webshot "${WS_ARGS[@]}"

if [[ -f "$OUTPUT_DIR/reports/screenshots.html" ]]; then
  log_info "Webshot gallery: $OUTPUT_DIR/reports/screenshots.html"
fi
