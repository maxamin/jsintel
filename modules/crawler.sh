#!/usr/bin/env bash
# Crawl authorized seed URLs and retain potentially useful client assets.
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BASE_DIR/modules/utils.sh"
INPUT="${1:?Input URL file or URL required}"; OUT="$OUTPUT_DIR/assets/crawled_urls.txt"
DEPTH=$(awk '/^crawler:/ {p=1; next} p && /^[[:space:]]+depth:/ {print $2; exit}' "$CONFIG" 2>/dev/null || true); DEPTH="${DEPTH:-5}"
SEEDS=$(mktemp); trap 'rm -f "$SEEDS"' EXIT
if [[ -f "$INPUT" ]]; then grep -E '^https?://' "$INPUT" | sed 's/\r$//' > "$SEEDS" || true; else printf '%s\n' "$INPUT" > "$SEEDS"; fi
[[ -s "$SEEDS" ]] || die "No valid http(s) seed URLs in: $INPUT"

if command -v katana >/dev/null 2>&1; then
  log_info "Crawling with katana (depth $DEPTH)"
  katana -list "$SEEDS" -d "$DEPTH" -jc -jsl -silent -c "$THREADS" 2>>"$LOG_FILE" \
    | grep -Ei '\.(js|mjs|map|json|wasm)([?#].*)?$|(^|[/._-])(service-)?worker([._/?#-]|$)|manifest(\.json|\.webmanifest)?([?#].*)?$' \
    | sed 's/[[:space:]]*$//' | sort -u > "$OUT" || true
else
  log_warn "katana is unavailable; treating input URLs as discovered assets"
  cp "$SEEDS" "$OUT"
fi
log_info "Crawler discovered $(wc -l < "$OUT" | tr -d ' ') candidate assets"
