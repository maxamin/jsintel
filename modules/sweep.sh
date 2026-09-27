#!/usr/bin/env bash
# Mass-sweep driver: run the full JSIntel pipeline against many targets.
#
# Each target domain from the supplied file is assessed independently in its own
# output directory (<OUTPUT_DIR>/targets/<domain>/), so findings, assets and the
# database never bleed between targets. Per-target stages (subdomain enumeration,
# web-service port scanning, content-discovery fuzzing) are toggled by the caller
# (jsintel.sh -S/-P/-F) and each uses its own target as the authorized scope --
# so a sweep only ever touches hosts under the targets you listed.
#
# Targets run with bounded parallelism (JSINTEL_SWEEP_PARALLEL, default 3). After
# every target finishes, an aggregate reports/sweep_summary.{json,md} rolls up the
# per-target counts (live subdomains, web services, assets, findings, fuzz hits).
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BASE_DIR/modules/utils.sh"

TARGETS_FILE="${1:?Mass sweep requires a targets file}"
[[ -f "$TARGETS_FILE" ]] || die "Targets file not found: $TARGETS_FILE"

OUTPUT_DIR="${OUTPUT_DIR:?OUTPUT_DIR must be set}"
mkdir -p "$OUTPUT_DIR/targets" "$OUTPUT_DIR/reports" "$OUTPUT_DIR/logs"
LOG_FILE="${LOG_FILE:-$OUTPUT_DIR/logs/jsintel.log}"; export LOG_FILE

SWEEP_SUBS="${SWEEP_SUBS:-0}"; SWEEP_PORTS="${SWEEP_PORTS:-0}"; SWEEP_FUZZ="${SWEEP_FUZZ:-0}"; SWEEP_WEBSHOT="${SWEEP_WEBSHOT:-0}"
SWEEP_THREADS="${SWEEP_THREADS:-}"; VERBOSE="${VERBOSE:-0}"
PARALLEL="${JSINTEL_SWEEP_PARALLEL:-3}"
[[ "$PARALLEL" =~ ^[1-9][0-9]*$ ]] || PARALLEL=3

# --- Normalise the target list ------------------------------------------------
# Accept bare domains or URLs; strip scheme/path/port; drop comments/blanks.
mapfile -t TARGETS < <(
  sed -E 's/\r$//; s/#.*$//' "$TARGETS_FILE" \
    | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:[0-9]+$##; s#.*@##' \
    | tr 'A-Z' 'a-z' | grep -E '^[a-z0-9._-]+\.[a-z]+$' | sort -u
)
[[ ${#TARGETS[@]} -gt 0 ]] || die "No valid target domains parsed from: $TARGETS_FILE"

STAGES="crawl+extract"
[[ "$SWEEP_SUBS" == "1" ]] && STAGES="subs+$STAGES"
[[ "$SWEEP_PORTS" == "1" ]] && STAGES="$STAGES+ports"
[[ "$SWEEP_WEBSHOT" == "1" ]] && STAGES="$STAGES+webshot"
[[ "$SWEEP_FUZZ" == "1" ]] && STAGES="$STAGES+fuzz"
log_info "Mass sweep: ${#TARGETS[@]} target(s), parallelism $PARALLEL, stages: $STAGES"

sanitize() { printf '%s\n' "$1" | tr '/:' '__'; }

run_one() {
  local target="$1"
  local safe tdir
  safe="$(sanitize "$target")"
  tdir="$OUTPUT_DIR/targets/$safe"
  mkdir -p "$tdir"
  local args=(-i "https://$target" -o "$tdir")
  [[ -n "$SWEEP_THREADS" ]] && args+=(-t "$SWEEP_THREADS")
  [[ "$SWEEP_SUBS" == "1" ]] && args+=(-s "$target")
  [[ "$SWEEP_PORTS" == "1" ]] && args+=(-p "$target")
  [[ "$SWEEP_WEBSHOT" == "1" ]] && args+=(-w)
  [[ "$SWEEP_FUZZ" == "1" ]] && args+=(-f "$target")
  [[ "$VERBOSE" == "1" ]] && args+=(-v)
  log_info "[sweep] start $target -> $tdir"
  # Each target is isolated: a failure in one must not abort the sweep.
  if bash "$BASE_DIR/jsintel.sh" "${args[@]}" >"$tdir/sweep_target.log" 2>&1; then
    log_info "[sweep] done  $target (ok)"
    printf 'ok\n' > "$tdir/.sweep_status"
  else
    local rc=$?
    log_warn "[sweep] done  $target (FAILED rc=$rc; see $tdir/sweep_target.log)"
    printf 'failed rc=%s\n' "$rc" > "$tdir/.sweep_status"
  fi
}

# --- Bounded-parallel execution ----------------------------------------------
running=0
for target in "${TARGETS[@]}"; do
  run_one "$target" &
  running=$((running + 1))
  if (( running >= PARALLEL )); then
    wait -n 2>/dev/null || wait   # wait for any one to finish (fallback: all)
    running=$((running - 1))
  fi
done
wait

# --- Aggregate ----------------------------------------------------------------
log_info "Mass sweep: aggregating per-target results"
PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" \
  python3 -m modules.sweep_aggregate --output "$OUTPUT_DIR" "${TARGETS[@]}"

log_info "Mass sweep complete. Aggregate: $OUTPUT_DIR/reports/sweep_summary.md"
