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
# JSINTEL_SWEEP_RESUME=1 skips targets whose .sweep_status is "ok", so an interrupted
# sweep (the 2026-10-09 run stopped at ~13.8k of 58.5k targets) continues where it
# left off in the same output dir instead of re-scanning finished targets.
RESUME="${JSINTEL_SWEEP_RESUME:-0}"

# --- Normalise the target list ------------------------------------------------
# Accept bare domains or URLs; strip scheme/path/port; drop comments/blanks.
# Only real hostnames survive: LDH labels, no leading/trailing "-", alphabetic TLD.
# Underscore names are DNS service/wildcard records, not web hosts -- the
# 2026-10-09 list carried _wildcard.yoca.sh and _carddavs._tcp.<domain>.
# JSINTEL_SWEEP_DENY is an optional comma/space list of shell globs to skip, e.g.
# "*.files.wordpress.com,*.aspmx.l.google.com" (shared platforms and mail-only
# names: *.files.wordpress.com was 396 of that sweep's 474 katana OOM kills).
mapfile -t TARGETS < <(
  sed -E 's/\r$//; s/#.*$//' "$TARGETS_FILE" \
    | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:[0-9]+$##; s#.*@##; s#\.$##' \
    | tr 'A-Z' 'a-z' | grep -E '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$' | sort -u
)
[[ ${#TARGETS[@]} -gt 0 ]] || die "No valid target domains parsed from: $TARGETS_FILE"
if [[ -n "${JSINTEL_SWEEP_DENY:-}" ]]; then
  read -r -a DENY <<<"${JSINTEL_SWEEP_DENY//,/ }"
  KEPT=()
  for t in "${TARGETS[@]}"; do
    denied=0
    for pat in "${DENY[@]}"; do
      # shellcheck disable=SC2053
      [[ "$t" == $pat ]] && { denied=1; break; }
    done
    (( denied )) || KEPT+=("$t")
  done
  log_info "Deny-list (JSINTEL_SWEEP_DENY) removed $(( ${#TARGETS[@]} - ${#KEPT[@]} )) target(s)"
  TARGETS=(${KEPT[@]+"${KEPT[@]}"})
  [[ ${#TARGETS[@]} -gt 0 ]] || die "Every target was removed by JSINTEL_SWEEP_DENY"
fi

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
  if [[ "$RESUME" == "1" && "$(cat "$tdir/.sweep_status" 2>/dev/null)" == "ok" ]]; then
    log_info "[sweep] skip  $target (already ok; JSINTEL_SWEEP_RESUME=1)"
    return 0
  fi
  log_info "[sweep] start $target -> $tdir"
  # Each target is isolated: a failure in one must not abort the sweep.
  # A stage killed by a crash signal (SIGSEGV/SIGBUS/SIGABRT/SIGKILL) is retried once:
  # the 2026-10-09 sweep lost 44 targets to sporadic bash 5.3 segfaults (rc=139) in
  # crawler.sh/portscan.sh with no kernel trace and no pattern by target. SIGINT and
  # SIGTERM (rc 130/143) are the operator stopping the run and are never retried.
  # The failed attempt's log is kept as sweep_target.attempt1.log.
  local rc=0 attempt
  for attempt in 1 2; do
    rc=0
    bash "$BASE_DIR/jsintel.sh" "${args[@]}" >"$tdir/sweep_target.log" 2>&1 || rc=$?
    case "$rc" in
      134|135|137|139) [[ "$attempt" == "1" ]] || break
        mv -f "$tdir/sweep_target.log" "$tdir/sweep_target.attempt1.log"
        log_warn "[sweep] retry $target (stage died with rc=$rc; retrying once)" ;;
      *) break ;;
    esac
  done
  if (( rc == 0 )); then
    log_info "[sweep] done  $target (ok)"
    printf 'ok\n' > "$tdir/.sweep_status"
  else
    log_warn "[sweep] done  $target (FAILED rc=$rc; see $tdir/sweep_target.log)"
    printf 'failed rc=%s\n' "$rc" > "$tdir/.sweep_status"
  fi
}

# --- Pre-filter: drop dead hosts and wildcard-DNS duplicates --------------------
# JSINTEL_SWEEP_PREFILTER: full (default; skip dead + wildcard duplicates), wildcard
# (only collapse wildcard duplicates -- use with -P to still port-scan hosts that do
# not answer on 80/443), off. Decisions: reports/prefilter.json. With resume, targets
# already ok are not probed again.
PREFILTER="${JSINTEL_SWEEP_PREFILTER:-full}"
RUN_TARGETS=("${TARGETS[@]}")
if [[ "$PREFILTER" != "off" && "$PREFILTER" != "0" ]]; then
  PENDING=()
  for t in "${TARGETS[@]}"; do
    if [[ "$RESUME" == "1" && "$(cat "$OUTPUT_DIR/targets/$(sanitize "$t")/.sweep_status" 2>/dev/null)" == "ok" ]]; then
      continue
    fi
    PENDING+=("$t")
  done
  if (( ${#PENDING[@]} )); then
    log_info "Pre-filter ($PREFILTER): probing ${#PENDING[@]} target(s) for liveness and wildcard DNS"
    if mapfile -t RUN_TARGETS < <(printf '%s\n' "${PENDING[@]}" \
         | PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m modules.sweep_prefilter \
             --output "$OUTPUT_DIR" --mode "$PREFILTER" 2>>"$LOG_FILE") && [[ -s "$OUTPUT_DIR/reports/prefilter.json" ]]; then
      log_info "Pre-filter kept ${#RUN_TARGETS[@]} of ${#PENDING[@]} target(s); see reports/prefilter.json"
    else
      log_warn "Pre-filter failed; running every target"
      RUN_TARGETS=("${PENDING[@]}")
    fi
  else
    RUN_TARGETS=()
  fi
fi

# --- Bounded-parallel execution ----------------------------------------------
running=0; completed=0
HEALTH_STAGES=""
[[ "$SWEEP_PORTS" == "1" ]] && HEALTH_STAGES+="ports,"
[[ "$SWEEP_WEBSHOT" == "1" ]] && HEALTH_STAGES+="webshot,"
for target in ${RUN_TARGETS[@]+"${RUN_TARGETS[@]}"}; do
  run_one "$target" &
  running=$((running + 1))
  if (( running >= PARALLEL )); then
    wait -n 2>/dev/null || wait   # wait for any one to finish (fallback: all)
    running=$((running - 1)); completed=$((completed + 1))
    # Health check after the first 50 targets, then every 1000: warn loudly when an
    # enabled stage has produced nothing anywhere (a broken stage, not empty targets).
    if (( completed == 50 || completed % 1000 == 0 )); then
      PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m modules.sweep_aggregate \
        --output "$OUTPUT_DIR" --health "$HEALTH_STAGES" "${RUN_TARGETS[@]}" 2>/dev/null \
        | while IFS= read -r line; do log_warn "[sweep] $line"; done || true
    fi
  fi
done
wait

# --- Aggregate ----------------------------------------------------------------
log_info "Mass sweep: aggregating per-target results"
PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" \
  python3 -m modules.sweep_aggregate --output "$OUTPUT_DIR" "${TARGETS[@]}"

log_info "Mass sweep complete. Aggregate: $OUTPUT_DIR/reports/sweep_summary.md"
