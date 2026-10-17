#!/usr/bin/env bash
# Shared logging and configuration helpers. This file is sourced, not executed.

# Python must import this repository's modules, never a `modules` package that happens
# to sit in the operator's current directory: `python3 -m modules.X` and script runs
# put the cwd (or the script's dir) ahead of PYTHONPATH. PYTHONSAFEPATH (3.11+) drops
# that entry; every stage passes PYTHONPATH="$BASE_DIR" (or adds the repo root itself).
export PYTHONSAFEPATH=1

log() { local level="$1"; shift; local line="$(date -u +'%Y-%m-%dT%H:%M:%SZ') [$level] $*"; printf '%s\n' "$line" >&2; [[ -n "${LOG_FILE:-}" ]] && printf '%s\n' "$line" >> "$LOG_FILE"; }
log_info() { log INFO "$@"; }
log_warn() { log WARN "$@"; }
log_error() { log ERROR "$@"; }
die() { log_error "$*"; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

# Read simple top-level scalar YAML keys without requiring PyYAML in shell modules.
config_value() {
  local key="$1" fallback="$2"
  [[ -f "${CONFIG:-}" ]] || { printf '%s\n' "$fallback"; return; }
  local value
  value=$(awk -F: -v k="$key" '$1 == k {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$CONFIG")
  printf '%s\n' "${value:-$fallback}"
}
