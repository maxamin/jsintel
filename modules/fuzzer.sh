#!/usr/bin/env bash
# Compatibility wrapper for the content-discovery fuzzer.
#
# Fuzzing sends live requests and therefore runs only against an explicit,
# authorized scope. This wrapper is a thin shim over `python3 -m modules.fuzzer`;
# it reads OUTPUT_DIR from the environment (as the other pipeline stages do) and
# forwards the authorized scope plus any extra options in JSINTEL_FUZZ_ARGS.
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BASE_DIR/modules/utils.sh"

SCOPE="${1:-}"
[[ -n "$SCOPE" ]] || die "Fuzzing requires an authorized scope (a domain you are permitted to test)"

# shellcheck disable=SC2206  # Intentional word splitting for optional extra args.
EXTRA_ARGS=(${JSINTEL_FUZZ_ARGS:-})

log_info "Fuzzing discovered paths against Assetnote wordlists (scope: $SCOPE)"
PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m modules.fuzzer \
  --output "$OUTPUT_DIR" \
  --scope "$SCOPE" \
  "${EXTRA_ARGS[@]}"
log_info "Fuzzing report written to $OUTPUT_DIR/reports/fuzz.json"
