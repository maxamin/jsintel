#!/usr/bin/env bash
# Compatibility wrapper for the streaming Python extraction engine.
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BASE_DIR/modules/utils.sh"

MANIFEST="${1:?assets.json manifest required}"
REPORT_DIR="$OUTPUT_DIR/reports"
PYTHONPATH="$BASE_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m modules.extractor.main \
  --manifest "$MANIFEST" \
  --output "$REPORT_DIR"
log_info "Extraction reports written to $REPORT_DIR"
