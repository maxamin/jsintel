#!/usr/bin/env bash
# JSIntel Phase 1 orchestration entry point.
set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$BASE_DIR/modules/utils.sh"

usage() {
  cat <<'EOF'
Usage: ./jsintel.sh -i <input_urls> [-o <output_directory>] [-t <threads>]

  -i  File containing seed URLs (one per line), or a single URL
  -o  Output directory (default: ./output)
  -t  Concurrent download/crawl workers (default: config value or 50)
EOF
}

INPUT=""; OUTPUT_DIR="$BASE_DIR/output"; THREADS=""
while getopts ":i:o:t:h" option; do
  case "$option" in
    i) INPUT="$OPTARG" ;; o) OUTPUT_DIR="$OPTARG" ;; t) THREADS="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG needs a value" ;; *) usage; exit 2 ;;
  esac
done
[[ -n "$INPUT" ]] || { usage; exit 2; }
[[ "$THREADS" =~ ^[1-9][0-9]*$ || -z "$THREADS" ]] || die "Threads must be a positive integer"

require_command python3
mkdir -p "$OUTPUT_DIR"/{assets,logs,database} "$OUTPUT_DIR/reports"
LOG_FILE="$OUTPUT_DIR/logs/jsintel.log"; export LOG_FILE
CONFIG="$BASE_DIR/config/config.yaml"; export CONFIG
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"; export OUTPUT_DIR
THREADS="${THREADS:-$(config_value threads 50)}"; export THREADS

log_info "JSIntel Phase 1 started (workers: $THREADS)"
log_info "Pipeline: Crawler -> Normalizer -> Classifier -> Downloader -> Extractor -> Database -> Reports"

bash "$BASE_DIR/modules/crawler.sh" "$INPUT"
bash "$BASE_DIR/modules/classifier.sh" "$OUTPUT_DIR/assets/crawled_urls.txt"
bash "$BASE_DIR/modules/downloader.sh" "$OUTPUT_DIR/reports/assets.json"
bash "$BASE_DIR/modules/extractor.sh" "$OUTPUT_DIR/reports/assets.json"
python3 "$BASE_DIR/modules/database.py" --output "$OUTPUT_DIR" --config "$CONFIG" ingest
python3 "$BASE_DIR/modules/reporter.py" --output "$OUTPUT_DIR" --config "$CONFIG"

log_info "Completed successfully. Reports: $OUTPUT_DIR/reports"
