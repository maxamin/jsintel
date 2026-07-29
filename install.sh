#!/usr/bin/env bash
# Installs system and language dependencies on Kali Linux / Debian.
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v apt-get >/dev/null; then
  echo "This installer supports Debian and Kali Linux only." >&2; exit 1
fi
SUDO=(); [[ ${EUID:-$(id -u)} -eq 0 ]] || SUDO=(sudo)
"${SUDO[@]}" apt-get update
"${SUDO[@]}" apt-get install -y python3 python3-pip python3-venv jq curl wget git sqlite3 golang-go

python3 -m pip install --user -r "$BASE_DIR/requirements.txt"
GO_BIN="$(go env GOPATH)/bin"
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "Installed Go tools in $GO_BIN. Add it to PATH if it is not already present:"
echo "  export PATH=\"\$PATH:$GO_BIN\""
echo "Installation complete."
