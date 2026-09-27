#!/usr/bin/env bash
# Local MariaDB instance for DVWA — a self-contained datadir under runtime/,
# bound ONLY to 127.0.0.1. Never touches the system MariaDB service.
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="$(cd "$HERE/.." && pwd)/runtime"
DATADIR="$RUNTIME/mariadb/data"
SOCK="$RUNTIME/mariadb/mysql.sock"
PIDF="$RUNTIME/mariadb/mariadb.pid"
LOG="$RUNTIME/mariadb/mariadb.log"
PORT=3306
mkdir -p "$RUNTIME/mariadb"

case "${1:-}" in
  provision)
    # MariaDB is AppArmor-confined to /var/lib/mysql on Debian/Kali; our datadir
    # lives under the repo, so relax the profile to complain mode (best effort).
    if command -v aa-complain >/dev/null 2>&1; then sudo aa-complain /usr/sbin/mariadbd >/dev/null 2>&1 || true; fi
    if [[ ! -d "$DATADIR/mysql" ]]; then
      echo "[dvwa-db] initializing datadir…"
      mariadb-install-db --no-defaults --user=root --datadir="$DATADIR" --auth-root-authentication-method=normal >/dev/null 2>&1 \
        || mysql_install_db --no-defaults --user=root --datadir="$DATADIR" >/dev/null 2>&1
    fi
    "$0" start
    # wait for socket
    for _ in $(seq 1 30); do [[ -S "$SOCK" ]] && break; sleep 1; done
    echo "[dvwa-db] creating dvwa db + user…"
    mariadb --no-defaults -S "$SOCK" -u root <<'SQL' || true
CREATE DATABASE IF NOT EXISTS dvwa;
CREATE USER IF NOT EXISTS 'dvwa'@'127.0.0.1' IDENTIFIED BY 'dvwa';
CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'dvwa';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'127.0.0.1';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
SQL
    ;;
  start)
    if [[ -f "$PIDF" ]] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then exit 0; fi
    echo "[dvwa-db] starting mariadbd on 127.0.0.1:$PORT (loopback only)…"
    ( /usr/sbin/mariadbd --no-defaults --user=root --datadir="$DATADIR" --socket="$SOCK" \
        --bind-address=127.0.0.1 --port="$PORT" --skip-networking=0 \
        --pid-file="$PIDF" >"$LOG" 2>&1 & echo $! >"$PIDF.tmp"; wait ) &
    sleep 3; [[ -f "$PIDF.tmp" ]] && mv -f "$PIDF.tmp" "$PIDF" 2>/dev/null || true
    ;;
  stop)
    if [[ -f "$PIDF" ]] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
      mariadb-admin --no-defaults -S "$SOCK" -u root shutdown 2>/dev/null || kill "$(cat "$PIDF")" 2>/dev/null || true
    fi
    pkill -f "$DATADIR" 2>/dev/null || true; rm -f "$PIDF"
    ;;
  *) echo "usage: dvwa-db.sh {provision|start|stop}"; exit 2 ;;
esac
