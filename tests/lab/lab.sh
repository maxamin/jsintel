#!/usr/bin/env bash
# JSIntel vulnerable-target lab controller.
#
# Stands up a small estate of intentionally-vulnerable web apps for AUTHORIZED,
# LOCAL regression/stress testing of JSIntel. Every service binds ONLY to
# 127.0.0.1 on a non-standard port and is reached through a /etc/hosts subdomain
# tree (see manifest.json). Nothing here is ever exposed beyond loopback.
#
# Usage:
#   tests/lab/lab.sh up [id...]      # provision + start all apps (or the named ids)
#   tests/lab/lab.sh down [id...]    # stop all apps (or the named ids)
#   tests/lab/lab.sh status          # show running state + health
#   tests/lab/lab.sh hosts           # print the /etc/hosts block
#   tests/lab/lab.sh hosts install   # add the block to /etc/hosts (sudo)
#   tests/lab/lab.sh hosts remove    # remove the block from /etc/hosts (sudo)
#   tests/lab/lab.sh seeds           # print seed URLs (feed to jsintel -i)
#   tests/lab/lab.sh scope           # print the comma-joined scope (feed to -s/-p/-f)
#
# App ids: juice vampi dvga webgoat dvwa
set -Eeuo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="$LAB_DIR/runtime"
TARGETS="$LAB_DIR/targets"
SHIM="$TARGETS/loopback-shim.js"
DOMAIN="vuln.lab"
LOOPBACK="127.0.0.1"
HOSTS_MARK="# >>> jsintel-lab >>>"
HOSTS_END="# <<< jsintel-lab <<<"
ALL_IDS=(juice vampi dvga webgoat dvwa)

mkdir -p "$RUNTIME"
log()  { printf '\033[1;34m[lab]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ ok]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!!]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[xx]\033[0m %s\n' "$*" >&2; }

# Ensure a Docker daemon is available for `docker export` (used to run VAmPI/DVGA
# from their images). This sandbox cannot bridge-network containers, so the daemon
# runs with vfs storage and no bridge -- fine, since export needs no networking.
require_docker() {
  command -v docker >/dev/null 2>&1 || { err "docker not installed (needed to export VAmPI/DVGA)"; return 1; }
  sudo docker info >/dev/null 2>&1 && return 0
  log "starting dockerd (vfs, no bridge) for image export…"
  (sudo dockerd --storage-driver=vfs --iptables=false --ip6tables=false --bridge=none >/tmp/jsintel-dockerd.log 2>&1 &)
  local i; for i in $(seq 1 20); do sudo docker info >/dev/null 2>&1 && { ok "dockerd up"; return 0; }; sleep 1; done
  err "dockerd did not become ready (see /tmp/jsintel-dockerd.log)"; return 1
}

# --- per-app metadata (kept in sync with manifest.json) ----------------------
host_of()  { case "$1" in juice) echo shop.$DOMAIN;; vampi) echo api.$DOMAIN;; dvga) echo graphql.$DOMAIN;; webgoat) echo goat.$DOMAIN;; dvwa) echo dvwa.$DOMAIN;; esac; }
port_of()  { case "$1" in juice) echo 3000;; vampi) echo 5001;; dvga) echo 5013;; webgoat) echo 8082;; dvwa) echo 8081;; esac; }
hpath_of() { case "$1" in webgoat) echo /WebGoat/login;; dvwa) echo /login.php;; *) echo /;; esac; }
name_of()  { case "$1" in juice) echo "OWASP Juice Shop";; vampi) echo "VAmPI";; dvga) echo "Damn Vulnerable GraphQL App";; webgoat) echo "OWASP WebGoat";; dvwa) echo "DVWA";; esac; }
# Each app gets its OWN loopback address (127.0.0.0/8 is all loopback on Linux),
# so the /etc/hosts subdomain tree points each host at a distinct IP and a port
# scan of one host sees only that host's real services (no cross-contamination).
bindip_of() { case "$1" in juice) echo 127.0.0.1;; webgoat) echo 127.0.0.2;; dvwa) echo 127.0.0.3;; vampi) echo 127.0.0.4;; dvga) echo 127.0.0.5;; esac; }

pidfile() { echo "$RUNTIME/$1.pid"; }
logfile() { echo "$RUNTIME/$1.log"; }

is_up() { # is_up <id> : pid alive?
  local pf; pf="$(pidfile "$1")"
  [[ -f "$pf" ]] && kill -0 "$(cat "$pf")" 2>/dev/null
}

health() { # health <id> : curl the health path, echo HTTP code
  local id="$1" code
  code="$(curl -sS -m 8 -o /dev/null -w '%{http_code}' "http://$(bindip_of "$id"):$(port_of "$id")$(hpath_of "$id")" 2>/dev/null)"
  echo "${code:-000}"
}

assert_loopback() { # assert_loopback <id> : FAIL if the port is bound to anything but 127.0.0.1/::1
  local id="$1" port; port="$(port_of "$id")"
  # Collect the local addresses listening on this port.
  local addrs
  addrs="$(ss -ltnH 2>/dev/null | awk -v p=":$port\$" '$4 ~ p {print $4}')"
  [[ -z "$addrs" ]] && { echo "no-listen"; return 1; }
  local a
  while IFS= read -r a; do
    [[ -z "$a" ]] && continue
    case "$a" in
      # All loopback forms are OK: IPv4 127.0.0.0/8, IPv6 ::1, and IPv4-mapped-IPv6 ::ffff:127.x
      127.*|"[::1]:"*|"[::ffff:127."*) : ;;
      # 0.0.0.0 / * / [::] / any routable address — NOT OK
      0.0.0.0:*|"*:"*|"[::]:"*|*) echo "EXPOSED:$a"; return 1 ;;
    esac
  done <<< "$addrs"
  echo loopback; return 0
}

wait_health() { # wait_health <id> <seconds>
  local id="$1" secs="${2:-60}" i code
  for ((i=0; i<secs; i++)); do
    code="$(health "$id")"
    [[ "$code" =~ ^(200|301|302|401|403)$ ]] && { echo "$code"; return 0; }
    sleep 1
  done
  echo "$(health "$id")"; return 1
}

start_bg() { # start_bg <id> <cmd...> : run cmd detached, record pid, bind is caller's job
  local id="$1"; shift
  local lf; lf="$(logfile "$id")"
  ( "$@" >"$lf" 2>&1 & echo $! >"$(pidfile "$id")" )
  disown 2>/dev/null || true
}

# =============================================================================
# Provisioning + start, one function pair per app. Provisioning is idempotent
# (skips work if the app is already present under runtime/).
# =============================================================================

# ---- Juice Shop (Node monolith release) -------------------------------------
JUICE_VER="20.2.0"
provision_juice() {
  local dir="$RUNTIME/juice-shop"
  [[ -f "$dir/app.js" || -f "$dir/build/app.js" ]] && return 0
  log "juice: fetching Juice Shop $JUICE_VER monolith…"
  local node_major tgz url
  node_major="$(node -p 'process.versions.node.split(".")[0]')"
  # Juice Shop ships prebuilt tarballs for a set of node majors; pick the closest <=.
  local cand
  for cand in "$node_major" 20 18; do
    tgz="juice-shop-${JUICE_VER}_node${cand}_linux_x64.tgz"
    url="https://github.com/juice-shop/juice-shop/releases/download/v${JUICE_VER}/${tgz}"
    if curl -fsSL -m 300 -o "$RUNTIME/$tgz" "$url" 2>/dev/null; then
      mkdir -p "$dir"; tar -xzf "$RUNTIME/$tgz" -C "$dir" --strip-components=1
      rm -f "$RUNTIME/$tgz"; ok "juice: extracted (node${cand} build)"; return 0
    fi
  done
  err "juice: could not download a compatible monolith tarball"; return 1
}
start_juice() {
  local dir="$RUNTIME/juice-shop" entry
  entry="$dir/app.js"; [[ -f "$entry" ]] || entry="$dir/build/app.js"
  ( cd "$dir" && setsid env PORT=3000 NODE_ENV=unsafe HOST="$(bindip_of juice)" LAB_BIND_IP="$(bindip_of juice)" \
      node --require "$SHIM" "$entry" >"$(logfile juice)" 2>&1 < /dev/null & echo $! >"$(pidfile juice)" )
}

# ---- VAmPI (REST/JWT) -- run from its Docker image via export + chroot --------
# VAmPI's pinned connexion/Flask/SQLAlchemy stack does not build on the host
# Python 3.14, so we run it from the image's own Python 3.11 + deps. See
# targets/rootfs.sh and TESTING_PROGRESS.md.
VAMPI_IMAGE="erev0s/vampi:latest"
provision_vampi() {
  local rf="$RUNTIME/vampi-rootfs"
  require_docker || return 1
  log "vampi: exporting $VAMPI_IMAGE root filesystem (first run only)…"
  bash "$TARGETS/rootfs.sh" export "$VAMPI_IMAGE" "$rf" || { err "vampi: image export failed"; return 1; }
  # Pin the server bind to this app's loopback IP (image hardcodes 0.0.0.0:5000).
  local app="$rf/vampi/app.py"
  grep -q "LAB_BIND_IP" "$app" 2>/dev/null || sed -i \
    "s/vuln_app.run(host='0.0.0.0', port=5000, debug=True)/import os as _os; vuln_app.run(host=_os.environ.get('LAB_BIND_IP','127.0.0.4'), port=int(_os.environ.get('LAB_PORT','5001')), debug=False, use_reloader=False)/" "$app"
  ok "vampi: provisioned (rootfs)"
}
start_vampi() {
  local rf="$RUNTIME/vampi-rootfs"
  bash "$TARGETS/rootfs.sh" start vampi "$rf" /vampi -- \
    "env PATH=/usr/local/bin:/usr/bin:/bin PYTHONUNBUFFERED=1 LAB_BIND_IP=$(bindip_of vampi) LAB_PORT=5001 python app.py"
}

# ---- DVGA (GraphQL) -- run from its Docker image via export + chroot ----------
DVGA_IMAGE="dolevf/dvga:latest"
provision_dvga() {
  local rf="$RUNTIME/dvga-rootfs"
  require_docker || return 1
  log "dvga: exporting $DVGA_IMAGE root filesystem (first run only)…"
  bash "$TARGETS/rootfs.sh" export "$DVGA_IMAGE" "$rf" || { err "dvga: image export failed"; return 1; }
  ok "dvga: provisioned (rootfs)"
}
start_dvga() {
  local rf="$RUNTIME/dvga-rootfs"
  # DVGA's deps are a --user install under /home/dvga/.local; HOME must point there.
  bash "$TARGETS/rootfs.sh" start dvga "$rf" /opt/dvga -- \
    "env HOME=/home/dvga PATH=/home/dvga/.local/bin:/usr/local/bin:/usr/bin:/bin PYTHONUNBUFFERED=1 WEB_HOST=$(bindip_of dvga) WEB_PORT=5013 python app.py"
}

# ---- WebGoat (Spring Boot jar) ----------------------------------------------
WEBGOAT_VER="2023.8"
provision_webgoat() {
  local jar="$RUNTIME/webgoat.jar"
  [[ -f "$jar" ]] && return 0
  log "webgoat: fetching WebGoat $WEBGOAT_VER jar…"
  local url="https://github.com/WebGoat/WebGoat/releases/download/v${WEBGOAT_VER}/webgoat-${WEBGOAT_VER}.jar"
  curl -fsSL -m 300 -o "$jar" "$url" 2>/dev/null || { err "webgoat: download failed"; rm -f "$jar"; return 1; }
  ok "webgoat: downloaded"
}
start_webgoat() {
  # The 2023.8 jar runs TWO apps (WebGoat + WebWolf), each reading its own env.
  # Both default to 127.0.0.1; we give them distinct non-standard ports. Do NOT
  # pass --server.port here — it overrides both profiles and makes them collide.
  local jar="$RUNTIME/webgoat.jar"
  ( setsid env WEBGOAT_HOST="$(bindip_of webgoat)" WEBGOAT_PORT=8082 \
               WEBWOLF_HOST="$(bindip_of webgoat)" WEBWOLF_PORT=9090 \
      java -Dfile.encoding=UTF-8 -jar "$jar" \
      >"$(logfile webgoat)" 2>&1 < /dev/null & echo $! >"$(pidfile webgoat)" )
}

# ---- DVWA (PHP + local MariaDB) ---------------------------------------------
provision_dvwa() {
  local dir="$RUNTIME/DVWA"
  if [[ ! -f "$dir/login.php" ]]; then
    log "dvwa: cloning DVWA…"
    git clone --depth 1 https://github.com/digininja/DVWA "$dir" >/dev/null 2>&1 || { err "dvwa: clone failed"; return 1; }
  fi
  # config
  if [[ ! -f "$dir/config/config.inc.php" ]]; then
    sed -e "s/'db_user' ] *= *'[^']*'/'db_user' ] = 'dvwa'/" \
        -e "s/'db_password' ] *= *'[^']*'/'db_password' ] = 'dvwa'/" \
        -e "s/'db_database' ] *= *'[^']*'/'db_database' ] = 'dvwa'/" \
        -e "s/'db_server' ] *= *'[^']*'/'db_server' ] = '127.0.0.1'/" \
        "$dir/config/config.inc.php.dist" > "$dir/config/config.inc.php"
  fi
  bash "$TARGETS/dvwa-db.sh" provision || { err "dvwa: db provisioning failed"; return 1; }
  ok "dvwa: provisioned"
}
start_dvwa() {
  bash "$TARGETS/dvwa-db.sh" start || true
  local dir="$RUNTIME/DVWA"
  # DVWA's config reads getenv() first; pass the creds our local MariaDB expects
  # (TCP to 127.0.0.1 — NOT 'localhost', which mysqli would treat as a socket).
  ( cd "$dir" && setsid env DB_SERVER=127.0.0.1 DB_PORT=3306 DB_DATABASE=dvwa DB_USER=dvwa DB_PASSWORD=dvwa \
      php -d display_errors=Off -S "$(bindip_of dvwa):8081" -t "$dir" \
      >"$(logfile dvwa)" 2>&1 < /dev/null & echo $! >"$(pidfile dvwa)" )
}

# =============================================================================
# Commands
# =============================================================================
do_up() {
  local ids=("$@"); [[ ${#ids[@]} -eq 0 ]] && ids=("${ALL_IDS[@]}")
  local id rc code up=() down=()
  for id in "${ids[@]}"; do
    if is_up "$id"; then ok "$(name_of "$id") already running (pid $(cat "$(pidfile "$id")"))"; up+=("$id"); continue; fi
    log "provisioning $(name_of "$id") ($id)…"
    if ! "provision_$id"; then down+=("$id (provision failed)"); continue; fi
    log "starting $(name_of "$id") on $LOOPBACK:$(port_of "$id")…"
    "start_$id"; sleep 1
    code="$(wait_health "$id" 90 || true)"
    # SAFETY GATE: never leave a deliberately-vulnerable app bound beyond loopback.
    local bind; bind="$(assert_loopback "$id" || true)"
    if [[ "$bind" == EXPOSED:* ]]; then
      err "$(name_of "$id") bound to a non-loopback address (${bind#EXPOSED:}) — KILLING it for safety."
      do_down "$id" >/dev/null 2>&1; sudo fuser -k "$(port_of "$id")/tcp" 2>/dev/null || true
      down+=("$id (refused: exposed ${bind#EXPOSED:})"); continue
    fi
    if [[ "$code" =~ ^(200|301|302|401|403)$ ]]; then
      ok "$(name_of "$id") up (loopback-only) — http://$(host_of "$id"):$(port_of "$id")$(hpath_of "$id") ($code)"; up+=("$id")
    else
      err "$(name_of "$id") did not become healthy (last=$code). Log tail:"; tail -6 "$(logfile "$id")" >&2 || true
      down+=("$id (unhealthy $code)")
    fi
  done
  echo; log "UP: ${up[*]:-none}"; [[ ${#down[@]} -gt 0 ]] && warn "NOT UP: ${down[*]}"
  echo; log "Add the hostnames with:  sudo $0 hosts install"
}

do_down() {
  local ids=("$@"); [[ ${#ids[@]} -eq 0 ]] && ids=("${ALL_IDS[@]}")
  local id pf pid
  for id in "${ids[@]}"; do
    # Apps running from an exported rootfs need their chroot bind-mounts torn down.
    case "$id" in
      vampi) bash "$TARGETS/rootfs.sh" stop vampi "$RUNTIME/vampi-rootfs" 2>/dev/null && ok "stopped $(name_of vampi)"; continue ;;
      dvga)  bash "$TARGETS/rootfs.sh" stop dvga  "$RUNTIME/dvga-rootfs"  2>/dev/null && ok "stopped $(name_of dvga)";  continue ;;
    esac
    pf="$(pidfile "$id")"
    if [[ -f "$pf" ]]; then pid="$(cat "$pf")"; if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; sleep 1; kill -9 "$pid" 2>/dev/null || true; fi; rm -f "$pf"; ok "stopped $(name_of "$id")"; fi
    # kill child processes that reparented (node/java spawn helpers)
    pkill -f "$RUNTIME/$id" 2>/dev/null || true
  done
  [[ " ${ids[*]} " == *" dvwa "* ]] && bash "$TARGETS/dvwa-db.sh" stop 2>/dev/null || true
}

do_status() {
  printf '%-9s %-18s %-6s %-9s %s\n' ID HOST PORT STATE HEALTH
  local id state code
  for id in "${ALL_IDS[@]}"; do
    if is_up "$id"; then state="running"; else state="stopped"; fi
    code="$(health "$id")"
    printf '%-9s %-18s %-6s %-9s %s\n' "$id" "$(host_of "$id")" "$(port_of "$id")" "$state" "$code"
  done
}

hosts_block() {
  echo "$HOSTS_MARK"
  local id; for id in "${ALL_IDS[@]}"; do printf '%s\t%s\n' "$(bindip_of "$id")" "$(host_of "$id")"; done
  echo "$HOSTS_END"
}
do_hosts() {
  case "${1:-print}" in
    print|"") hosts_block ;;
    install)
      sed -i "/$HOSTS_MARK/,/$HOSTS_END/d" /etc/hosts 2>/dev/null || true
      hosts_block >> /etc/hosts; ok "installed lab hosts into /etc/hosts"; grep -A6 "$HOSTS_MARK" /etc/hosts ;;
    remove)
      sed -i "/$HOSTS_MARK/,/$HOSTS_END/d" /etc/hosts; ok "removed lab hosts from /etc/hosts" ;;
    *) err "unknown hosts subcommand: $1"; exit 2 ;;
  esac
}

do_seeds() { local id; for id in "${ALL_IDS[@]}"; do echo "http://$(host_of "$id"):$(port_of "$id")/"; done; }
do_scope() { local id out=(); for id in "${ALL_IDS[@]}"; do out+=("$(host_of "$id")"); done; local IFS=,; echo "${out[*]}"; }

case "${1:-}" in
  up)     shift; do_up "$@" ;;
  down)   shift; do_down "$@" ;;
  status) do_status ;;
  hosts)  shift; do_hosts "$@" ;;
  seeds)  do_seeds ;;
  scope)  do_scope ;;
  *) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 2 ;;
esac
