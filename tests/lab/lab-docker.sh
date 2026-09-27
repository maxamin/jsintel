#!/usr/bin/env bash
# JSIntel vulnerable-lab controller for a REAL Docker host.
#
# Same UX as lab.sh, but drives tests/lab/docker-compose.yml (the full 10-app
# estate, including the multi-service/CMS apps that can't run in the native
# sandbox: bWAPP, Mutillidae, NodeGoat, RailsGoat). Every service is published on
# 127.0.0.1:<port>, so the /etc/hosts subdomain tree maps every host to 127.0.0.1
# and is distinguished by port. Point JSIntel at the seeds exactly as with lab.sh.
#
# Usage:
#   tests/lab/lab-docker.sh up [svc...]     # docker compose up -d + health-check
#   tests/lab/lab-docker.sh down            # docker compose down
#   tests/lab/lab-docker.sh status          # container state + per-host health
#   tests/lab/lab-docker.sh hosts install   # add the subdomain tree to /etc/hosts (sudo)
#   tests/lab/lab-docker.sh hosts remove     # remove it (sudo)
#   tests/lab/lab-docker.sh hosts print      # print the block
#   tests/lab/lab-docker.sh seeds           # seed URLs (feed to jsintel -i)
#   tests/lab/lab-docker.sh scope           # comma-joined scope (feed to -s/-p/-f)
set -Eeuo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$LAB_DIR/docker-compose.yml"
LOOPBACK="127.0.0.1"
HOSTS_MARK="# >>> jsintel-lab-docker >>>"
HOSTS_END="# <<< jsintel-lab-docker <<<"

log()  { printf '\033[1;34m[lab-docker]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ ok]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!!]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[xx]\033[0m %s\n' "$*" >&2; }

# host  ->  published port  ->  health path. Kept in sync with docker-compose.yml.
# Format: "host|port|healthpath"
ESTATE=(
  "shop.vuln.docker|3000|/"
  "goat.vuln.docker|8082|/WebGoat/login"
  "wolf.vuln.docker|9090|/WebWolf/login"
  "dvwa.vuln.docker|8081|/login.php"
  "api.vuln.docker|5001|/"
  "graphql.vuln.docker|5013|/"
  "bwapp.vuln.docker|8083|/install.php"
  "mutillidae.vuln.docker|8084|/"
  "wp.vuln.docker|8085|/"
  "nodegoat.vuln.docker|4000|/login"
  "railsgoat.vuln.docker|3001|/login"
)

# --- docker compose invocation (support the v2 plugin and the v1 binary) ------
detect_compose() {
  if docker compose version >/dev/null 2>&1; then COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then COMPOSE=(docker-compose)
  else err "neither 'docker compose' nor 'docker-compose' is available"; exit 2; fi
  COMPOSE+=(-f "$COMPOSE_FILE")
}

health() { # health <host> <port> <path>
  curl -sS -m 8 -o /dev/null -w '%{http_code}' "http://$LOOPBACK:$2$3" 2>/dev/null || echo 000
}

wait_health() { # wait_health <host> <port> <path> <seconds>
  local i code
  for ((i=0; i<${4:-120}; i++)); do
    code="$(health "$1" "$2" "$3")"
    [[ "$code" =~ ^(200|301|302|401|403)$ ]] && { echo "$code"; return 0; }
    sleep 2
  done
  echo "$(health "$1" "$2" "$3")"; return 1
}

hosts_block() {
  echo "$HOSTS_MARK"
  local row; for row in "${ESTATE[@]}"; do IFS='|' read -r h _ _ <<< "$row"; printf '%s\t%s\n' "$LOOPBACK" "$h"; done
  echo "$HOSTS_END"
}

do_up() {
  detect_compose
  log "docker compose up -d${*:+ ($*)}…"
  "${COMPOSE[@]}" up -d "$@"
  log "waiting for services to become healthy (compose pulls on first run — can take a while)…"
  local row h p hp code up=() down=()
  for row in "${ESTATE[@]}"; do
    IFS='|' read -r h p hp <<< "$row"
    code="$(wait_health "$h" "$p" "$hp" 150 || true)"
    if [[ "$code" =~ ^(200|301|302|401|403)$ ]]; then
      ok "$h -> http://$h:$p$hp ($code)"; up+=("$h")
    else
      warn "$h (:$p) not healthy yet (last=$code) — may still be starting or not in the 'up' set"; down+=("$h")
    fi
  done
  echo; log "UP: ${up[*]:-none}"; [[ ${#down[@]} -gt 0 ]] && warn "not-yet-healthy: ${down[*]}"
  echo; log "Add the hostnames with:  sudo $0 hosts install"
}

do_down() { detect_compose; log "docker compose down…"; "${COMPOSE[@]}" down "$@"; }

do_status() {
  detect_compose
  "${COMPOSE[@]}" ps 2>/dev/null || true
  echo
  printf '%-20s %-6s %-18s %s\n' HOST PORT HEALTH URL
  local row h p hp
  for row in "${ESTATE[@]}"; do
    IFS='|' read -r h p hp <<< "$row"
    printf '%-20s %-6s %-18s %s\n' "$h" "$p" "$(health "$h" "$p" "$hp")" "http://$h:$p$hp"
  done
}

do_hosts() {
  case "${1:-print}" in
    print|"") hosts_block ;;
    install)
      sed -i "/$HOSTS_MARK/,/$HOSTS_END/d" /etc/hosts 2>/dev/null || true
      hosts_block >> /etc/hosts; ok "installed docker-lab hosts into /etc/hosts"; grep -A12 "$HOSTS_MARK" /etc/hosts ;;
    remove)
      sed -i "/$HOSTS_MARK/,/$HOSTS_END/d" /etc/hosts; ok "removed docker-lab hosts from /etc/hosts" ;;
    *) err "unknown hosts subcommand: $1"; exit 2 ;;
  esac
}

do_seeds() { local row h p hp; for row in "${ESTATE[@]}"; do IFS='|' read -r h p hp <<< "$row"; echo "http://$h:$p$hp"; done; }
do_scope() { local row h out=(); for row in "${ESTATE[@]}"; do IFS='|' read -r h _ _ <<< "$row"; out+=("$h"); done; local IFS=,; echo "${out[*]}"; }

case "${1:-}" in
  up)     shift; do_up "$@" ;;
  down)   shift; do_down "$@" ;;
  status) do_status ;;
  hosts)  shift; do_hosts "$@" ;;
  seeds)  do_seeds ;;
  scope)  do_scope ;;
  *) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 2 ;;
esac
