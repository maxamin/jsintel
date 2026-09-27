#!/usr/bin/env bash
# Run an app from a Docker-exported root filesystem via chroot, bound to loopback.
#
# Used for apps whose pinned dependencies do not build on the host Python (VAmPI,
# DVGA on Python 3.14): we run them from their image's OWN interpreter + deps.
# The chroot shares the host network namespace, so binding a 127.x address is
# reachable from the host; nothing is exposed off loopback.
#
#   rootfs.sh export <image> <rootfs>          # docker export image -> rootfs (idempotent)
#   rootfs.sh start  <id> <rootfs> <workdir> -- <shell command...>
#   rootfs.sh stop   <id> <rootfs>
#
# The caller passes the COMPLETE command (with its own env, e.g.
# `env HOME=/home/dvga WEB_HOST=127.0.0.5 ... python app.py`) so each app can set
# whatever it needs; this script only handles the bind mounts and the chroot.
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="$(cd "$HERE/.." && pwd)/runtime"

_mount_binds() {
  local rf="$1"
  # /proc is the only mount the app runtimes actually need. We deliberately do NOT
  # bind-mount the host /dev (devtmpfs) or /sys into the repo tree: a live devtmpfs
  # bind under a git-tracked/moved/removed directory is a real hazard (a recursive
  # rm or mv could traverse into the host's real device tree). Instead we create the
  # few device nodes a web app needs as real on-disk nodes (no mount to leak).
  mkdir -p "$rf/proc"
  mountpoint -q "$rf/proc" || sudo mount -t proc proc "$rf/proc" 2>/dev/null || sudo mount --bind /proc "$rf/proc"
  mkdir -p "$rf/dev"
  [[ -c "$rf/dev/null" ]]    || sudo mknod -m 666 "$rf/dev/null"    c 1 3 2>/dev/null || true
  [[ -c "$rf/dev/zero" ]]    || sudo mknod -m 666 "$rf/dev/zero"    c 1 5 2>/dev/null || true
  [[ -c "$rf/dev/random" ]]  || sudo mknod -m 666 "$rf/dev/random"  c 1 8 2>/dev/null || true
  [[ -c "$rf/dev/urandom" ]] || sudo mknod -m 666 "$rf/dev/urandom" c 1 9 2>/dev/null || true
  # Minimal resolver files so a server's startup banner never stalls on DNS.
  [[ -f "$rf/etc/hosts" ]]      || printf '127.0.0.1\tlocalhost\n' | sudo tee "$rf/etc/hosts" >/dev/null
  [[ -f "$rf/etc/resolv.conf" ]]|| echo 'nameserver 127.0.0.1'      | sudo tee "$rf/etc/resolv.conf" >/dev/null
}
_umount_binds() {
  local rf="$1"
  # Only /proc is ever mounted now; the device nodes are plain files (no unmount).
  mountpoint -q "$rf/proc" && sudo umount -lf "$rf/proc" 2>/dev/null || true
}

cmd="${1:-}"; shift || true
case "$cmd" in
  export)
    image="$1"; rf="$2"
    [[ -x "$rf/usr/local/bin/python" || -x "$rf/usr/bin/python3" ]] && exit 0   # already exported
    mkdir -p "$rf"
    local_cid="$(sudo docker create "$image")" || { echo "rootfs: docker create failed for $image"; exit 1; }
    sudo docker export "$local_cid" | tar -x -C "$rf"
    sudo docker rm "$local_cid" >/dev/null 2>&1 || true
    ;;
  start)
    id="$1"; rf="$2"; workdir="$3"; shift 3
    [[ "${1:-}" == "--" ]] && shift
    _mount_binds "$rf"
    # setsid so the app survives the launching shell.
    ( setsid chroot "$rf" /bin/sh -c "cd '$workdir' && exec $*" \
        >"$RUNTIME/$id.log" 2>&1 < /dev/null & echo $! >"$RUNTIME/$id.pid" )
    ;;
  stop)
    id="$1"; rf="$2"
    if [[ -f "$RUNTIME/$id.pid" ]]; then
      pid="$(cat "$RUNTIME/$id.pid")"; kill "$pid" 2>/dev/null || true; sleep 1; kill -9 "$pid" 2>/dev/null || true
      rm -f "$RUNTIME/$id.pid"
    fi
    sudo fuser -k "$rf" 2>/dev/null || true   # kill any chroot'd children holding the mounts
    _umount_binds "$rf"
    ;;
  *) echo "usage: rootfs.sh {export|start|stop} ..."; exit 2 ;;
esac
