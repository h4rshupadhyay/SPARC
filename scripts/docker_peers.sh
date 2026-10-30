#!/usr/bin/env bash
# Run two SPARC GUI peers on a local Linux Docker Engine and X11 desktop.
set -euo pipefail

fail() { printf 'SPARC Docker: %s\n' "$*" >&2; exit 1; }
usage() {
    printf 'Usage: %s [up|down|status|logs|check|build|config]\n' "$0"
}

action=${1:-up}
[[ $# -le 1 ]] || { usage >&2; exit 2; }
case "$action" in
    up|down|status|logs|check|build|config) ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

[[ $(uname -s) == Linux ]] || fail 'This launcher requires Linux with a local Docker Engine.'
command -v docker >/dev/null || fail 'Install Docker Engine and Docker Compose first.'
docker compose version >/dev/null || fail 'Docker Compose is unavailable.'

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
runtime_dir="$repo_dir/.demo/docker"
export SPARC_UID
export SPARC_GID
export SPARC_XAUTHORITY="$runtime_dir/Xauthority"
SPARC_UID=$(id -u)
SPARC_GID=$(id -g)
# These defaults let lifecycle commands work outside a graphical login.
export DISPLAY=${DISPLAY:-}
compose=(docker compose --project-directory "$repo_dir" -f "$repo_dir/compose.yaml")

case "$action" in
    up)
        [[ $SPARC_UID != 0 ]] || fail 'Run this as your desktop user, without sudo.'
        [[ $DISPLAY =~ ^:[0-9]+(\.[0-9]+)?$ ]] || \
            fail 'DISPLAY must name a local X11 display (for example :0 or :1). Run from your desktop terminal.'
        display_number=${DISPLAY#:}
        display_number=${display_number%%.*}
        [[ -S /tmp/.X11-unix/X$display_number ]] || fail 'The local X11 display socket is missing.'
        command -v xauth >/dev/null || fail 'Install xauth (sudo apt install xauth).'
        docker info >/dev/null || fail 'Cannot reach Docker Engine; check your Docker permissions.'
        umask 077
        mkdir -p -- "$runtime_dir"
        chmod 700 -- "$runtime_dir"
        authority_tmp=$(mktemp "$runtime_dir/Xauthority.XXXXXX")
        trap 'rm -f -- "$authority_tmp"' EXIT
        # FamilyWild lets the same local-display cookie work with container hostnames.
        # The cookie remains in this pipeline and is never printed to the terminal.
        if ! xauth nlist "$DISPLAY" | sed 's/^..../ffff/' | xauth -f "$authority_tmp" nmerge -; then
            fail 'Could not copy X11 authorization. Check DISPLAY and XAUTHORITY.'
        fi
        [[ -s $authority_tmp ]] || fail 'No X11 cookie found. Check DISPLAY and XAUTHORITY.'
        mv -f -- "$authority_tmp" "$SPARC_XAUTHORITY"
        # Recreate so a repeated launch mounts the new cookie file, not its old inode.
        "${compose[@]}" up --build --force-recreate -d
        printf '\nAlice: 172.30.50.10   Bob: 172.30.50.11   Listener port: 47655\n'
        printf 'Create/unlock each identity in its desktop window. See docs/docker-peers.md.\n'
        ;;
    down)
        "${compose[@]}" down
        rm -f -- "$SPARC_XAUTHORITY"
        ;;
    status) "${compose[@]}" ps -a ;;
    logs) "${compose[@]}" logs --tail=80 ;;
    check)
        "${compose[@]}" exec -T alice python -m sparc --check --data-dir /data/alice
        "${compose[@]}" exec -T bob python -m sparc --check --data-dir /data/bob
        ;;
    build) "${compose[@]}" build ;;
    config) "${compose[@]}" config --quiet ;;
esac

