#!/usr/bin/env bash
# FILE: tools/maintenance/docker-cleanup.sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Maurice Garcia

set -euo pipefail

print_usage() {
    cat <<'EOU'
docker-cleanup.sh

Usage:
  docker-cleanup.sh [--safe] [--images] [--builder] [--volumes] [--aggressive] [--force-running] [--dry-run] [--yes]

Modes:
  --safe         Prune stopped containers + unused networks + dangling images (default)
  --images       Prune all unused images (equivalent to: docker image prune -a)
  --builder      Prune build cache (equivalent to: docker builder prune -a)
  --volumes      Prune unused volumes (equivalent to: docker volume prune)
  --aggressive   Prune: containers + networks + images (-a) + builder (-a) + volumes
  --force-running Stop and remove running containers before destructive cleanup
  --dry-run      Print what would run; make no changes
  --yes          Do not prompt

Notes:
  - Destructive modes refuse to touch running containers unless --force-running is set.
  - If docker requires root, the script will try sudo automatically.

Examples:
  ./scripts/docker-cleanup.sh
  ./scripts/docker-cleanup.sh --images --builder --yes
  ./scripts/docker-cleanup.sh --aggressive --force-running --yes
EOU
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

docker_cmd() {
    if need_cmd docker; then
        if docker info >/dev/null 2>&1; then
            echo "docker"
            return 0
        fi
        if need_cmd sudo; then
            if sudo -n docker info >/dev/null 2>&1; then
                echo "sudo -n docker"
                return 0
            fi
            echo "sudo docker"
            return 0
        fi
    fi
    return 1
}

run() {
    local cmd="$1"

    if [ "${DRY_RUN}" -eq 1 ]; then
        printf '%s\n' "[dry-run] ${cmd}"
        return 0
    fi

    eval "${cmd}"
}

confirm() {
    local prompt="$1"

    if [ "${ASSUME_YES}" -eq 1 ]; then
        return 0
    fi

    printf '%s' "${prompt} [y/N]: "
    read -r ans
    case "${ans}" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

running_containers_count() {
    local dc="$1"
    ${dc} ps -q 2>/dev/null | wc -l | tr -d ' '
}

print_snapshot() {
    local dc="$1"

    echo "Filesystem:"
    df -hT / || true
    echo
    echo "Docker usage:"
    ${dc} system df || true
    echo
}

DRY_RUN=0
ASSUME_YES=0
FORCE_RUNNING=0

MODE_SAFE=1
DO_IMAGES=0
DO_BUILDER=0
DO_VOLUMES=0
MODE_AGGRESSIVE=0

if [ "${#}" -gt 0 ]; then
    MODE_SAFE=0
fi

while [ "${#}" -gt 0 ]; do
    case "$1" in
        -h|--help)
            print_usage
            exit 0
            ;;
        --safe)
            MODE_SAFE=1
            MODE_AGGRESSIVE=0
            ;;
        --images)
            DO_IMAGES=1
            ;;
        --builder)
            DO_BUILDER=1
            ;;
        --volumes)
            DO_VOLUMES=1
            ;;
        --aggressive)
            MODE_AGGRESSIVE=1
            MODE_SAFE=0
            DO_IMAGES=1
            DO_BUILDER=1
            DO_VOLUMES=1
            ;;
        --force-running)
            FORCE_RUNNING=1
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        --yes)
            ASSUME_YES=1
            ;;
        *)
            echo "Unknown option: $1"
            echo
            print_usage
            exit 2
            ;;
    esac
    shift
done

if ! need_cmd docker; then
    echo "docker not installed; nothing to do."
    exit 0
fi

DC="$(docker_cmd || true)"
if [ -z "${DC}" ]; then
    echo "docker is installed but not accessible (permission/daemon)."
    echo "Try: sudo usermod -aG docker ${USER} ; then log out/in, or run with sudo."
    exit 1
fi

echo "Before:"
print_snapshot "${DC}"

RUNNING="$(running_containers_count "${DC}")"
if [ "${RUNNING}" -ne 0 ]; then
    if [ "${MODE_AGGRESSIVE}" -eq 1 ] || [ "${DO_IMAGES}" -eq 1 ] || [ "${DO_VOLUMES}" -eq 1 ]; then
        if [ "${FORCE_RUNNING}" -eq 1 ]; then
            echo "Stopping and removing ${RUNNING} running container(s)..."
            run "${DC} stop \$(${DC} ps -q)"
            run "${DC} rm -f \$(${DC} ps -aq)"
        else
        echo "Refusing: ${RUNNING} running container(s) detected."
        echo "Stop containers first or use --force-running."
        exit 1
        fi
    fi
fi

if [ "${MODE_SAFE}" -eq 1 ]; then
    if confirm "Run SAFE cleanup (stopped containers, networks, dangling images)?" ; then
        run "${DC} container prune -f"
        run "${DC} network prune -f"
        run "${DC} image prune -f"
    else
        echo "Canceled."
        exit 0
    fi
fi

if [ "${DO_IMAGES}" -eq 1 ]; then
    if confirm "Prune ALL unused images (docker image prune -a)?" ; then
        run "${DC} image prune -a -f"
    fi
fi

if [ "${DO_BUILDER}" -eq 1 ]; then
    if confirm "Prune build cache (docker builder prune -a)?" ; then
        run "${DC} builder prune -a -f"
    fi
fi

if [ "${DO_VOLUMES}" -eq 1 ]; then
    if confirm "Prune unused volumes (docker volume prune)?" ; then
        run "${DC} volume prune -f"
    fi
fi

if [ "${MODE_AGGRESSIVE}" -eq 1 ]; then
    run "${DC} container prune -f"
    run "${DC} network prune -f"
fi

echo
echo "After:"
print_snapshot "${DC}"
