#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER_SCRIPT="${SCRIPT_DIR}/install-pypnm-docker-container.sh"
TARGET_TAG="${1:-}"

if [[ ! -x "${INSTALLER_SCRIPT}" ]]; then
  echo "Missing Docker installer helper: ${INSTALLER_SCRIPT}" >&2
  exit 1
fi

if [[ -n "${TARGET_TAG}" ]]; then
  exec "${INSTALLER_SCRIPT}" --update "${TARGET_TAG}"
fi

exec "${INSTALLER_SCRIPT}" --update
