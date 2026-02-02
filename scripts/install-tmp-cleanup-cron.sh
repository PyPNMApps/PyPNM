#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRON_TAG="pypnm-tmp-cache-cleanup"
CRON_SCHEDULE="0 * * * *"

VENV_ACTIVATE="${PROJECT_ROOT}/.env/bin/activate"
if [[ -f "${VENV_ACTIVATE}" ]]; then
  CRON_CMD="cd ${PROJECT_ROOT} && . ${VENV_ACTIVATE} >/dev/null 2>&1 && python3 -m pypnm.tools.tmp_cache_cleanup"
else
  CRON_CMD="cd ${PROJECT_ROOT} && python3 -m pypnm.tools.tmp_cache_cleanup"
fi

EXISTING="$(crontab -l 2>/dev/null || true)"
if echo "${EXISTING}" | grep -q "${CRON_TAG}"; then
  echo "Tmp cache cleanup cron is already installed."
  exit 0
fi

( echo "${EXISTING}"; echo "${CRON_SCHEDULE} ${CRON_CMD} # ${CRON_TAG}" ) | crontab -

echo "Installed tmp cache cleanup cron: ${CRON_SCHEDULE} ${CRON_CMD}"
