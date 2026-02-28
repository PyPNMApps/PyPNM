#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_DIR="${SCRIPT_DIR}/compose"
CONFIG_DIR="${SCRIPT_DIR}/config"
PYPNM_SHARED_GROUP="${PYPNM_SHARED_GROUP:-pypnm}"

create_file_if_missing() {
  local src="$1"
  local dest="$2"
  local label="$3"

  if [ -f "$dest" ]; then
    echo "✔ ${label} already exists: ${dest}"
  else
    cp "$src" "$dest"
    echo "➕ Created ${label}: ${dest}"
  fi
}

create_file_if_missing "${COMPOSE_DIR}/.env.example" "${COMPOSE_DIR}/.env" "compose/.env"
create_file_if_missing "${CONFIG_DIR}/system.json.template" "${CONFIG_DIR}/system.json" "config/system.json"

if [[ "$(uname -s)" == "Linux" ]]; then
  mkdir -p /tmp/pypnm >/dev/null 2>&1 || true
  chgrp "${PYPNM_SHARED_GROUP}" /tmp/pypnm >/dev/null 2>&1 || true
  chmod 2775 /tmp/pypnm >/dev/null 2>&1 || true
fi

cat <<'MSG'
Next steps:
  1. Edit deploy/docker/config/system.json with your environment details.
  2. (Optional) Edit deploy/docker/compose/.env to pin a specific GHCR tag or host port.
  3. From deploy/docker/compose/, run: docker compose pull && docker compose up -d

To tear down later, run: docker compose down --volumes
MSG
