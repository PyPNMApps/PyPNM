#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# PyPNM Docker Installer (No Manual Git Operations Required)
# - Assumes Docker Engine + docker compose plugin are already installed
# - Copies the deploy bundle (from the repo or a release asset) into $PYPNM_DEPLOY_DIR
# - Runs deploy/docker/install.sh to seed config + .env, then starts the compose stack
# - If no version is specified, automatically installs the latest GitHub release

set -euo pipefail
IFS=$'\n\t'

PYPNM_TAG="${PYPNM_TAG:-}"
PYPNM_PORT="${PYPNM_PORT:-8000}"
PYPNM_DEPLOY_DIR="${PYPNM_DEPLOY_DIR:-/opt/pypnm}"
PYPNM_USER="${PYPNM_USER:-${USER}}"
PYPNM_SHARED_GROUP="${PYPNM_SHARED_GROUP:-pypnm}"
PYPNM_IMAGE="ghcr.io/PyPNMApps/pypnm:${PYPNM_TAG}"
PYPNM_FALLBACK_TAG="${PYPNM_FALLBACK_TAG:-v0.9.34.0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DEPLOY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)/deploy/docker"
TMP_BUNDLE_DIR=""
BANNER_PATH="${SCRIPT_DIR}/../tools/banner.txt"

if [[ -f "${BANNER_PATH}" ]]; then
  cat "${BANNER_PATH}"
  echo
fi

cleanup() {
  if [[ -n "${TMP_BUNDLE_DIR}" && -d "${TMP_BUNDLE_DIR}" ]]; then
    rm -rf "${TMP_BUNDLE_DIR}"
  fi
}
trap cleanup EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Error: missing required command: $1" >&2; exit 1; }
}

run_with_privilege_if_needed() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
    return $?
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
    return $?
  fi
  return 1
}

usage() {
  cat <<'EOF'
Usage: install-pypnm-docker-container.sh [options]

Options:
  --tag <tag>           Install a specific PyPNM release (e.g., v0.9.26.0).
                        If omitted, the latest GitHub release is used.
  --port <port>         Host port that maps to container port 8000 (default: 8000).
  --deploy-dir <path>   Target directory for the deploy bundle (default: /opt/pypnm).
  --user <name>         User that should own the deploy directory (default: current user).
  --help                Show this help and exit.

Examples:
  ./scripts/install-pypnm-docker-container.sh
  ./scripts/install-pypnm-docker-container.sh --tag v0.9.26.0 --port 8080
EOF
}

fetch_latest_tag() {
  require_cmd curl
  require_cmd python3
  local api="https://api.github.com/repos/PyPNMApps/PyPNM/releases/latest"
  local response
  if ! response="$(curl -fsSL "${api}")"; then
    echo "Failed to query ${api}" >&2
    return 1
  fi
  printf '%s' "${response}" | python3 - <<'PY'
import json, sys
data = json.load(sys.stdin)
print(data["tag_name"])
PY
}

fetch_latest_tag_via_redirect() {
  require_cmd curl
  local url="https://github.com/PyPNMApps/PyPNM/releases/latest"
  local header
  if ! header="$(curl -fsI "${url}" 2>/dev/null)"; then
    return 1
  fi
  # Look for "location: https://github.com/.../tag/vX.Y.Z.W"
  while IFS= read -r line; do
    if [[ "${line,,}" =~ location:\ https://github\.com/PyPNMApps/PyPNM/releases/tag/(v[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      printf '%s' "${BASH_REMATCH[1]}"
      return 0
    fi
  done <<< "${header}"
  return 1
}

fetch_latest_tag_from_tags_api() {
  require_cmd curl
  require_cmd python3
  local api="https://api.github.com/repos/PyPNMApps/PyPNM/tags?per_page=1"
  local response
# Fallback to git ls-remote if API fails
  if ! response="$(curl -fsSL "${api}")"; then
    echo "Failed to query ${api}, falling back to git ls-remote" >&2
    if ! command -v git >/dev/null 2>&1; then
      return 1
    fi
    git ls-remote --tags https://github.com/PyPNMApps/PyPNM.git \
      | awk -F/ 'END{print $NF}'
    return $?
  fi
  printf '%s' "${response}" | python3 - <<'PY'
import json, sys
data = json.load(sys.stdin)
if not data:
    raise SystemExit(1)
print(data[0]["name"])
PY
}

latest_local_tag() {
  if ! command -v git >/dev/null 2>&1; then
    return 1
  fi
  local repo_root
  repo_root="$(cd "${SCRIPT_DIR}/.." && pwd)"
  if ! git -C "${repo_root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    return 1
  fi
  local tag
  tag="$(git -C "${repo_root}" tag --list 'v*' | sort -V | tail -1)"
  if [[ -z "${tag}" ]]; then
    return 1
  fi
  printf '%s' "${tag}"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag)
        shift
        PYPNM_TAG="${1:-}"
        ;;
      --port)
        shift
        PYPNM_PORT="${1:-8000}"
        ;;
      --deploy-dir)
        shift
        PYPNM_DEPLOY_DIR="${1:-/opt/pypnm}"
        ;;
      --user)
        shift
        PYPNM_USER="${1:-${PYPNM_USER}}"
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      -*)
        echo "Unknown option: $1" >&2
        usage
        exit 1
        ;;
      *)
        echo "Unexpected argument: $1" >&2
        usage
        exit 1
        ;;
    esac
    shift
  done
}

resolve_tag() {
  if [[ -z "${PYPNM_TAG}" ]]; then
    echo "No tag specified; discovering latest release..."
    if ! PYPNM_TAG="$(fetch_latest_tag)"; then
      echo "GitHub API lookup failed; trying redirect-based lookup..." >&2
      if ! PYPNM_TAG="$(fetch_latest_tag_via_redirect)"; then
        echo "Release redirect lookup failed; trying tags API..." >&2
        if ! PYPNM_TAG="$(fetch_latest_tag_from_tags_api)"; then
          echo "Unable to query GitHub releases. Falling back to local git tags..." >&2
          if ! PYPNM_TAG="$(latest_local_tag)"; then
            echo "Failed to determine PyPNM tag from local repository." >&2
            PYPNM_TAG=""
          else
            echo "Using local tag ${PYPNM_TAG}"
          fi
        else
          echo "Detected latest tag ${PYPNM_TAG}"
        fi
      else
        echo "Detected latest release tag ${PYPNM_TAG}"
      fi
    fi
  fi
  if [[ -z "${PYPNM_TAG}" ]]; then
    if [[ -n "${PYPNM_FALLBACK_TAG}" ]]; then
      echo "Falling back to default tag ${PYPNM_FALLBACK_TAG}" >&2
      PYPNM_TAG="${PYPNM_FALLBACK_TAG}"
    else
      echo "Unable to determine PyPNM tag. Provide --tag <version>." >&2
      exit 1
    fi
  fi
  PYPNM_IMAGE="ghcr.io/PyPNMApps/pypnm:${PYPNM_TAG}"
}

ensure_docker_ok() {
  require_cmd docker
  if docker info >/dev/null 2>&1; then
    return 0
  fi

  echo "Docker is not accessible as the current user (likely /run/docker.sock permission)." >&2
  echo "Attempting to add '${PYPNM_USER}' to docker group and refresh session..." >&2

  sudo groupadd docker >/dev/null 2>&1 || true
  sudo usermod -aG docker "${PYPNM_USER}"

  echo
  echo "Docker group updated. Start a new login shell, then re-run this script:"
  echo "  exec su -l ${PYPNM_USER}"
  echo "  ${0}"
  echo
  exit 1
}

ensure_compose_ok() {
  if docker compose version >/dev/null 2>&1; then
    return 0
  fi
  echo "Error: docker compose plugin not found. Install docker compose v2 and retry." >&2
  exit 1
}

ensure_pypnm_shared_group() {
  local users=("${PYPNM_USER}" "${SUDO_USER:-}" "${USER}")
  local target_user=""

  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Skipping '${PYPNM_SHARED_GROUP}' group setup on non-Linux host."
    return
  fi

  if getent group "${PYPNM_SHARED_GROUP}" >/dev/null 2>&1; then
    echo "Group '${PYPNM_SHARED_GROUP}' already exists."
  else
    run_with_privilege_if_needed groupadd "${PYPNM_SHARED_GROUP}" || {
      echo "Unable to create group '${PYPNM_SHARED_GROUP}'." >&2
      return
    }
    echo "Created group '${PYPNM_SHARED_GROUP}'."
  fi

  for target_user in "${users[@]}"; do
    [[ -z "${target_user}" ]] && continue
    if ! id "${target_user}" >/dev/null 2>&1; then
      continue
    fi
    if id -nG "${target_user}" 2>/dev/null | tr ' ' '\n' | grep -qx "${PYPNM_SHARED_GROUP}"; then
      continue
    fi
    if run_with_privilege_if_needed usermod -aG "${PYPNM_SHARED_GROUP}" "${target_user}"; then
      echo "Added user '${target_user}' to group '${PYPNM_SHARED_GROUP}'."
    else
      echo "Unable to add user '${target_user}' to group '${PYPNM_SHARED_GROUP}'." >&2
    fi
  done
}

ensure_tmp_pypnm_shared_permissions() {
  local tmp_root="/tmp/pypnm"
  mkdir -p "${tmp_root}" || {
    echo "Unable to create ${tmp_root}" >&2
    return
  }

  chgrp "${PYPNM_SHARED_GROUP}" "${tmp_root}" >/dev/null 2>&1 || run_with_privilege_if_needed chgrp "${PYPNM_SHARED_GROUP}" "${tmp_root}" >/dev/null 2>&1 || {
    echo "Unable to set group '${PYPNM_SHARED_GROUP}' on ${tmp_root}" >&2
  }

  chmod 2775 "${tmp_root}" >/dev/null 2>&1 || run_with_privilege_if_needed chmod 2775 "${tmp_root}" >/dev/null 2>&1 || {
    echo "Unable to set permissions 2775 on ${tmp_root}" >&2
  }
}

set_env_var() {
  local file="$1"
  local key="$2"
  local value="$3"

  if grep -q "^${key}=" "$file"; then
    sudo sed -i "s/^${key}=.*/${key}=${value}/" "$file"
  else
    echo "${key}=${value}" | sudo tee -a "$file" >/dev/null
  fi
}

ensure_secret_key() {
  local env_file="$1"

  if grep -q "^PYPNM_SECRET_KEY=" "$env_file"; then
    local existing
    existing="$(grep "^PYPNM_SECRET_KEY=" "$env_file" | tail -1 | cut -d= -f2-)"
    if [[ -n "${existing}" ]]; then
      echo "PYPNM_SECRET_KEY already set in ${env_file}"
      return
    fi
  fi

  local key
  key="$(python3 - <<'PY'
import base64, secrets
print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
PY
)"
  set_env_var "${env_file}" "PYPNM_SECRET_KEY" "${key}"
  echo "Seeded PYPNM_SECRET_KEY in ${env_file}"
}

download_release_asset() {
  local dest_dir="$1"
  local url="https://github.com/PyPNMApps/PyPNM/releases/download/${PYPNM_TAG}/pypnm-deploy-${PYPNM_TAG}.tar.gz"
  local tarball="${dest_dir}/deploy.tar.gz"

  echo "Attempting to download release asset ${url}" >&2
  if ! curl -fsSL "${url}" -o "${tarball}"; then
    echo "Release asset not available at ${url}" >&2
    return 1
  fi

  tar -xzf "${tarball}" -C "${dest_dir}"
  rm -f "${tarball}"
  echo "${dest_dir}"
  return 0
}

download_repo_archive() {
  local dest_dir="$1"
  local ref="$2"
  local url="https://github.com/PyPNMApps/PyPNM/archive/refs/${ref}.tar.gz"
  local tarball="${dest_dir}/repo.tar.gz"

  echo "Attempting to download repo archive ${url}" >&2
  if ! curl -fsSL "${url}" -o "${tarball}"; then
    echo "Failed to download ${url}" >&2
    return 1
  fi

  tar -xzf "${tarball}" -C "${dest_dir}"
  rm -f "${tarball}"

  local deploy_dir
  deploy_dir="$(find "${dest_dir}" -maxdepth 3 -type d -path "*/deploy/docker" | head -1 || true)"
  if [[ -z "${deploy_dir}" ]]; then
    echo "Repository archive did not contain a deploy/docker folder" >&2
    return 1
  fi
  echo "${deploy_dir}"
  return 0
}

download_bundle() {
  require_cmd curl
  require_cmd tar
  TMP_BUNDLE_DIR="$(mktemp -d)"

  local bundle_path
  if bundle_path="$(download_release_asset "${TMP_BUNDLE_DIR}")"; then
    echo "${bundle_path}"
    return 0
  fi

  echo "Falling back to source archives..." >&2
  if bundle_path="$(download_repo_archive "${TMP_BUNDLE_DIR}" "tags/${PYPNM_TAG}")"; then
    echo "${bundle_path}"
    return 0
  fi

  echo "Tag archive not found; using main branch snapshot." >&2
  if bundle_path="$(download_repo_archive "${TMP_BUNDLE_DIR}" "heads/main")"; then
    echo "${bundle_path}"
    return 0
  fi

  echo "Unable to fetch deploy bundle from any source." >&2
  return 1
}

sync_deploy_bundle() {
  local source_dir
  if [[ -d "${REPO_DEPLOY_DIR}" ]]; then
    source_dir="${REPO_DEPLOY_DIR}"
  else
    if ! source_dir="$(download_bundle)"; then
      echo "Failed to obtain deploy bundle." >&2
      exit 1
    fi
  fi

  echo "Copying deploy bundle into ${PYPNM_DEPLOY_DIR}"
  sudo rm -rf "${PYPNM_DEPLOY_DIR}"
  sudo mkdir -p "${PYPNM_DEPLOY_DIR}"
  (cd "${source_dir}" && sudo tar -cf - .) | (cd "${PYPNM_DEPLOY_DIR}" && sudo tar -xf -)
  sudo chown -R "${PYPNM_USER}:${PYPNM_SHARED_GROUP}" "${PYPNM_DEPLOY_DIR}"
  sudo chmod 2775 "${PYPNM_DEPLOY_DIR}" || true
}

initialize_bundle() {
  if [[ ! -x "${PYPNM_DEPLOY_DIR}/install.sh" ]]; then
    echo "Missing install.sh in ${PYPNM_DEPLOY_DIR}" >&2
    exit 1
  fi
  echo "Initializing config and .env via install.sh"
  sudo -u "${PYPNM_USER}" bash -c "cd '${PYPNM_DEPLOY_DIR}' && ./install.sh"

  local env_file="${PYPNM_DEPLOY_DIR}/compose/.env"
  if [[ ! -f "${env_file}" ]]; then
    echo "Expected ${env_file} to exist after install.sh" >&2
    exit 1
  fi
  set_env_var "${env_file}" "PYPNM_TAG" "${PYPNM_TAG}"
  set_env_var "${env_file}" "PYPNM_PORT" "${PYPNM_PORT}"
  ensure_secret_key "${env_file}"
}

pull_and_start() {
  echo "Pulling ${PYPNM_IMAGE}"
  docker pull "${PYPNM_IMAGE}"

  echo "Starting PyPNM with docker compose"
  (
    cd "${PYPNM_DEPLOY_DIR}/compose"
    docker compose pull
    docker compose up -d
  )
}

verify() {
  echo
  echo "Container status:"
  docker ps --filter "name=pypnm" || true
  echo
  echo "Logs:"
  echo "  cd ${PYPNM_DEPLOY_DIR}/compose && docker compose logs -f --tail=200 pypnm-api"
  echo
  echo "Verify:"
  echo
  echo "  curl -I http://127.0.0.1:${PYPNM_PORT}/docs"
  echo
  echo "Run config-menu (if you need to tweak settings):"
  echo
  echo "  cd ${PYPNM_DEPLOY_DIR}/compose && sudo docker compose run --rm config-menu"
  echo
  echo "  cd ${PYPNM_DEPLOY_DIR}/compose && sudo docker compose restart pypnm-api" 
  echo
  echo "Installation complete!"
  echo
}

main() {
  parse_args "$@"
  resolve_tag
  require_cmd python3
  ensure_docker_ok
  ensure_compose_ok
  ensure_pypnm_shared_group
  ensure_tmp_pypnm_shared_permissions
  sync_deploy_bundle
  initialize_bundle
  pull_and_start
  verify
}

main "$@"
