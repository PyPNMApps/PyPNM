#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="v1.0.0"

usage() {
  cat <<'EOF'
Auto-commit and push the current Git repository.

Usage:
  git-push.sh [--commit-msg "Message"]

If --commit-msg is not supplied, a timestamped "Auto-push" message is used.
By default this script is intended for main/hot-fix branches.
EOF
}

run_check() {
  local label="$1"
  shift
  echo "[check] ${label}..."
  if "$@"; then
    echo "[pass]  ${label}"
  else
    echo "[fail]  ${label}" >&2
    exit 1
  fi
}

run_quality_gates() {
  if ! command -v ruff >/dev/null 2>&1; then
    echo "ERROR: ruff is not installed or not in PATH." >&2
    exit 1
  fi

  run_check "ruff check src" ruff check src
  run_check "pytest -q" python3 -m pytest -q
  run_check "secret scan" ./tools/security/scan-secrets.sh
  run_check "encrypted secret scan" python3 ./tools/security/scan-enc-secrets.py
  run_check "MAC scan" ./tools/security/scan-mac-addresses.py --fail-on-found
  run_check "hardcoded .data path scan" python3 ./tools/security/scan-hardcoded-data-paths.py --fail-on-found
}

commit_msg=""
while [[ $# -gt 0 ]]; do
  case "${1}" in
    --commit-msg)
      shift
      if [[ "${1:-}" == "" ]] || [[ "${1}" =~ ^[[:space:]]*$ ]]; then
        echo "ERROR: --commit-msg requires a non-empty value." >&2
        exit 1
      fi
      commit_msg="${1}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -v|--version)
      echo "${SCRIPT_NAME} ${SCRIPT_VERSION}"
      exit 0
      ;;
    *)
      echo "ERROR: Unknown argument: ${1}" >&2
      usage
      exit 1
      ;;
  esac
done

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: This script must be run inside a Git repository." >&2
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

if [[ -z "${commit_msg}" ]]; then
  commit_msg="Auto-push: $(date +'%Y-%m-%d %H:%M:%S')"
fi
current_branch="$(git rev-parse --abbrev-ref HEAD)"

if [[ "${current_branch}" == "HEAD" ]]; then
  echo "ERROR: Detached HEAD detected. Check out a branch before pushing." >&2
  exit 1
fi

if [[ "${current_branch}" != "main" && "${current_branch}" != "hot-fix" ]]; then
  echo "WARNING: Current branch is '${current_branch}' (not main/hot-fix)." >&2
  echo "WARNING: This branch may not exist on the remote repository." >&2
  read -r -p "Continue anyway? [y/N]: " confirm_first
  if [[ "${confirm_first,,}" != "y" && "${confirm_first,,}" != "yes" ]]; then
    echo "Aborted."
    exit 1
  fi

  read -r -p "Are you really sure you want to push '${current_branch}'? [y/N]: " confirm_second
  if [[ "${confirm_second,,}" != "y" && "${confirm_second,,}" != "yes" ]]; then
    echo "Aborted."
    exit 1
  fi
fi

if git diff --quiet && git diff --cached --quiet; then
  echo "No changes to commit."
  exit 0
fi

echo "Running quality and hygiene checks..."
run_quality_gates

echo "Staging changes..."
git add -A

echo "Creating commit..."
git commit -m "${commit_msg}"

remote_name="$(git config branch."${current_branch}".remote || true)"
push_remote="${remote_name:-origin}"

echo "Pushing to ${push_remote} (${current_branch})..."
if [[ -z "${remote_name}" ]]; then
  git push -u "${push_remote}" "${current_branch}"
else
  if ! git push "${push_remote}" "${current_branch}"; then
    echo "Initial push failed; retrying with upstream setup..."
    git push -u "${push_remote}" "${current_branch}"
  fi
fi

echo "Done."
