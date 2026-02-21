#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="v1.0.0"

usage() {
  cat <<'EOF'
Stage and commit the current Git repository.

Usage:
  git-save.sh [--commit-msg "Message"] [--push]

Options:
  --commit-msg  Commit message prefix (default: "Update").
  --push        Push the current branch after commit.
  -h, --help    Show this help.
  -v, --version Show script version.
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
}

commit_msg="Update"
do_push="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --commit-msg)
      shift
      if [[ "${1:-}" == "" ]]; then
        echo "ERROR: --commit-msg requires a value." >&2
        exit 1
      fi
      commit_msg="$1"
      shift
      ;;
    --push)
      do_push="true"
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
      echo "ERROR: Unknown argument: $1" >&2
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

current_branch="$(git rev-parse --abbrev-ref HEAD)"
pending_changes="$(git status --short)"

echo "========================================"
echo "Git Save"
echo "Branch: ${current_branch}"
echo "Changes:"
if [[ -z "${pending_changes}" ]]; then
  echo "  (none)"
else
  printf '%s\n' "${pending_changes}"
fi
echo "========================================"

timestamp="$(date +'%Y-%m-%d %H:%M:%S')"
final_msg="${commit_msg} - ${timestamp}"

if git diff --quiet && git diff --cached --quiet; then
  echo "No changes to commit."
  exit 0
fi

echo "Running quality and hygiene checks..."
run_quality_gates

echo "Staging changes..."
git add -A

echo "Creating commit..."
git commit -m "${final_msg}"

if [[ "${do_push}" == "true" ]]; then
  remote_name="$(git config branch."${current_branch}".remote || true)"
  echo "Pushing to origin (${current_branch})..."
  if [[ -z "${remote_name}" ]]; then
    git push -u origin "${current_branch}"
  else
    git push "${remote_name}" "${current_branch}"
  fi
else
  echo "Push skipped. Use --push to push."
fi

echo "Done."
