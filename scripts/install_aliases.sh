#!/usr/bin/env bash
set -euo pipefail

# Silent alias installer for PyPNM.
# - No echo / user-facing output.
# - Appends aliases to detected shell rc file.
# - Safe to re-run; skips aliases already present.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

detect_shell_rc_file() {
  if [[ -n "${ZSH_VERSION:-}" && -f "${HOME}/.zshrc" ]]; then
    echo "${HOME}/.zshrc"
    return
  fi

  if [[ -n "${BASH_VERSION:-}" && -f "${HOME}/.bashrc" ]]; then
    echo "${HOME}/.bashrc"
    return
  fi

  if [[ -f "${HOME}/.bashrc" ]]; then
    echo "${HOME}/.bashrc"
    return
  fi

  if [[ -f "${HOME}/.zshrc" ]]; then
    echo "${HOME}/.zshrc"
    return
  fi

  echo "${HOME}/.profile"
}

RC_FILE="${PYPNM_SHELL_RC:-$(detect_shell_rc_file)}"

mkdir -p "$(dirname "${RC_FILE}")"
if [[ ! -f "${RC_FILE}" ]]; then
  : > "${RC_FILE}"
fi

if ! grep -Fq "# PyPNM aliases" "${RC_FILE}" 2>/dev/null; then
  {
    printf '\n'
    printf '# PyPNM aliases\n'
  } >> "${RC_FILE}"
fi

append_alias() {
  local line="$1"
  if grep -Fq "${line}" "${RC_FILE}" 2>/dev/null; then
    return
  fi
  printf '%s\n' "${line}" >> "${RC_FILE}"
}

# ---------------------------------------------------------------------------
# Alias definitions
#   - Add new aliases here as needed.
#   - First alias: config-menu → tools/system_config/menu.py
# ---------------------------------------------------------------------------

append_alias "alias config-menu='cd \"${PROJECT_ROOT}\" && python tools/system_config/menu.py'"
append_alias "alias pypnm-release='cd \"${PROJECT_ROOT}\" && python tools/release/release.py'"
append_alias "alias pypnm-release-hot-fix='cd \"${PROJECT_ROOT}\" && python tools/release/release.py --branch hot-fix --next build'"
append_alias "alias pypnm-clean='cd \"${PROJECT_ROOT}\" && ./tools/maintenance/clean.sh'"
append_alias "alias pypnm-support-bundle='cd \"${PROJECT_ROOT}\" && python tools/build/support_bundle_builder.py'"
append_alias "alias pypnm-mac-update='cd \"${PROJECT_ROOT}\" && python tools/pnm/pnm-mac-updater.py'"
append_alias "alias pypnm-version-check='cd \"${PROJECT_ROOT}\" && python tools/release/check_version.py'"

# Example placeholder for future aliases (keep but commented-out for now):
# append_alias "alias pypnm-env='cd \"${PROJECT_ROOT}\" && source .env/bin/activate'"
