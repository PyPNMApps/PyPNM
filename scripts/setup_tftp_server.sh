#!/usr/bin/env bash
set -euo pipefail

TFTPD_DEFAULTS_FILE="/etc/default/tftpd-hpa"
DEFAULT_TFTP_USER="tftp"
DEFAULT_TFTP_DIR="/srv/tftp"
DEFAULT_TFTP_ADDRESS=":69"
DEFAULT_TFTP_OPTIONS="--secure --create"

prompt_yes_no() {
  local prompt="${1}"
  local default_answer="${2:-N}"
  local answer=""

  read -r -p "${prompt} " answer || true
  if [[ -z "${answer}" ]]; then
    answer="${default_answer}"
  fi

  case "${answer}" in
    y|Y|yes|YES)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
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
  echo "Privilege escalation is required for: $*"
  return 1
}

is_tftpd_hpa_installed() {
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^tftpd-hpa\.service'; then
      return 0
    fi
  fi

  if command -v dpkg-query >/dev/null 2>&1; then
    if dpkg-query -W -f='${Status}\n' tftpd-hpa 2>/dev/null | grep -q '^install ok installed$'; then
      return 0
    fi
  fi

  return 1
}

read_tftp_setting() {
  local key="${1}"
  local default_value="${2}"

  if [[ ! -f "${TFTPD_DEFAULTS_FILE}" ]]; then
    printf '%s\n' "${default_value}"
    return
  fi

  local line=""
  line="$(grep -E "^${key}=" "${TFTPD_DEFAULTS_FILE}" 2>/dev/null | tail -n 1 || true)"
  if [[ -z "${line}" ]]; then
    printf '%s\n' "${default_value}"
    return
  fi

  line="${line#*=}"
  line="${line%\"}"
  line="${line#\"}"
  printf '%s\n' "${line}"
}

normalize_tftp_options() {
  local raw_options="${1}"
  local normalized=""
  local token=""

  for token in ${raw_options}; do
    if [[ "${token}" == "--create" ]]; then
      continue
    fi
    normalized="${normalized} ${token}"
  done

  normalized="${normalized} --create"
  normalized="$(printf '%s\n' "${normalized}" | xargs)"

  if [[ -z "${normalized}" ]]; then
    normalized="${DEFAULT_TFTP_OPTIONS}"
  fi

  printf '%s\n' "${normalized}"
}

write_tftpd_defaults() {
  local tftp_user="${1}"
  local tftp_dir="${2}"
  local tftp_address="${3}"
  local tftp_options="${4}"
  local tmp_file=""

  tmp_file="$(mktemp)"
  cat > "${tmp_file}" <<EOF
# /etc/default/tftpd-hpa

TFTP_USERNAME="${tftp_user}"
TFTP_DIRECTORY="${tftp_dir}"
TFTP_ADDRESS="${tftp_address}"
TFTP_OPTIONS="${tftp_options}"
EOF

  run_with_privilege_if_needed install -m 0644 "${tmp_file}" "${TFTPD_DEFAULTS_FILE}"
  rm -f "${tmp_file}"
}

ensure_tftp_directory() {
  local tftp_user="${1}"
  local tftp_dir="${2}"
  local tftp_group="${tftp_user}"

  if id -u "${tftp_user}" >/dev/null 2>&1; then
    tftp_group="$(id -gn "${tftp_user}")"
  else
    echo "User '${tftp_user}' does not exist; cannot verify writable TFTP directory."
    return 1
  fi

  run_with_privilege_if_needed mkdir -p "${tftp_dir}"
  run_with_privilege_if_needed chown "${tftp_user}:${tftp_group}" "${tftp_dir}"
  run_with_privilege_if_needed chmod 0775 "${tftp_dir}"

  if [[ "$(id -u)" -eq 0 ]]; then
    runuser -u "${tftp_user}" -- test -w "${tftp_dir}"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u "${tftp_user}" test -w "${tftp_dir}"
  else
    test -w "${tftp_dir}"
  fi
}

restart_tftpd_hpa() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found; skipping tftpd-hpa restart."
    return
  fi

  run_with_privilege_if_needed systemctl enable tftpd-hpa
  run_with_privilege_if_needed systemctl restart tftpd-hpa
}

main() {
  if [[ ! -t 0 ]]; then
    echo "TFTP setup requires an interactive terminal."
    exit 0
  fi

  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Local tftpd-hpa setup is only supported on Linux hosts."
    exit 0
  fi

  if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "CI environment detected; skipping interactive tftpd-hpa setup."
    exit 0
  fi

  if ! is_tftpd_hpa_installed; then
    echo "tftpd-hpa is not installed on this host."
    echo "Install it with: sudo apt-get install -y tftpd-hpa"
    echo "Then rerun: ./scripts/setup_tftp_server.sh"
    exit 0
  fi

  if [[ ! -f "${TFTPD_DEFAULTS_FILE}" ]]; then
    echo "Detected tftpd-hpa, but ${TFTPD_DEFAULTS_FILE} is not present."
    echo "This helper currently manages Debian/Ubuntu-style tftpd-hpa defaults."
    echo "On this distro, adjust your tftpd-hpa service configuration manually and rerun PyPNM setup."
    exit 0
  fi

  local tftp_user=""
  local tftp_dir=""
  local tftp_address=""
  local tftp_options=""

  tftp_user="$(read_tftp_setting "TFTP_USERNAME" "${DEFAULT_TFTP_USER}")"
  tftp_dir="$(read_tftp_setting "TFTP_DIRECTORY" "${DEFAULT_TFTP_DIR}")"
  tftp_address="$(read_tftp_setting "TFTP_ADDRESS" "${DEFAULT_TFTP_ADDRESS}")"
  tftp_options="$(read_tftp_setting "TFTP_OPTIONS" "${DEFAULT_TFTP_OPTIONS}")"
  tftp_options="$(normalize_tftp_options "${tftp_options}")"

  echo "Current tftpd-hpa configuration:"
  echo "  defaults file : ${TFTPD_DEFAULTS_FILE}"
  echo "  TFTP_USERNAME : ${tftp_user}"
  echo "  TFTP_DIRECTORY: ${tftp_dir}"
  echo "  TFTP_ADDRESS  : ${tftp_address}"
  echo "  TFTP_OPTIONS  : ${tftp_options}"

  if ! prompt_yes_no "Apply upload-capable tftpd-hpa settings now? [y/N]" "N"; then
    echo "Skipping local TFTP server setup."
    exit 0
  fi

  write_tftpd_defaults "${tftp_user}" "${tftp_dir}" "${tftp_address}" "${tftp_options}"

  if ensure_tftp_directory "${tftp_user}" "${tftp_dir}"; then
    echo "Verified writable TFTP directory: ${tftp_dir}"
  else
    echo "Unable to verify TFTP directory writability for ${tftp_user} at ${tftp_dir}."
    exit 1
  fi

  restart_tftpd_hpa

  echo "Local tftpd-hpa setup complete."
  echo "  TFTP_DIRECTORY: ${tftp_dir}"
  echo "  TFTP_OPTIONS  : ${tftp_options}"
}

main "$@"
