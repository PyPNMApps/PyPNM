#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  kill-pypnm.sh --list
  kill-pypnm.sh --kill-pid <PID>
  kill-pypnm.sh --kill-all

Options:
  --list           List active processes with "pypnm" in the command line.
  --kill-pid PID   Kill a single active pypnm process by PID (SIGTERM).
  --kill-all       Kill all active pypnm processes (SIGTERM).
  -h, --help       Show this help.
EOF
}

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required for kill-pypnm.sh" >&2
  exit 1
fi

SUDO=(sudo)

is_integer() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

get_pypnm_processes() {
  # Output format: PID<TAB>COMMAND
  "${SUDO[@]}" ps -eo pid=,args= | awk -v self_pid="$$" '
    BEGIN { IGNORECASE = 1 }
    {
      pid = $1
      $1 = ""
      sub(/^[[:space:]]+/, "", $0)
      cmd = $0

      if (pid == self_pid) next
      if (cmd ~ /kill-pypnm\.sh/) next
      if (cmd ~ /^awk[[:space:]]/) next
      if (cmd ~ /^ps[[:space:]]/) next
      if (cmd ~ /pypnm/) print pid "\t" cmd
    }
  '
}

list_processes() {
  local rows
  rows="$(get_pypnm_processes || true)"
  if [[ -z "${rows}" ]]; then
    echo "No active pypnm processes found."
    return 0
  fi

  printf "%-8s %s\n" "PID" "COMMAND"
  echo "${rows}" | while IFS=$'\t' read -r pid cmd; do
    [[ -z "${pid:-}" ]] && continue
    printf "%-8s %s\n" "${pid}" "${cmd}"
  done
}

pid_is_pypnm() {
  local target_pid="$1"
  get_pypnm_processes | awk -F '\t' -v pid="${target_pid}" '$1 == pid { found = 1 } END { exit(found ? 0 : 1) }'
}

kill_one() {
  local target_pid="$1"
  if ! is_integer "${target_pid}"; then
    echo "Invalid PID: ${target_pid}" >&2
    exit 2
  fi

  if ! "${SUDO[@]}" kill -0 "${target_pid}" 2>/dev/null; then
    echo "PID ${target_pid} is not running."
    exit 1
  fi

  if ! pid_is_pypnm "${target_pid}"; then
    echo "PID ${target_pid} is not an active pypnm process (refusing to kill)." >&2
    exit 1
  fi

  "${SUDO[@]}" kill "${target_pid}"
  echo "Sent SIGTERM to pypnm process PID ${target_pid}."
}

kill_all() {
  local rows
  rows="$(get_pypnm_processes || true)"
  if [[ -z "${rows}" ]]; then
    echo "No active pypnm processes found."
    return 0
  fi

  local count=0
  while IFS=$'\t' read -r pid _cmd; do
    [[ -z "${pid:-}" ]] && continue
    "${SUDO[@]}" kill "${pid}"
    count=$((count + 1))
    echo "Sent SIGTERM to PID ${pid}."
  done <<< "${rows}"

  echo "Sent SIGTERM to ${count} pypnm process(es)."
}

main() {
  if [[ $# -eq 0 ]]; then
    usage
    exit 2
  fi

  case "${1:-}" in
    --list)
      [[ $# -eq 1 ]] || { usage; exit 2; }
      list_processes
      ;;
    --kill-pid)
      [[ $# -eq 2 ]] || { usage; exit 2; }
      kill_one "$2"
      ;;
    --kill-all)
      [[ $# -eq 1 ]] || { usage; exit 2; }
      kill_all
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage
      exit 2
      ;;
  esac
}

main "$@"
