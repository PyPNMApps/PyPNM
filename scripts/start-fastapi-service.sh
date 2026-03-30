#!/usr/bin/env bash
set -euo pipefail

PROFILE_ENV_FILE="${PYPNM_SERVE_ENV_FILE:-.data/runtime/pypnm-serve.env}"

if [[ -f "${PROFILE_ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${PROFILE_ENV_FILE}"
fi

args=("$@")
has_workers="0"
has_limit_max_requests="0"
has_subcommand="0"

for arg in "${args[@]}"; do
  case "${arg}" in
    serve|config-menu)
      has_subcommand="1"
      ;;
    --workers|--workers=*)
      has_workers="1"
      ;;
    --limit-max-requests|--limit-max-requests=*)
      has_limit_max_requests="1"
      ;;
  esac
done

if [[ "${has_subcommand}" == "0" ]]; then
  args=("serve" "${args[@]}")
fi

profile_loaded="0"
if [[ -f "${PROFILE_ENV_FILE}" ]]; then
  profile_loaded="1"
fi

if [[ "${has_workers}" == "0" && -n "${PYPNM_SERVE_WORKERS:-}" ]]; then
  args+=("--workers" "${PYPNM_SERVE_WORKERS}")
fi

if [[ "${has_limit_max_requests}" == "0" && -n "${PYPNM_SERVE_LIMIT_MAX_REQUESTS:-}" ]]; then
  args+=("--limit-max-requests" "${PYPNM_SERVE_LIMIT_MAX_REQUESTS}")
fi

active_workers="${PYPNM_SERVE_WORKERS:-}"
active_limit_max_requests="${PYPNM_SERVE_LIMIT_MAX_REQUESTS:-}"
active_source="start_script_default"

if [[ "${has_workers}" == "1" || "${has_limit_max_requests}" == "1" ]]; then
  active_source="explicit_cli"
fi

if [[ "${active_source}" != "explicit_cli" && "${profile_loaded}" == "1" ]]; then
  active_source="seeded_profile"
fi

for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    --workers)
      if (( i + 1 < ${#args[@]} )); then
        active_workers="${args[$((i + 1))]}"
      fi
      ;;
    --workers=*)
      active_workers="${args[$i]#--workers=}"
      ;;
    --limit-max-requests)
      if (( i + 1 < ${#args[@]} )); then
        active_limit_max_requests="${args[$((i + 1))]}"
      fi
      ;;
    --limit-max-requests=*)
      active_limit_max_requests="${args[$i]#--limit-max-requests=}"
      ;;
  esac
done

export PYPNM_SERVE_ENV_FILE="${PROFILE_ENV_FILE}"
export PYPNM_ACTIVE_RUNTIME_SOURCE="${active_source}"
export PYPNM_ACTIVE_WORKERS="${active_workers}"
export PYPNM_ACTIVE_LIMIT_MAX_REQUESTS="${active_limit_max_requests}"

exec pypnm "${args[@]}"
