#!/usr/bin/env bash
# Local kind smoke test: build image, load into kind, apply manifests, check /health.
set -euo pipefail

CLUSTER_NAME="pypnm-dev"
IMAGE_NAME="pypnm:local"
PYTHON_VERSION="3.12"
ORIGINAL_ARGS=("$@")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BANNER_PATH="${SCRIPT_DIR}/../banner.txt"

if [[ -f "${BANNER_PATH}" ]]; then
  cat "${BANNER_PATH}"
  echo
fi

if [[ -z "${PYPNM_KUBECONFIG_PATH:-}" ]]; then
  PYPNM_KUBECONFIG_PATH="${KUBECONFIG:-${HOME}/.kube/config}"
fi
export PYPNM_KUBECONFIG_PATH
export KUBECONFIG="${PYPNM_KUBECONFIG_PATH}"

usage() {
  cat <<'EOF'
Local Kubernetes smoke test (kind).

Usage:
  tools/local/local_kubernetes_smoke.sh [--cluster <name>] [--image <name>] [--python <version>]

Options:
  --cluster  kind cluster name (default: pypnm-dev)
  --image    image tag to build/load (default: pypnm:local)
  --python   Python version build arg (default: 3.12)
  --help     Show this help message
EOF
}

maybe_reexec_with_sudo() {
  if [[ "${EUID}" -eq 0 ]]; then
    return 0
  fi
  if [[ "${PYPNM_SUDO_REEXEC:-0}" == "1" ]]; then
    return 0
  fi

  if command -v docker >/dev/null 2>&1; then
    if ! docker info >/dev/null 2>&1; then
      exec sudo PYPNM_SUDO_REEXEC=1 PYPNM_KUBECONFIG_PATH="${PYPNM_KUBECONFIG_PATH}" "$0" "$@"
    fi
  fi

  if command -v kubectl >/dev/null 2>&1; then
    if ! kubectl config view >/dev/null 2>&1; then
      exec sudo PYPNM_SUDO_REEXEC=1 PYPNM_KUBECONFIG_PATH="${PYPNM_KUBECONFIG_PATH}" "$0" "$@"
    fi
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster)
      CLUSTER_NAME="$2"
      shift 2
      ;;
    --image)
      IMAGE_NAME="$2"
      shift 2
      ;;
    --python)
      PYTHON_VERSION="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

maybe_reexec_with_sudo "${ORIGINAL_ARGS[@]}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }
}

require_cmd docker
require_cmd kind
require_cmd kubectl

if ! docker info >/dev/null 2>&1; then
  echo "Cannot talk to Docker daemon (permission denied?). Try running with sudo or add your user to the docker group." >&2
  exit 1
fi

if ! kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  kind create cluster --name "${CLUSTER_NAME}"
fi

echo ">> Refreshing kubeconfig for ${CLUSTER_NAME}..."
kind export kubeconfig --name "${CLUSTER_NAME}" --kubeconfig "${KUBECONFIG}" >/dev/null
kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null

echo ">> Building local image..."
docker build -t "${IMAGE_NAME}" --build-arg PYTHON_VERSION="${PYTHON_VERSION}" .

echo ">> Loading image into kind..."
kind load docker-image "${IMAGE_NAME}" --name "${CLUSTER_NAME}"

echo ">> Applying manifests..."
kubectl apply -k deploy/kubernetes
kubectl rollout status deploy/pypnm-api --timeout=120s

cleanup() {
  if [ -n "${PF_PID:-}" ]; then
    kill "${PF_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo ">> Health check..."
PF_LOG_DIR="release-reports/logs"
PF_LOG="${PF_LOG_DIR}/pypnm-k8s-pf.log"
PF_REQUESTED_PORT=""
PF_LOCAL_PORT=""
PF_PID=""

start_port_forward() {
  local port_spec="$1"
  PF_REQUESTED_PORT="${port_spec}"
  PF_LOCAL_PORT=""
  mkdir -p "${PF_LOG_DIR}"
  : > "${PF_LOG}"
  kubectl port-forward deploy/pypnm-api "${port_spec}:8000" >"${PF_LOG}" 2>&1 &
  PF_PID=$!
}

start_port_forward "8000"
sleep 3

ensure_port_forward_ready() {
  if ! grep -q "Forwarding from" "${PF_LOG}"; then
    return 1
  fi
  return 0
}

if ! ensure_port_forward_ready; then
  if grep -q "address already in use" "${PF_LOG}"; then
    echo "Port 8000 busy, retrying health check with a random local port..."
    kill "${PF_PID}" >/dev/null 2>&1 || true
    wait "${PF_PID}" 2>/dev/null || true
    start_port_forward "0"
    sleep 3
  else
    echo "Port-forward failed:"
    cat "${PF_LOG}"
    exit 1
  fi
fi

if ! ensure_port_forward_ready; then
  echo "Port-forward failed:"
  cat "${PF_LOG}"
  echo "Inspect port-forward log at ${PF_LOG}."
  exit 1
fi

PF_LOCAL_PORT="${PF_REQUESTED_PORT}"
PF_LOCAL_HOST=""
if [[ "${PF_REQUESTED_PORT}" == "0" ]]; then
  if grep -q "Forwarding from \\[::1\\]:" "${PF_LOG}"; then
    PF_LOCAL_HOST="::1"
    PF_LOCAL_PORT=$(sed -nE 's/.*Forwarding from \\[::1\\]:([0-9]+).*/\\1/p' "${PF_LOG}" | head -n1)
  else
    PF_LOCAL_HOST="127.0.0.1"
    PF_LOCAL_PORT=$(sed -nE 's/.*Forwarding from ([0-9.]+):([0-9]+).*/\\2/p' "${PF_LOG}" | head -n1)
  fi
elif [[ -z "${PF_LOCAL_PORT}" ]]; then
  PF_LOCAL_PORT="8000"
fi

if [[ -z "${PF_LOCAL_HOST}" ]]; then
  if grep -q "Forwarding from \\[::1\\]:" "${PF_LOG}"; then
    PF_LOCAL_HOST="::1"
  else
    PF_LOCAL_HOST="127.0.0.1"
  fi
fi

if [[ -z "${PF_LOCAL_PORT}" ]]; then
  echo "Unable to determine local port from port-forward output:"
  cat "${PF_LOG}"
  echo "Inspect port-forward log at ${PF_LOG}."
  exit 1
fi

if [[ "${PF_LOCAL_HOST}" == *":"* ]]; then
  curl -fsS --max-time 10 "http://[${PF_LOCAL_HOST}]:${PF_LOCAL_PORT}/health" >/dev/null
else
  curl -fsS --max-time 10 "http://${PF_LOCAL_HOST}:${PF_LOCAL_PORT}/health" >/dev/null
fi

echo "✅ Kubernetes smoke test passed."
