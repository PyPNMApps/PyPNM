#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="pypnm-dev"
NAMESPACE="default"
IMAGE_SOURCE="local"
IMAGE_TAG="latest"
REPLICAS="1"
PYTHON_VERSION="3.12"
CREATE_CLUSTER="0"
TEARDOWN="0"
ORIGINAL_ARGS=("$@")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BANNER_PATH="${SCRIPT_DIR}/../banner.txt"

if [[ -f "${BANNER_PATH}" ]]; then
  cat "${BANNER_PATH}"
  echo
fi

usage() {
  cat <<'EOF'
PyPNM Kubernetes toolkit (kind).

Usage:
  tools/k8s/pypnm_k8s_toolkit.sh --create [options]
  tools/k8s/pypnm_k8s_toolkit.sh --teardown [options]

Options:
  --create               Create cluster if needed and deploy PyPNM.
  --teardown             Delete deployment resources (and cluster if --delete-cluster).
  --delete-cluster       Delete the kind cluster after teardown.
  --cluster <name>       Kind cluster name (default: pypnm-dev).
  --namespace <name>     Kubernetes namespace (default: default).
  --image-source <src>   local | ghcr (default: local).
  --tag <tag>            GHCR tag (default: latest). Ignored for local.
  --replicas <n>         Replica count (default: 1).
  --python <version>     Python build arg for local image (default: 3.12).
  --help                 Show this help message.
EOF
}

maybe_reexec_with_sudo() {
  if [[ "${EUID}" -eq 0 ]]; then
    return 0
  fi
  if [[ "${PYPNM_SUDO_REEXEC:-0}" == "1" ]]; then
    return 0
  fi

  if [[ "${IMAGE_SOURCE}" == "local" ]]; then
    if command -v docker >/dev/null 2>&1; then
      if ! docker info >/dev/null 2>&1; then
        exec sudo PYPNM_SUDO_REEXEC=1 "$0" "$@"
      fi
    fi
  fi

  if command -v kubectl >/dev/null 2>&1; then
    if ! kubectl config view >/dev/null 2>&1; then
      exec sudo PYPNM_SUDO_REEXEC=1 "$0" "$@"
    fi
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --create)
      CREATE_CLUSTER="1"
      shift
      ;;
    --teardown)
      TEARDOWN="1"
      shift
      ;;
    --delete-cluster)
      DELETE_CLUSTER="1"
      shift
      ;;
    --cluster)
      CLUSTER_NAME="$2"
      shift 2
      ;;
    --namespace)
      NAMESPACE="$2"
      shift 2
      ;;
    --image-source)
      IMAGE_SOURCE="$2"
      shift 2
      ;;
    --tag)
      IMAGE_TAG="$2"
      shift 2
      ;;
    --replicas)
      REPLICAS="$2"
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

if [[ "${CREATE_CLUSTER}" == "0" && "${TEARDOWN}" == "0" ]]; then
  echo "You must specify --create or --teardown." >&2
  usage
  exit 1
fi

maybe_reexec_with_sudo "${ORIGINAL_ARGS[@]}"

if ! command -v kind >/dev/null 2>&1; then
  echo "Missing required command: kind" >&2
  exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
  echo "Missing required command: kubectl" >&2
  exit 1
fi

if [[ "${IMAGE_SOURCE}" == "local" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Missing required command: docker" >&2
    exit 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Missing required command: python3" >&2
    exit 1
  fi
fi

if [[ "${TEARDOWN}" == "1" ]]; then
  kubectl delete -k deploy/kubernetes -n "${NAMESPACE}" || true
  if [[ "${DELETE_CLUSTER:-0}" == "1" ]]; then
    kind delete cluster --name "${CLUSTER_NAME}"
  fi
  exit 0
fi

if ! kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  if [[ "${CREATE_CLUSTER}" == "1" ]]; then
    kind create cluster --name "${CLUSTER_NAME}"
  fi
fi

if ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
  kubectl create namespace "${NAMESPACE}"
fi

load_image_into_kind() {
  local image_name="$1"
  local cluster_name="$2"
  local retries="${KIND_LOAD_RETRIES:-3}"
  local delay="${KIND_LOAD_DELAY:-2}"
  local attempt=1
  local image_repo=""
  local image_tag=""
  local node_name=""

  image_repo="${image_name%:*}"
  image_tag="${image_name##*:}"
  if [[ "${image_repo}" == "${image_tag}" ]]; then
    image_tag="latest"
  fi
  if [[ "${image_repo}" != */* ]]; then
    image_repo="docker.io/library/${image_repo}"
  fi
  node_name="${cluster_name}-control-plane"

  while (( attempt <= retries )); do
    if kind load docker-image "${image_name}" --name "${cluster_name}"; then
      if docker exec "${node_name}" crictl images 2>/dev/null | \
        grep -Eq "^${image_repo}[[:space:]]+${image_tag}[[:space:]]"; then
        return 0
      fi
      echo "kind load docker-image reported success but image not visible yet (attempt ${attempt}/${retries})." >&2
    else
      echo "kind load docker-image failed (attempt ${attempt}/${retries}); retrying in ${delay}s..." >&2
    fi
    sleep "${delay}"
    attempt=$((attempt + 1))
  done

  return 1
}

if [[ "${IMAGE_SOURCE}" == "local" ]]; then
  docker build -t pypnm:local --build-arg PYTHON_VERSION="${PYTHON_VERSION}" .
  if ! load_image_into_kind "pypnm:local" "${CLUSTER_NAME}"; then
    echo "Failed to load image into kind cluster ${CLUSTER_NAME}." >&2
    exit 1
  fi
  KUSTOMIZE_PATH="deploy/kubernetes"
else
  KUSTOMIZE_PATH="deploy/kubernetes/overlays/ghcr"
  kubectl kustomize "${KUSTOMIZE_PATH}" | \
    sed "s|newTag: latest|newTag: ${IMAGE_TAG}|" > /tmp/pypnm-k8s.yaml
  kubectl apply -n "${NAMESPACE}" -f /tmp/pypnm-k8s.yaml
  kubectl rollout status deploy/pypnm-api --namespace "${NAMESPACE}" --timeout=120s
  kubectl scale deploy/pypnm-api --namespace "${NAMESPACE}" --replicas="${REPLICAS}"
  exit 0
fi

kubectl apply -k "${KUSTOMIZE_PATH}" -n "${NAMESPACE}"
kubectl rollout status deploy/pypnm-api --namespace "${NAMESPACE}" --timeout=120s
kubectl scale deploy/pypnm-api --namespace "${NAMESPACE}" --replicas="${REPLICAS}"

PF_LOG="/tmp/pypnm-k8s-pf.log"
kubectl port-forward --namespace "${NAMESPACE}" deploy/pypnm-api 8000:8000 >"${PF_LOG}" 2>&1 &
PF_PID=$!
sleep 3
if ! curl -fsS http://127.0.0.1:8000/health >/dev/null; then
  echo "Health check failed; inspect port-forward log at ${PF_LOG}."
  kill "${PF_PID}" >/dev/null 2>&1 || true
  exit 1
fi
kill "${PF_PID}" >/dev/null 2>&1 || true
