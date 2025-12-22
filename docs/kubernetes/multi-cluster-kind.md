# Multiple kind clusters (hard isolation)

This scenario runs separate kind clusters on the same VM for strong isolation.
Each cluster has its own kubeconfig context and its own PyPNM deployment.

## Create clusters

```bash
CLUSTER_A="pypnm-dev-a"
CLUSTER_B="pypnm-dev-b"

kind create cluster --name "${CLUSTER_A}"
kind create cluster --name "${CLUSTER_B}"
```

## Deploy to each cluster

```bash
TAG="v1.0.3.0"
NAMESPACE="pypnm-default"

kubectl config use-context kind-pypnm-dev-a
kubectl create namespace "${NAMESPACE}" || true
kubectl config set-context --current --namespace="${NAMESPACE}"
curl -fsSL https://raw.githubusercontent.com/PyPNMApps/PyPNM/main/tools/k8s/pypnm_k8s_remote_deploy.sh \
  -o /tmp/pypnm_k8s_remote_deploy.sh
bash /tmp/pypnm_k8s_remote_deploy.sh --create --tag "${TAG}" --namespace "${NAMESPACE}" --replicas 1

kubectl config use-context kind-pypnm-dev-b
kubectl create namespace "${NAMESPACE}" || true
kubectl config set-context --current --namespace="${NAMESPACE}"
bash /tmp/pypnm_k8s_remote_deploy.sh --create --tag "${TAG}" --namespace "${NAMESPACE}" --replicas 1
```

## Port-forward each cluster

```bash
kubectl config use-context kind-pypnm-dev-a
kubectl -n pypnm-default port-forward deploy/pypnm-api 8100:8000

kubectl config use-context kind-pypnm-dev-b
kubectl -n pypnm-default port-forward deploy/pypnm-api 8101:8000
```
