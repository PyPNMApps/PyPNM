# Local Kubernetes (kind) install

Use this for lightweight local Kubernetes testing on a Docker-enabled host. For deeper configuration options, refer to the [official kind site](https://kind.sigs.k8s.io/).

Docker is required to run kind. If it is not installed yet, follow the [Docker install guide](../docker/install-docker.md) first.

## Install kubectl + kind (Debian/Ubuntu)

Follow this flow:

1) Install Docker first: [Docker install guide](../docker/install-docker.md).
2) Run the bootstrap script to install `kubectl` + `kind`.

```bash
curl -fsSL https://raw.githubusercontent.com/PyPNMApps/PyPNM/main/tools/k8s/pypnm_kind_vm_bootstrap.sh \
  -o /tmp/pypnm_kind_vm_bootstrap.sh
bash /tmp/pypnm_kind_vm_bootstrap.sh
```

## Create a local cluster

```bash
kind create cluster --name pypnm-dev
kubectl get nodes
```

## Script-only deploy (no repo clone)

```bash
TAG="v1.0.3.0"
NAMESPACE="pypnm-cmts-a"
curl -fsSL https://raw.githubusercontent.com/PyPNMApps/PyPNM/main/tools/k8s/pypnm_k8s_remote_deploy.sh \
  -o /tmp/pypnm_k8s_remote_deploy.sh
bash /tmp/pypnm_k8s_remote_deploy.sh --create --tag "${TAG}" --namespace "${NAMESPACE}" --replicas 1
```

Next step: deploy PyPNM from GHCR using [PyPNM on Kubernetes (kind)](pypnm-deploy.md).

## Delete the cluster

```bash
kind delete cluster --name pypnm-dev
```
