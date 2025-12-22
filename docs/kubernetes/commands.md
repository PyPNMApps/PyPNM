# Kubernetes (kind) commands

## Table of contents

- [Cluster lifecycle](#cluster-lifecycle)
- [Context and nodes](#context-and-nodes)
- [Apply and inspect](#apply-and-inspect)
- [Rollout and health](#rollout-and-health)
- [Images](#images)
- [Script-only deploy (no repo clone)](#script-only-deploy-no-repo-clone)
- [Cleanup](#cleanup)
- [Scaling and multiple instances](#scaling-and-multiple-instances)
- [Full teardown](#full-teardown)

Common commands for local kind-based testing.

## Cluster lifecycle

Create, list, and delete kind clusters.

```bash
kind create cluster --name pypnm-dev
kind get clusters
kind delete cluster --name pypnm-dev
```

## Context and nodes

Switch contexts and verify node readiness.

```bash
kubectl config get-contexts
kubectl config use-context kind-pypnm-dev
kubectl get nodes -o wide
```

## Apply and inspect

Apply manifests and inspect pod status/logs.

```bash
kubectl apply -k deploy/kubernetes
kubectl get pods -o wide
kubectl describe pod -l app=pypnm-api
kubectl logs -l app=pypnm-api --tail=200
```

## Rollout and health

Wait for rollout and validate the health endpoint.

```bash
kubectl rollout status deploy/pypnm-api --timeout=120s
kubectl port-forward deploy/pypnm-api 8000:8000
curl -i http://127.0.0.1:8000/health
```

## Images

Build a local image, load into kind, and restart the deployment.

```bash
docker build -t pypnm:local --build-arg PYTHON_VERSION=3.12 .
kind load docker-image pypnm:local --name pypnm-dev
kubectl set image deploy/pypnm-api pypnm-api=pypnm:local
kubectl rollout restart deploy/pypnm-api
```

## Script-only deploy (no repo clone)

Deploy from GHCR using a remote manifest (no repo clone required):

```bash
curl -fsSL https://raw.githubusercontent.com/PyPNMApps/PyPNM/main/tools/k8s/pypnm_k8s_remote_deploy.sh \
  -o /tmp/pypnm_k8s_remote_deploy.sh

TAG="v1.0.2.0"
NAMESPACE="pypnm-cmts-a"

bash /tmp/pypnm_k8s_remote_deploy.sh --create --tag "${TAG}" --namespace "${NAMESPACE}" --replicas 1
```

Teardown:

```bash
bash /tmp/pypnm_k8s_remote_deploy.sh --teardown --namespace "${NAMESPACE}"
```

## Cleanup

Remove the deployment and related resources.

```bash
kubectl delete -k deploy/kubernetes
```

## Scaling and multiple instances

Scale replicas or create a second kind cluster.

```bash
kubectl scale deploy/pypnm-api --replicas=3
kubectl get pods -o wide
```

Use a different kind cluster name for multiple isolated instances:

```bash
kind create cluster --name pypnm-dev-2
kubectl config use-context kind-pypnm-dev-2
kubectl apply -k deploy/kubernetes
```

## Full teardown

Delete resources and remove the cluster.

```bash
kubectl delete -k deploy/kubernetes
kind delete cluster --name pypnm-dev
```
