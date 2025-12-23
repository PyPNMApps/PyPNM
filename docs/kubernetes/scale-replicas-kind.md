# Single namespace with 10 replicas (one port)

This scenario scales a single PyPNM deployment to 10 replicas behind one Service.
Use it for throughput testing or simple HA without per-namespace isolation.

## Deploy (or update) and scale

```bash
TAG="v1.0.7.0"
NAMESPACE="pypnm-default"
REPLICAS="10"

curl -fsSL https://raw.githubusercontent.com/PyPNMApps/PyPNM/main/tools/k8s/pypnm_k8s_remote_deploy.sh \
  -o /tmp/pypnm_k8s_remote_deploy.sh

bash /tmp/pypnm_k8s_remote_deploy.sh --create --tag "${TAG}" --namespace "${NAMESPACE}" --replicas ${REPLICAS}
```

## Port-forward (single port)

```bash
NAMESPACE="pypnm-default"
LOCAL_PORT="8100"

kubectl -n "${NAMESPACE}" port-forward deploy/pypnm-api ${LOCAL_PORT}:8000
```

## Verify

```bash
LOCAL_PORT="8100"
curl -i http://127.0.0.1:${LOCAL_PORT}/health
```
