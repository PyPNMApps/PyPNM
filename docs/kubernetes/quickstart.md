# Kubernetes quickstart (kind)

Copy-paste flow using the current release tag:

```bash
TAG="v1.0.6.0"
tools/k8s/pypnm_k8s_toolkit.sh --create --image-source ghcr --tag ${TAG} --replicas 1
```

To target a specific namespace (useful for one PyPNM per CMTS):

```bash
TAG="v1.0.6.0"
NAMESPACE="pypnm-cmts-a"
tools/k8s/pypnm_k8s_toolkit.sh --create --image-source ghcr --tag ${TAG} --replicas 1 --namespace ${NAMESPACE}
```

To use a local image:

```bash
tools/k8s/pypnm_k8s_toolkit.sh --create --image-source local --replicas 1
```

Script-only deploy (no repo clone) is covered in [PyPNM on Kubernetes (kind)](pypnm-deploy.md).
