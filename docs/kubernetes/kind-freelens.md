# kind + FreeLens on a VM (GHCR)

This guide documents a VM-friendly workflow for running PyPNM on kind and managing it in FreeLens. The model below assumes **one PyPNM service per CMTS**, with multiple namespaces living on a single VM/cluster.

## Prerequisites

- VM with Docker installed and running.
- `curl` and `sudo` available.
- Network access to GHCR (`ghcr.io/PyPNMApps/pypnm`).

## Install kubectl + kind

Use the bootstrap helper for Debian/Ubuntu-style hosts (no repo clone required):

```bash
curl -fsSL https://raw.githubusercontent.com/PyPNMApps/PyPNM/main/tools/k8s/pypnm_kind_vm_bootstrap.sh \
  -o /tmp/pypnm_kind_vm_bootstrap.sh
bash /tmp/pypnm_kind_vm_bootstrap.sh
```

## Create the cluster and deploy from GHCR

Pick a release tag, then deploy into a namespace (one namespace per CMTS). This script pulls manifests from GitHub, so no repo clone is required:

```bash
TAG="v1.0.2.4"
NAMESPACE="pypnm-cmts-a"

curl -fsSL https://raw.githubusercontent.com/PyPNMApps/PyPNM/main/tools/k8s/pypnm_k8s_remote_deploy.sh \
  -o /tmp/pypnm_k8s_remote_deploy.sh
bash /tmp/pypnm_k8s_remote_deploy.sh --create --tag "${TAG}" --namespace "${NAMESPACE}" --replicas 1
```

Health check:

```bash
kubectl port-forward --namespace "${NAMESPACE}" deploy/pypnm-api 8000:8000
curl -i http://127.0.0.1:8000/health
```

If the returned `version` is older than expected, verify the tag used in the deploy command and confirm the namespace matches the running deployment.

## Connect with FreeLens

1. Add the kubeconfig from the VM to FreeLens.
   - If FreeLens runs on the VM, it can use `~/.kube/config` directly.
   - If FreeLens runs on your workstation, copy the kubeconfig from the VM:

     ```bash
     VM_USER="dev01"
     VM_HOST="10.0.0.10"
     LOCAL_KUBECONFIG="${HOME}/.kube/pypnm-dev-kubeconfig"

     scp ${VM_USER}@${VM_HOST}:~/.kube/config "${LOCAL_KUBECONFIG}"
     ```

     PowerShell:

     ```powershell
     $VM_USER = "dev01"
     $VM_HOST = "10.0.0.10"
     $LOCAL_KUBECONFIG_DIR = "$env:USERPROFILE\\.kube"
     $LOCAL_KUBECONFIG = "$LOCAL_KUBECONFIG_DIR\\pypnm-dev-kubeconfig"

     New-Item -ItemType Directory -Force -Path $LOCAL_KUBECONFIG_DIR | Out-Null
     scp ${VM_USER}@${VM_HOST}:~/.kube/config "$LOCAL_KUBECONFIG"
     ```

   - In FreeLens: **Catalog → Clusters → Add Cluster → From kubeconfig**, then select the copied file.
   - If FreeLens runs on Windows, update any file paths inside the kubeconfig (for example, replace `/home/dev01/...` with `C:\\Users\\<you>\\...`).
     Then use an SSH tunnel for the API port:

     ```bash
     VM_USER="dev01"
     VM_HOST="10.0.0.10"
     VM_PORT="8000"

     ssh -L ${VM_PORT}:127.0.0.1:${VM_PORT} ${VM_USER}@${VM_HOST}
     ```

     PowerShell:

     ```powershell
     $VM_USER = "dev01"
     $VM_HOST = "10.0.0.10"
     $VM_PORT = "8000"

     ssh -L ${VM_PORT}:127.0.0.1:${VM_PORT} ${VM_USER}@${VM_HOST}
     ```
2. Select the target namespace (`pypnm-cmts-a`).
   - In FreeLens 1.7.0: open **Catalog** (top-left icon), choose **Clusters**, then switch the namespace selector in the top bar to `pypnm-cmts-a`.
3. In FreeLens, open the target namespace and locate `pypnm-api` (Service or Pod).
4. Start a port-forward for `pypnm-api` to local port 8000.
   - Service: forward `8000 -> 8000`.
   - Pod: forward `8000 -> 8000`.
5. Open `http://127.0.0.1:8000/health` in your browser.
   - If you are tunneling, keep the SSH tunnel running and use the same `http://127.0.0.1:8000` URL on Windows.

Tip: keep one FreeLens workspace per CMTS namespace so it is easy to keep sessions isolated.

## Deployment examples

| Example | When to use |
| --- | --- |
| [Single namespace with 10 replicas](scale-replicas-kind.md) | Load testing or simple HA with one endpoint. |
| [10 namespaces, 10 ports](ten-instances-kind.md) | One instance per CMTS or per customer. |
| [Multiple kind clusters](multi-cluster-kind.md) | Hard isolation between environments. |

## One VM, multiple CMTS (one PyPNM per CMTS)

Deploy a PyPNM instance per CMTS by assigning a unique namespace and configuration per CMTS:

```bash
TAG="v1.0.2.4"

for CMTS in cmts-a cmts-b cmts-c; do
  NAMESPACE="pypnm-${CMTS}"
  bash /tmp/pypnm_k8s_remote_deploy.sh --create --tag "${TAG}" --namespace "${NAMESPACE}" --replicas 1
done
```

### CMTS-specific config

Each instance should point at exactly one CMTS. Use a per-namespace config patch and apply it as described in [PyPNM on Kubernetes (kind)](pypnm-deploy.md) ("Config overrides" section). Keep the CMTS routing and retrieval settings unique per namespace.

## Teardown

```bash
NAMESPACE="pypnm-cmts-a"

bash /tmp/pypnm_k8s_remote_deploy.sh --teardown --namespace "${NAMESPACE}"
```

To delete the cluster after all namespaces are removed:

```bash
kind delete cluster --name pypnm-dev
```
