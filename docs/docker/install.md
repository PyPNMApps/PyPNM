# PyPNM Docker Install & Usage

PyPNM ships with Docker assets so you can run the API quickly on a workstation, lab host, or VM. This guide covers the common flows:

- Install the published release image via the helper script.
- Use the deploy bundle (tarball) directly.
- Manual steps for hosts without GitHub access.

## Table of Contents

- [Fast path (helper script)](#fast-path-helper-script)
- [Deploy bundle flow (tarball)](#deploy-bundle-flow-tarball)
- [Manual/no-network notes](#manualno-network-notes)

## Fast path: PyPNM Docker container install

```bash
TAG="v1.0.2.0"
PORT=8080

curl -fsSLo install-pypnm-docker-container.sh \
  https://raw.githubusercontent.com/PyPNMApps/PyPNM/main/scripts/install-pypnm-docker-container.sh

chmod +x install-pypnm-docker-container.sh

sudo ./install-pypnm-docker-container.sh --tag ${TAG} --port ${PORT}
```

What the script does:

- Downloads the deploy bundle (falls back to tag source if the asset is missing).
- Seeds `deploy/docker/config/system.json` and `deploy/docker/compose/.env`.
- Pulls `ghcr.io/PyPNMApps/pypnm:${TAG}` and starts the stack in `/opt/pypnm/compose`.
- Prints next steps (logs, reload docs, config-menu).

After install (from `/opt/pypnm/compose`):

```bash
sudo docker compose logs -f --tail=200 pypnm-api
curl -I http://127.0.0.1:${PORT}/docs
sudo docker compose run --rm config-menu

# Reload after config changes, this assumes IP/PORT is set as above:
curl -X GET http://127.0.0.1:${PORT}/pypnm/system/webService/reload -H 'accept: application/json'
```

## Deploy bundle flow (tarball)

```bash
TAG="v1.0.2.0"
WORKING_DIR="PyPNM-${TAG}"

mkdir -p "${WORKING_DIR}"
cd "${WORKING_DIR}"

wget "https://github.com/PyPNMApps/PyPNM/archive/refs/tags/${TAG}.tar.gz"
tar -xvf "${TAG}.tar.gz" --strip-components=1

cd deploy/docker
./install.sh

cd compose
sudo docker compose pull
sudo docker compose up -d
```

Edit `deploy/docker/config/system.json` as needed, then reload the service (curl or `sudo docker compose restart pypnm-api`).

## Manual/no-network notes

- If the host cannot reach GitHub, copy the `deploy/docker/` folder from a clone or a downloaded tarball and run `deploy/docker/install.sh`.
- The helper script falls back to the tag archive and then to `main` if the deploy asset is missing.
- The runtime config lives in `deploy/docker/config/system.json`; config-menu and the API share this file.

Need Docker itself first? See [Install Docker prerequisites](install-docker.md).
