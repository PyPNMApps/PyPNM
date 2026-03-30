# Scripts Reference

Utility scripts located in `scripts/` that support installation, quality control, and day-to-day development tasks.

## Secrets and environment setup

| Script | Purpose | Typical usage |
|--------|---------|---------------|
| `init_secrets_key.sh` | Generates the Fernet key and `.env` entries required for encrypted `system.json` secrets. | Run once per repo clone: `./scripts/init_secrets_key.sh` (prompts before overwriting existing keys). |
| `install_py_path.sh` | Ensures the project path is appended to the user’s `PYTHONPATH` for CLI tooling. | `./scripts/install_py_path.sh` (adds exports to `~/.bashrc`). |
| `install_aliases.sh` | Installs convenience shell aliases (e.g., `config-menu`, `pypnm-clean`). | `./scripts/install_aliases.sh` after initial `./install.sh`. |
| `seed-fastapi-worker-profile.py` | Detects host CPU/RAM and writes recommended FastAPI worker defaults for install/runtime helpers. | `./scripts/seed-fastapi-worker-profile.py --write .data/runtime/pypnm-serve.env` during install bootstrap or after hardware changes. |
| `setup_tftp_server.sh` | Inspects a local `tftpd-hpa` install and enforces upload-capable config (`--create`) plus a writable TFTP root. | `./scripts/setup_tftp_server.sh` after installing `tftpd-hpa`; applies Debian/Ubuntu defaults directly and exits cleanly on other Linux layouts. |
| `update_env.sh` | Activates the local venv and exports common dev env vars. | `./scripts/update_env.sh .env` (or with your venv path). |

## Build, update, and quality control

| Script | Purpose | Typical usage |
|--------|---------|---------------|
| `update-dep.sh` | Batch-updates pinned dependencies (uses `pip-tools` under the hood). | `./scripts/update-dep.sh --all` before cutting a release. |
| `setup-and-test.sh` | One-shot script for CI/local QC: installs dependencies, runs lint/tests. | `./scripts/setup-and-test.sh` in clean CI images or before PRs. |

## Service lifecycle

| Script | Purpose | Typical usage |
|--------|---------|---------------|
| `start-fastapi-service.sh` | Launches the FastAPI service with sensible defaults and consumes the generated worker-profile env file when present. | `./scripts/start-fastapi-service.sh --reload` during local dev or `./scripts/start-fastapi-service.sh` after install seeding. |

> **See also:** Additional tooling lives in [`tools/`](../tools/index.md) (e.g., support bundles, config menus). Use this page for the core scripts shipped in `scripts/`.
