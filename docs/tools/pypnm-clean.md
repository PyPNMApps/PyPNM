# PyPNM Cleanup Script

The PyPNM Cleanup Script is a shell utility located in the `tools/` directory. It provides a structured way to clean up logs, Python cache files, build artifacts, generated output, internal `.data` folders related to PNM processing, and Docker artifacts.

> Use this tool to reset analysis directories and keep the repository free of stale or generated files.

## Features

* Clean specific categories of build and runtime artifacts or perform a full cleanup.
* Support for scoped operations (for example, Python caches only, or PNM data only).
* Can be run from any root directory (defaults to the current directory).
* Uses simple, repeatable patterns for targeted or full cleanup flows.

## Directories and Options

The table below summarizes which directories are affected by each option. All paths are resolved relative to the chosen `ROOT_DIR`.

| Option        | Description                                      | Directories removed (if present)                                       |
|---------------|--------------------------------------------------|------------------------------------------------------------------------|
| `--logs`      | Clean application logs (truncate file, keep inode). | `logs/pypnm.log`                                                       |
| `--python`    | Clean Python cache artifacts.                    | `**/__pycache__/`, `**/*.pyc`, `.pytest_cache/`                        |
| `--build`     | Clean build and packaging outputs.               | `build/`, `dist/`, `*.egg-info`                                       |
| `--pnm`       | Clean PNM working data and databases.            | `.data/pnm/`, `.data/db/`                                             |
| `--archive`   | Clean archive artifacts only.                    | `.data/archive/`                                                      |
| `--excel`     | Clean Excel/CSV exports.                         | `.data/xlsx/`, `.data/csv/`                                           |
| `--json`      | Clean JSON exports.                              | `.data/json/`                                                         |
| `--plot-data` | Clean plotting data and archive artifacts.       | `.data/png/`, `.data/csv/`, `.data/archive/`                          |
| `--msg-rsp`   | Clean message-response artifacts.                | `.data/msg_rsp/`                                                      |
| `--output`    | Clean high-level output files.                   | `output/`                                                             |
| `--issues`    | Clean support bundles (preserves `issues/` directory). | `issues/` contents                                                    |
| `--remove-issues` | Remove the entire `issues/` directory.        | `issues/`                                                             |
| `--settings-backup` | Remove `system.bak.*.json` backups.        | `src/pypnm/settings/system.bak.*.json`                                |
| `--docker`    | Clean Docker artifacts.                         | running containers, stopped containers, unused images, build cache, unused volumes, unused networks |
| `--all`       | Run every cleanup operation listed above.        | All of the above, including destructive Docker cleanup                |

## Usage

```bash
./tools/maintenance/clean.sh [OPTIONS] [ROOT_DIR]
```

* `OPTIONS`: One or more of the flags listed in the table above. Combine them to target multiple areas (for example, `--python --build`).

* `ROOT_DIR`: Optional path that serves as the root of the cleanup operation.  
  If omitted, the script uses the current working directory.

### Examples

Clean everything under the current directory:

```bash
./tools/maintenance/clean.sh --all
```

This includes destructive Docker cleanup. When Docker artifacts exist, `--all` now:

1. stops running containers
2. removes containers
3. prunes unused images
4. prunes build cache
5. prunes unused volumes
6. prunes unused networks

Use `--all` only when you intentionally want a full local reset.

Clean only Python caches and build artifacts:

```bash
./tools/maintenance/clean.sh --python --build
```

Clean PNM data and plot-related data from a specific project root:

```bash
./tools/maintenance/clean.sh --pnm --plot-data ~/Projects/PyPNM
```

Clean message-response artifacts only:

```bash
./tools/maintenance/clean.sh --msg-rsp
```

Clean only Docker artifacts:

```bash
./tools/maintenance/clean.sh --docker
```

## Notes

* The script uses `set -euo pipefail` to fail fast on errors or undefined variables.
* Deletion is performed via a small helper that checks for path existence before removal.
* All directories are interpreted relative to `ROOT_DIR`, which allows you to point the script at different clones or sandboxes.
* `--docker` and `--all` use the Docker cleanup helper under `tools/maintenance/docker-cleanup.sh`.
* Destructive Docker cleanup can stop and remove running containers. Do not use it on a host with containers you intend to keep running.
