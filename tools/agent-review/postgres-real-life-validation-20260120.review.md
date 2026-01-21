## Agent Review Bundle Summary
- Goal: Add deterministic Postgres validation workflow, CI proof that Postgres tests execute, and operator-facing checklist.
- Changes: Added local Postgres validation script, tightened CI postgres-test dependency install and proof step, improved Postgres skip diagnostics, and documented the real-life validation flow.
- Files: tests/postgres_test_utils.py, .github/workflows/daily-build.yml, tools/db/validate_postgres_local.sh, docs/tests/pypnm-software-qa.md.
- Tests: python3 -m compileall src; ruff check src; ruff format --check .; pytest -q (Postgres-gated tests skipped: PYPNM_TEST_POSTGRES not set).
- Notes: Postgres proof step fails on skips and prints masked DSN plus psycopg version.

# FILE: tests/postgres_test_utils.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
from types import ModuleType

import pytest

from pypnm.lib.types import DatabaseDsn


def require_postgres() -> tuple[DatabaseDsn, ModuleType]:
    if os.environ.get("PYPNM_TEST_POSTGRES", "").strip() != "1":
        pytest.skip(
            "PYPNM_TEST_POSTGRES not set; export PYPNM_TEST_POSTGRES=1 to enable Postgres tests"
        )
    dsn = os.environ.get("PYPNM_DB_POSTGRES_DSN", "").strip()
    if dsn == "":
        pytest.skip(
            "PYPNM_DB_POSTGRES_DSN not set; export PYPNM_DB_POSTGRES_DSN=postgresql://USER:PASS@HOST:PORT/DB"
        )
    try:
        import psycopg
    except ImportError:
        pytest.skip("psycopg not installed; install with pypnm-docsis[postgres]")
    return DatabaseDsn(dsn), psycopg
# FILE: .github/workflows/daily-build.yml
name: Build

on:
  push:
    branches: [main]         # Run on every commit to main
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 8 * * *"      # Every day at 08:00 UTC
  workflow_dispatch:          # Allow manual triggering from GitHub UI

jobs:
  daily-test:
    runs-on: ubuntu-latest

    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11", "3.12", "3.13"]

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"

      - name: Run checks
        run: |
          pypnm-software-qa-checker

  postgres-test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: pypnm
          POSTGRES_PASSWORD: pypnm
          POSTGRES_DB: pypnm
        ports:
          - 5432:5432
        options: >-
          --health-cmd="pg_isready -U pypnm -d pypnm"
          --health-interval=10s
          --health-timeout=5s
          --health-retries=5

    env:
      PYPNM_DB_BACKEND: postgres
      PYPNM_DB_POSTGRES_DSN: postgresql://pypnm:pypnm@localhost:5432/pypnm
      PYPNM_TEST_POSTGRES: "1"
      PGPASSWORD: pypnm

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev,postgres]"

      - name: Install Postgres client
        run: |
          sudo apt-get update
          sudo apt-get install -y postgresql-client

      - name: Wait for Postgres
        run: |
          for attempt in $(seq 1 30); do
            if pg_isready -h localhost -p 5432 -U pypnm -d pypnm; then
              exit 0
            fi
            sleep 2
          done
          echo "Postgres did not become ready"
          exit 1

      - name: Postgres test diagnostics
        run: |
          echo "PYPNM_TEST_POSTGRES=${PYPNM_TEST_POSTGRES}"
          python - <<'PY'
          import os
          from urllib.parse import urlparse

          dsn = os.environ.get("PYPNM_DB_POSTGRES_DSN", "")
          parsed = urlparse(dsn)
          host = parsed.hostname or ""
          port = parsed.port or ""
          db = parsed.path.lstrip("/")
          user = parsed.username or ""
          print(f\"PYPNM_DB_POSTGRES_DSN=postgresql://{user}:***@{host}:{port}/{db}\")
          PY
          python -c "import psycopg; print(psycopg.__version__)"

      - name: Postgres-gated test proof
        run: |
          set -euo pipefail
          proof_output="$(python -m pytest -q -ra \
            tests/test_db_schema_manager.py::test_postgres_schema_init_optional \
            tests/test_artifact_repository.py::test_postgres_transaction_artifact_resolution_optional)"
          printf '%s\n' "$proof_output"
          if printf '%s\n' "$proof_output" | grep -qi "skipped"; then
            echo "Postgres-gated proof tests were skipped; check env vars and psycopg install." >&2
            exit 1
          fi

      - name: Run checks
        run: |
          pypnm-software-qa-checker

  docker-compose:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    env:
      COMPOSE_PROJECT_NAME: ci

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Seed demo config for container build
        run: |
          cp demo/settings/system.json deploy/docker/config/system.json
          cp demo/settings/system.json deploy/docker/config/system.json.template

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build Docker image
        run: |
          docker compose build --progress plain

      - name: Start stack
        run: |
          docker compose up -d

      - name: Wait for API health
        run: |
          container_id="$(docker compose ps -q pypnm-api)"
          if [ -z "$container_id" ]; then
            echo "API container was not created"
            docker compose ps
            exit 1
          fi

          for attempt in $(seq 1 30); do
            status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id")"
            if [ "$status" = "healthy" ]; then
              exit 0
            fi
            echo "Container not healthy yet (status: $status); waiting..."
            sleep 5
          done

          echo "Container failed to become healthy"
          docker compose logs
          exit 1

      - name: Tear down
        if: always()
        run: |
          docker compose down --volumes
# FILE: tools/db/validate_postgres_local.sh
#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Validate Postgres-backed tests locally using Docker.

Usage:
  tools/db/validate_postgres_local.sh

Environment overrides:
  PYPNM_POSTGRES_CONTAINER_NAME (default: pypnm-postgres-local)
  PYPNM_POSTGRES_PORT           (default: 5432)
  PYPNM_POSTGRES_USER           (default: pypnm)
  PYPNM_POSTGRES_PASSWORD       (default: pypnm)
  PYPNM_POSTGRES_DB             (default: pypnm)

Notes:
- Requires Docker and python3.
- Runs pytest twice: a small Postgres-gated proof set with -ra, then pytest -q.
EOF
}

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
  usage
  exit 0
elif [[ $# -gt 0 ]]; then
  usage
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found in PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found in PATH" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Cannot talk to Docker daemon (permission denied?)." >&2
  echo "Try running with sudo or add your user to the docker group." >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
cd "$REPO_ROOT"

CONTAINER_NAME="${PYPNM_POSTGRES_CONTAINER_NAME:-pypnm-postgres-local}"
POSTGRES_PORT="${PYPNM_POSTGRES_PORT:-5432}"
POSTGRES_USER="${PYPNM_POSTGRES_USER:-pypnm}"
POSTGRES_PASSWORD="${PYPNM_POSTGRES_PASSWORD:-pypnm}"
POSTGRES_DB="${PYPNM_POSTGRES_DB:-pypnm}"

cleanup() {
  if docker ps -a --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

cleanup

docker run -d \
  --name "${CONTAINER_NAME}" \
  -e POSTGRES_USER="${POSTGRES_USER}" \
  -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
  -e POSTGRES_DB="${POSTGRES_DB}" \
  -p "${POSTGRES_PORT}:5432" \
  postgres:16 >/dev/null

for attempt in $(seq 1 30); do
  if docker exec "${CONTAINER_NAME}" pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

if ! docker exec "${CONTAINER_NAME}" pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" >/dev/null 2>&1; then
  echo "Postgres did not become ready in time" >&2
  exit 1
fi

export PYPNM_DB_BACKEND="postgres"
export PYPNM_TEST_POSTGRES="1"
export PYPNM_DB_POSTGRES_DSN="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:${POSTGRES_PORT}/${POSTGRES_DB}"

python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev,postgres]"

python3 - <<'PY'
import os
from urllib.parse import urlparse

dsn = os.environ.get("PYPNM_DB_POSTGRES_DSN", "")
parsed = urlparse(dsn)
host = parsed.hostname or ""
port = parsed.port or ""
db = parsed.path.lstrip("/")
user = parsed.username or ""
print(f"PYPNM_DB_POSTGRES_DSN=postgresql://{user}:***@{host}:{port}/{db}")
PY
python3 -c "import psycopg; print(psycopg.__version__)"

proof_output="$(python3 -m pytest -q -ra \
  tests/test_db_schema_manager.py::test_postgres_schema_init_optional \
  tests/test_artifact_repository.py::test_postgres_transaction_artifact_resolution_optional)"
printf '%s\n' "$proof_output"
if printf '%s\n' "$proof_output" | grep -qi "skipped"; then
  echo "Postgres-gated proof tests were skipped; check env vars and psycopg install." >&2
  exit 1
fi

python3 -m pytest -q
# FILE: docs/tests/pypnm-software-qa.md
# pypnm-software-qa-checker User Guide

A lightweight command-line helper that runs a standard set of **software quality checks** for the PyPNM
codebase. It is intended for local development (before commits) and for simple CI pipelines.

## 1. Prerequisites

Before using the QA checker, make sure you have the development dependencies installed in your virtual
environment:

```bash
cd ~/Projects/PyPNM
pip install -e '.[dev]'
```

This ensures the following tools are available (as defined in `pyproject.toml`):

- `ruff` - linting and unused-code detection
- `pytest` - unit and integration tests
- `pyright` - optional static type checking (when enabled via CLI flag)

## 2. Command Overview

Once installed via `pyproject.toml` as a console script, the QA checker is available as:

```bash
pypnm-software-qa-checker [OPTIONS]
```

By default (with no options), it runs a **standard QA sweep** over your project:

1. `./tools/security/scan-secrets.sh`
2. `python ./tools/security/scan-enc-secrets.py`
3. `./tools/security/scan-mac-addresses.py --fail-on-found`
4. `python ./tools/maintenance/add-required-python-headers.py`
5. `ruff check src`
6. `python -m pypnm.tools.loop_nesting_checker src`
7. `pytest`

Each step is run in sequence; the checker continues through all steps and returns the first non-zero exit
code encountered. It prints the failing command(s) as they run.

If you enable the optional Pyright step (see below), it will run **after Ruff** and **before pytest**.

## 3. Options

The CLI is intentionally minimal and focused on the PyPNM layout (`src/`).

| Option            | Description                                                                                     |
|-------------------|-------------------------------------------------------------------------------------------------|
| `--with-pyright`  | Add a `pyright` static type-check step after Ruff and before pytest.                            |

Any additional arguments you pass are forwarded to underlying tools where applicable (for example, `pytest`
arguments will still behave as expected when appended after the QA checker command).

### 3.1 Enabling Pyright

When you want to run a deeper static analysis pass with Pyright in addition to the default checks, use:

```bash
pypnm-software-qa-checker --with-pyright
```

This is effectively equivalent to:

1. `./tools/security/scan-secrets.sh`
2. `python ./tools/security/scan-enc-secrets.py`
3. `./tools/security/scan-mac-addresses.py --fail-on-found`
4. `python ./tools/maintenance/add-required-python-headers.py`
5. `ruff check src`
6. `pyright`
7. `python -m pypnm.tools.loop_nesting_checker src`
8. `pytest`

If Pyright is not installed or not on `PATH`, the QA checker will report it as “NOT FOUND” and continue
based on Pyright’s exit status.

## 4. Typical Workflows

### 4.1 Full QA before pushing (fast path, no Pyright)

Use this when you are about to push a feature branch or submit a PR and you want a quick but comprehensive
check (lint + tests + cycle detection):

```bash
pypnm-software-qa-checker
```

Effectively runs:

- Lint (style / unused / basic correctness via `ruff`)
- Loop nesting guard (`python -m pypnm.tools.loop_nesting_checker src`)
- Tests (`pytest`)

### 4.2 Full QA including Pyright

Use this when you want to include static type checking via Pyright (for example before a release or when
working on critical modules):

```bash
pypnm-software-qa-checker --with-pyright
```

Effectively runs:

- Secret scanning (`./tools/security/scan-secrets.sh`)
- Encrypted password scan (`python ./tools/security/scan-enc-secrets.py`)
- MAC address scan (`./tools/security/scan-mac-addresses.py --fail-on-found`)
- SPDX/license header scan (`python ./tools/maintenance/add-required-python-headers.py`)
- Lint (`ruff check src`)
- Static type checking (`pyright`)
- Loop nesting guard (`python -m pypnm.tools.loop_nesting_checker src`)
- Tests (`pytest`)

### 4.3 Running individual tools directly

You can still run each tool directly when you need fine-grained control:

```bash
./tools/security/scan-secrets.sh
python ./tools/security/scan-enc-secrets.py
./tools/security/scan-mac-addresses.py --fail-on-found
python ./tools/maintenance/add-required-python-headers.py
ruff check src
python -m pypnm.tools.loop_nesting_checker src
pytest -m 'not slow'
pyright
```

The QA checker is simply a convenience wrapper that standardizes a good default sequence for PyPNM.

## 5. Exit Codes and CI Integration

The script is designed to be CI-friendly:

- Exit code `0` - all selected checks passed
- Non-zero exit code - the first failing step’s exit code

A simple GitHub Actions step could look like:

```yaml
- name: PyPNM software QA
  run: pypnm-software-qa-checker
```

To include Pyright as well:

```yaml
- name: PyPNM software QA (with Pyright)
  run: pypnm-software-qa-checker --with-pyright
```

### 5.1 Postgres Backend Validation

CI validates both SQLite and Postgres. To run Postgres validation locally, start a Postgres instance (Docker is fine) and set:

```bash
export PYPNM_DB_BACKEND=postgres
export PYPNM_DB_POSTGRES_DSN=postgresql://pypnm:pypnm@localhost:5432/pypnm
python -m compileall src
pytest
ruff check .
ruff format --check .
```

The `pypnm` credentials are intended for local and CI use only.

### 5.2 Real-life Postgres validation (local)

Preconditions:
- Docker is installed and the daemon is running.
- python3 is available in your environment.

Run the local validation script:

```bash
tools/db/validate_postgres_local.sh
```

What the script does:
- Starts a Postgres 16 container with local-only defaults (`pypnm` / `pypnm`).
- Installs `.[dev,postgres]` to ensure `psycopg` is available.
- Prints a masked Postgres DSN and the `psycopg` version.
- Executes a small Postgres-gated proof set (`-ra`) followed by `pytest -q`.

Expected pass criteria:
- The proof tests report `2 passed` and do not show skip reasons.
- `pytest -q` completes without Postgres-gated tests being skipped.
- Schema init and health checks succeed, and artifact resolution reads from Postgres tables.

If you see skips when running tests manually, check for:
- `PYPNM_TEST_POSTGRES` not set.
- `PYPNM_DB_POSTGRES_DSN` not set.
- `psycopg` not installed (install with `pypnm-docsis[postgres]`).

## 6. Troubleshooting

### 6.1 `pypnm-software-qa-checker: command not found`

- Make sure you are in the right virtual environment.
- Reinstall in editable mode with dev extras:

  ```bash
  pip install -e '.[dev]'
  ```

- Confirm the console script is listed by running:

  ```bash
  pip show pypnm
  ```

### 6.2 Ruff, Pyright, or pytest not installed

If the script reports that it cannot find `ruff`, `pyright`, or `pytest`, verify that:

- You are in the environment where `.[dev]` was installed.
- The tools appear in `pip list` for that environment.

If you prefer not to install Pyright, simply avoid the `--with-pyright` flag; the default QA sweep does
not require it.

## 7. Where the Script Lives

The recommended layout is:

- Script module: `src/pypnm/tools/qa_checker.py`
- Console entry point in `pyproject.toml`:

  ```toml
  [project.scripts]
  pypnm      = "pypnm.cli:main"
  docs-serve = "mkdocs.__main__:serve"
  docs-build = "mkdocs.__main__:build"
  pypnm-software-qa-checker  = "pypnm.tools.qa_checker:main"
  ```

This keeps all tooling namespaced under `pypnm.tools` while giving you a short,
memorable `pypnm-software-qa-checker` command from the shell.
