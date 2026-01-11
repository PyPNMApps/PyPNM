### Summary
Aligned CI checks to use the QA checker command in daily-test and postgres-test, and tightened the Postgres validation sentence in the QA guide.

### Modified Files
- .github/workflows/daily-build.yml
- docs/tests/pypnm-software-qa.md

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `pytest` → pass (520 passed, 4 skipped)
- `ruff check .` → pass
- `ruff format --check .` → pass (342 files already formatted)

### Tests
- `pytest` → pass (4 skipped: 3 hardware integration, 1 Postgres DSN not set)
- `ruff` → pass
- `python3 -m compileall src` → pass

### Notes / Warnings
- Postgres integration test skipped locally because `PYPNM_DB_POSTGRES_DSN` is not set.

### Remaining TODOs / Follow-Ups
- None

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
          pip install -e ".[dev]"
          pip install "psycopg[binary]"

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
- `pycycle` - import cycle detection
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
4. `./tools/build/add-required-python-headers.py`
5. `ruff check src`
6. `pytest`
7. `pycycle --here` (from the project root)

Each step is run in sequence; if any step fails (non-zero exit code), the script exits with that code and
prints the failing command.

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
4. `./tools/build/add-required-python-headers.py`
5. `ruff check src`
6. `pyright`
7. `pytest`
8. `pycycle --here`

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
- Tests (`pytest`)
- Import cycle detection (`pycycle --here`)

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
- SPDX/license header scan (`./tools/build/add-required-python-headers.py`)
- Lint (`ruff check src`)
- Static type checking (`pyright`)
- Tests (`pytest`)
- Import cycle detection (`pycycle --here`)

### 4.3 Running individual tools directly

You can still run each tool directly when you need fine-grained control:

```bash
./tools/security/scan-secrets.sh
python ./tools/security/scan-enc-secrets.py
./tools/security/scan-mac-addresses.py --fail-on-found
./tools/build/add-required-python-headers.py
ruff check src
pytest -m 'not slow'
pycycle --here
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

### 6.2 Ruff, Pyright, pytest, or pycycle not installed

If the script reports that it cannot find `ruff`, `pyright`, `pytest`, or `pycycle`, verify that:

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
