## Agent Review Bundle Summary
- Goal: Stabilize CI health checks by waiting for Uvicorn startup before curl.
- Changes: Added retry loop for health endpoint in macOS CI and post-build workflows.
- Files: .github/workflows/macos-ci.yml, .github/workflows/post-build.yml
- Tests: Not run (CI workflow change only).
- Notes: Added curl readiness loop to reduce flakiness.

# FILE: .github/workflows/macos-ci.yml
name: MacOS CI

on:
  workflow_dispatch:
  push:
    branches:
      - "main"
      - "develop"
  pull_request:
    branches:
      - "main"
      - "develop"

permissions:
  contents: read

jobs:
  test-macos:
    name: macOS · Python ${{ matrix.python-version }}
    runs-on: macos-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11", "3.12"]

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set Up Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip

      - name: Upgrade Pip Tooling
        run: |
          python -m pip install --upgrade pip setuptools wheel

      - name: Install Project
        run: |
          python -m pip install -e .
          python -m pip install -e ".[dev,docs]"

      - name: Run Tests
        env:
          PYTHONWARNINGS: default
        run: |
          python -m pytest -q

      - name: Start PyPNM
        run: |
          python -m uvicorn pypnm.api.main:app --host 127.0.0.1 --port 8000 &
          for attempt in {1..20}; do
            if curl -fsS http://127.0.0.1:8000/health >/dev/null; then
              break
            fi
            sleep 1
          done
          curl -fsS http://127.0.0.1:8000/health
          pkill -f "uvicorn pypnm.api.main:app"

      - name: Compile Python
        run: |
          python -m compileall src

      - name: Build Docs (Strict)
        run: |
          mkdocs build --strict

# FILE: .github/workflows/post-build.yml
name: Post Build

on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]

jobs:
  downstream:
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev,docs]"

      - name: Compile Python
        run: |
          python -m compileall src

      - name: Ruff Check
        run: |
          ruff check src

      - name: Ruff Format Check
        run: |
          ruff format --check src

      - name: Run Tests
        env:
          PYTHONWARNINGS: default
        run: |
          python -m pytest -q

      - name: Start PyPNM
        run: |
          python -m uvicorn pypnm.api.main:app --host 127.0.0.1 --port 8000 &
          for attempt in {1..20}; do
            if curl -fsS http://127.0.0.1:8000/health >/dev/null; then
              break
            fi
            sleep 1
          done
          curl -fsS http://127.0.0.1:8000/health
          pkill -f "uvicorn pypnm.api.main:app"
