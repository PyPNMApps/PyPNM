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
