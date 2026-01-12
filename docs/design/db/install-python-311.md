# Default Python 3.11 At Install Time

This note captures a future-facing plan to make **Python 3.11** the default (and minimum supported) Python version for installs across the PyPNM ecosystem, in preparation for the upcoming **PyPMA** add-on, which requires Python 3.11+.

## Goals

- Standardize installs on **Python 3.11**.
- Ensure package metadata prevents installation on older Python versions.
- Keep developer workflows (local dev, CI, containers) consistent.
- Prepare for PyPMA (Profile Management Application) as a Python 3.11+ add-on, while keeping PyPNM and PyPMA aligned.

## Scope

- PyPNM (core): set minimum to **3.11** and recommend 3.11 as the default runtime.
- PyPMA (add-on): require **3.11+** from day one.
- This is intended as a later implementation item (not immediate).

## Implementation Checklist

### 1) Package Metadata (Authoritative)

Update `pyproject.toml` for each package to enforce Python 3.11+ at install time:

- Set the minimum interpreter version.
- Ensure classifiers match.
- Ensure tooling targets match (ruff/mypy/pytest, etc.)

Example (recommended):

```toml
[project]
requires-python = ">=3.11"
classifiers = [
  "Programming Language :: Python :: 3",
  "Programming Language :: Python :: 3.11",
  "Programming Language :: Python :: 3.12",
  "Programming Language :: Python :: 3.13",
]
```

Notes:
- `requires-python` is what pip honors to block unsupported installs.
- Keep classifiers aligned with what you actually test in CI.

### 2) Local Dev Defaults (Practical)

Recommended developer defaults:

- Use `pyenv` or `asdf` to pin the repo version to 3.11.
- Add a `.python-version` file with `3.11.x` (or a specific patch version you standardize on).

Example:

```text
3.11.8
```

If you prefer not to pin patch level, document the minimum and let tooling choose:

```text
3.11
```

### 3) Virtual Environment Guidance (Docs)

Update install docs to state that Python 3.11 is required and show a 3.11-first workflow.

Example:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -e .
```

If you support `uv`:

```bash
uv venv --python 3.11
source .venv/bin/activate
uv pip install -e .
```

### 4) CI Matrix (Make It Explicit)

Update GitHub Actions (or equivalent) to test on:

- 3.11 (baseline)
- 3.12+ (optional, but recommended)

Example matrix guidance:

- Minimum: `3.11`
- Recommended: `3.11` and `3.12`
- Optional future: `3.13` once stable in your dependency set

### 5) Containers (If Applicable)

If you ship Docker images:

- Use a Python 3.11 base image for builders/runtimes.
- Keep runtime and build-time Python versions aligned.

### 6) Cross-Repo Policy (PyPNM + PyPMA)

Because PyPMA is an add-on and will require 3.11+, it is preferable to align PyPNM to the same minimum:

- Avoids split-brain dependency matrices.
- Reduces support surface area.
- Simplifies documentation and CI.

## Change Management Notes

When you implement this:

- Announce the change in release notes as a breaking change (minimum Python version bump).
- If you maintain long-lived branches, decide whether older branches remain 3.10-compatible.
- Confirm your dependency graph supports 3.11 cleanly (especially DB drivers and FastAPI stack).

## Quick Verification Steps

After implementation:

1) Ensure `pip install .` fails on Python 3.10 with a clear version error.
2) Ensure installs succeed on Python 3.11 in a clean venv.
3) Run standard checks:
   - `python3 -m compileall src`
   - `ruff check .`
   - `ruff format --check .`
   - `pytest -q`
