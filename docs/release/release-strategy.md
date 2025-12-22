# PyPNM Release Guide (Single-Branch Model Using `tools/release/release.py`)

## Table of contents

[1. Branch Model](#1-branch-model)

[2. Version Source Of Truth And Mirrored Locations](#2-version-source-of-truth-and-mirrored-locations)

[3. Versioning Scheme](#3-versioning-scheme)

[4. Release Script Overview (`tools/release/release.py`)](#4-release-script-overview-toolsreleasereleasepy)

 * [4.1 High Level Release Steps](#41-high-level-release-steps)

[5. Release Modes And Examples](#5-release-modes-and-examples)

* [5.1 Automatic Maintenance Release (Default)](#51-automatic-maintenance-release-default)
* [5.2 Automatic Next Version By Mode (`--next`)](#52-automatic-next-version-by-mode-next)
* [5.3 Explicit Version (`--version`)](#53-explicit-version-version)

[6. Preflight controls and prerequisites](#6-preflight-controls-and-prerequisites)

[7. Quick Reference](#7-quick-reference)

This guide describes how to manage versions and releases for the PyPNM project using a single primary branch and the `tools/release/release.py` helper script. The `release` script is the primary entry point for bumping versions, running tests, creating tags, and pushing changes.

## 1. Branch Model

For current PyPNM development, a **single-branch** model is used:

* `main`  
  Active development and release branch. All regular work and official releases happen from `main`.

Optional branches you may use later:

* `feature/*`  
  Short-lived branches for experiments or isolated changes. Merge back into `main` when done, then delete.

* `stable` (optional, future)  
  You can introduce a `stable` branch later if you need a dedicated GA branch. For now, it is not required; tags on `main` provide clear release points.

When in doubt, work directly on `main`, create tags for each release, and use Git history plus tags to reproduce any version.

## 2. Version Source Of Truth And Mirrored Locations

The canonical version string is defined in a single Python module and mirrored into `pyproject.toml` by the release tooling.

Canonical source:

```text
src/pypnm/version.py
```

Recommended structure:

```python
from __future__ import annotations

__all__ = ["__version__"]

# MAJOR.MINOR.MAINTENANCE.BUILD
__version__: str = "0.2.1.0"
```

Rules:

* Treat `src/pypnm/version.py` as the **single source of truth**.  
* The `[project].version` field in `pyproject.toml` is a **mirror** that must always match `__version__`.  
* Do not hand-edit the version in `pyproject.toml`; let the release script maintain it.

Example FastAPI wiring:

```python
from fastapi import FastAPI
from pypnm.version import __version__

app = FastAPI(
    title="PyPNM REST API",
    version=__version__,
    description=fast_api_description,
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)
```

### 2.1 Files Touched By A Release

When you run the release script, it updates or validates these locations:

* `src/pypnm/version.py`  
  Canonical `__version__` definition. Updated to the new four-part version string.

* `pyproject.toml`  
  `[project].version` is kept in lockstep with `__version__`. Updated to the same value as in `src/pypnm/version.py`.

The release script also performs git operations (commit, tag, push) once the version is updated and tests pass.

## 3. Versioning Scheme

PyPNM uses a four-part version:

```text
MAJOR.MINOR.MAINTENANCE.BUILD
```

Guidelines:

* `MAJOR`  
  Increment when there are significant breaking changes or large structural shifts.

* `MINOR`  
  Increment when adding features in a backward-compatible way.

* `MAINTENANCE`  
  Increment when fixing bugs or making compatible improvements that are smaller than a full minor release.

* `BUILD`  
  Increment for very small hotfixes or internal rebuilds that do not change public behavior but still need a distinct version.

Note: any version with a non-zero `BUILD` segment is considered a hot-fix release (typically cut from the `hot-fix` branch). These releases are not treated as clean GA releases and are not guaranteed to pass the full test matrix.

Examples:

* `0.2.1.0` - Minor feature set with maintenance updates.  
* `0.2.2.0` - Next maintenance release.  
* `0.3.0.0` - Next minor release.  
* `1.0.0.0` - First major release.

All four segments must be numeric. Both `src/pypnm/version.py` and `pyproject.toml` must carry the same four-part string after a release.

## 4. Release Script Overview (`tools/release/release.py`)

The `tools/release/release.py` script is the primary entry point for performing a release. It is responsible for:

* Computing or accepting a target version.  
* Updating version strings in both version files.  
* Running the test suite.  
* Creating a release commit.  
* Tagging the release.  
* Pushing branch and tags to `origin`.
* Writing a markdown release report under `release-reports/` with a summary table of the last commit.

You typically run this script directly; it internally handles all version file changes.

### 4.1 High Level Release Steps

When you run `tools/release/release.py` (and confirm the prompt when applicable), it performs the following:

1. Read the current version from `src/pypnm/version.py`.  
2. Read the `[project].version` from `pyproject.toml` and verify they match.  
3. Compute the target version, either:
   - From an explicit `--version` argument, or  
   - From a `--next` mode (major, minor, maintenance, build), or  
   - From an implicit **maintenance bump** when neither `--version` nor `--next` is provided.  
4. Display the planned version bump (for auto-computed versions) and wait for a `y` / `yes` confirmation.  
5. Ensure the git working tree is clean.  
6. Checkout the target branch (default `main`) and pull with `--ff-only`.  
7. Update both version files to the target version.  
8. Optionally run `pytest` (unless `--skip-tests` is used).  
9. Optionally run local Docker build + health preflight (`tools/local/local_container_build.sh --smoke`; skip with `--skip-docker-test`).  
10. Build docs with `mkdocs --strict`.  
11. Commit the version bump.  
12. Create an annotated git tag.  
13. Push the branch and tag to `origin` (skipped when running `--test-release`).

If any step fails (for example, tests fail or versions do not match), the script prints an error and exits without completing the release.

## 5. Release Modes And Examples

You can run the release script in different ways depending on how you want to control the version.

### 5.1 Automatic Maintenance Release (Default)

If you run `tools/release/release.py` with no version arguments, it computes the **next maintenance version** automatically.

Example:

```bash
tools/release/release.py
```

Behavior:

* Reads `current_version` (for example `0.2.1.0`).  
* Computes `next_version` as the next maintenance version (for example `0.2.2.0`).  
* Prints:

  ```text
  Current version: 0.2.1.0
  Planned version bump: 0.2.1.0 -> 0.2.2.0
  Proceed with release? [y/N]:
  ```

* Only proceeds with the release if you respond with `y` or `yes`. Any other input aborts.

This mode is convenient for routine maintenance updates.

### 5.2 Automatic Next Version By Mode (`--next`)

You can ask the script to compute the next version using a specific mode:

```bash
tools/release/release.py --next major
tools/release/release.py --next minor
tools/release/release.py --next maintenance
tools/release/release.py --next build
```

Behavior:

* Reads the current version.  
* Computes the next version using the requested mode.  
* Shows the current and proposed version, then waits for a `y` / `yes` confirmation.  
* Runs the release flow after you confirm.

Use this when you want to clearly indicate the type of release (major, minor, maintenance, build) without manually typing the version string.

### 5.3 Explicit Version (`--version`)

If you want complete control of the target version, you can pass it explicitly:

```bash
tools/release/release.py --version 0.3.0.0
```

Behavior:

* Validates the explicit version string.  
* Skips auto-computation since you already chose the version.  
* Does not ask for version confirmation (you have already decided the version).  
* Proceeds with the release steps directly.

This mode is helpful when you have a predefined release version (for example, aligning with external documentation or planning notes).

### 5.4 Dry Run (`--dry-run`)

You can preview what the script would do without performing any changes:

```bash
tools/release/release.py --dry-run
tools/release/release.py --next minor --dry-run
tools/release/release.py --version 0.3.0.0 --dry-run
```

Behavior:

* Computes the target version (if needed).  
* Prints a step-by-step list of planned actions, including the version bump and git operations.  
* Exits without touching any files, running tests, committing, tagging, or pushing.

Use this to sanity-check a release before running it for real.

### 5.5 Skipping Tests (`--skip-tests`)

You can skip running `pytest` during a release (not recommended for normal use):

```bash
tools/release/release.py --skip-tests
tools/release/release.py --next minor --skip-tests
tools/release/release.py --version 0.3.0.0 --skip-tests
```

The release flow remains the same except the test step is skipped.

### 5.6 Target Branch (`--branch`) And Tag Prefix (`--tag-prefix`)

By default, the release script operates on `main` and uses `v` as the tag prefix.

You can override these:

```bash
# Release from stable
tools/release/release.py --branch stable

# Release from stable with minor bump
tools/release/release.py --branch stable --next minor

# Use a custom tag prefix, for example pypnm-0.3.0.0
tools/release/release.py --version 0.3.0.0 --tag-prefix pypnm-
```

If you use the optional aliases from `scripts/install_aliases.sh`, the defaults are:

* `pypnm-release` runs on `main` with the default maintenance bump.  
* `pypnm-release-hot-fix` runs on `hot-fix` and bumps the build segment.  

The tag name is always built as `<tag-prefix><version>`, for example:

* `v0.2.2.0`  
* `pypnm-0.3.0.0`

### 5.7 Test-Only Release (`--test-release`)

Use this to exercise the full release flow locally without modifying Git history.

```bash
tools/release/release.py --test-release
```

Behavior:

* Runs the same checks as a normal release (hygiene scans, tests, docker/k8s preflight, mkdocs).
* Does not checkout/pull the release branch.
* Skips commit, tag, and push steps.
* Restores version files and TAG placeholders back to the original version.

### 5.8 Commit Report Only

Use these when you only want a change summary report without running the release flow:

```bash
# Report the previous commit
tools/release/release.py --last-commit-report

# Report the current commit
tools/release/release.py --latest-commit-report
```

Behavior:

* Writes a markdown report under `release-reports/`.
* Prints the section summary table in the CLI.
* If multiple commits are ahead of the upstream branch, includes an additional summary for the pending range.

## 6. Standard Release Flow On `main`

Below is an example of a typical release workflow using automatic maintenance bumping on `main`:

```bash
# 1) Make sure main is up to date and clean
git checkout main
git pull origin main
git status

# 2) Optional: inspect the current version
tools/release/release.py --dry-run

# 3) Run the real release (auto maintenance bump)
tools/release/release.py
```

Results:

* `src/pypnm/version.py` is updated (for example `0.2.1.0` -> `0.2.2.0`).  
* `pyproject.toml` `[project].version` is updated to the same value.  
* A commit `Release 0.2.2.0` is added on `main`.  
* Tag `v0.2.2.0` is created and pushed to `origin`.  
* You can later reproduce this release with:

  ```bash
  git checkout v0.2.2.0
  ```

If you prefer to explicitly control version semantics, replace the last step with:

```bash
# Minor release
tools/release/release.py --next minor

# Or a fully explicit version
tools/release/release.py --version 0.3.0.0
```

## 6. Preflight controls and prerequisites

* Skip tests: `--skip-tests` (omits pytest).  
* Skip Docker preflight: `--skip-docker-test` (omits `tools/local/local_container_build.sh --smoke`).  
* Docker preflight requirements: Docker Engine with buildx and the docker compose plugin on PATH (for Debian/Ubuntu you can install via apt, or use the official Docker CE repository), and permission to talk to the daemon (use `sudo` or add your user to the `docker` group and re-login). If buildx is missing, Docker will fall back to the legacy builder and emit a deprecation warning during image builds.

Example (Debian/Ubuntu) to satisfy the preflight prerequisites:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-buildx-plugin docker-compose-plugin
# allow non-root docker (log out/in after this):
sudo usermod -aG docker "$USER"
```

## 7. Quick Reference

* Automatic maintenance release (prompted):

  ```bash
  tools/release/release.py
  ```

* Automatic next version by mode (prompted):

  ```bash
  tools/release/release.py --next major
  tools/release/release.py --next minor
  tools/release/release.py --next maintenance
  tools/release/release.py --next build
  ```

* Explicit version (no version prompt):

  ```bash
  tools/release/release.py --version 0.3.0.0
  ```

* Dry run only:

  ```bash
  tools/release/release.py --dry-run
  ```

* Release from another branch (for example future `stable`):

  ```bash
  tools/release/release.py --branch stable --next minor
  ```

* Test-only local release (no commit/tag/push):

  ```bash
  tools/release/release.py --test-release
  ```

With this model, the `tools/release/release.py` script is the primary entry point for PyPNM releases. It computes or accepts the version, updates all necessary version files, runs tests, commits, tags, and pushes the result, giving you a repeatable and controlled release process.
