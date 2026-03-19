# Git Save

`git-save.sh` is the standard local save helper for PyPNM development.

Path:

```bash
./tools/git/git-save.sh
```

## Purpose

Use this tool to:

- run the standard local quality gates
- stage the current repository changes
- advance the local build notation before commit
- create a timestamped commit

This is a developer save helper, not a release workflow.

## Default Behavior

When you run `git-save.sh`, it performs these steps:

1. Runs quality and hygiene checks:
   - `ruff check src`
   - `pytest -q`
   - secret scan
   - encrypted secret scan
   - MAC scan
2. Bumps only the `BUILD` segment of the version
3. Stages repository changes with `git add -A`
4. Creates your requested commit, including the updated version files

The build bump updates only:

- `src/pypnm/version.py`
- `pyproject.toml`

It does not rewrite README or docs tag placeholders during `git-save.sh`.

## Important Version-Control Note

Example:

```text
Working tree before save:  1.5.3.0
Committed change set:      1.5.3.1
```

This build bump is part of the save commit. If you run `git-save.sh --push`,
the pushed commit already includes the updated version notation.

## Usage

```bash
./tools/git/git-save.sh --commit-msg "Feature: add health memory reporting
- add rss_bytes to the /health response
- add pytest coverage for the health payload"
```

Optional push:

```bash
./tools/git/git-save.sh --commit-msg "Docs: update health endpoint docs
- document memory and data sizing fields" --push
```

## Relationship To Release Tooling

Use `git-save.sh` for normal development commits.

Use `tools/release/release.py` when you need a real release flow that:

- computes or accepts a release version
- runs release preflight checks
- commits the release version
- creates a git tag
- pushes the branch and tag

`git-save.sh` does not replace the release process.
