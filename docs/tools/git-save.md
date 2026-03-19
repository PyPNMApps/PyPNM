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
- create a timestamped commit
- advance the local build notation after the commit

This is a developer save helper, not a release workflow.

## Default Behavior

When you run `git-save.sh`, it performs these steps:

1. Runs quality and hygiene checks:
   - `ruff check src`
   - `pytest -q`
   - secret scan
   - encrypted secret scan
   - MAC scan
2. Stages repository changes with `git add -A`
3. Creates your requested commit
4. Bumps only the `BUILD` segment of the version
5. Leaves the version bump as local, uncommitted file changes

The post-save version bump updates only:

- `src/pypnm/version.py`
- `pyproject.toml`

It does not rewrite README or docs tag placeholders during `git-save.sh`.

## Important Version-Control Note

After `git-save.sh` completes successfully, your working tree will usually still
show modified version files.

That is expected.

Example:

```text
Committed change set:      1.5.3.0
Local working tree after:  1.5.3.1
```

This local build bump is a notation advance for the next save/release cycle. It
is not automatically committed or pushed by `git-save.sh`.

If you run `git-save.sh --push`, only the newly created content commit is
pushed. The local post-save version bump remains uncommitted until a later save
or release flow captures it.

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
