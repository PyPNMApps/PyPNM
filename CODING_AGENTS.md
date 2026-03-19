# General-Purpose AI Coding Guide

This document provides a generic coding guide for AI contributors. It focuses on code style,
reuse, and maintainability.

## Core Principles

- Reuse before adding: prefer existing types, helpers, models, and utilities.
- Keep diffs minimal and focused; avoid formatting churn.
- Preserve existing naming, alignment, and whitespace patterns.
- Favor clarity and explicit typing over clever shortcuts.
- Review this document before making any changes.
  This is a generic guide and does not replace `AGENTS.md`.

## Reuse-First Checklist

Before introducing new types, validators, formats, or storage conventions:

- Search for similar helpers in `src/pypnm/lib/` and `src/pypnm/api/`.
- Check `tools/agent-review/` for any reuse or symbol index guidance.
- Prefer existing semantic aliases over raw `str` identifiers.
- Prefer existing constants over inline values.
- Prefer existing Pydantic models for public data structures.
- Refer to shared utilities and helpers before creating new classes.
- For SNMP-related operations, check `Snmp_v2c` first before creating new helpers. If logic is generic/reusable, add it as a static/class method on `Snmp_v2c`.

## Common Locations To Consult

- Types and semantic aliases: `src/pypnm/lib/types.py`
- Constants: `src/pypnm/lib/constants.py`
- Validators and parsing helpers: `src/pypnm/lib/`
- Config models and defaults: `src/pypnm/config/`
- Shared API models and schemas: `src/pypnm/api/` (including `src/pypnm/api/common/`)

## Coding Style (General)

- Use built-in generics (`list[str]`, `dict[str, int]`) and `A | B` unions.
- Avoid `Any` unless unavoidable; isolate and justify its usage.
- Annotate all function arguments and return types.
- Prefer classes or static methods over standalone functions.
- Use Pydantic `BaseModel` for public interfaces instead of raw dicts.
- Keep public method docstrings detailed; private method docstrings minimal.

## Workflow Guidance

- Validate changes with repository test entry points.
- When adding new behavior, include tests covering the change.
- New classes must have pytest coverage at a minimum for IPC and system calls.
- Use `SystemCall` (`src/pypnm/lib/system_call/`) for subprocess/system calls; do not call `subprocess.run` directly in app code.
- Avoid `try`/`except` inside hot loops; Ruff PERF rules flag this often. Move exception handling into a helper or restructure the loop before handing back commit/save commands.
- Avoid broad refactors unless explicitly requested.
- Any changes to `deploy/docker/config/system.json` must also be made in `demo/settings/system.json`.
- Keep `deploy/docker/config/system.json.template` aligned with `deploy/docker/config/system.json`.
- Keep a brief summary of user prompts after any request for a commit message and track changes since the most recent commit message request.
- When asked for a commit message, respond with the specified format, keep it succinct, and include all changes since the last commit message request.
- Before changing version behavior or release tooling, review `tools/git/`,
  `tools/release/`, and `tools/support/bump_version.py` to avoid version-control
  drift.
- `tools/git/git-save.sh` advances the local `BUILD` notation in
  `src/pypnm/version.py` and `pyproject.toml` before creating the save commit.
- The `git-save.sh` commit includes the bumped version files; do not describe
  that save-path build bump as a release or tag.
- `tools/release/release.py` is the only supported flow for committed release
  version updates, tags, and pushes.

## Commit Message Format
- If request via chat request starts with commit-msg, then preface command ./tools/git/git-save.sh with commit-msg "<commit-msg>"
- One line summary (max 50 characters)
- One line Summary start: Feature: , Bugfix: , Docs: , Refactor: , Test:
- Detailed description lines (max 72 characters per line); every line after the first must start with `-`
- When the user asks for a commit message, provide plain text for direct paste into the terminal or UI text box.
- Do not wrap commit message suggestions in quotes (`"`), backticks (`` ` ``), or code fences unless the user explicitly asks for that format.
- Prefer detailed commit messages that describe the current change set clearly.
- Do not default to a one-line commit message when the change set is broad; provide a title plus concise bullet points.
- Avoid redundant wording and avoid repeating the exact prior commit message suggestion unless the diff is unchanged and the user explicitly asks to reuse it.
- If the user asks for "in a text box", return plain text only (no markdown fence).
- If the user asks for "in a markdown text box", return the commit message inside a fenced code block with `text`.

## Agent Constraints

- General workflow:
  - Make minimal diffs; avoid formatting churn.
  - Preserve whitespace/alignment in existing files (no auto-reflow).
  - Do not add broad refactors unless explicitly requested.
  - Provide an end-of-run Agent Review Bundle summary: goal, changes, files, tests, notes.
- Typing and API style:
  - Strict typing everywhere; avoid `Dict`/`List`/`Tuple`/`Union` and avoid `Any`.
  - Prefer built-in generics (`dict[str, int]`, `list[str]`) and `A | B` rather than `Union`.
  - Prefer Pydantic `BaseModel` over dict returns for public interfaces.
  - Device-scoped API responses must follow the canonical top-level `device` block contract (`device.mac_address`, `device.system_description`).
  - Do not omit `device.system_description` on device-scoped responses; when unavailable, return an empty sysDescr model rather than `null`.
  - `BaseModel` fields must be one-line `Field(...)` declarations with descriptions.
  - Avoid generic returns; every method must have an explicit return type annotation.
  - Every method argument must have an explicit type annotation.
  - Public/shared method types must be defined in `src/pypnm/lib/types.py`.
  - Only define local types in a module when the type is strictly private and not reused.
  - Common folder methods must use types defined in `src/pypnm/lib/types.py`.
- Prefer `match/case` over long if/else chains.
- No one-line if statements (E701 compliance).
- Avoid 3+ nested loops; 2 nested loops discouraged unless necessary.
- If `STATUS` is used as a return type, return `STATUS_OK` or `STATUS_NOK` for readability.
- Code structure and documentation:
  - Prefer classes/static methods; minimize standalone global functions.
  - Public methods must have detailed docstrings; private methods minimal.
  - Keep code self-documented; avoid method-level debug logging.
  - Logger pattern in classes: `self.logger = logging.getLogger(f"{self.__class__.__name__}")`.
- Release hygiene / headers:
  - Code files must include `SPDX-License-Identifier: Apache-2.0`.
  - Copyright lines must include only the year or year range (no author names).
  - Any touched code files must have SPDX copyright year updated per Repo Hygiene rules (single year or range).
  - Do not add SPDX headers to Markdown files.
  - Remove SPDX lines embedded inside Markdown code blocks if encountered (especially SQL appendices).
- Docs / Markdown rules (MkDocs + GitHub compatible):
  - No emojis in docs.
  - No horizontal rules (`---`) in Markdown.
  - Keep tables ~132 characters wide when possible.
  - Use placeholders consistently in examples:
    - MAC: `aa:bb:cc:dd:ee:ff`
    - IP: `192.168.0.100`
    - system_description JSON: `{"HW_REV":"1.0","VENDOR":"LANCity","BOOTR":"NONE","SW_REV":"1.0.0","MODEL":"LCPET-3"}`
  - For code file links in docs: use HTTP GitHub links; relative links only for other Markdown files.
  - Always include a downloadable link at the end of any Markdown you generate (when generating Markdown as an artifact in chat; for repo docs, follow repo conventions).
- Shell scripts:
  - Proper indentation.
  - Emojis allowed only in `install.sh` and `pypnm-cmts` CLI output; do not use emojis elsewhere.
- Testing expectations:
  - Run at least: `python3 -m compileall src`, `ruff check src`, `ruff format --check .`, `pytest -q`.
  - After any code change, run `ruff check src` and `pytest -q`. If only Markdown changes are made, run `mkdocs build -s` instead.
  - Review new loops and exception paths for Ruff performance rules before finalizing; do not rely on the user to discover PERF issues during `git-save.sh`.
  - This is mandatory for every code update in this repo: do not finalize work without reporting `ruff check` and `pytest` results (or a clear blocker).
  - If an integration test is optional/gated (for example Postgres DSN), note skips explicitly in the summary.
- Troubleshooting:
  - When debugging endpoint behavior, include `tail -n 25 /home/dev01/Projects/PyPNM/logs/pypnm.log` in the troubleshooting steps.

## Endpoint Requirements

- Device-scoped API responses must use the canonical top-level `device` block.
- Canonical device fields are `device.mac_address` and `device.system_description`.
- Do not introduce new top-level `mac_address` or top-level `system_description` fields for device-scoped responses.
- `device.system_description` must always be present for device-scoped responses; return an empty sysDescr model when unavailable (never `null`).
- Shared response models (for example `BaseDeviceResponse` / `CommonResponse`) must preserve the canonical `device` shape for endpoint outputs.
- If legacy constructor/input shims are used internally for compatibility, endpoint JSON output must still use the canonical `device` block.

## Pytest Guidance (PyPNM Pattern)

- Place new tests under `tests/` with `test_*.py` naming.
- Prefer small, focused unit tests that mirror the existing test style.
- Use fixtures for shared data (see current `tests/` patterns).
- Prefer module-level test functions over new class wrappers unless an existing test uses classes.
- Reuse `tests/files/` for binary fixtures and sample data.
- Favor hermetic tests: no live devices, no external services.
- When testing IPC or system calls, isolate behavior with fakes/mocks and assert edge cases.
- Keep tests aligned with existing patterns in similar modules before introducing new structures.
  Start by locating a similar test file and mirror its structure.

## Notes

- This document is intentionally generic. Use `AGENTS.md` for this repository’s
  authoritative rules and workflow constraints.
