## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

### Summary
Updated the FAQ note to explicitly call out `capture_group_id` as canonical and `capture_group` as a transitional fallback, and removed the completed TODO.

### Modified Files
- docs/issues/index.md
- docs/todo/todo.md

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass (375 files already formatted)
- `pytest -q` → pass (585 passed, 4 skipped)

### Tests
- `pytest -q` → pass (585 passed, 4 skipped)
- `ruff check .` → pass
- `ruff format --check .` → pass

### Notes / Warnings
- pytest skips: `PNM_CM_IT` not set (3 tests), `PYPNM_DB_POSTGRES_DSN` not set (1 test)

### Remaining TODOs / Follow-Ups
- None

# FILE: docs/issues/index.md
# Reporting Issues

If you encounter a bug or unexpected behavior while using PyPNM, please report it
so we can investigate and resolve the issue. This document outlines the steps to
create a support bundle that captures the necessary data for debugging.

[REPORTING ISSUES](reporting-issues.md)

## Support Bundle Script

PyPNM includes a support bundle script that collects relevant logs, database
entries, and configuration files related to your issue. This script helps
sanitize sensitive information before sharing it with the PyPNM support team.

[Support Bundle Builder](support-bundle.md)

## FAQ

### Multi-capture results return 404 with legacy operation_capture.json

The canonical key is `capture_group_id`, but `capture_group` is still accepted
as a fallback for existing persisted JSON during this transition. If multi-
capture result endpoints return 404 while `operation_capture.json` stores the
legacy key, upgrade to a build that accepts it and backfills the mapping into
the DB.

# FILE: docs/todo/todo.md
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Maurice Garcia -->

# TODO

- Add the agent review bundle summary template block at the top of all `*.review.md` bundles.
- Update agent response preferences: do not print file contents in chat unless explicitly requested.
- Document the 3000-line multi-part agent review bundle requirement in AGENTS.md.
