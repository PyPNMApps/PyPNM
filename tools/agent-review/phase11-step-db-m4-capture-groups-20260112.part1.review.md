## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

### Summary
Shifted capture-group and operation linkage persistence to DB-backed repositories with JSON fallback/backfill, aligned schema assets, and updated tests to seed DB transactions for capture group linking while keeping existing API shapes stable. Added a brief FAQ entry for the legacy operation_capture key handling, recorded a TODO to confirm the FAQ update, and documented the multi-part bundle line cap.

### Modified Files
- AGENTS.md
- docs/design/db/database-backend-burndown.md
- docs/design/db/database-backend.md
- docs/design/db/schema_postgres.sql
- docs/design/db/schema_sqlite.sql
- docs/issues/index.md
- docs/todo/todo.md
- src/pypnm/api/routes/advance/common/operation_manager.py
- src/pypnm/api/routes/common/classes/file_capture/capture_group.py
- src/pypnm/api/routes/common/classes/file_capture/pnm_file_opearation.py
- src/pypnm/api/routes/common/classes/file_capture/pnm_file_transaction.py
- src/pypnm/api/routes/docs/pnm/files/service.py
- src/pypnm/lib/db/capture_group_repository.py
- src/pypnm/lib/db/db_schema_manager.py
- src/pypnm/lib/db/transaction_repository.py
- src/pypnm/startup/startup.py
- tests/test_capture_group_empty_transaction.py
- tests/test_capture_group_persistence_normalizes_transaction_id.py
- tests/test_db_schema_manager.py
- tests/test_multi_channel_estimation_result.py
- tests/test_multi_channel_estimation_start_and_analysis.py
- tests/test_multi_rxmer_result_resolves_transactions.py
- tests/test_multi_rxmer_start_returns_operation_and_group.py
- tests/test_operation_manager_capture_group_id.py
- tests/test_operation_manager_get_capture_group.py
- tests/test_operation_workflow.py
- tests/test_transaction_id_persistence_guards.py
- tests/test_transaction_repository.py

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
- Confirm the FAQ entry for legacy operation_capture capture_group fallback is published.

# FILE: AGENTS.md
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Maurice Garcia -->

# AGENTS.md

This file provides guidance for coding agents working in this repository.
Keep it short, accurate, and updated when workflows change.

## Agent Permissions

<environment_context>
    <sandbox_mode>danger-full-access</sandbox_mode>
    <network_access>enabled</network_access>
    <!-- Access is governed by this file and explicit user approval -->
</environment_context>

## Project Basics

- Language: Python (3.10+)
- This repo is NOT greenfield; extend existing code and patterns.
- Build/test entry points are defined in `pyproject.toml`, `Makefile`, or `scripts/`.
- Read `README.md` first for setup and usage.
- Type checking is strict; avoid `Any` and generic container types.
- Ruff compliance is required (do not auto-format unless explicitly requested).

## External Consumers (Compatibility Contract)

- PyPNM is the authoritative engine and is consumed by downstream repos (example: PyPNM-CMTS).
- Preserve public API stability unless the user explicitly approves breaking changes.
- Do not embed downstream app concerns into PyPNM (keep PyPNM reusable and transport-agnostic).
- If a change affects downstream repos, call it out explicitly before making it.

## Repo Conventions (PyPNM)

- Persistence is filesystem-based artifacts plus metadata persistence per the DB backend design:
  - Binaries and derived artifacts remain on disk under `.data/` roots.
  - Transaction/group/operation metadata is DB-backed (SQLite or Postgres) per `docs/design/db/`.
- DB backend selection is owned by PyPNM at install time (no runtime “auto switching”).
- SQLite is intended for single-writer deployments (standalone/lab/demo).
- Postgres is recommended for multi-worker / multi-process deployments.

## Documentation

- Docs must follow the existing repo docs layout and conventions.
- Update docs alongside code changes (choose the correct location by inspecting the existing docs tree; do not invent parallel structures).
- Do not modify `mkdocs.yml` or navigation unless explicitly required by the task.
- Markdown must render correctly in both MkDocs and GitHub.
- No emojis in documentation.
- Use generic placeholders:
  - MAC: `aa:bb:cc:dd:ee:ff`
  - IP: `192.168.0.100`
- Emojis are allowed only in `install.sh`; they are prohibited everywhere else.
- When adding new terms or acronyms, update `docs/definition/index.md` and keep entries in alphabetical order.
- After completing a task, create a single “agent review” file that concatenates the full contents of all files changed in that task (path and naming should follow existing repo practice).
- Always regenerate the agent review bundle after any subsequent edits so it reflects every changed file.
- When an error is fixed, add or update a FAQ entry with the error and resolution, and add a TODO entry noting the FAQ update requirement.

### Reuse Index

- Agents MUST consult the existing reuse / symbol index under `tools/agent-review/` (if present) before introducing new:
  - types, validators, ID formats, storage conventions, persistence adapters, or config namespaces
- Any deviation requires an explicit gap justification and user approval.

## DB Backend Migration (Locked Decisions)

Agents working on the DB backend refactor MUST follow the locked decisions recorded in the design docs (see `docs/design/db/`):

- PyPNM owns persistence, schema initialization, and DB APIs.
- Install-time backend selection via `install.sh` flags + interactive default to SQLite.
- Postgres secrets via env var overrides (no plaintext requirement in tracked JSON).
- Idempotent schema apply using shipped DDL assets + seeding `UNKNOWN` sysDescr + default artifact store(s).
- SQLite for single-writer; Postgres recommended for multi-worker / multi-process (especially downstream orchestration use).
- Paths stored in DB are portable (app-root relative), resolved at runtime.
- CI validates SQLite (required) and Postgres (service container, recommended as required).
- JSON ledger persistence is deprecated and removed from runtime paths (optional offline migrator only).

## Configuration

- `system.json` is the single source of truth.
- New configuration namespaces must be implemented as Pydantic BaseModels.
- BaseModels must use one-line `Field(..., description="...")`.
- Avoid generic `str` for semantic identifiers or paths in public models and APIs; use an existing semantic type or add a new alias in `src/pypnm/lib/types.py`.
- When working with MAC or inet strings, validate using `MacAddress()` or `Inet()` instead of assuming `str(...)` formatting is valid.
- Request override defaults: missing or null means use `system.json` defaults; blank strings are invalid.

## Timestamp Conventions

- All stored timestamps are epoch seconds.
- Convert to ISO-8601 only at display or external response boundaries.

## Coding Guidelines (Strict)

- No generic container imports (`Dict`, `List`, `Tuple`, `Union`).
  Use built-in types and `|`.
- Avoid `Any` unless unavoidable; isolate and justify its usage.
- Every function argument must be annotated.
- Avoid `None` returns; prefer empty values unless `None` is semantically required.
- Avoid magic numbers; use named constants.
- Prefer `BaseModel` over raw dicts for public/stateful structures (state, configuration, persistence records).
- dicts are allowed only for short-lived internal glue logic.
- Prefer classes with static methods over standalone functions.
- Public methods MUST have detailed docstrings.
- Private methods may have minimal docstrings.
- Avoid method-level debug logs.
- Do not add Ruff ignores (`# noqa`, `# ruff: noqa`). If an ignore is needed, ask for permission first.
- Logging pattern in classes:

  ```python
  self.logger = logging.getLogger(f"{self.__class__.__name__}")
  ```

- Prefer `match/case` over long if/else chains.
- No code should contain 3+ nested loops. 2 nested loops are discouraged unless necessary.
- No one-line if statements (E701).
- Preserve all existing whitespace and alignment.
- Never auto-format or re-align code.
- Do not enforce snake_case; keep existing naming conventions as-is.

## FastAPI Guidelines (PyPNM)

- Router files must be lean:
  - `router.py` contains routing glue only (APIRouter configuration, endpoint registration, HTTP status translation).
  - No business logic in `router.py`. Business logic must live in `service.py` for that route group (same folder) or a shared service module if reused.
- All request/response bodies must be Pydantic BaseModels.
- Prefer POST for payload submission and endpoint contracts (PyPNM default).
  - Allow GET only where already present or clearly appropriate (health, readiness, version, status).
- Reuse shared models under the existing `src/pypnm/api/common/` structure (inspect current tree before adding anything new).
- Do not block request paths with `time.sleep()`.

## Tests (Mandatory)

- Every phase deliverable MUST include pytest coverage for new or changed behavior.
- Do not claim a phase item is complete unless pytest has been added and executed (or a concrete blocker is documented).
- Tests must remain hermetic: no live CMTS/cable modem dependencies.

## Burndown Governance

- Agents MUST consult the current burndown and DB design docs before implementing work.
- Agents MUST NOT update burndown checkmarks unless explicitly instructed by the user.
- Code written does not imply progress accepted.

## Workflow Rules

- When the user says “train”, read code silently until told otherwise.
- Do not assume missing context; ask.
- Keep changes minimal and scoped.
- Do not refactor unrelated code.
- Avoid destructive commands unless explicitly requested.
- Do not print file contents into chat unless the user explicitly requests it; ask first if unsure.
- Always end tasks with an agent review bundle containing the full contents of all files touched in the task.
- Agent review bundles must start with the standard summary template block below (before any `# FILE:` sections).
- If a review bundle exceeds 3000 lines, split it into multiple bundles (part1/part2/part3...) and keep each bundle at or below 3000 lines without splitting files.
- When the user says `CAT_FILES`, create a single bundle file containing the full contents of every file touched in the task, each preceded by `# FILE: <path>`, and provide the `cat` command for the bundle.

### Agent Review Bundle Summary Template (Standard)

Use this Summary block at the very top of every `*.review.md` bundle (before any `# FILE:` sections).

### Summary
<1–3 sentences describing what changed and why. Keep it factual and phase-scoped.>

### Modified Files
- <absolute or repo-relative path 1>
- <path 2>
- <path N>

### Commands Executed And Results
- `<command 1>` → <result (pass/fail + key output)>
- `<command 2>` → <result>
- `<command N>` → <result>

### Tests
- `pytest` → <pass/fail + notes>
- `ruff` → <pass/fail + notes>
- <other> → <pass/fail + notes>

### Notes / Warnings
- <any relevant warnings, deprecations, expected exclusions, or operational notes>
- <or: None>

### Remaining TODOs / Follow-Ups
- <todo 1>
- <todo 2>
- <or: None>

## Repo Hygiene

- License is Apache-2.0; keep SPDX headers and `NOTICE`.
- For any modified or newly created file, update the SPDX header year to 2026.
- If a file already has a SPDX year and the year has changed, update it as a range (example: 2025 -> 2025-2026).
- Keep `tools/` organized by category.
- Do not add files directly under `tools/` root.

## Agent Self-Checks

Before responding:

- Re-read this file and `README.md`.
- Confirm pytest coverage exists or is explicitly blocked.
- Confirm pytest and ruff output have no deprecation warnings (treat as failures).
- Confirm changes align to the current phase and do not leak scope.
- Confirm formatting and alignment are preserved.

## Training

When the user requests "train", read the following sources:

- `AGENTS.md`
- `docs/design/db/` (all files)
- `src/pypnm/lib/` (DB/persistence + config helpers)
- `src/pypnm/api/` (routing/service patterns, where applicable)
- `tools/agent-review/` (all files, if present)

# FILE: docs/design/db/database-backend-burndown.md
# PyPNM DB Backend Refactor Burndown (With ToC)

## Table Of Contents

- [Overview](#overview)
- [Recent Status Update (2026-01-11)](#recent-status-update-2026-01-11)
- [Phase 7.7 Burndown Tracker (Updated 2026-01-11)](#phase-77-burndown-tracker-updated-2026-01-11)
- [Locked Decisions (Selection Summary)](#locked-decisions-selection-summary)
- [Milestones](#milestones)
- [Phase 0 · Guardrails And Release Hygiene (M0)](#phase-0--guardrails-and-release-hygiene-m0)
- [Phase 1 · Install-Time Backend Selection And Config Contract (M1)](#phase-1--install-time-backend-selection-and-config-contract-m1)
- [Phase 2 · Schema Introduction And DB Abstraction Layer (M2)](#phase-2--schema-introduction-and-db-abstraction-layer-m2)
- [Phase 3 · Transactions Migration (Replace `transactions.json`) (M3)](#phase-3--transactions-migration-replace-transactionsjson-m3)
- [Phase 4 · Capture Group And Operation Migration (Replace `capture_group.json`, `operation_capture.json`) (M4)](#phase-4--capture-group-and-operation-migration-replace-capture_groupjson-operation_capturejson-m4)
- [Phase 5 · Artifact Linkage (Filesystem References) (M5)](#phase-5--artifact-linkage-filesystem-references-m5)
- [Phase 6 · Remove Ledger JSON Design And Code (M6)](#phase-6--remove-ledger-json-design-and-code-m6)
- [Phase 7 · Pytest And GitHub Actions Migration (M7)](#phase-7--pytest-and-github-actions-migration-m7)
- [Cross-Cutting Requirements](#cross-cutting-requirements)
- [Suggested Codex Tracking Rules](#suggested-codex-tracking-rules)

## Overview

This burndown converts PyPNM from JSON ledger persistence under `.data/db/*.json` to a DB-backed persistence layer with install-time backend selection:

- SQLite (local file under `.data/db/pypnm.sqlite3`)
- PostgreSQL (external service)

Binary artifacts remain filesystem-based. The DB stores metadata and references via `artifact_stores`, `file_artifacts`, and `transaction_artifacts`.

PyPNM owns backend selection at install time. PyPNM-CMTS inherits this selection through PyPNM and must not implement a separate DB selection mechanism.

Concurrency note (design constraint carried into implementation and docs):

- SQLite is supported and recommended for single-process / single-writer deployments (PyPNM standalone, labs, demos).
- Postgres is recommended when PyPNM is used as a dependency in PyPNM-CMTS, or whenever multiple workers/processes may access the DB concurrently.

DB-only cutover policy (current intent):

- Runtime persistence is DB-only once a given domain has landed in DB form (transactions in M3; capture groups/ops in M4; artifacts in M5).
- JSON ledgers become legacy-only for migrated domains:
  - Not written by runtime once the DB write paths land for that domain.
  - Not read by runtime endpoints once DB read paths land for that domain.
  - Optional offline migrator may exist, but is not part of runtime behavior.

## Recent Status Update (2026-01-11)

Work completed since the last burndown sync (per Agent Review Bundles):

- **Transactions are now DB-backed (M3 complete):**
  - Introduced repository helpers for sysDescr/device_details dims and transaction_records.
  - Wired `PnmFileTransaction` reads/writes to DB while preserving legacy payload shapes.
  - Updated file manager reads (`search_files`, `get_mac_addresses`) to query DB-backed repositories.
  - Updated multi-capture result tests to seed DB transactions and added repository unit coverage for:
    - sysDescr de-duplication
    - device_details de-duplication
    - deterministic listing and ordering (timestamp + transaction_id tie-break)

- `install.sh`
  - DB backend selection runs before `pytest` so tests execute against the selected backend contract.
  - Added `--db-install-sqlite` and `--db-install-postgres`, plus an interactive prompt when no flag is provided (defaults to SQLite in non-interactive/CI).
  - Added Postgres DSN prompt with password redaction (passwords are not persisted into `system.json`).
  - Fixed DSN redaction backreference and aligned DSN env-var warning logic to `POSTGRES_DSN_ENV_VAR` via indirect expansion.

- `docs/system/system-config.md`
  - Updated `PnmFileRetrieval` heading/anchor for GitHub compatibility.
  - Documented runtime DB location policy and recommended env var usage for Postgres DSNs.

Out-of-scope but in-flight (separate hygiene workstream): Ruff baseline cleanup (125 remaining issues after `ruff check . --fix`, including `PnmParsers` undefined name).

## Phase 7.7 Burndown Tracker (Updated 2026-01-11)

This tracker is a near-term hygiene lane that should remain compatible with the DB migration. It is not a replacement for the DB cutover milestones.

### Recent Completions

- Unified operation workflow payload shape:
  - Dual-status support (legacy `status` string + canonical `service_status`)
  - Centralized workflow schemas via re-exports
  - Registry status responses aligned to shared `time_remaining` contract
- Multi-capture registry status endpoints aligned to `time_remaining` contract:
  - Multi-RxMER `/advance/multiRxMer/status` (POST)
  - Multi-ChannelEstimation `/advance/multiChannelEstimation/status` (POST)
  - Safe coercion and default fallback when missing/invalid
- Docs updated:
  - `docs/api/fast-api/multi/capture-operation.md` updated to reflect unified payload shape
- Tests added/updated:
  - Operation workflow dual-status tests
  - Multi-RxMER + Multi-ChannelEstimation registry `time_remaining` behavior tests
  - Transaction repository unit tests and multi-capture result tests seeded via DB
- Verification complete:
  - `python3 -m compileall src` pass
  - `ruff check .` pass
  - `ruff format --check .` pass
  - `pytest -q` pass (583 passed, 4 skipped)

### Remaining Phase 7.7 TODOs (Open Items)

1) Address `PytestConfigWarning` related to `asyncio_mode` configuration
   - Goal: eliminate warning via explicit pytest config (no runtime impact, but hygiene blocker)

2) Final “legacy-key hygiene” scan
   - Goal: confirm no remaining deprecated/legacy keys or payload fields are being written or relied upon unintentionally
   - Scope: operation/capture records, workflow responses, and multi-capture start/status/result payloads

### Validation Gate (Must Stay Green)

- `python3 -m compileall src`
- `ruff check .`
- `ruff format --check .`
- `pytest -q`
- Optional (when enabled): SNMP integration tests via `PNM_CM_IT`
- Optional (when enabled): Postgres schema init via `PYPNM_DB_POSTGRES_DSN`

## Locked Decisions (Selection Summary)

This burndown must implement (and keep consistent with the design doc) the locked decision set:

`1A, 2B+2.1B, 3B, 4A(SQLite)+4C(Postgres when PyPNM-CMTS/multi-worker), 5C+5.1A, 6B+6.1A, 7B, 8A`

Implications that must remain explicit in tasks and acceptance criteria:

- PyPNM owns backend selection and schema init; PyPNM-CMTS is a consumer only.
- `install.sh` defaults to SQLite and prompts when no flag is provided.
- Postgres secrets must be supported via env var overrides; `pypnm/pypnm` is dev/CI only.
- Schema apply is idempotent from shipped DDL assets; seeds UNKNOWN sysDescr and artifact store rows.
- SQLite is for single-writer; Postgres is recommended for multi-worker and PyPNM-CMTS.
- DB stores portable app-root relative paths; runtime resolution builds absolute paths.
- CI must validate SQLite and Postgres (Postgres via service container; not “allowed failure”).
- JSON ledgers are deprecated; removal is tracked explicitly in M6 (do not introduce new ledger features).

## Milestones

Status guidance:

- Complete: done and validated.
- In progress: started, partials landed.
- Not started: planned.

Milestone status (as of 2026-01-11):

- M0: In progress (docs updated; packaging/docker hygiene still open)
- M1: In progress (installer selection landed; config template + settings accessors still open)
- M2: **Complete** (DB schema init + backend-aware connection path landed; schema manager in use)
- M3: **Complete** (transactions are DB-backed; `transactions.json` is no longer a runtime write/read dependency)
- M4: Not started (capture groups + operations migration; stops `capture_group.json` / `operation_capture.json` writes)
- M5: Not started (artifact linkage; DB becomes authoritative for path resolution)
- M6: Not started (delete ledger code paths and ledger docs)
- M7: Partially done (Postgres CI job plumbing landed; full DB-backed test suite pending)

## Phase 0 · Guardrails And Release Hygiene (M0)

### Goal

Prevent DB/data leakage into releases and formalize runtime data placement.

### Tasks

- [ ] Add `.data/` and `demo/.data/` to `.gitignore` and confirm no tracked data remains.
- [ ] Ensure Python packaging excludes runtime data:
  - [ ] Exclude `.data/**` and `demo/.data/**` from sdist/wheel.
  - [ ] Confirm build config does not include runtime paths.
- [ ] Ensure Docker build excludes runtime data:
  - [ ] `.dockerignore` includes `.data/`, `demo/.data/`, `*.sqlite3`, `*.db`.
  - [ ] Dockerfiles do not `COPY` `.data/` or demo datasets into images.
- [x] Document runtime DB location rules:
  - [x] SQLite path under `.data/db/`
  - [x] Postgres external (no local DB file)
- [x] Add doc note: demo uses isolated root (`demo/`) and isolated DB.

### Acceptance Criteria

- [ ] Building sdist/wheel does not contain `.data/` or any DB files.
- [ ] Docker images do not contain `.data/` contents.
- [x] Docs state the runtime DB location policy clearly.

## Phase 1 · Install-Time Backend Selection And Config Contract (M1)

### Goal

Make DB backend selection a first-class install-time choice owned by PyPNM and visible in docs.

### Tasks

- [x] Extend `install.sh`:
  - [x] Support `--db-install-postgres`
  - [x] Support `--db-install-sqlite`
  - [x] Add interactive prompt if no flag provided (default: SQLite)
  - [x] Add install-time warning text:
    - [x] SQLite is recommended for standalone PyPNM / single-writer
    - [x] Postgres is recommended for PyPNM-CMTS and/or multi-worker/multi-process
  - [x] Add a Postgres config prompt path when Postgres is selected:
    - [x] Allow DSN entry OR discrete fields that render into a DSN
    - [x] Host / port / database / user / password / ssl mode
    - [x] Ensure password can be provided via env var override (no plaintext requirement in JSON)
    - [x] Ensure passwords are not persisted into `system.json` (DSN redaction + field-based DSN omits password)

- [ ] Add config keys to `settings/system.json.template` (and demo template if used):
  - [ ] `Database.backend` = `sqlite` | `postgres`
  - [ ] `Database.sqlite.path` default `.data/db/pypnm.sqlite3`
  - [ ] Postgres connection settings:
    - [ ] Support `Database.postgres.dsn`
    - [ ] Optional discrete settings for UX (installer can populate DSN)
  - [ ] Support environment variable overrides for secrets (do not require plaintext passwords in tracked JSON)

- [ ] Add `SystemConfigSettings` accessors for DB settings.

- [x] Ensure docs explicitly describe:
  - [x] Install-time backend selection mechanism
  - [x] SQLite vs Postgres recommendation (single-writer vs multi-worker)
  - [ ] PyPNM-CMTS inherits backend (no separate selection)

- [ ] Add pytest coverage for config defaults and validation (missing/blank handling).

### Notes: Postgres Credentials Policy

- Development defaults like `pypnm/pypnm` are acceptable for local dev and CI only.
- Do not recommend these credentials for production.
- Prefer environment variables or a local `.env` file for passwords and DSNs.
- Do not commit `.env` or populated DB settings containing real credentials.

### Acceptance Criteria

- [x] Fresh install can select backend via flag or prompt.
- [ ] Config settings are available via `SystemConfigSettings`.
- [ ] Tests cover selection and default behavior.

## Phase 2 · Schema Introduction And DB Abstraction Layer (M2)

### Goal

Introduce both schemas and a stable DB API that hides backend differences.

### Tasks

- [ ] Ensure schema assets exist and are treated as authoritative:
  - [ ] `docs/design/db/schema_postgres.sql`
  - [ ] `docs/design/db/schema_sqlite.sql`
  - Notes:
    - If DDL currently exists only in design doc appendices, extract it into these authoritative assets.

- [x] Implement DB connection layer in PyPNM:
  - [x] SQLite connection opens with `PRAGMA foreign_keys = ON`
  - [x] SQLite enables WAL + sets a busy timeout (to reduce transient contention)
  - [x] Postgres connection opens via DSN (minimum) or discrete settings
  - [x] Minimal connection factory based on `Database.backend`

- [x] Implement schema apply/init (idempotent, using shipped DDL assets):
  - [x] Apply DDL idempotently on startup/install
  - [x] Seed canonical `UNKNOWN` sysDescr row idempotently
  - [ ] Seed default `artifact_stores` row idempotently:
    - [ ] prod store: `.data/pnm`
    - [ ] demo store: `demo/.data/pnm` (only if demo enabled/used)

- [x] Add “DB health” check function for diagnostics:
  - [x] Connect, verify required tables exist, verify `UNKNOWN` row exists
  - [x] Verify schema version compatibility (`schema_meta.schema_version`)

- [x] Add pytest coverage:
  - [x] SQLite: init creates tables and seed rows (pure unit test)
  - [x] Postgres: init path is wired; CI runs minimal integration

### Acceptance Criteria

- [x] PyPNM can initialize DB schema for SQLite reliably.
- [x] Postgres path is implemented and can be exercised with integration tests.
- [x] `UNKNOWN` sysDescr exists after init.
- [x] Schema version mismatch fails fast with an actionable error.

## Phase 3 · Transactions Migration (Replace `transactions.json`) (M3)

### Goal

Replace JSON transactions ledger with DB-backed `transaction_records` plus de-dup dimensions, and update endpoint read paths.

Cutover note:

- Runtime must stop writing and reading `transactions.json` once DB-backed transactions are enabled.
- Other ledgers (`capture_group.json`, `operation_capture.json`) remain until M4.

### Tasks

- [x] Implement repository/service layer:
  - [x] `SystemDescriptionRepository` (upsert by hash)
  - [x] `DeviceDetailsRepository` (upsert by hash, FK sysDescr)
  - [x] `TransactionRepository` (insert/get/list/search)

- [x] Enforce safeguards:
  - [x] MAC normalization in app (lowercase)
  - [x] Rely on DB CHECK constraints for MAC format enforcement

- [x] Update transaction creation/read code to use DB:
  - [x] Stop writing `transactions.json`
  - [x] Preserve external API shapes as needed by current services/endpoints

- [x] Update file-manager endpoints to query DB (no `transactions.json` traversal):
  - [x] `getMacAddresses`
  - [x] `searchFiles/{mac_address}`
  - [x] `download/transactionID/{transaction_id}` resolves filename via DB record (artifact linkage becomes authoritative in M5)

- [x] Add pytest coverage:
  - [x] Insert transaction creates dims (sysDescr/device details)
  - [x] De-dup sysDescr across multiple transactions
  - [x] De-dup device details across multiple transactions
  - [x] Endpoint-compatible query behavior (service-level tests)

### Acceptance Criteria

- [x] Captures produce DB rows instead of writing `transactions.json`.
- [x] File manager flows can fetch transactions from DB (no JSON ledger traversal for transactions).
- [x] There is no runtime write/read path that touches `transactions.json`.

## Phase 4 · Capture Group And Operation Migration (Replace `capture_group.json`, `operation_capture.json`) (M4)

### Goal

Move multi-capture and operation tracking to DB, updating operation-based endpoints.

Cutover note:

- This phase stops runtime writes to capture-group and operation ledgers.
- Once complete, operation status/result endpoints must resolve via DB-backed repositories.

### Tasks

- [ ] Implement `CaptureGroupRepository`:
  - [ ] Create capture group
  - [ ] Add ordered transaction membership (`position`)
  - [ ] Load capture group with ordered transactions

- [ ] Implement `OperationCaptureRepository`:
  - [ ] Create operation capture linking to capture group
  - [ ] Resolve operation capture -> capture group -> ordered transaction list

- [ ] Update existing grouping/operation services to use DB:
  - [ ] Stop writing `.data/db/capture_group.json`
  - [ ] Stop writing `.data/db/operation_capture.json`
  - [ ] Stop reading capture/operation ledgers from runtime paths

- [ ] Update file-manager endpoint behavior:
  - [ ] `download/operationID/{operation_id}` resolves op -> group -> ordered tx list

- [ ] Add pytest coverage:
  - [ ] Position uniqueness within group
  - [ ] Operation capture references group correctly
  - [ ] Endpoint path resolution uses DB (service-level tests)

### Acceptance Criteria

- [ ] Multi-capture workflows no longer use JSON ledger files.
- [ ] Operation workflows resolve through DB (no JSON traversal).
- [ ] There is no runtime write path that touches capture/operation ledger JSON.

## Phase 5 · Artifact Linkage (Filesystem References) (M5)

### Goal

Make file linkage explicit via `artifact_stores`, `file_artifacts`, and `transaction_artifacts` so file resolution is DB-driven.

### Tasks

- [ ] Implement repositories:
  - [ ] `ArtifactStoreRepository`:
    - [ ] Ensure a default store exists (prod)
    - [ ] Ensure demo store exists when demo mode is used

  - [ ] `FileArtifactRepository`:
    - [ ] Insert/upsert file artifacts (sha256 + relative path)
    - [ ] Store `relative_path` relative to artifact store root
    - [ ] Capture `size_bytes` and optional `mime_type`

  - [ ] `TransactionArtifactRepository`:
    - [ ] Link transaction to artifact via `role`

- [ ] Update capture flow:
  - [ ] On capture success, write artifact row and link to transaction (`role=pnm_raw`)

- [ ] Update upload flow:
  - [ ] Create transaction using `UNKNOWN` sysDescr when sysDescr is missing
  - [ ] Store artifact linkage to uploaded file (`role=pnm_uploaded_raw`)

- [ ] Update file-manager service methods to resolve through artifact linkage:
  - [ ] `get_pnm_path_for_transaction()` resolves by role preference:
    - [ ] Prefer `pnm_raw`
    - [ ] Fallback `pnm_uploaded_raw`
  - [ ] Keep `transaction_records.filename` for readability/back-compat, but do not treat it as authoritative

- [ ] Add pytest coverage:
  - [ ] Resolve absolute paths from `app_root + store.root_path + artifact.relative_path`
  - [ ] Demo root isolation (`demo/.data/...` paths)
  - [ ] ZIP archive generation for MAC and operation uses DB-linked artifacts

### Acceptance Criteria

- [ ] Transactions resolve to binaries without any legacy settings JSON linkage.
- [ ] Demo and prod are isolated by data root and DB.
- [ ] Endpoints resolve files via DB artifact linkage exclusively.

## Phase 6 · Remove Ledger JSON Design And Code (M6)

### Goal

Delete ledger JSON code paths and remove ledger JSON design from documentation, replacing it with DB backend documentation.

### Tasks

- [ ] Remove JSON ledger creation paths:
  - [ ] Stop creating `.data/db/*.json` ledgers in capture flows
  - [ ] Remove any remaining ledger read code paths

- [ ] Remove or deprecate config keys related to ledgers:
  - [ ] `transaction_db`, `capture_group_db`, `operation_db`, `json_transaction_db`

- [ ] Remove or repurpose ledger modules:
  - [ ] Remove `pypnm/lib/db/json_transaction.py` if no longer needed
  - [ ] Remove/retire any code paths that still materialize ledger JSON in memory

- [ ] Documentation cleanup (explicit requirement):
  - [ ] Remove/replace all doc references to:
    - [ ] `.data/db/transactions.json`
    - [ ] `.data/db/capture_group.json`
    - [ ] `.data/db/operation_capture.json`
  - [ ] Update file-manager docs to state DB-backed persistence for transactions/groups/operations
  - [ ] Ensure diagrams and examples reflect DB-backed persistence and artifact linkage

- [ ] MkDocs + tooling support for Mermaid (if not already satisfied in the repo):
  - [ ] Update `mkdocs.yml` to render Mermaid fences (Material: `pymdownx.superfences`)
  - [ ] Add the Mermaid plugin dependency to the docs extras in `pyproject.toml` (avoid redundant deps)

- [ ] Final hygiene scan:
  - [ ] Ensure no `.data/` artifacts are tracked or packaged

### Acceptance Criteria

- [ ] No code path depends on JSON ledgers at runtime.
- [ ] Docs and examples reflect DB backend design (no ledger design remains as “current”).
- [ ] Release artifacts contain no DB data.

## Phase 7 · Pytest And GitHub Actions Migration (M7)

### Goal

Ensure all tests and GitHub workflows pass with the new DB layer, removing ledger assumptions and validating Postgres support.

### Tasks

- [ ] Pytest refactor:
  - [ ] Locate and update/remove any tests that read/write `.data/db/*.json`
  - [ ] Replace ledger fixtures with DB fixtures (SQLite by default)
  - [ ] Add DB test utilities:
    - [ ] Temporary SQLite DB per test (or per module) under `tmp_path`
    - [ ] Schema init helper (idempotent DDL apply)
    - [ ] Seed helper for artifact stores and `UNKNOWN` sysDescr
  - [ ] Convert endpoint-level tests (if present) to use DB-backed services (no JSON)

- [ ] GitHub Actions refactor (required for DB backend release confidence):
  - [ ] Add a DB backend test matrix:
    - [ ] SQLite job (required)
    - [x] Postgres job (required; not “allowed failure”)
  - [x] Postgres service container job:
    - [x] Use `postgres` service with `POSTGRES_USER=pypnm`, `POSTGRES_PASSWORD=pypnm`, `POSTGRES_DB=pypnm`
    - [x] Provide DSN via env var to tests (no committed secrets)
    - [x] Apply schema during test setup (idempotent)
  - [ ] Ensure tests remain hermetic:
    - [ ] No external CMTS/SNMP dependencies in CI

- [ ] Developer documentation:
  - [x] Document what backends CI validates
  - [x] Document how to run Postgres tests locally (docker compose recommended)
  - [x] Document DSN override via environment variables

### Acceptance Criteria

- [ ] `pytest` passes locally for SQLite with DB-backed services.
- [ ] GitHub Actions passes with SQLite in the DB-backed test path.
- [x] Postgres path is validated in CI with a service container.

## Cross-Cutting Requirements

### PyPNM-CMTS Contract

- [ ] PyPNM-CMTS must not select a different backend than PyPNM.
- [ ] All DB interactions in PyPNM-CMTS must occur through PyPNM APIs only.

### Runtime Cutover Rule

- [ ] Runtime must not fall back to JSON ledger reads once DB read paths exist for that domain.
- [ ] Any legacy ledger handling must be isolated to an offline migrator tool (optional) and must not be required for normal runtime.

### Docker And K8 Notes

- [ ] SQLite: require a persistent volume mount for `.data/` and single-writer deployment.
- [ ] Postgres: require DSN secrets/config; stateless PyPNM containers.

### Testing

- [ ] Every phase adds pytest coverage for new/changed behavior.
- [ ] Tests must not require external CMTS or live SNMP.
- [ ] Treat deprecation warnings as failures.

## Suggested Codex Tracking Rules

Codex should maintain a running checklist aligned to these phases:

- Current phase and status
- Files changed in the phase
- Tests added and executed
- CI workflow impacts validated
- Deferred items (with rationale)

# FILE: docs/design/db/database-backend.md
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Maurice Garcia -->

# PyPNM Database Backend Design

## Table Of Contents

- [0. Status Snapshot (2026-01-11)](#0-status-snapshot-2026-01-11)
- [1. Purpose](#1-purpose)
- [2. Scope](#2-scope)
- [3. Non-Goals](#3-non-goals)
- [4. Design Requirements](#4-design-requirements)
- [5. Terminology](#5-terminology)
- [6. Target Operating Model](#6-target-operating-model)
  - [6.1 DB Responsibility Contract](#61-db-responsibility-contract)
  - [6.2 What Stays On Disk](#62-what-stays-on-disk)
  - [6.3 What Moves Into The DB](#63-what-moves-into-the-db)
- [7. Backend Selection And Installation Contract](#7-backend-selection-and-installation-contract)
  - [7.1 install.sh Flags And Interactive Prompt](#71-installsh-flags-and-interactive-prompt)
  - [7.2 Configuration Keys](#72-configuration-keys)
  - [7.3 DB Location Policy](#73-db-location-policy)
  - [7.4 PostgreSQL Authentication And Secrets](#74-postgresql-authentication-and-secrets)
- [8. Release Hygiene Requirements](#8-release-hygiene-requirements)
  - [8.1 Git Ignore And Packaging Exclusions](#81-git-ignore-and-packaging-exclusions)
  - [8.2 Docker And Container Image Hygiene](#82-docker-and-container-image-hygiene)
- [9. Data Model](#9-data-model)
  - [9.1 Dimensions](#91-dimensions)
  - [9.2 Fact Tables](#92-fact-tables)
  - [9.3 Grouping Constructs](#93-grouping-constructs)
  - [9.4 Artifact Linkage](#94-artifact-linkage)
  - [9.5 Constraints And Indexing](#95-constraints-and-indexing)
  - [9.6 UNKNOWN sysDescr Seed Row](#96-unknown-sysdescr-seed-row)
- [10. Path Contract And Portability](#10-path-contract-and-portability)
  - [10.1 Portable Paths](#101-portable-paths)
  - [10.2 Absolute Path Construction](#102-absolute-path-construction)
  - [10.3 Demo Isolation](#103-demo-isolation)
- [11. Endpoint Compatibility Requirements](#11-endpoint-compatibility-requirements)
  - [11.1 Current File Manager Endpoints](#111-current-file-manager-endpoints)
  - [11.2 DB Queries Needed By Each Endpoint](#112-db-queries-needed-by-each-endpoint)
  - [11.3 Artifact Resolution Rules](#113-artifact-resolution-rules)
- [12. Workflows](#12-workflows)
  - [12.1 Upload Flow](#121-upload-flow)
  - [12.2 Download By Transaction ID](#122-download-by-transaction-id)
  - [12.3 Search Files By MAC](#123-search-files-by-mac)
  - [12.4 Download By MAC (ZIP)](#124-download-by-mac-zip)
  - [12.5 Download By Operation ID (ZIP)](#125-download-by-operation-id-zip)
- [13. Documentation And Tooling Updates](#13-documentation-and-tooling-updates)
  - [13.1 Remove Ledger JSON Design From Docs](#131-remove-ledger-json-design-from-docs)
  - [13.2 Add Mermaid Support To MkDocs And pyproject](#132-add-mermaid-support-to-mkdocs-and-pyproject)
- [14. Migration Strategy](#14-migration-strategy)
  - [14.1 Cutover Philosophy](#141-cutover-philosophy)
  - [14.2 Legacy Ledger Data](#142-legacy-ledger-data)
  - [14.3 Implementation Milestones And Cutover Moment](#143-implementation-milestones-and-cutover-moment)
- [15. Testing Requirements](#15-testing-requirements)
  - [15.1 CI And GitHub Workflow Considerations](#151-ci-and-github-workflow-considerations)
- [16. Concurrency Model And Backend Guidance](#16-concurrency-model-and-backend-guidance)
  - [16.1 SQLite Concurrency Limits](#161-sqlite-concurrency-limits)
  - [16.2 PostgreSQL Recommendation Guidance](#162-postgresql-recommendation-guidance)
- [17. Appendix A: Mermaid ER Diagram](#17-appendix-a-mermaid-er-diagram)
- [18. Appendix B: PostgreSQL DDL](#18-appendix-b-postgresql-ddl)
- [19. Appendix C: SQLite DDL](#19-appendix-c-sqlite-ddl)

## 0. Status Snapshot (2026-01-11)

This section is a working marker so you can see progress against the design while the implementation is still ledger-backed.

Work completed that supports DB cutover stability (but does not yet change persistence):

- Unified operation workflow payload shape across newer registry-style endpoints:
  - Dual-status support (legacy `status` string plus canonical `service_status`)
  - Shared `time_remaining` contract on registry status endpoints, including safe coercion and default fallback behavior
- Multi-capture registry status endpoints aligned to the shared `time_remaining` contract:
  - Multi-RxMER `/advance/multiRxMer/status` (POST)
  - Multi-ChannelEstimation `/advance/multiChannelEstimation/status` (POST)
- Test coverage added to lock in the above contract behavior and keep the validation gate green.

Cutover statement:

- The JSON ledgers remain in use until Phase 3 through Phase 5 complete (transactions, groups/operations, artifact linkage).
- The cutover moment is defined explicitly in [14.3 Implementation Milestones And Cutover Moment](#143-implementation-milestones-and-cutover-moment).

## 1. Purpose

PyPNM currently persists transaction metadata using JSON “ledger” files under `.data/db/` (for example `transactions.json`,
`capture_group.json`, and `operation_capture.json`). This design defines the target state for replacing the ledger with a
relational database while preserving PyPNM’s operational model (filesystem-based binary artifacts plus lightweight
metadata persistence).

This document is authoritative for:

- PyPNM (authoritative engine and persistence owner)
- PyPNM-CMTS (consumer of PyPNM; inherits PyPNM’s backend choice)

## 2. Scope

In scope:

- Install-time DB backend selection owned by PyPNM (`sqlite` or `postgres`)
- A normalized relational schema for transaction metadata and grouping constructs (capture groups and operations)
- A durable, explicit way to link transactions to one-or-more files on disk (raw capture binaries and future derived artifacts)
- Demo mode isolation using the same schema with different data roots and or a different DB target
- Release hygiene rules to guarantee no runtime DB/data is shipped in sdists wheels images
- Documentation updates to remove ledger JSON design and replace it with DB-backed persistence
- Endpoint compatibility for the existing PNM File Manager API routes (no JSON ledger traversal at runtime)
- CI viability for both backends (SQLite as baseline, Postgres as service-backed integration in CI when enabled)

Out of scope:

- Security sanitization pipeline refactor (tracked as a later work item, but design constraints are captured here)
- Any change to PNM binary formats
- Any separate persistence mechanism in PyPNM-CMTS

## 3. Non-Goals

- No database-specific business logic in PyPNM-CMTS
- No separate DB selection logic in PyPNM-CMTS
- No database embedded in the Python package directory (no `.sqlite3` inside `src/pypnm/...`)
- No requirement for Kubernetes APIs or a K8 operator

## 4. Design Requirements

1) PyPNM owns persistence  
   PyPNM selects the backend and initializes schema. PyPNM-CMTS must use PyPNM APIs only and inherit the same backend.

2) Epoch timestamps  
   All stored timestamps remain epoch seconds.

3) Explicit artifact linkage  
   A transaction must reference one-or-more on-disk artifacts (raw binary capture, uploads, derived artifacts, archives).

4) SysDescr de-duplication  
   `system_description` values are normalized. A special `UNKNOWN` row exists for user uploads lacking sysDescr.

5) Demo mode uses the same schema  
   Same code path, same tables. Only data differs (dataset root and DB target).

6) Paths stored in DB are portable  
   No user-specific absolute paths are stored (for example `/home/dev01/...`). Store repo app-root relative strings.

7) Backward-facing endpoint shapes remain stable  
   The FastAPI file manager endpoints must continue to function with the same request response models (or minimally invasive
   changes), while switching persistence from JSON ledgers to DB.

8) Release artifacts must never ship runtime DB or data  
   Sdists, wheels, and container images must not contain `.data/`, `demo/.data/`, SQLite DB files, or captured artifacts.

9) DB must be capable of resolving a transaction to a binary without legacy settings JSON linkage  
   The DB must provide sufficient metadata to locate the authoritative binary on disk for download, analysis, and hexdump.

10) DB backend guidance must be explicit for multi-worker deployments  
   SQLite is acceptable for single-writer or small deployments. Postgres is recommended for multi-worker service deployments,
   especially when running PyPNM-CMTS on top of PyPNM.

11) Schema version compatibility is enforced  
   PyPNM must persist a schema version (via `schema_meta`) and must fail fast with a clear error if the DB schema version
   is unsupported. No silent or destructive migrations are permitted in normal runtime flows.

## 5. Terminology

- app_root: The runtime root directory resolved by PyPNM (repo root in dev, container path like `/app` in Docker).
- artifact store: A named root directory relative to app_root (for example `.data/pnm`).
- artifact: A file on disk referenced by the DB (raw PNM binary or a derived packaged artifact).
- transaction: A logical capture event (one PNM binary and its metadata).
- capture group: A grouping of multiple transactions captured together.
- operation capture: A higher-level operation identifier that points to a capture group.
- role: A transaction to artifact linkage label that indicates which file is authoritative for a given purpose (for example `pnm_raw`).

## 6. Target Operating Model

### 6.1 DB Responsibility Contract

PyPNM is the persistence owner:

- Selects backend at install time
- Initializes schema (idempotent)
- Enforces schema version compatibility (fail fast on mismatch)
- Provides repository service APIs that hide backend differences
- Owns all queries required by the file manager endpoints

Initialization ownership contract:

- `install.sh` is responsible for selecting the backend and generating settings that describe it.
- PyPNM runtime is responsible for idempotent schema ensurement:
  - SQLite: create directory and DB file under configured `.data/` root when missing.
  - Postgres: validate connectivity, ensure schema exists, and validate `schema_meta.schema_version`.
- PyPNM runtime must never “silently downgrade” or “auto-migrate” a schema across major versions. If schema version is not
  supported, PyPNM must raise a clear, actionable error with remediation steps.

PyPNM-CMTS is a consumer:

- Never selects a different backend
- Never embeds its own schema or persistence logic for PyPNM transaction metadata
- Calls PyPNM APIs for file transaction resolution

### 6.2 What Stays On Disk

Binary artifacts remain filesystem-based:

- Raw PNM binaries captured via SNMP TFTP HTTP and saved into `.data/pnm/` (or demo equivalent)
- Derived files (CSV JSON PNG PDF ZIP) remain in `.data/<type>/` directories as currently designed
- Archives (ZIP) remain under `.data/archive/`

The DB stores metadata and references to those artifacts.

### 6.3 What Moves Into The DB

Replace the JSON ledgers with DB-backed tables:

- Transaction metadata
- Capture group membership and ordering
- Operation capture linkage
- Artifact store roots and artifact file linkage

## 7. Backend Selection And Installation Contract

### 7.1 install.sh Flags And Interactive Prompt

PyPNM’s `install.sh` must support:

- `--db-install-sqlite` (default if not specified)
- `--db-install-postgres`

If neither flag is provided, the installer must prompt:

- Question: choose `sqlite` or `postgres`
- Default: `sqlite`

Selection is written into the generated settings file (for example `settings/system.json`), and PyPNM uses it at runtime.

Implementation status (2026-01-10):

- Flags and interactive selection have been implemented, and selection occurs before pytest so the suite runs against the chosen backend contract.
- Postgres DSN capture supports password redaction and recommends env var injection rather than plaintext persistence.

### 7.2 Configuration Keys

A single configuration contract, applicable to both prod and demo datasets:

```json
{
  "Database": {
    "backend": "sqlite",
    "sqlite": {
      "path": ".data/db/pypnm.sqlite3"
    },
    "postgres": {
      "dsn": ""
    }
  }
}
```

Notes:

- Postgres must accept a DSN at minimum. Discrete fields may exist, but DSN is the lowest common denominator.
- Demo mode may point to `demo/.data/db/pypnm.sqlite3` and the demo artifact root via artifact store seeding.
- Secret handling: the DSN may be supplied via environment variables in service deployments to avoid plaintext passwords in
  tracked configuration files.

DSN resolution order (contract):

1) Environment variable override (if set)
2) Settings file value (`Database.postgres.dsn`)
3) Installer-generated discrete fields (if implemented) composed into a DSN

Recommended environment variable keys (contract):

- `PYPNM_DB_BACKEND` (optional override for dev and CI)
- `PYPNM_DB_POSTGRES_DSN` (preferred secret injection mechanism for Postgres DSN)

Implementation note:

- As of 2026-01-11, the design contract is stable, but `settings/system.json.template` and `SystemConfigSettings` accessors still need to be updated to fully reflect this configuration surface.

### 7.3 DB Location Policy

The DB is runtime state and must live under `.data/` roots, not inside the package directory.

Recommended defaults (repo app-root relative):

- SQLite: `.data/db/pypnm.sqlite3`
- Demo SQLite: `demo/.data/db/pypnm.sqlite3`
- Postgres: external service; no local DB file

### 7.4 PostgreSQL Authentication And Secrets

Development defaults may use `pypnm` / `pypnm` for local containers or CI service containers, but the design requires:

- No credentials hardcoded in source code
- DSN or discrete connection fields populated via:
  - settings file generated by `install.sh`, and or
  - environment variables or secret injection in container deployments
- CI should use a service-container (or equivalent) and pass DSN through env vars
- Documentation must include an example DSN pattern without embedding real customer credentials

Credential guidance contract:

- Local dev and CI may use the well-known defaults:
  - user: `pypnm`
  - password: `pypnm`
  - db: `pypnm`
- Production documentation must explicitly warn that the above defaults are not acceptable for production environments.
- If a password is present in `settings/system.json`, it must only be present because the user explicitly chose to keep it there
  during `install.sh`. In all other cases, prefer DSN injection using `PYPNM_DB_POSTGRES_DSN` and avoid plaintext secrets.

Example DSN pattern (documentation-only example):

- `postgresql://pypnm:${PYPNM_DB_POSTGRES_PASSWORD}@localhost:5432/pypnm`

PyPNM must treat DSN strings as secrets:

- Do not log full DSNs at INFO level (mask or omit password portion).
- If diagnostics need to report connectivity, log only host, port, dbname, user, and SSL mode.

## 8. Release Hygiene Requirements

When building releases (sdist, wheel, container images):

- Never ship `.data/` or `demo/.data/` content
- Never ship any `.sqlite3` or `.db` files
- Never ship customer binary captures or derived artifacts

### 8.1 Git Ignore And Packaging Exclusions

Concrete safeguards:

- `.gitignore` includes `.data/` and `demo/.data/`
- Packaging config excludes `.data/**` and `demo/.data/**`
- Any demo dataset DB file is also excluded (`demo/.data/db/pypnm.sqlite3`)

### 8.2 Docker And Container Image Hygiene

- `.dockerignore` includes `.data/`, `demo/.data/`, `*.sqlite3`, `*.db`
- Dockerfiles do not `COPY` `.data/` or demo datasets into image layers (data must come from runtime volumes)

## 9. Data Model

### 9.1 Dimensions

system_description_dim:

- Normalized sysDescr fields
- Unique by `sysdescr_hash`
- Includes `UNKNOWN` row

device_details:

- References system_description_dim
- Stores device details JSON (extensible)
- Unique by `device_details_hash`

### 9.2 Fact Tables

transaction_records:

- One row per transaction
- Includes transaction_id, timestamp_epoch, mac_address, pnm_test_type, filename (legacy convenience)
- References device_details via device_detail_id

### 9.3 Grouping Constructs

capture_groups:

- One row per capture group id

capture_group_transactions:

- Join table linking capture groups to transactions
- Stores ordering via `position`

operation_captures:

- One row per operation id
- References capture group id

### 9.4 Artifact Linkage

artifact_stores:

- Named store roots relative to app_root (for example `.data/pnm`, `demo/.data/pnm`)

file_artifacts:

- One row per file artifact
- Unique by `(store_id, relative_path)` and by `sha256`

transaction_artifacts:

- Join table linking transactions to file artifacts
- Includes `role` (for example `pnm_raw`, `pnm_uploaded_raw`, `analysis_zip`, `analysis_json`)

### 9.5 Constraints And Indexing

- MAC address format enforced via CHECK constraints
- Unique constraints on dimension hashes and artifact uniqueness
- Indices on timestamp, mac_address, pnm_test_type, FK columns

### 9.6 UNKNOWN sysDescr Seed Row

The schema seeds a canonical UNKNOWN sysDescr row, used when:

- A file is uploaded by the user and sysDescr cannot be derived
- A capture flow fails to collect sysDescr but still persists a transaction record

Canonical sysDescr JSON example (normal case, not UNKNOWN):

```json
{"HW_REV":"1.0","VENDOR":"LANCity","BOOTR":"NONE","SW_REV":"1.0.0","MODEL":"LCPET-3"}
```

## 10. Path Contract And Portability

### 10.1 Portable Paths

Store only repo app-root relative paths:

- artifact_stores.root_path: store root (for example `.data/pnm`, `demo/.data/pnm`)
- file_artifacts.relative_path: path relative to store root (often a filename, may be nested)

### 10.2 Absolute Path Construction

At runtime:

`absolute_path = Path(app_root) / artifact_stores.root_path / file_artifacts.relative_path`

No absolute paths are stored in the DB.

### 10.3 Demo Isolation

Demo uses:

- Separate DB target (recommended): `demo/.data/db/pypnm.sqlite3`
- Separate artifact store root: `demo/.data/pnm`

Prod uses:

- `.data/db/pypnm.sqlite3`
- `.data/pnm`

Same schema, different data.

## 11. Endpoint Compatibility Requirements

### 11.1 Current File Manager Endpoints

The following endpoints (existing shapes) must remain functionally equivalent:

- `GET /docs/pnm/files/getMacAddresses/`
- `GET /docs/pnm/files/searchFiles/{mac_address}`
- `GET /docs/pnm/files/download/transactionID/{transaction_id}`
- `GET /docs/pnm/files/download/macAddress/{mac_address}`
- `GET /docs/pnm/files/download/operationID/{operation_id}`
- `POST /docs/pnm/files/upload`
- `POST /docs/pnm/files/getAnalysis`
- `GET /docs/pnm/files/getHexdump/transactionID/{transaction_id}`

### 11.2 DB Queries Needed By Each Endpoint

1) getMacAddresses  
   Query: distinct MACs from transaction_records with latest timestamp per MAC, include best-effort system_description derived
   from joined device_details system_description_dim.

2) searchFiles/{mac}  
   Query: transaction_records filtered by mac_address, sorted by timestamp, returning `transaction_id`, `filename`, `pnm_test_type`,
   `timestamp_epoch`, and system_description.

3) download/transactionID/{transaction_id}  
   Query: resolve transaction -> artifact by role (prefer `pnm_raw` then `pnm_uploaded_raw`); construct absolute path; serve file.

4) download/macAddress/{mac}  
   Query: list transactions for MAC; resolve artifacts per transaction; zip.

5) download/operationID/{operation_id}  
   Query: operation -> capture_group -> ordered tx list; resolve artifacts; zip.

6) upload  
   Insert: create transaction record with UNKNOWN sysDescr device_details if necessary; insert artifact and link as `pnm_uploaded_raw`.

7) getAnalysis  
   Resolve file as in download; analysis logic continues as-is once a filesystem path is available.

8) getHexdump  
   Resolve file as in download; hexdump logic continues as-is.

### 11.3 Artifact Resolution Rules

When resolving the on-disk file for a transaction:

- First choice role: `pnm_raw` (captured file)
- Second choice role: `pnm_uploaded_raw` (uploaded file)
- If neither exists, treat as missing file (404)

## 12. Workflows

### 12.1 Upload Flow

```mermaid
flowchart TD
    A[Client POST /upload] --> B[Write file to artifact store root]
    B --> C[Parse PNM header to find file_type and mac_address]
    C --> D[Upsert system_description_dim (or UNKNOWN)]
    D --> E[Upsert device_details]
    E --> F[Insert transaction_records]
    F --> G[Insert file_artifacts (sha256, size_bytes)]
    G --> H[Insert transaction_artifacts role=pnm_uploaded_raw]
    H --> I[Return transaction_id + filename + mac]
```

### 12.2 Download By Transaction ID

```mermaid
flowchart TD
    A[Client GET /download/transactionID/{transaction_id}] --> B[Select artifact by role pnm_raw or pnm_uploaded_raw]
    B --> C[Resolve absolute path from app_root + store_root + relative_path]
    C --> D{File exists?}
    D -->|Yes| E[Return FileResponse]
    D -->|No| F[404 File not found on disk]
```

### 12.3 Search Files By MAC

```mermaid
flowchart TD
    A[Client GET /searchFiles/{mac}] --> B[Select transaction_records where mac_address = mac]
    B --> C[Join device_details + system_description_dim]
    C --> D[Return list of FileEntry objects]
```

### 12.4 Download By MAC (ZIP)

```mermaid
flowchart TD
    A[Client GET /download/macAddress/{mac}] --> B[List transactions for mac]
    B --> C[Resolve artifact path for each tx]
    C --> D[Zip existing files]
    D --> E{Any files?}
    E -->|Yes| F[Return zip FileResponse]
    E -->|No| G[404 No files on disk]
```

### 12.5 Download By Operation ID (ZIP)

```mermaid
flowchart TD
    A[Client GET /download/operationID/{op_id}] --> B[Resolve op_id -> capture_group_id]
    B --> C[Get ordered tx list for group]
    C --> D[Resolve artifact path for each tx]
    D --> E[Zip existing files]
    E --> F[Return zip FileResponse]
```

## 13. Documentation And Tooling Updates

### 13.1 Remove Ledger JSON Design From Docs

Documentation changes required:

- Remove or clearly mark deprecated any documentation that describes JSON ledger persistence as the design
- Update file manager docs to state: transactions capture groups operations are DB-backed; binaries remain on disk
- Update any docs that mention `.data/db/transactions.json`, `.data/db/capture_group.json`, or `.data/db/operation_capture.json`
- Ensure examples and diagrams in docs reflect DB-backed persistence and artifact linkage

### 13.2 Add Mermaid Support To MkDocs And pyproject

Your docs now include Mermaid diagrams. Ensure the docs build supports Mermaid.

Implementation expectations:

- Add Mermaid support in your MkDocs configuration (Material approach is typical):
  - enable `pymdownx.superfences` with mermaid fences, and or
  - add a Mermaid plugin appropriate for your MkDocs stack
- Add the required docs dependency to `pyproject.toml` so `pip install .[docs]` enables Mermaid rendering

Candidate dependency (Codex must verify what your docs stack already uses):

- `mkdocs-mermaid2-plugin`

If your current docs stack already supports Mermaid via existing extensions, treat this as a configuration-only change and do not add redundant dependencies.

## 14. Migration Strategy

### 14.1 Cutover Philosophy

- Introduce schema + DB API first (SQLite path fully testable)
- Migrate write paths to DB, then migrate read paths used by endpoints
- Remove JSON ledger code after DB-backed implementation is verified by tests

Schema versioning posture:

- The initial DB-backed release is `schema_version = 1` (persisted via `schema_meta`).
- PyPNM is permitted to perform idempotent initialization (create tables, seed rows) but is not permitted to perform
  destructive migrations at runtime.
- If a future schema change is required, it must be implemented as an explicit migration step (CLI tool or install-time
  action) with a clear upgrade path and release notes.

### 14.2 Legacy Ledger Data

If you want to preserve legacy ledger data:

- Provide an optional one-time migrator tool that reads old JSON ledgers and inserts DB rows
- Keep it out of normal runtime flow
- Do not ship any populated DB in releases

If you do not need legacy migration, remove the ledgers and start fresh for new installs.

### 14.3 Implementation Milestones And Cutover Moment

Milestone mapping to the burndown:

- Phase 1: Installer/config contract is complete (backend selection, template keys, settings accessors).
- Phase 2: DB abstraction exists and schema init is idempotent for SQLite and wired for Postgres.
- Phase 3: Transactions write and read paths are DB-backed (ledger is no longer authoritative for transactions).
- Phase 4: Capture group and operation persistence is DB-backed (ledger group and operation files are no longer authoritative).
- Phase 5: Artifact linkage exists and file resolution is DB-driven (DB becomes authoritative for locating binaries).
- Phase 6: Ledger JSON code paths and config keys are removed and docs are updated accordingly.

Cutover definition (authoritative):

- PyPNM is considered “DB-only” only after Phase 3 through Phase 6 are complete.
- Until then, any DB work is preparatory and must not introduce behavior that depends on ledgers being present, except for optional offline migration tooling.

## 15. Testing Requirements

- SQLite: unit tests must validate schema init and CRUD without external services
- Postgres: integration is optional, but code paths must be wired and guarded
- Endpoint-level tests (FastAPI TestClient) must validate that the file manager endpoints resolve transactions to paths
  through DB-backed repositories (no JSON file reads)
- Tests must not require live SNMP or CMTS access
- Clean up any pytest coverage that was explicitly validating the JSON-ledger persistence model

### 15.1 CI And GitHub Workflow Considerations

CI contract:

- SQLite must run in all CI jobs (no external dependencies, deterministic).
- Postgres integration must be supported by CI when enabled by the project (recommended once Postgres backend is implemented):
  - a GitHub Actions job using a Postgres service container
  - schema init performed as part of the test setup
  - DSN passed via environment variables (no committed secrets)

Recommended CI Postgres service defaults:

- `POSTGRES_USER=pypnm`
- `POSTGRES_PASSWORD=pypnm`
- `POSTGRES_DB=pypnm`

Recommended DSN injection:

- `PYPNM_DB_POSTGRES_DSN=postgresql://pypnm:pypnm@localhost:5432/pypnm`

Minimum CI validation expectations:

- Schema init applies cleanly and seeds `schema_meta` + `UNKNOWN` sysDescr + default artifact store.
- A minimal CRUD test suite passes for Postgres (create transaction, link artifact, resolve path).
- Endpoint-level tests continue to use SQLite by default unless an explicit Postgres job is running.

## 16. Concurrency Model And Backend Guidance

### 16.1 SQLite Concurrency Limits

SQLite is appropriate for:

- Standalone PyPNM usage
- Lab environments
- Small deployments with limited concurrent writes

Operational considerations:

- SQLite is single-writer (concurrent reads are fine, concurrent writes serialize).
- Multi-process deployments (multiple Uvicorn workers) increase contention risk.
- For best behavior, enable WAL mode and set a reasonable busy timeout in the SQLite connection layer.
- For containers: SQLite requires a persistent volume mount and is not suitable for horizontal scaling with multiple replicas
  writing to the same DB file.
- SQLite must be treated as a single-writer backend when PyPNM is deployed as a service.

### 16.2 PostgreSQL Recommendation Guidance

Postgres is recommended for:

- Production deployments with high concurrency
- Any deployment where PyPNM-CMTS runs as a service with multiple workers and frequent reads writes
- Scenarios where multiple PyPNM processes (or containers) may touch the same persistence layer

Guidance statement to include in docs:

- For PyPNM standalone use, SQLite is fine and is the default for minimal-risk installs.
- For PyPNM-CMTS or any multi-worker service mode, Postgres is recommended.

## 17. Appendix A: Mermaid ER Diagram

```mermaid
erDiagram
    SCHEMA_META {
        INT        schema_meta_id PK
        INT        schema_version
        BIGINT     applied_epoch
    }

    SYSTEM_DESCRIPTION_DIM {
        BIGINT     sysdescr_id PK
        TEXT       hw_rev
        TEXT       vendor
        TEXT       bootr
        TEXT       sw_rev
        TEXT       model
        JSON        sysdescr_json
        TEXT       sysdescr_hash UK
        BOOLEAN    is_unknown
        BIGINT     created_epoch
    }

    DEVICE_DETAILS {
        BIGINT     device_detail_id PK
        BIGINT     sysdescr_id FK
        JSON       device_details_json
        TEXT       device_details_hash UK
        BIGINT     created_epoch
    }

    TRANSACTION_RECORDS {
        TEXT       transaction_id PK
        BIGINT     timestamp_epoch
        TEXT       mac_address
        TEXT       pnm_test_type
        TEXT       filename
        BIGINT     device_detail_id FK
        BIGINT     created_epoch
    }

    CAPTURE_GROUPS {
        TEXT       capture_group_id PK
        BIGINT     created_epoch
    }

    CAPTURE_GROUP_TRANSACTIONS {
        BIGINT     capture_group_transaction_id PK
        TEXT       capture_group_id FK
        TEXT       transaction_id FK
        INT        position
        BIGINT     added_epoch
    }

    OPERATION_CAPTURES {
        TEXT       operation_id PK
        TEXT       capture_group_id FK
        BIGINT     created_epoch
    }

    ARTIFACT_STORES {
        BIGINT     store_id PK
        TEXT       store_name UK
        TEXT       root_path
        BIGINT     created_epoch
    }

    FILE_ARTIFACTS {
        BIGINT     artifact_id PK
        BIGINT     store_id FK
        TEXT       relative_path
        TEXT       filename
        TEXT       sha256 UK
        BIGINT     size_bytes
        TEXT       mime_type
        BIGINT     created_epoch
    }

    TRANSACTION_ARTIFACTS {
        BIGINT     transaction_artifact_id PK
        TEXT       transaction_id FK
        BIGINT     artifact_id FK
        TEXT       role
        BIGINT     created_epoch
    }

    SYSTEM_DESCRIPTION_DIM ||--o{ DEVICE_DETAILS : "1_to_many"
    DEVICE_DETAILS        ||--o{ TRANSACTION_RECORDS : "1_to_many"

    CAPTURE_GROUPS        ||--o{ CAPTURE_GROUP_TRANSACTIONS : "1_to_many"
    TRANSACTION_RECORDS   ||--o{ CAPTURE_GROUP_TRANSACTIONS : "1_to_many"
    CAPTURE_GROUPS        ||--o{ OPERATION_CAPTURES : "1_to_many"

    ARTIFACT_STORES       ||--o{ FILE_ARTIFACTS : "1_to_many"
    FILE_ARTIFACTS        ||--o{ TRANSACTION_ARTIFACTS : "1_to_many"
    TRANSACTION_RECORDS   ||--o{ TRANSACTION_ARTIFACTS : "1_to_many"
```

## 18. Appendix B: PostgreSQL DDL

```sql
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Maurice Garcia

BEGIN;

CREATE TABLE IF NOT EXISTS schema_meta (
    schema_meta_id  SMALLINT PRIMARY KEY,
    schema_version  INTEGER  NOT NULL,
    applied_epoch   BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT ck_schema_meta_single_row CHECK (schema_meta_id = 1),
    CONSTRAINT ck_schema_version_positive CHECK (schema_version >= 1)
);

INSERT INTO schema_meta (schema_meta_id, schema_version)
VALUES (1, 1)
ON CONFLICT (schema_meta_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS system_description_dim (
    sysdescr_id    BIGSERIAL PRIMARY KEY,
    hw_rev         TEXT      NOT NULL,
    vendor         TEXT      NOT NULL,
    bootr          TEXT      NOT NULL,
    sw_rev         TEXT      NOT NULL,
    model          TEXT      NOT NULL,
    sysdescr_json  JSONB     NOT NULL DEFAULT '{}'::jsonb,
    sysdescr_hash  TEXT      NOT NULL UNIQUE,
    is_unknown     BOOLEAN   NOT NULL DEFAULT FALSE,
    created_epoch  BIGINT    NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT ck_sysdescr_unknown_consistency CHECK (
        (is_unknown = TRUE  AND sysdescr_json = '{}'::jsonb AND hw_rev = 'UNKNOWN' AND vendor = 'UNKNOWN' AND bootr = 'UNKNOWN' AND sw_rev = 'UNKNOWN' AND model = 'UNKNOWN')
     OR (is_unknown = FALSE AND sysdescr_json <> '{}'::jsonb)
    )
);

CREATE INDEX IF NOT EXISTS idx_system_description_hash
ON system_description_dim (sysdescr_hash);

CREATE TABLE IF NOT EXISTS device_details (
    device_detail_id     BIGSERIAL PRIMARY KEY,
    sysdescr_id          BIGINT   NOT NULL REFERENCES system_description_dim(sysdescr_id) ON DELETE RESTRICT,
    device_details_json  JSONB    NOT NULL DEFAULT '{}'::jsonb,
    device_details_hash  TEXT     NOT NULL UNIQUE,
    created_epoch        BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_device_details_sysdescr_id
ON device_details (sysdescr_id);

CREATE INDEX IF NOT EXISTS idx_device_details_hash
ON device_details (device_details_hash);

CREATE TABLE IF NOT EXISTS transaction_records (
    transaction_id    TEXT    PRIMARY KEY,
    timestamp_epoch   BIGINT  NOT NULL,
    mac_address       TEXT    NOT NULL,
    pnm_test_type     TEXT    NOT NULL,
    filename          TEXT    NOT NULL,
    device_detail_id  BIGINT  NOT NULL REFERENCES device_details(device_detail_id) ON DELETE RESTRICT,
    created_epoch     BIGINT  NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT ck_transaction_mac_format CHECK (
        mac_address ~* '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
    )
);

CREATE INDEX IF NOT EXISTS idx_transaction_timestamp_epoch
ON transaction_records (timestamp_epoch);

CREATE INDEX IF NOT EXISTS idx_transaction_mac_address
ON transaction_records (mac_address);

CREATE INDEX IF NOT EXISTS idx_transaction_pnm_test_type
ON transaction_records (pnm_test_type);

CREATE INDEX IF NOT EXISTS idx_transaction_device_detail_id
ON transaction_records (device_detail_id);

CREATE TABLE IF NOT EXISTS capture_groups (
    capture_group_id  TEXT   PRIMARY KEY,
    created_epoch     BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_capture_groups_created_epoch
ON capture_groups (created_epoch);

CREATE TABLE IF NOT EXISTS capture_group_transactions (
    capture_group_transaction_id  BIGSERIAL PRIMARY KEY,
    capture_group_id              TEXT     NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE CASCADE,
    transaction_id                TEXT     NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    position                      INTEGER  NOT NULL,
    added_epoch                   BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT uq_capture_group_position UNIQUE (capture_group_id, position),
    CONSTRAINT uq_capture_group_transaction UNIQUE (capture_group_id, transaction_id)
);

CREATE INDEX IF NOT EXISTS idx_cg_tx_capture_group_id
ON capture_group_transactions (capture_group_id);

CREATE INDEX IF NOT EXISTS idx_cg_tx_transaction_id
ON capture_group_transactions (transaction_id);

CREATE TABLE IF NOT EXISTS operation_captures (
    operation_id     TEXT   PRIMARY KEY,
    capture_group_id TEXT   NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,
    created_epoch    BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_operation_captures_capture_group_id
ON operation_captures (capture_group_id);

CREATE TABLE IF NOT EXISTS artifact_stores (
    store_id      BIGSERIAL PRIMARY KEY,
    store_name    TEXT      NOT NULL UNIQUE,
    root_path     TEXT      NOT NULL,
    created_epoch BIGINT    NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE TABLE IF NOT EXISTS file_artifacts (
    artifact_id    BIGSERIAL PRIMARY KEY,
    store_id       BIGINT   NOT NULL REFERENCES artifact_stores(store_id) ON DELETE RESTRICT,
    relative_path  TEXT     NOT NULL,
    filename       TEXT     NOT NULL,
    sha256         TEXT     NOT NULL,
    size_bytes     BIGINT   NOT NULL DEFAULT 0,
    mime_type      TEXT     NOT NULL DEFAULT '',
    created_epoch  BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT uq_artifact_store_path UNIQUE (store_id, relative_path),
    CONSTRAINT uq_artifact_sha256 UNIQUE (sha256)
);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_store_id
ON file_artifacts (store_id);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_sha256
ON file_artifacts (sha256);

CREATE TABLE IF NOT EXISTS transaction_artifacts (
    transaction_artifact_id  BIGSERIAL PRIMARY KEY,
    transaction_id           TEXT    NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    artifact_id              BIGINT  NOT NULL REFERENCES file_artifacts(artifact_id) ON DELETE RESTRICT,
    role                     TEXT    NOT NULL,
    created_epoch            BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT uq_tx_role UNIQUE (transaction_id, role),
    CONSTRAINT uq_tx_artifact UNIQUE (transaction_id, artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_transaction_artifacts_tx
ON transaction_artifacts (transaction_id);

CREATE INDEX IF NOT EXISTS idx_transaction_artifacts_artifact
ON transaction_artifacts (artifact_id);

INSERT INTO system_description_dim (
    hw_rev, vendor, bootr, sw_rev, model,
    sysdescr_json, sysdescr_hash, is_unknown
)
VALUES (
    'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
    '{}'::jsonb, 'UNKNOWN', TRUE
)
ON CONFLICT (sysdescr_hash) DO NOTHING;

COMMIT;
```

## 19. Appendix C: SQLite DDL

```sql
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Maurice Garcia

PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS schema_meta (
    schema_meta_id  INTEGER PRIMARY KEY,
    schema_version  INTEGER NOT NULL,
    applied_epoch   INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    CHECK (schema_meta_id = 1),
    CHECK (schema_version >= 1)
);

INSERT OR IGNORE INTO schema_meta (schema_meta_id, schema_version)
VALUES (1, 1);

CREATE TABLE IF NOT EXISTS system_description_dim (
    sysdescr_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    hw_rev         TEXT    NOT NULL,
    vendor         TEXT    NOT NULL,
    bootr          TEXT    NOT NULL,
    sw_rev         TEXT    NOT NULL,
    model          TEXT    NOT NULL,
    sysdescr_json  TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(sysdescr_json)),
    sysdescr_hash  TEXT    NOT NULL UNIQUE,
    is_unknown     INTEGER NOT NULL DEFAULT 0 CHECK (is_unknown IN (0, 1)),
    created_epoch  INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    CHECK (
        (is_unknown = 1 AND sysdescr_json = '{}' AND hw_rev = 'UNKNOWN' AND vendor = 'UNKNOWN' AND bootr = 'UNKNOWN' AND sw_rev = 'UNKNOWN' AND model = 'UNKNOWN')
     OR (is_unknown = 0 AND sysdescr_json <> '{}')
    )
);

CREATE INDEX IF NOT EXISTS idx_system_description_hash
ON system_description_dim (sysdescr_hash);

CREATE TABLE IF NOT EXISTS device_details (
    device_detail_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    sysdescr_id          INTEGER NOT NULL REFERENCES system_description_dim(sysdescr_id) ON DELETE RESTRICT,
    device_details_json  TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(device_details_json)),
    device_details_hash  TEXT    NOT NULL UNIQUE,
    created_epoch        INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_device_details_sysdescr_id
ON device_details (sysdescr_id);

CREATE INDEX IF NOT EXISTS idx_device_details_hash
ON device_details (device_details_hash);

CREATE TABLE IF NOT EXISTS transaction_records (
    transaction_id    TEXT    PRIMARY KEY,
    timestamp_epoch   INTEGER NOT NULL,
    mac_address       TEXT    NOT NULL,
    pnm_test_type     TEXT    NOT NULL,
    filename          TEXT    NOT NULL,
    device_detail_id  INTEGER NOT NULL REFERENCES device_details(device_detail_id) ON DELETE RESTRICT,
    created_epoch     INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    CHECK (
        length(mac_address) = 17
        AND mac_address GLOB
            '[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]'
    )
);

CREATE INDEX IF NOT EXISTS idx_transaction_timestamp_epoch
ON transaction_records (timestamp_epoch);

CREATE INDEX IF NOT EXISTS idx_transaction_mac_address
ON transaction_records (mac_address);

CREATE INDEX IF NOT EXISTS idx_transaction_pnm_test_type
ON transaction_records (pnm_test_type);

CREATE INDEX IF NOT EXISTS idx_transaction_device_detail_id
ON transaction_records (device_detail_id);

CREATE TABLE IF NOT EXISTS capture_groups (
    capture_group_id  TEXT    PRIMARY KEY,
    created_epoch     INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_capture_groups_created_epoch
ON capture_groups (created_epoch);

CREATE TABLE IF NOT EXISTS capture_group_transactions (
    capture_group_transaction_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_group_id              TEXT    NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE CASCADE,
    transaction_id                TEXT    NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    position                      INTEGER NOT NULL,
    added_epoch                   INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    UNIQUE (capture_group_id, position),
    UNIQUE (capture_group_id, transaction_id)
);

CREATE INDEX IF NOT EXISTS idx_cg_tx_capture_group_id
ON capture_group_transactions (capture_group_id);

CREATE INDEX IF NOT EXISTS idx_cg_tx_transaction_id
ON capture_group_transactions (transaction_id);

CREATE TABLE IF NOT EXISTS operation_captures (
    operation_id     TEXT    PRIMARY KEY,
    capture_group_id TEXT    NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,
    created_epoch    INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_operation_captures_capture_group_id
ON operation_captures (capture_group_id);

CREATE TABLE IF NOT EXISTS artifact_stores (
    store_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    store_name    TEXT    NOT NULL UNIQUE,
    root_path     TEXT    NOT NULL,
    created_epoch INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE TABLE IF NOT EXISTS file_artifacts (
    artifact_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id       INTEGER NOT NULL REFERENCES artifact_stores(store_id) ON DELETE RESTRICT,
    relative_path  TEXT    NOT NULL,
    filename       TEXT    NOT NULL,
    sha256         TEXT    NOT NULL,
    size_bytes     INTEGER NOT NULL DEFAULT 0,
    mime_type      TEXT    NOT NULL DEFAULT '',
    created_epoch  INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    UNIQUE (store_id, relative_path),
    UNIQUE (sha256)
);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_store_id
ON file_artifacts (store_id);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_sha256
ON file_artifacts (sha256);

CREATE TABLE IF NOT EXISTS transaction_artifacts (
    transaction_artifact_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id           TEXT    NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    artifact_id              INTEGER NOT NULL REFERENCES file_artifacts(artifact_id) ON DELETE RESTRICT,
    role                     TEXT    NOT NULL,
    created_epoch            INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    UNIQUE (transaction_id, role),
    UNIQUE (transaction_id, artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_transaction_artifacts_tx
ON transaction_artifacts (transaction_id);

CREATE INDEX IF NOT EXISTS idx_transaction_artifacts_artifact
ON transaction_artifacts (artifact_id);

INSERT OR IGNORE INTO system_description_dim (
    hw_rev, vendor, bootr, sw_rev, model,
    sysdescr_json, sysdescr_hash, is_unknown
)
VALUES (
    'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
    '{}', 'UNKNOWN', 1
);

COMMIT;
```

# FILE: docs/design/db/schema_postgres.sql
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Maurice Garcia

-- PyPNM DB Schema (Postgres)
-- Fresh install schema. Store timestamps as epoch seconds.
-- Hashes (sysdescr_hash/device_details_hash/sha256) are computed in Python.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_meta (
    schema_meta_id  SMALLINT PRIMARY KEY,
    schema_version  INTEGER  NOT NULL,
    applied_epoch   BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT ck_schema_meta_single_row CHECK (schema_meta_id = 1),
    CONSTRAINT ck_schema_version_positive CHECK (schema_version >= 1)
);

INSERT INTO schema_meta (schema_meta_id, schema_version)
VALUES (1, 1)
ON CONFLICT (schema_meta_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS system_description_dim (
    sysdescr_id    BIGSERIAL PRIMARY KEY,
    hw_rev         TEXT      NOT NULL,
    vendor         TEXT      NOT NULL,
    bootr          TEXT      NOT NULL,
    sw_rev         TEXT      NOT NULL,
    model          TEXT      NOT NULL,
    sysdescr_json  JSONB     NOT NULL DEFAULT '{}'::jsonb,
    sysdescr_hash  TEXT      NOT NULL UNIQUE,
    is_unknown     BOOLEAN   NOT NULL DEFAULT FALSE,
    created_epoch  BIGINT    NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT ck_sysdescr_unknown_consistency CHECK (
        (is_unknown = TRUE  AND sysdescr_json = '{}'::jsonb AND hw_rev = 'UNKNOWN' AND vendor = 'UNKNOWN' AND bootr = 'UNKNOWN' AND sw_rev = 'UNKNOWN' AND model = 'UNKNOWN')
     OR (is_unknown = FALSE AND sysdescr_json <> '{}'::jsonb)
    )
);

CREATE INDEX IF NOT EXISTS idx_system_description_hash
ON system_description_dim (sysdescr_hash);

CREATE TABLE IF NOT EXISTS device_details (
    device_detail_id     BIGSERIAL PRIMARY KEY,
    sysdescr_id          BIGINT   NOT NULL REFERENCES system_description_dim(sysdescr_id) ON DELETE RESTRICT,
    device_details_json  JSONB    NOT NULL DEFAULT '{}'::jsonb,
    device_details_hash  TEXT     NOT NULL UNIQUE,
    created_epoch        BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_device_details_sysdescr_id
ON device_details (sysdescr_id);

CREATE INDEX IF NOT EXISTS idx_device_details_hash
ON device_details (device_details_hash);

CREATE TABLE IF NOT EXISTS transaction_records (
    transaction_id    TEXT    PRIMARY KEY,
    timestamp_epoch   BIGINT  NOT NULL,
    mac_address       TEXT    NOT NULL,
    pnm_test_type     TEXT    NOT NULL,
    filename          TEXT    NOT NULL,
    device_detail_id  BIGINT  NOT NULL REFERENCES device_details(device_detail_id) ON DELETE RESTRICT,
    created_epoch     BIGINT  NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT ck_transaction_mac_format CHECK (
        mac_address ~* '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'
    )
);

CREATE INDEX IF NOT EXISTS idx_transaction_timestamp_epoch
ON transaction_records (timestamp_epoch);

CREATE INDEX IF NOT EXISTS idx_transaction_mac_address
ON transaction_records (mac_address);

CREATE INDEX IF NOT EXISTS idx_transaction_pnm_test_type
ON transaction_records (pnm_test_type);

CREATE INDEX IF NOT EXISTS idx_transaction_device_detail_id
ON transaction_records (device_detail_id);

CREATE TABLE IF NOT EXISTS capture_groups (
    capture_group_id  TEXT   PRIMARY KEY,
    created_epoch     BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_capture_groups_created_epoch
ON capture_groups (created_epoch);

CREATE TABLE IF NOT EXISTS capture_group_transactions (
    capture_group_transaction_id  BIGSERIAL PRIMARY KEY,
    capture_group_id              TEXT     NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE CASCADE,
    transaction_id                TEXT     NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    position                      INTEGER  NOT NULL,
    added_epoch                   BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT uq_capture_group_position UNIQUE (capture_group_id, position),
    CONSTRAINT uq_capture_group_transaction UNIQUE (capture_group_id, transaction_id)
);

CREATE INDEX IF NOT EXISTS idx_cg_tx_capture_group_id
ON capture_group_transactions (capture_group_id);

CREATE INDEX IF NOT EXISTS idx_cg_tx_transaction_id
ON capture_group_transactions (transaction_id);

CREATE TABLE IF NOT EXISTS operation_captures (
    operation_id     TEXT   PRIMARY KEY,
    capture_group_id TEXT   NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,
    created_epoch    BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_operation_captures_capture_group_id
ON operation_captures (capture_group_id);

-- ---------------------------------------------------------------------------
-- Artifact linkage (file system integration)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS artifact_stores (
    store_id      BIGSERIAL PRIMARY KEY,
    store_name    TEXT      NOT NULL UNIQUE,
    root_path     TEXT      NOT NULL,
    created_epoch BIGINT    NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE TABLE IF NOT EXISTS file_artifacts (
    artifact_id    BIGSERIAL PRIMARY KEY,
    store_id       BIGINT   NOT NULL REFERENCES artifact_stores(store_id) ON DELETE RESTRICT,
    relative_path  TEXT     NOT NULL,
    filename       TEXT     NOT NULL,
    sha256         TEXT     NOT NULL,
    size_bytes     BIGINT   NOT NULL DEFAULT 0,
    mime_type      TEXT     NOT NULL DEFAULT '',
    created_epoch  BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT uq_artifact_store_path UNIQUE (store_id, relative_path),
    CONSTRAINT uq_artifact_sha256 UNIQUE (sha256)
);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_store_id
ON file_artifacts (store_id);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_sha256
ON file_artifacts (sha256);

CREATE TABLE IF NOT EXISTS transaction_artifacts (
    transaction_artifact_id  BIGSERIAL PRIMARY KEY,
    transaction_id           TEXT    NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    artifact_id              BIGINT  NOT NULL REFERENCES file_artifacts(artifact_id) ON DELETE RESTRICT,
    role                     TEXT    NOT NULL,
    created_epoch            BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT uq_tx_role UNIQUE (transaction_id, role),
    CONSTRAINT uq_tx_artifact UNIQUE (transaction_id, artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_transaction_artifacts_tx
ON transaction_artifacts (transaction_id);

CREATE INDEX IF NOT EXISTS idx_transaction_artifacts_artifact
ON transaction_artifacts (artifact_id);

-- ---------------------------------------------------------------------------
-- Seed: canonical UNKNOWN sysDescr row (for uploaded PNM without sysDescr)
-- ---------------------------------------------------------------------------

INSERT INTO system_description_dim (
    hw_rev, vendor, bootr, sw_rev, model,
    sysdescr_json, sysdescr_hash, is_unknown
)
VALUES (
    'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
    '{}'::jsonb, 'UNKNOWN', TRUE
)
ON CONFLICT (sysdescr_hash) DO NOTHING;

COMMIT;

# FILE: docs/design/db/schema_sqlite.sql
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Maurice Garcia

PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS schema_meta (
    schema_meta_id  INTEGER PRIMARY KEY,
    schema_version  INTEGER NOT NULL,
    applied_epoch   INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    CHECK (schema_meta_id = 1),
    CHECK (schema_version >= 1)
);

INSERT OR IGNORE INTO schema_meta (schema_meta_id, schema_version)
VALUES (1, 1);

CREATE TABLE IF NOT EXISTS system_description_dim (
    sysdescr_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    hw_rev         TEXT    NOT NULL,
    vendor         TEXT    NOT NULL,
    bootr          TEXT    NOT NULL,
    sw_rev         TEXT    NOT NULL,
    model          TEXT    NOT NULL,
    sysdescr_json  TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(sysdescr_json)),
    sysdescr_hash  TEXT    NOT NULL UNIQUE,
    is_unknown     INTEGER NOT NULL DEFAULT 0 CHECK (is_unknown IN (0, 1)),
    created_epoch  INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    CHECK (
        (is_unknown = 1 AND sysdescr_json = '{}' AND hw_rev = 'UNKNOWN' AND vendor = 'UNKNOWN' AND bootr = 'UNKNOWN' AND sw_rev = 'UNKNOWN' AND model = 'UNKNOWN')
     OR (is_unknown = 0 AND sysdescr_json <> '{}')
    )
);

CREATE INDEX IF NOT EXISTS idx_system_description_hash
ON system_description_dim (sysdescr_hash);

CREATE TABLE IF NOT EXISTS device_details (
    device_detail_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    sysdescr_id          INTEGER NOT NULL REFERENCES system_description_dim(sysdescr_id) ON DELETE RESTRICT,
    device_details_json  TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(device_details_json)),
    device_details_hash  TEXT    NOT NULL UNIQUE,
    created_epoch        INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_device_details_sysdescr_id
ON device_details (sysdescr_id);

CREATE INDEX IF NOT EXISTS idx_device_details_hash
ON device_details (device_details_hash);

CREATE TABLE IF NOT EXISTS transaction_records (
    transaction_id    TEXT    PRIMARY KEY,
    timestamp_epoch   INTEGER NOT NULL,
    mac_address       TEXT    NOT NULL,
    pnm_test_type     TEXT    NOT NULL,
    filename          TEXT    NOT NULL,
    device_detail_id  INTEGER NOT NULL REFERENCES device_details(device_detail_id) ON DELETE RESTRICT,
    created_epoch     INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    CHECK (
        length(mac_address) = 17
        AND mac_address GLOB
            '[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]'
    )
);

CREATE INDEX IF NOT EXISTS idx_transaction_timestamp_epoch
ON transaction_records (timestamp_epoch);

CREATE INDEX IF NOT EXISTS idx_transaction_mac_address
ON transaction_records (mac_address);

CREATE INDEX IF NOT EXISTS idx_transaction_pnm_test_type
ON transaction_records (pnm_test_type);

CREATE INDEX IF NOT EXISTS idx_transaction_device_detail_id
ON transaction_records (device_detail_id);

CREATE TABLE IF NOT EXISTS capture_groups (
    capture_group_id  TEXT    PRIMARY KEY,
    created_epoch     INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_capture_groups_created_epoch
ON capture_groups (created_epoch);

CREATE TABLE IF NOT EXISTS capture_group_transactions (
    capture_group_transaction_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_group_id              TEXT    NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE CASCADE,
    transaction_id                TEXT    NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    position                      INTEGER NOT NULL,
    added_epoch                   INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    UNIQUE (capture_group_id, position),
    UNIQUE (capture_group_id, transaction_id)
);

CREATE INDEX IF NOT EXISTS idx_cg_tx_capture_group_id
ON capture_group_transactions (capture_group_id);

CREATE INDEX IF NOT EXISTS idx_cg_tx_transaction_id
ON capture_group_transactions (transaction_id);

CREATE TABLE IF NOT EXISTS operation_captures (
    operation_id     TEXT    PRIMARY KEY,
    capture_group_id TEXT    NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,
    created_epoch    INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_operation_captures_capture_group_id
ON operation_captures (capture_group_id);

CREATE TABLE IF NOT EXISTS artifact_stores (
    store_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    store_name    TEXT    NOT NULL UNIQUE,
    root_path     TEXT    NOT NULL,
    created_epoch INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE TABLE IF NOT EXISTS file_artifacts (
    artifact_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id       INTEGER NOT NULL REFERENCES artifact_stores(store_id) ON DELETE RESTRICT,
    relative_path  TEXT    NOT NULL,
    filename       TEXT    NOT NULL,
    sha256         TEXT    NOT NULL,
    size_bytes     INTEGER NOT NULL DEFAULT 0,
    mime_type      TEXT    NOT NULL DEFAULT '',
    created_epoch  INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    UNIQUE (store_id, relative_path),
    UNIQUE (sha256)
);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_store_id
ON file_artifacts (store_id);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_sha256
ON file_artifacts (sha256);

CREATE TABLE IF NOT EXISTS transaction_artifacts (
    transaction_artifact_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id           TEXT    NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    artifact_id              INTEGER NOT NULL REFERENCES file_artifacts(artifact_id) ON DELETE RESTRICT,
    role                     TEXT    NOT NULL,
    created_epoch            INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    UNIQUE (transaction_id, role),
    UNIQUE (transaction_id, artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_transaction_artifacts_tx
ON transaction_artifacts (transaction_id);

CREATE INDEX IF NOT EXISTS idx_transaction_artifacts_artifact
ON transaction_artifacts (artifact_id);

INSERT OR IGNORE INTO system_description_dim (
    hw_rev, vendor, bootr, sw_rev, model,
    sysdescr_json, sysdescr_hash, is_unknown
)
VALUES (
    'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
    '{}', 'UNKNOWN', 1
);

COMMIT;

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

If multi-capture result endpoints return 404 while `operation_capture.json`
stores `capture_group` instead of `capture_group_id`, upgrade to a build that
accepts the legacy key and backfills the operation-to-capture-group mapping
into the DB.

# FILE: docs/todo/todo.md
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Maurice Garcia -->

# TODO

- Add the agent review bundle summary template block at the top of all `*.review.md` bundles.
- Update agent response preferences: do not print file contents in chat unless explicitly requested.
- Confirm the FAQ entry for legacy operation_capture capture_group fallback is published.
- Document the 3000-line multi-part agent review bundle requirement in AGENTS.md.

# FILE: src/pypnm/api/routes/advance/common/operation_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import cast
from pypnm.lib.db.capture_group_repository import (
    CaptureGroupRepository,
    OperationCaptureRepository,
)
from pypnm.lib.types import GroupId, OperationId, TimestampSec

_DEFAULT_CREATED_EPOCH: int = 0


class OperationManager:
    """
    Manager for mapping background capture operations to their capture group IDs.

    Each operation is assigned a unique operation_id and linked to a
    capture_group_id. Mappings are persisted in the DB backend so that
    captures can be looked up later by operation ID.
    """

    def __init__(self, capture_group_id: GroupId, db_path: Path | None = None) -> None:
        """
        Initialize a new operation manager for a given capture group.

        Args:
            capture_group_id: The ID of the capture group to associate.
            db_path: Optional path to the operations DB file; if None,
                     retrieves from ConfigManager under
                     [PnmFileRetrieval].operation_db.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.capture_group_id: GroupId = capture_group_id
        self.operation_id: OperationId = cast(OperationId, uuid.uuid4().hex[:16])

        self._capture_repo = CaptureGroupRepository.from_system_config()
        self._operation_repo = OperationCaptureRepository.from_system_config()

        # Resolve legacy DB file path (fallback reads only)
        if db_path:
            self.db_path = db_path
        else:
            db_str = SystemConfigSettings.operation_db()
            self.db_path = Path(db_str)

    def register(self) -> OperationId:
        """
        Register this operation with its capture group ID in the DB.

        Verifies that the associated capture group exists before registration.

        Returns:
            The operation_id assigned.

        Raises:
            ValueError: If the capture_group_id is not present in the CaptureGroup database.
        """
        if not self._capture_repo.capture_group_exists(self.capture_group_id):
            raise ValueError(f"CaptureGroup '{self.capture_group_id}' does not exist")

        created_epoch = TimestampSec(int(time.time()))
        self._operation_repo.upsert_operation_capture(
            self.operation_id, self.capture_group_id, created_epoch
        )
        self.logger.info(
            f"Registered operation {self.operation_id} for group {self.capture_group_id}"
        )
        return self.operation_id

    @classmethod
    def get_capture_group(
        cls, operation_id: OperationId, db_path: Path | None = None
    ) -> GroupId | None:
        """
        Retrieve the capture_group_id for a given operation_id.

        Args:
            operation_id: The operation ID to look up.
            db_path: Optional override for the operations DB file.

        Returns:
            capture_group_id if found, otherwise None.
        """
        logger = logging.getLogger(cls.__name__)
        operation_repo = OperationCaptureRepository.from_system_config()
        capture_repo = CaptureGroupRepository.from_system_config()
        capture_group_id = operation_repo.get_capture_group_id(operation_id)
        if capture_group_id is not None:
            return capture_group_id

        if not db_path:
            db_str = SystemConfigSettings.operation_db()
            db_path = Path(db_str)
        try:
            with db_path.open("r", encoding="utf-8") as f:
                db = json.load(f)
            rec = db.get(operation_id)
            if isinstance(rec, dict):
                capture_group_id_value = rec.get("capture_group_id")
                legacy_capture_group = rec.get("capture_group")
                if capture_group_id_value:
                    capture_group_id = GroupId(str(capture_group_id_value))
                elif legacy_capture_group:
                    logger.warning(
                        "Operation record for %s uses legacy 'capture_group' field",
                        operation_id,
                    )
                    capture_group_id = GroupId(str(legacy_capture_group))
                else:
                    return None

                created_value = rec.get("created")
                created_epoch = (
                    int(created_value) if created_value else _DEFAULT_CREATED_EPOCH
                )
                capture_repo.get_or_create_capture_group(
                    capture_group_id, TimestampSec(created_epoch)
                )
                operation_repo.upsert_operation_capture(
                    operation_id, capture_group_id, TimestampSec(created_epoch)
                )
                return capture_group_id
            return None
        except Exception as e:
            logger.error(f"Error retrieving capture group for {operation_id}: {e}")
            return None

    @classmethod
    def list_operations(cls, db_path: Path | None = None) -> list[str]:
        """
        List all registered operation IDs.

        Args:
            db_path: Optional override for the operations DB file.

        Returns:
            List of operation_id strings.
        """
        operation_repo = OperationCaptureRepository.from_system_config()
        operation_ids = operation_repo.list_operation_ids()
        if operation_ids:
            return [str(op_id) for op_id in operation_ids]

        if not db_path:
            db_str = SystemConfigSettings.operation_db()
            db_path = Path(db_str)
        try:
            with db_path.open("r", encoding="utf-8") as f:
                return list(json.load(f).keys())
        except Exception as e:
            logging.getLogger(cls.__name__).error(f"Error listing operations: {e}")
            return []

# FILE: src/pypnm/api/routes/common/classes/file_capture/capture_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.transaction_repository import TransactionRepository
from pypnm.lib.types import GroupId, TransactionId


class CaptureGroup:
    """
    Manage sessions of capture operations (e.g., multi-RxMER runs) by grouping
    multiple file-transfer transactions under a single UUID-based group ID.

    Features:
      - Persist groups and their transaction lists in the DB backend.
      - Generate or load a 16-character hexadecimal group ID per session.
      - Add, list, delete transactions; prune stale groups.

    Example:
        # New session
        cg = CaptureGroup()
        group_id = cg.create_group()

        # Existing session
        cg2 = CaptureGroup(group_id=group_id)
        txns = cg2.get_transactions()
    """

    def __init__(
        self, group_id: GroupId | None = None, db_path: Path | None = None
    ) -> None:
        """
        Initialize the CaptureGroup manager.

        Args:
            group_id: Optional existing group ID to load; generates a new one if None.
            db_path: Optional Path for the JSON DB file. Defaults to config [PnmFileRetrieval].capture_group_db.

        Raises:
            OSError: If the parent directory cannot be created.
        """
        self.logger = logging.getLogger(self.__class__.__name__)

        self._repo = CaptureGroupRepository.from_system_config()
        self._transaction_repo = TransactionRepository.from_system_config()

        # Resolve legacy DB file path (fallback reads only)
        if db_path:
            self.db_path = Path(db_path)
        else:
            cfg_db_path = SystemConfigSettings.capture_group_db()
            self.db_path = Path(cfg_db_path)
        self._grp_id: GroupId = group_id
        self._create_group_id()

    def _create_group_id(self) -> str:
        """
        Ensure a group ID is set (use existing or generate new).
        Returns the active group ID.
        """
        if not self._grp_id:
            self._grp_id = uuid.uuid4().hex[:16]
        return self._grp_id

    def get_group_id(self) -> GroupId:
        """
        Get the current active group ID.
        Raises AssertionError if uninitialized.
        """
        assert self._grp_id, "Group ID not initialized"
        return self._grp_id

    def create_group(self) -> GroupId:
        """
        Add the current group to the DB (no-op if exists).
        Returns the group ID.
        """
        gid = self.get_group_id()
        created_epoch = int(time.time())
        self._repo.get_or_create_capture_group(gid, created_epoch)
        self.logger.info(f"Created new group: {gid}")
        return gid

    def add_transaction(self, txn_id: str) -> None:
        """
        Append a transaction ID to this group, saving the DB.
        Raises ValueError if group missing.
        """
        tx_id = str(txn_id).strip()
        if not tx_id:
            self.logger.warning("Skipping empty transaction_id persistence")
            return
        gid = self.get_group_id()
        if not self._repo.capture_group_exists(gid):
            raise ValueError("Group not found; create_group() first")
        if self._transaction_repo.get_transaction_record(TransactionId(tx_id)) is None:
            self.logger.warning(
                "Skipping capture_group link for missing transaction_id=%s",
                tx_id,
            )
            return
        created_epoch = int(time.time())
        self._repo.add_transaction(gid, TransactionId(tx_id), created_epoch)
        self.logger.debug(f"Added txn {tx_id} to group {gid}")

    def getTransactionIds(self) -> list[TransactionId]:
        """
        Return all transaction IDs for this group (empty list if none).
        """
        return self._repo.list_transactions(self.get_group_id())

    def delete_group(self) -> None:
        """
        Remove this group and its transactions from the DB; resets group ID.
        """
        gid = self.get_group_id()
        self._repo.delete_capture_group(gid)
        self.logger.info(f"Deleted group: {gid}")
        self._grp_id = None

    def list_groups(self) -> list[str]:
        """
        List all group IDs currently in the DB.
        """
        return [str(group_id) for group_id in self._repo.list_capture_groups()]

    def prune_older_than(self, seconds: int) -> None:
        """
        Remove groups older than the given age (seconds).
        """
        cutoff = int(time.time()) - seconds
        deleted_count = self._repo.prune_older_than(cutoff)
        if deleted_count:
            self.logger.info(f"Pruned groups: {deleted_count}")

# FILE: src/pypnm/api/routes/common/classes/file_capture/pnm_file_opearation.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import json
import logging
from pathlib import Path

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import (
    CaptureGroupRepository,
    OperationCaptureRepository,
)
from pypnm.lib.db.transaction_repository import TransactionRepository
from pypnm.lib.types import GroupId, OperationId, TimestampSec, TransactionId

_DEFAULT_CREATED_EPOCH: int = 0


class OperationCaptureGroupResolver:
    """
    Resolve Operation IDs Into Capture Groups And Transaction Records.

    This helper class ties together DB-backed datasets with legacy JSON fallback:

    1) Operation Database
       - DB: operation_captures table (fallback to SystemConfigSettings.operation_db)
       - Shape:
         {
           "<operation_id>": {
             "capture_group_id": "<capture_group_id>",
             "created": <epoch>
           },
           ...
         }

    2) Capture Group Database
       - DB: capture_groups/capture_group_transactions tables
       - Path: SystemConfigSettings.capture_group_db (fallback)
       - Shape:
         {
           "<capture_group_id>": {
             "created": <epoch>,
             "transactions": [
               "<txn_id_1>",
               "<txn_id_2>",
               ...
             ]
           },
           ...
         }

    3) Transaction Database (transaction_records)
       - Already managed by PnmFileTransaction.

    Public APIs:
      - get_capture_group_id(operation_id)
      - get_transaction_ids_for_operation(operation_id)
      - get_transaction_models_for_operation(operation_id)
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self._capture_repo = CaptureGroupRepository.from_system_config()
        self._operation_repo = OperationCaptureRepository.from_system_config()
        self._transaction_repo = TransactionRepository.from_system_config()
        self.operation_db_path = Path(SystemConfigSettings.operation_db())
        self.capture_group_db_path = Path(SystemConfigSettings.capture_group_db())

        self.operation_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.capture_group_db_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Internal JSON helpers
    # ------------------------------------------------------------------ #
    def _load_json(self, path: Path) -> dict[str, dict]:
        try:
            with path.open("r") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                self.logger.warning("Expected dict at %s, got %s", path, type(data))
                return {}
            return data
        except json.JSONDecodeError:
            self.logger.error("Failed to parse JSON database at %s", path)
            return {}
        except FileNotFoundError:
            self.logger.warning("JSON database not found at %s", path)
            return {}

    # ------------------------------------------------------------------ #
    # Resolution helpers
    # ------------------------------------------------------------------ #
    def get_capture_group_id(self, operation_id: OperationId) -> GroupId | None:
        """
        Resolve A Capture Group Identifier From An Operation ID.

        Returns the associated capture_group_id string when present in the
        operation database; otherwise returns None.
        """
        capture_group_id = self._operation_repo.get_capture_group_id(operation_id)
        if capture_group_id is not None:
            return capture_group_id

        op_db = self._load_json(self.operation_db_path)
        rec = op_db.get(operation_id)
        if not rec:
            self.logger.info(
                "No operation record found for operation_id=%s", operation_id
            )
            return None

        capture_group_id_value = rec.get("capture_group_id")
        if capture_group_id_value:
            capture_group_id = GroupId(str(capture_group_id_value))
        else:
            legacy_capture_group = rec.get("capture_group")
            if legacy_capture_group:
                self.logger.warning(
                    "Operation record for %s uses legacy 'capture_group' field",
                    operation_id,
                )
                capture_group_id = GroupId(str(legacy_capture_group))
            self.logger.warning(
                "Operation record for %s is missing 'capture_group_id' field",
                operation_id,
            )
            if not legacy_capture_group:
                return None

        created_value = rec.get("created")
        created_epoch = int(created_value) if created_value else _DEFAULT_CREATED_EPOCH
        self._capture_repo.get_or_create_capture_group(
            capture_group_id, TimestampSec(created_epoch)
        )
        self._operation_repo.upsert_operation_capture(
            operation_id, capture_group_id, TimestampSec(created_epoch)
        )
        return capture_group_id

    def get_transaction_ids_for_capture_group(
        self, capture_group_id: GroupId
    ) -> list[TransactionId]:
        """
        Resolve All Transaction IDs Belonging To A Capture Group.

        Returns an ordered list of TransactionId values, or an empty list if
        the capture group is unknown or has no associated transactions.
        """
        db_transactions = self._capture_repo.list_transactions(capture_group_id)
        if db_transactions:
            return db_transactions

        cg_db = self._load_json(self.capture_group_db_path)
        rec = cg_db.get(capture_group_id)
        if not rec:
            self.logger.info(
                "No capture group record found for capture_group_id=%s",
                capture_group_id,
            )
            return []

        txns = rec.get("transactions") or []
        if not isinstance(txns, list):
            self.logger.warning(
                "Capture group %s has non-list 'transactions' field: %r",
                capture_group_id,
                type(txns),
            )
            return []

        created_value = rec.get("created")
        created_epoch = int(created_value) if created_value else _DEFAULT_CREATED_EPOCH
        self._capture_repo.get_or_create_capture_group(
            capture_group_id, TimestampSec(created_epoch)
        )

        transaction_ids: list[TransactionId] = []
        for tid in txns:
            tx_id = str(tid)
            if not tx_id.strip():
                self.logger.warning(
                    "Skipping empty transaction_id in capture_group_db for capture_group_id=%s",
                    capture_group_id,
                )
                continue
            transaction_id = TransactionId(tx_id)
            transaction_ids.append(transaction_id)
            if self._transaction_repo.get_transaction_record(transaction_id) is None:
                self.logger.warning(
                    "Skipping capture_group backfill for missing transaction_id=%s",
                    transaction_id,
                )
                continue
            self._capture_repo.add_transaction(
                capture_group_id, transaction_id, TimestampSec(created_epoch)
            )
        return transaction_ids

    def get_transaction_ids_for_operation(
        self, operation_id: OperationId
    ) -> list[TransactionId]:
        """
        Resolve All Transaction IDs Associated With An Operation ID.

        This is a convenience wrapper that:
          1) Finds the capture_group_id for the supplied operation_id.
          2) Returns the list of TransactionId values for that capture group.
        """
        capture_group_id = self.get_capture_group_id(operation_id)
        if not capture_group_id:
            return []
        return self.get_transaction_ids_for_capture_group(capture_group_id)

    def get_transaction_models_for_operation(
        self, operation_id: OperationId
    ) -> list[TransactionRecordModel]:
        """
        Resolve TransactionRecordModel Instances For An Operation ID.

        For each transaction id mapped to the given operation, this method
        constructs a canonical TransactionRecordModel via PnmFileTransaction.

        Missing records are skipped; only models with a non-empty transaction_id
        field are returned.
        """
        txn_ids = self.get_transaction_ids_for_operation(operation_id)
        if not txn_ids:
            self.logger.info(
                "No transaction IDs found for operation_id=%s", operation_id
            )
            return []

        txn_store = PnmFileTransaction()
        models: list[TransactionRecordModel] = []

        for tid in txn_ids:
            model = txn_store.getRecordModel(tid)
            # Assuming TransactionRecordModel.null() sets transaction_id to an empty string.
            tx_id = str(getattr(model, "transaction_id", "")).strip()
            if tx_id:
                models.append(model)
            else:
                self.logger.warning(
                    "TransactionRecordModel for tid=%s is null/empty and will be skipped",
                    tid,
                )

        return models
