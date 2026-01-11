### Summary
Shifted capture-group and operation linkage persistence to DB-backed repositories with JSON fallback/backfill, aligned schema assets, and updated tests to seed DB transactions for capture group linking while keeping existing API shapes stable. Added a brief FAQ entry for the legacy operation_capture key handling and recorded a TODO to confirm the FAQ update.

### Modified Files
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

# FILE: docs/design/db/database-backend-burndown.md
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2025-2026 Maurice Garcia -->

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

- Runtime persistence is DB-only once M3/M4/M5 are implemented for the relevant flows.
- JSON ledgers become legacy-only:
  - Not written by runtime once the DB write paths land.
  - Not read by runtime endpoints once DB read paths land.
  - Optional offline migrator may exist, but is not part of runtime behavior.

## Recent Status Update (2026-01-11)

Work completed since the last burndown sync (per Agent Review Bundles):

- `install.sh`
  - DB backend selection runs before `pytest` so tests execute against the selected backend contract.
  - Added `--db-install-sqlite` and `--db-install-postgres`, plus an interactive prompt when no flag is provided (defaults to SQLite in non-interactive/CI).
  - Added Postgres DSN prompt with password redaction (passwords are not persisted into `system.json`).
  - Fixed DSN redaction backreference and aligned DSN env-var warning logic to `POSTGRES_DSN_ENV_VAR` via indirect expansion.
- `docs/system/system-config.md`
  - Updated `PnmFileRetrieval` heading/anchor for GitHub compatibility.
  - Documented runtime DB location policy and recommended env var usage for Postgres DSNs.
- Design docs updated to reinforce the end state:
  - JSON ledger persistence is deprecated and the target state is DB-backed persistence for transactions, capture groups, and operations.

Out-of-scope but in-flight (separate hygiene workstream): Ruff baseline cleanup (125 remaining issues after `ruff check . --fix`, including `PnmParsers` undefined name).

## Phase 7.7 Burndown Tracker (Updated 2026-01-11)

This tracker is a near-term hygiene lane that should remain compatible with the DB migration. It is not a replacement for the DB cutover milestones.

## Recent Completions

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
- Verification complete:
  - `python3 -m compileall src` pass
  - `ruff check .` pass
  - `ruff format --check .` pass
  - `pytest -q` pass (577 passed, 4 skipped)

## Remaining Phase 7.7 TODOs (Open Items)

1) Address `PytestConfigWarning` related to `asyncio_mode` configuration
   - Goal: eliminate warning via explicit pytest config (no runtime impact, but hygiene blocker)

2) Final “legacy-key hygiene” scan
   - Goal: confirm no remaining deprecated/legacy keys or payload fields are being written or relied upon unintentionally
   - Scope: operation/capture records, workflow responses, and multi-capture start/status/result payloads

## Validation Gate (Must Stay Green)

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
- M2: Not started (schema assets + DB abstraction layer)
- M3: Not started (transactions migration; stops `transactions.json` writes)
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

- [ ] Implement DB connection layer in PyPNM:
  - [ ] SQLite connection opens with `PRAGMA foreign_keys = ON`
  - [ ] SQLite enables WAL + sets a busy timeout (to reduce transient contention)
  - [ ] Postgres connection opens via DSN (minimum) or discrete settings
  - [ ] Minimal connection factory based on `Database.backend`

- [ ] Implement schema apply/init (idempotent, using shipped DDL assets):
  - [ ] Apply DDL idempotently on startup/install
  - [ ] Seed canonical `UNKNOWN` sysDescr row idempotently
  - [ ] Seed default `artifact_stores` row idempotently:
    - [ ] prod store: `.data/pnm`
    - [ ] demo store: `demo/.data/pnm` (only if demo enabled/used)

- [ ] Add “DB health” check function for diagnostics:
  - [ ] Connect, verify required tables exist, verify `UNKNOWN` row exists
  - [ ] Verify schema version compatibility (`schema_meta.schema_version`)

- [ ] Add pytest coverage:
  - [ ] SQLite: init creates tables and seed rows (pure unit test)
  - [ ] Postgres: init path is wired; CI runs minimal integration

### Acceptance Criteria

- [ ] PyPNM can initialize DB schema for SQLite reliably.
- [ ] Postgres path is implemented and can be exercised with integration tests.
- [ ] `UNKNOWN` sysDescr exists after init.
- [ ] Schema version mismatch fails fast with an actionable error.

## Phase 3 · Transactions Migration (Replace `transactions.json`) (M3)

### Goal

Replace JSON transactions ledger with DB-backed `transaction_records` plus de-dup dimensions, and update endpoint read paths.

Cutover note:

- This phase is the first hard break where runtime must stop writing `transactions.json`.
- Runtime must not implement fallback reads from JSON ledgers once DB reads exist (DB-only policy).

### Tasks

- [ ] Implement repository/service layer:
  - [ ] `SystemDescriptionRepository` (upsert by hash)
  - [ ] `DeviceDetailsRepository` (upsert by hash, FK sysDescr)
  - [ ] `TransactionRepository` (insert/get/list/search)

- [ ] Enforce safeguards:
  - [ ] MAC normalization in app (lowercase)
  - [ ] Rely on DB CHECK constraints for MAC format enforcement

- [ ] Update transaction creation/read code to use DB:
  - [ ] Stop writing `transactions.json`
  - [ ] Preserve external API shapes as needed by current services/endpoints

- [ ] Update file-manager endpoints to query DB (no ledger reads):
  - [ ] `getMacAddresses`
  - [ ] `searchFiles/{mac_address}`
  - [ ] `download/transactionID/{transaction_id}` (resolution depends on Phase 5 tables)

- [ ] Add pytest coverage:
  - [ ] Insert transaction creates dims (sysDescr/device details)
  - [ ] De-dup sysDescr across multiple transactions
  - [ ] De-dup device details across multiple transactions
  - [ ] Endpoint-compatible query behavior (service-level tests)

### Acceptance Criteria

- [ ] Captures produce DB rows instead of writing `transactions.json`.
- [ ] File manager flows can fetch transactions from DB (no JSON ledger traversal).
- [ ] There is no runtime write path that touches `transactions.json`.

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

- [ ] Runtime must not fall back to JSON ledger reads once DB read paths exist.
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

# FILE: src/pypnm/api/routes/common/classes/file_capture/pnm_file_transaction.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import hashlib
import logging
import time

from pypnm.api.routes.common.classes.file_capture.types import (
    DeviceDetailsModel,
    TransactionRecordModel,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRecordRow,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import FileName, TimestampSec, TransactionId
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


class PnmFileTransaction:
    """
    Manages persistent tracking of PNM file transactions across the PyPNM system.

    Each transaction corresponds to a PNM test result file (e.g., RxMER, Spectrum Analysis),
    whether generated through automated measurements or manually uploaded by a user.

    A transaction includes:
        - A unique transaction ID (16-char SHA-256 digest)
        - Timestamp (epoch time)
        - MAC address of the cable modem
        - PNM test type (e.g., DS_RXMER, SPECTRUM_ANALYZER)
        - Filename of the associated binary data file

    Transactions are stored in the configured database backend (SQLite/Postgres)
    using the DB schema defined under docs/design/db/.

    Usage Scenarios:
        - When a measurement test completes and produces a file.
        - When a user uploads a file manually via the REST API.
        - When retrieving metadata about previously captured test files.

    Record structure mirrors the legacy JSON layout so downstream parsers stay stable:
        {
            "timestamp": int,
            "mac_address": "<cable modem mac address>",
            "pnm_test_type": "<PNM Test Type>",
            "filename": "<FileName>",
            "device_details": {
                "system_description": { ... }
            }
        }
    """

    PNM_TEST_TYPE = "pnm_test_type"
    FILE_NAME = "filename"
    DEVICE_DETAILS = "device_details"
    MAC_ADDRESS = "mac_address"

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self._sysdescr_repo = SystemDescriptionRepository.from_system_config()
        self._device_details_repo = DeviceDetailsRepository.from_system_config()
        self._transaction_repo = TransactionRepository.from_system_config()

    async def insert(
        self, cable_modem: CableModem, pnm_test_type: DocsPnmCmCtlTest, filename: str
    ) -> TransactionId:
        """
        Record A Transaction Initiated From An Actual Cable Modem Test.

        This method is invoked by measurement services once a PNM capture has
        successfully completed and produced a result file. It pulls the current
        system description from the cable modem, generates a new transaction
        identifier, and appends a normalized record into the transaction
        database.

        Parameters
        ----------
        cable_modem:
            Live `CableModem` instance representing the device under test. Used
            to obtain the MAC address and system description snapshot.
        pnm_test_type:
            Enumeration value describing which PNM test produced the file
            (for example, DS_RXMER, DS_OFDM_HISTOGRAM, DS_CONSTELLATION).
        filename:
            Relative or absolute path to the generated PNM binary file, as
            stored by the calling measurement service.

        Returns
        -------
        str
            Newly generated transaction identifier (16-character SHA-256
            digest prefix) suitable for later lookup (download and analysis).
        """
        sd: SystemDescriptor = await cable_modem.getSysDescr()
        return self._insert_generic(
            mac_address=cable_modem.get_mac_address,
            pnm_test_type=pnm_test_type,
            filename=filename,
            system_description=sd.to_dict(),
        )

    @staticmethod
    def set_file_by_user(
        mac_address: MacAddress, pnm_test_type: DocsPnmCmCtlTest, filename: FileName
    ) -> TransactionId:
        """
        Record A Transaction For A Manually Supplied File (User Upload).

        This path is used when the file is not the result of an automated test
        initiated by PyPNM, but rather provided by the user (for example, a
        lab-captured PNM file uploaded via REST). The record is normalized into
        the same transaction database used for automated captures.

        Parameters
        ----------
        mac_address:
            MAC address of the cable modem associated with the uploaded file.
        pnm_test_type:
            Enumeration describing the semantic PNM test type for the file,
            allowing downstream analysis routing to behave consistently.
        filename:
            Filesystem path or name where the uploaded file has been stored on
            the server.

        Returns
        -------
        str
            Newly generated transaction identifier bound to the uploaded file.
        """
        txn = PnmFileTransaction()
        return txn._insert_generic(
            mac_address=mac_address,
            pnm_test_type=pnm_test_type,
            filename=filename,
        )

    def get_record(self, transaction_id: TransactionId) -> dict | None:
        """
        Fetch A Plain Dictionary Representation Of A Transaction Record.

        This method provides a minimal, schema-free view into the transaction
        database. It is intended for low-level callers that need direct access
        to the stored fields without constructing a Pydantic model.

        Parameters
        ----------
        transaction_id:
            Unique transaction identifier for the record to retrieve.

        Returns
        -------
        dict | None
            The underlying transaction record as a dictionary, or `None` when
            the identifier does not exist in the database.
        """
        record = self._transaction_repo.get_transaction_record(transaction_id)
        if record is None:
            return None
        return self._record_to_payload(record)

    def get(self, transaction_id: TransactionId) -> dict | None:
        return self.get_record(transaction_id)

    def getRecordModel(self, transaction_id: TransactionId) -> TransactionRecordModel:
        """
        Build A Canonical TransactionRecordModel For A Transaction Identifier.

        This convenience wrapper resolves the DB-backed record and constructs
        the normalized Pydantic model. If the record does not exist, a
        `null()` sentinel model is returned.

        Parameters
        ----------
        transaction_id:
            Unique transaction identifier for which a model representation is
            requested.

        Returns
        -------
        TransactionRecordModel
            Canonical, fully-normalized transaction model, or the sentinel
            `TransactionRecordModel.null()` instance for missing records.
        """
        record = self._transaction_repo.get_transaction_record(transaction_id)
        if record is None:
            return TransactionRecordModel.null()
        return self._record_to_model(record)

    def get_file_info_via_macaddress(
        self, mac_address: MacAddress
    ) -> list[TransactionRecordModel]:
        """
        Retrieve All Transaction Records Associated With A Given MAC Address.

        This method scans the transaction database and collects all entries
        whose stored `mac_address` matches the supplied cable modem MAC (case-
        insensitive). Each matching record is returned as a fully normalized
        `TransactionRecordModel`, using the same parsing logic as individual
        lookups.

        Typical usage patterns include:
        - Building a catalog of all PNM files available for a modem.
        - Populating UI tables of historical captures keyed by MAC address.
        - Providing selection lists for downstream download or analysis calls.

        Parameters
        ----------
        mac_address:
            Cable modem MAC address used as the primary lookup key. The value
            is normalized to lower-case for comparison against stored records.

        Returns
        -------
        List[TransactionRecordModel]
            List of canonical `TransactionRecordModel` instances for all
            transactions associated with the given MAC address. The list is
            empty when no matching records are found.
        """
        records = self._transaction_repo.list_transactions_for_mac(mac_address)
        models: list[TransactionRecordModel] = []
        for record in records:
            model = self._record_to_model(record)
            models.append(model)
        return models

    def get_all_record_models(self) -> list[TransactionRecordModel]:
        """
        Retrieve All Transaction Records As Canonical Models.

        This scans the transaction database and returns each record as a fully
        normalized `TransactionRecordModel`. Any per-record parse failures are
        logged and skipped so callers can still operate on partial data.

        Returns
        -------
        list[TransactionRecordModel]
            List of all transaction models currently stored in the transaction
            database. The list is empty when no records exist.
        """
        records = self._transaction_repo.list_all_transactions()
        if not records:
            return []

        models: list[TransactionRecordModel] = []
        for record in records:
            model = self._safe_record_model(record)
            if model is not None:
                models.append(model)

        return models

    def _safe_record_model(
        self, record: TransactionRecordRow
    ) -> TransactionRecordModel | None:
        try:
            return self._record_to_model(record)
        except Exception as exc:
            self.logger.warning("Skipping transaction due to parse error: %s", exc)
            return None

    # ---------------------------
    # Write helpers
    # ---------------------------

    def _insert_generic(
        self,
        mac_address: MacAddress,
        pnm_test_type: DocsPnmCmCtlTest,
        filename: str,
        system_description: dict[str, str] | None = None,
    ) -> TransactionId:
        """
        Common Logic For Creating And Persisting A Transaction Record.

        This internal helper generates a new transaction identifier, assembles
        the DB-backed record structure, and persists the transaction to the
        configured database backend.

        Parameters
        ----------
        mac_address:
            MAC address of the cable modem associated with the transaction.
        pnm_test_type:
            Enumeration describing the PNM test type that produced or owns the
            associated file.
        filename:
            Path or name of the PNM data file linked to this transaction.
        system_description:
            Optional system description snapshot dictionary, typically produced
            via `SystemDescriptor.to_dict()`. When omitted, an empty mapping is
            stored under `device_details.system_description`.

        Returns
        -------
        str
            Newly created transaction identifier associated with the record.
        """
        timestamp = int(time.time())
        hash_input = f"{filename}{timestamp}".encode()
        transaction_id = TransactionId(hashlib.sha256(hash_input).hexdigest()[:16])
        tx_id = str(transaction_id)
        if not tx_id.strip():
            self.logger.warning(
                "Skipping transaction insert for empty transaction_id (filename=%s, mac=%s)",
                filename,
                mac_address,
            )
            return TransactionId("")

        normalized_sd = self._normalize_system_description(system_description)
        device_details = {"system_description": normalized_sd}
        sysdescr_payload = normalized_sd if normalized_sd else None
        sysdescr_id = self._sysdescr_repo.get_or_create_sysdescr_id(sysdescr_payload)
        device_detail_id = self._device_details_repo.get_or_create_device_detail_id(
            device_details, sysdescr_id
        )
        self._transaction_repo.insert_transaction(
            transaction_id=transaction_id,
            timestamp_epoch=TimestampSec(timestamp),
            mac_address=mac_address,
            pnm_test_type=pnm_test_type.name,
            filename=filename,
            device_detail_id=device_detail_id,
        )
        return transaction_id

    @staticmethod
    def _normalize_system_description(
        system_description: dict[str, str] | None,
    ) -> dict[str, str]:
        if not system_description:
            return {}
        return SystemDescriptor.load_from_dict(system_description).to_dict()

    def _record_to_payload(self, record: TransactionRecordRow) -> dict:
        return {
            "timestamp": int(record.timestamp_epoch),
            "mac_address": str(record.mac_address),
            "pnm_test_type": record.pnm_test_type,
            "filename": str(record.filename),
            "device_details": {
                "system_description": record.system_description or {},
            },
        }

    def _record_to_model(self, record: TransactionRecordRow) -> TransactionRecordModel:
        sysdesc = record.system_description or {}
        system_description = SystemDescriptor.load_from_dict(sysdesc).to_model()
        return TransactionRecordModel(
            transaction_id=record.transaction_id,
            timestamp=TimestampSec(int(record.timestamp_epoch)),
            mac_address=record.mac_address,
            pnm_test_type=record.pnm_test_type,
            filename=record.filename,
            device_details=DeviceDetailsModel(system_description=system_description),
        )

# FILE: src/pypnm/api/routes/docs/pnm/files/service.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import cast

from fastapi import HTTPException
from fastapi.responses import FileResponse

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisRptMatplotConfig
from pypnm.api.routes.basic.channel_estimation_analysis_rpt import ChanEstimationReport
from pypnm.api.routes.basic.constellation_display_analysis_rpt import (
    ConstDisplayAnalysisRptMatplotConfig,
    ConstellationDisplayReport,
)
from pypnm.api.routes.basic.fec_summary_analysis_rpt import FecSummaryAnalysisReport
from pypnm.api.routes.basic.modulation_profile_analysis_rpt import (
    ModulationProfileReport,
)
from pypnm.api.routes.basic.rxmer_analysis_rpt import RxMerAnalysisReport
from pypnm.api.routes.basic.us_ofdma_pre_eq_analysis_rpt import CmUsOfdmaPreEqReport
from pypnm.api.routes.common.classes.analysis.model.schema import (
    ParserAnalysisModelReturn,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.file_capture.pnm_file_opearation import (
    OperationCaptureGroupResolver,
)
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.docs.pnm.files.schemas import (
    FileAnalysisRequest,
    FileEntry,
    FileQueryRequest,
    FileQueryResponse,
    HexDumpResponse,
    MacAddressSystemDescriptorEntry,
    MacAddressSystemDescriptorResponse,
    UploadFileResponse,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.archive.manager import ArchiveManager
from pypnm.lib.constants import MediaType
from pypnm.lib.db.transaction_repository import TransactionRepository
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    FileName,
    MacAddressStr,
    OperationId,
    PathLike,
    TransactionId,
)
from pypnm.lib.utils import Generate
from pypnm.pnm.parser.model.parser_rtn_models import (
    CmDsConstDispMeasModel,
    CmDsHistModel,
    CmDsOfdmChanEstimateCoefModel,
    CmDsOfdmFecSummaryModel,
    CmDsOfdmModulationProfileModel,
    CmDsOfdmRxMerModel,
    CmUsOfdmaPreEqModel,
)
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_parameter import (
    GetPnmParserAndParameters,
    PnmParserParametersModel,
    PnmParsers,
)
from pypnm.pnm.parser.pnm_type_header_mapper import PnmFileTypeMapper


class PnmFileService:
    """
    Handles file storage, metadata registration, and high-level analysis
    for PNM-related binary data pushed into the PyPNM system.

    Methods:
        - search_files: List available files by MAC.
        - get_file_by_transaction_id: Download raw PNM file by transaction ID.
        - get_file_by_operation_id: Download all files for an operation as a ZIP.
        - get_file_by_mac_address: Download all files for a MAC as a ZIP.
        - upload_file: Accepts uploaded files, saves, and registers.
        - get_analysis: Produces analysis for a stored file.
        - get_file: Serve generated CSV/JSON/ARCHIVE files.
    """

    def __init__(self) -> None:
        self.pnm_dir: PathLike = SystemConfigSettings.pnm_dir()
        self.logger = logging.getLogger(self.__class__.__name__)

    def search_files(self, req: FileQueryRequest) -> FileQueryResponse:
        """
        Searches for all registered PNM files tied to a specific MAC address.
        """
        try:
            mac = MacAddress(req.mac_address)
            txn = PnmFileTransaction()
            results = txn.get_file_info_via_macaddress(mac)

            if not results:
                self.logger.warning(f"No files found for MAC: {mac}")
                return FileQueryResponse(files={str(mac): []})

            file_entries: list[FileEntry] = []

            for entry in results:
                device_details = getattr(entry, "device_details", None)

                if hasattr(device_details, "model_dump"):
                    system_description = device_details.model_dump()
                elif isinstance(device_details, dict):
                    system_description = device_details
                else:
                    system_description = None

                file_entries.append(
                    FileEntry(
                        transaction_id=entry.transaction_id,
                        filename=entry.filename,
                        pnm_test_type=entry.pnm_test_type,
                        timestamp=entry.timestamp,
                        system_description=system_description,
                    )
                )

            return FileQueryResponse(files={str(mac): file_entries})

        except Exception as e:
            self.logger.error(f"Failed to search files for MAC {req.mac_address}: {e}")
            return FileQueryResponse(files={req.mac_address: []})

    def get_file_by_transaction_id(self, transaction_id: TransactionId) -> FileResponse:
        """
        Retrieves and serves the binary file associated with the given transaction ID.
        """
        txn_data = PnmFileTransaction().get_record(transaction_id)

        if not txn_data:
            raise HTTPException(status_code=404, detail="Transaction ID not found.")

        filename = txn_data.get("filename")
        full_path = Path(self.pnm_dir) / str(filename)

        self.logger.info(
            f"Retrieving file for transaction {transaction_id}: {full_path}"
        )

        if not full_path.exists():
            raise HTTPException(status_code=404, detail="File not found on disk.")

        return FileResponse(
            path=full_path,
            filename=filename,
            media_type=MediaType.APPLICATION_OCTET_STREAM,
        )

    def get_file_by_operation_id(self, operation_id: OperationId) -> FileResponse:
        """
        Retrieve All PNM Files For An Operation ID As A ZIP Archive.

        Resolves the capture group associated with the supplied operation ID,
        then collects all transaction records in that group, locates their
        corresponding PNM files on disk, and packages them into a single ZIP
        archive for download.
        """
        resolver = OperationCaptureGroupResolver()
        txn_models = resolver.get_transaction_models_for_operation(operation_id)

        if not txn_models:
            raise HTTPException(
                status_code=404, detail="No transactions found for Operation ID."
            )

        files_to_archive: list[Path] = []
        for rec in txn_models:
            src_path = Path(self.pnm_dir) / Path(rec.filename)
            if not src_path.is_file():
                self.logger.warning(
                    "Skipping missing file for transaction %s at %s",
                    rec.transaction_id,
                    src_path,
                )
                continue
            files_to_archive.append(src_path)

        if not files_to_archive:
            raise HTTPException(
                status_code=404, detail="No files on disk for Operation ID."
            )

        archive_dir = Path(SystemConfigSettings.archive_dir())
        archive_dir.mkdir(parents=True, exist_ok=True)

        archive_name = f"pnm_operation_{operation_id}_{Generate.time_stamp()}.zip"
        archive_path = archive_dir / archive_name

        ArchiveManager.zip_files(
            files=files_to_archive,
            archive_path=archive_path,
            mode="w",
            compression="zipdeflated",
            preserve_tree=False,
        )

        if not archive_path.is_file():
            self.logger.error(
                "Archive creation failed for Operation ID %s at %s",
                operation_id,
                archive_path,
            )
            raise HTTPException(
                status_code=500, detail="Failed to create archive for Operation ID."
            )

        self.logger.info(
            "Returning ZIP archive for Operation ID %s: %s", operation_id, archive_path
        )

        return FileResponse(
            path=str(archive_path),
            filename=archive_name,
            media_type=MediaType.APPLICATION_ZIP,
        )

    def get_file_by_mac_address(self, mac_address: MacAddressStr) -> FileResponse:
        """
        Retrieve All PNM Files For A MAC Address As A ZIP Archive.

        Looks up all transaction records bound to the provided cable modem
        MAC address, collects their associated PNM files from the PNM
        directory, and packages them into a single ZIP archive for download.

        If no records are found, or none of the files exist on disk, a 404 is raised.
        """
        records = PnmFileTransaction().get_file_info_via_macaddress(
            MacAddress(mac_address)
        )

        if not records:
            raise HTTPException(
                status_code=404, detail="No transactions found for MAC address."
            )

        files_to_archive: list[Path] = []
        for rec in records:
            src_path = Path(self.pnm_dir) / Path(rec.filename)
            if not src_path.is_file():
                self.logger.warning(
                    "Skipping missing file for transaction %s: %s",
                    rec.transaction_id,
                    src_path,
                )
                continue
            files_to_archive.append(src_path)

        if not files_to_archive:
            raise HTTPException(
                status_code=404, detail="No files on disk for MAC address."
            )

        archive_dir = Path(SystemConfigSettings.archive_dir())
        archive_dir.mkdir(parents=True, exist_ok=True)

        safe_mac = str(MacAddress(mac_address).to_mac_format())
        archive_name = f"pnm_files_{safe_mac}_{Generate.time_stamp()}.zip"
        archive_path = archive_dir / archive_name

        ArchiveManager.zip_files(
            files=files_to_archive,
            archive_path=archive_path,
            mode="w",
            compression="zipdeflated",
            preserve_tree=False,
        )

        if not archive_path.is_file():
            self.logger.error(
                "Archive creation failed for MAC %s at %s", mac_address, archive_path
            )
            raise HTTPException(
                status_code=500, detail="Failed to create archive for MAC address."
            )

        self.logger.info(
            "Returning ZIP archive for MAC %s: %s", mac_address, archive_path
        )

        return FileResponse(
            path=str(archive_path),
            filename=archive_name,
            media_type=MediaType.APPLICATION_ZIP,
        )

    def upload_file(self, filename: FileName, data: bytes) -> UploadFileResponse:
        """
        Handle A User-Initiated Upload Of A Raw PNM Binary File.

        1. Saves the file locally to the configured directory.
        2. Inspects its header to identify the PNM file type and MAC.
        3. Maps it to a known DOCSIS test type.
        4. Registers the transaction and returns the transaction ID.
        """
        os.makedirs(self.pnm_dir, exist_ok=True)
        filepath = os.path.join(self.pnm_dir, filename)

        processor = FileProcessor(filepath)
        success = processor.write_file(data)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to write file")

        params = GetPnmParserAndParameters(processor.read_file()).to_model()
        mac_address = params.mac_address or MacAddress.null()
        pnm_file_type: PnmFileType = params.file_type

        transaction_id = PnmFileTransaction().set_file_by_user(
            mac_address=MacAddress(mac_address),
            pnm_test_type=PnmFileTypeMapper.get_test_type(pnm_file_type),
            filename=filename,
        )

        return UploadFileResponse(
            mac_address=MacAddress(mac_address).mac_address,
            filename=filename,
            transaction_id=transaction_id,
        )

    def get_file(self, file_type: FileType, filename: PathLike) -> FileResponse:
        """
        Serve a generated file from its configured directory.

        Supported types:
        - CSV: returns text/csv from SystemConfigSettings.csv_dir
        - JSON: returns application/json from SystemConfigSettings.json_dir
        - ARCHIVE: returns application/zip from SystemConfigSettings.archive_dir
        """
        safe_name = Path(filename).name

        valid_extensions = [".csv", ".json", ".zip"]
        if not any(safe_name.endswith(ext) for ext in valid_extensions):
            raise HTTPException(
                status_code=400, detail=f"Invalid file extension, file: {safe_name}"
            )

        if file_type == FileType.CSV:
            base_dir = SystemConfigSettings.csv_dir()
            media_type = MediaType.TEXT_CSV

        elif file_type == FileType.JSON:
            base_dir = SystemConfigSettings.json_dir()
            media_type = MediaType.APPLICATION_JSON

        elif file_type == FileType.ARCHIVE:
            base_dir = SystemConfigSettings.archive_dir()
            media_type = MediaType.APPLICATION_ZIP

        else:
            self.logger.error(f"Unsupported file type requested: {file_type.name}")
            raise HTTPException(
                status_code=400, detail=f"Unsupported file type: {file_type.name}"
            )

        file_path = Path(base_dir) / safe_name
        if not file_path.is_file():
            self.logger.warning(f"File not found: {file_path}")
            raise HTTPException(status_code=404, detail="File not found on disk.")

        return FileResponse(
            path=str(file_path),
            filename=safe_name,
            media_type=media_type,
        )

    def get_analysis(
        self, req: FileAnalysisRequest
    ) -> tuple[ParserAnalysisModelReturn, PnmFileType]:
        """
        Returns basic analysis result for a stored PNM file identified by transaction ID.
        The analysis performed depends on the PNM file type.

        Return:
        Tuple[ParserAnalysisModelReturn, PnmFileType]
            A tuple containing the analysis model and the PNM file type.
        """
        txn_rec = PnmFileTransaction().get_record(req.search.transaction_id)
        if not txn_rec:
            raise HTTPException(
                status_code=404, detail="Transaction ID not found for analysis."
            )

        filename = txn_rec.get("filename")
        if not filename:
            raise HTTPException(
                status_code=404, detail="Filename not found in transaction record."
            )

        self.logger.info(
            f"Starting analysis for transaction ID {req.search.transaction_id} on file: {self.pnm_dir}/{filename}"
        )

        # Get binary file
        file_path = f"{self.pnm_dir}/{filename}"

        if not Path(file_path).is_file():
            raise HTTPException(
                status_code=404, detail="PNM file not found on disk for analysis."
            )
        fp = FileProcessor(file_path).read_file()

        # Get PnmHeader to Determine PnmFileType
        from pypnm.pnm.parser.pnm_parameter import GetPnmParserAndParameters

        parser, model = GetPnmParserAndParameters(fp).get_parser()

        self.logger.info(
            f"Performing {model.file_type.name} analysis for transaction {req.search.transaction_id} on file {filename}"
        )

        return self.__get_analysis(parser, model)

    def get_pnm_path_for_transaction(self, transaction_id: TransactionId) -> Path:
        """
        Resolve The Filesystem Path For A PNM File From A Transaction ID.

        Parameters
        ----------
        transaction_id:
            Transaction identifier associated with the PNM capture file.

        Returns
        -------
        Path
            Fully-resolved path to the PNM file on disk.

        Raises
        ------
        HTTPException
            If the transaction record does not exist, the filename is missing,
            or the file is not present on disk.
        """
        txn_data = PnmFileTransaction().get_record(transaction_id)
        if not txn_data:
            raise HTTPException(status_code=404, detail="Transaction ID not found.")

        filename = txn_data.get("filename")
        if not filename:
            raise HTTPException(
                status_code=404, detail="Filename not found in transaction record."
            )

        full_path = Path(self.pnm_dir) / str(filename)

        self.logger.info(
            "Resolving PNM file for transaction %s at %s",
            transaction_id,
            full_path,
        )

        if not full_path.exists() or not full_path.is_file():
            self.logger.warning(
                "PNM file not found on disk for transaction %s at %s",
                transaction_id,
                full_path,
            )
            raise HTTPException(status_code=404, detail="PNM file not found on disk.")

        return full_path

    def get_hexdump_by_transaction_id(
        self, transaction_id: TransactionId, bytes_per_line: int
    ) -> HexDumpResponse:
        """
        Generate A Structured Hexdump For A PNM File Identified By Transaction ID.

        Parameters
        ----------
        transaction_id:
            Transaction identifier associated with the PNM capture file.
        bytes_per_line:
            Number of bytes per output line in the hexdump view. Typical values
            are 8, 16, or 32. Non-positive values are coerced to the default
            configured via DEFAULT_HEXDUMP_BYTES_PER_LINE.

        Returns
        -------
        HexDumpResponse
            Structured hexdump payload including the transaction ID, the
            effective bytes-per-line setting, and formatted hexdump lines
            containing offset, hex bytes, and ASCII representation.
        """
        DEFAULT_HEXDUMP_BYTES_PER_LINE = 16

        if bytes_per_line <= 0:
            bytes_per_line = DEFAULT_HEXDUMP_BYTES_PER_LINE

        file_path = self.get_pnm_path_for_transaction(transaction_id)
        processor = FileProcessor(file_path)
        lines = processor.hexdump(bytes_per_line=bytes_per_line)

        if not lines:
            self.logger.error(
                "Hexdump generation failed or produced no data for transaction %s at %s",
                transaction_id,
                file_path,
            )
            raise HTTPException(
                status_code=500, detail="Failed to generate hexdump for PNM file."
            )

        return HexDumpResponse(
            transaction_id=transaction_id,
            bytes_per_line=bytes_per_line,
            lines=lines,
        )

    def __get_analysis(
        self, parser: PnmParsers, model: PnmParserParametersModel
    ) -> tuple[ParserAnalysisModelReturn, PnmFileType]:
        """
        Internal method to instantiate the Analysis class with the given parser and model.
        """
        from pypnm.api.routes.common.classes.analysis.analysis import Analysis

        if model.file_type == PnmFileType.RECEIVE_MODULATION_ERROR_RATIO:
            return Analysis.basic_analysis_rxmer_from_model(
                cast(CmDsOfdmRxMerModel, parser.to_model())
            ), model.file_type

        elif model.file_type == PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT:
            return Analysis.basic_analysis_ds_chan_est_from_model(
                cast(CmDsOfdmChanEstimateCoefModel, parser.to_model())
            ), model.file_type

        elif model.file_type == PnmFileType.OFDM_MODULATION_PROFILE:
            return Analysis.basic_analysis_ds_modulation_profile_from_model(
                cast(CmDsOfdmModulationProfileModel, parser.to_model())
            ), model.file_type

        elif model.file_type == PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY:
            return Analysis.basic_analysis_ds_constellation_display_from_model(
                cast(CmDsConstDispMeasModel, parser.to_model())
            ), model.file_type

        elif model.file_type == PnmFileType.DOWNSTREAM_HISTOGRAM:
            return Analysis.basic_analysis_ds_histogram_from_model(
                cast(CmDsHistModel, parser.to_model())
            ), model.file_type

        elif model.file_type == PnmFileType.OFDM_FEC_SUMMARY:
            return Analysis.basic_analysis_ds_ofdm_fec_summary_from_model(
                cast(CmDsOfdmFecSummaryModel, parser.to_model())
            ), model.file_type

        elif (
            model.file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS
            or model.file_type
            == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE
        ):
            return Analysis.basic_analysis_us_ofdma_pre_equalization_from_model(
                cast(CmUsOfdmaPreEqModel, parser.to_model())
            ), model.file_type

        raise HTTPException(
            status_code=400,
            detail=f"Analysis not implemented for file type: {model.file_type.name}",
        )

    def get_archive(self, request: FileAnalysisRequest) -> FileResponse:
        rpt: Path = Path()

        theme = request.analysis.plot.ui.theme
        plot_config = AnalysisRptMatplotConfig(theme=theme)
        analysis_model, pnm_ftype = self.get_analysis(request)

        # TODO: Need to clean up circlar import at next major release
        from pypnm.api.routes.common.classes.analysis.analysis import Analysis

        analysis = Analysis.get_analysis_from_model(analysis_model)

        if pnm_ftype == PnmFileType.RECEIVE_MODULATION_ERROR_RATIO:
            analysis_rpt = RxMerAnalysisReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT:
            analysis_rpt = ChanEstimationReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.OFDM_MODULATION_PROFILE:
            analysis_rpt = ModulationProfileReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY:
            plot_config = ConstDisplayAnalysisRptMatplotConfig(theme=theme)
            analysis_rpt = ConstellationDisplayReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif (
            pnm_ftype == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS
            or pnm_ftype == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE
        ):
            plot_config = ConstDisplayAnalysisRptMatplotConfig(theme=theme)
            analysis_rpt = CmUsOfdmaPreEqReport(analysis)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        elif pnm_ftype == PnmFileType.OFDM_FEC_SUMMARY:
            plot_config = ConstDisplayAnalysisRptMatplotConfig(theme=theme)
            analysis_rpt = FecSummaryAnalysisReport(analysis, plot_config)
            rpt: Path = cast(Path, analysis_rpt.build_report())

        return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

    def get_mac_addresses(self) -> MacAddressSystemDescriptorResponse:
        """
        Retrieve Unique MAC Addresses With Registered PNM Files.

        This scans all transaction records and returns a de-duplicated set of
        MAC addresses. When multiple records exist for the same MAC, the most
        recent record (by timestamp) is used as the source for the system
        descriptor when available.

        Parameters
        ----------
        req:
            Placeholder request model for endpoint compatibility. Currently not
            used for filtering.

        Returns
        -------
        MacAddressSystemDescriptorResponse
            Unique MAC address list with optional system descriptor per MAC.
        """
        entries = TransactionRepository.from_system_config().list_macs()
        if not entries:
            return MacAddressSystemDescriptorResponse(mac_addresses=[])

        response_entries = [
            MacAddressSystemDescriptorEntry(
                mac_address=entry.mac_address,
                system_description=entry.system_description,
            )
            for entry in entries
        ]

        return MacAddressSystemDescriptorResponse(mac_addresses=response_entries)

# FILE: src/pypnm/lib/db/capture_group_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from dataclasses import dataclass

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import (
    DatabaseSchemaManager,
    DbConnection,
)
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    OperationId,
    TimestampSec,
    TransactionId,
)

_POSITION_START: int = 0
_OPERATION_ID_COLUMN: str = "operation_id"
_LEGACY_OPERATION_ID_COLUMN: str = "operation_capture_id"


@dataclass(frozen=True)
class CaptureGroupRow:
    capture_group_id: GroupId
    created_epoch: TimestampSec


class CaptureGroupRepository:
    """
    Repository for capture_groups and capture_group_transactions tables.
    """

    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._schema_manager = DatabaseSchemaManager.from_overrides(
            backend, sqlite_path, postgres_dsn
        )
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def from_system_config(cls) -> CaptureGroupRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
        """
        return cls(
            SystemConfigSettings.database_backend(),
            SystemConfigSettings.database_sqlite_path(),
            SystemConfigSettings.database_postgres_dsn(),
        )

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> CaptureGroupRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def get_or_create_capture_group(
        self, capture_group_id: GroupId | str, created_epoch: TimestampSec
    ) -> CaptureGroupRow:
        """
        Resolve or insert a capture group row.
        """
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            existing = self._fetch_capture_group(connection, group_id)
            if existing is not None:
                return existing
            self._insert_capture_group(connection, group_id, created_epoch)
            fetched = self._fetch_capture_group(connection, group_id)
            if fetched is None:
                raise RuntimeError("Failed to resolve capture_group after insert")
            return fetched
        finally:
            connection.close()

    def capture_group_exists(self, capture_group_id: GroupId | str) -> bool:
        """
        Check whether a capture group exists.
        """
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            return self._fetch_capture_group(connection, group_id) is not None
        finally:
            connection.close()

    def add_transaction(
        self,
        capture_group_id: GroupId | str,
        transaction_id: TransactionId | str,
        created_epoch: TimestampSec,
    ) -> None:
        """
        Add a transaction membership row (idempotent). Assigns sequential position.
        """
        group_id = GroupId(str(capture_group_id))
        txn_id = TransactionId(str(transaction_id))
        connection = self._connect()
        try:
            existing = self._fetch_capture_group_transaction(
                connection, group_id, txn_id
            )
            if existing:
                return
            position = self._next_position(connection, group_id)
            self._insert_capture_group_transaction(
                connection, group_id, txn_id, position, created_epoch
            )
        finally:
            connection.close()

    def list_transactions(self, capture_group_id: GroupId | str) -> list[TransactionId]:
        """
        List transaction IDs for a capture group in deterministic order.
        """
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            rows = self._fetch_capture_group_transactions(connection, group_id)
        finally:
            connection.close()
        return [TransactionId(str(row[0])) for row in rows]

    def list_capture_groups(self) -> list[GroupId]:
        """
        List all capture group identifiers.
        """
        connection = self._connect()
        try:
            rows = self._fetch_capture_groups(connection)
        finally:
            connection.close()
        return [GroupId(str(row[0])) for row in rows]

    def delete_capture_group(self, capture_group_id: GroupId | str) -> None:
        """
        Delete a capture group and its membership rows.
        """
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        "DELETE FROM capture_groups WHERE capture_group_id = ?;",
                        (str(group_id),),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM capture_groups WHERE capture_group_id = %s;",
                            (str(group_id),),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def prune_older_than(self, cutoff_epoch: TimestampSec) -> int:
        """
        Delete capture groups older than the cutoff epoch and return count.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        "DELETE FROM capture_groups WHERE created_epoch < ?;",
                        (int(cutoff_epoch),),
                    )
                    connection.commit()
                    return int(cursor.rowcount or 0)
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM capture_groups WHERE created_epoch < %s;",
                            (int(cutoff_epoch),),
                        )
                        deleted = cursor.rowcount
                    connection.commit()
                    return int(deleted or 0)
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def _connect(self) -> DbConnection:
        return self._schema_manager.connect()

    def _fetch_capture_group(
        self, connection: DbConnection, group_id: GroupId
    ) -> CaptureGroupRow | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT capture_group_id, created_epoch FROM capture_groups WHERE capture_group_id = ?;",
                    (str(group_id),),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT capture_group_id, created_epoch FROM capture_groups WHERE capture_group_id = %s;",
                        (str(group_id),),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if row is None:
            return None
        return CaptureGroupRow(
            capture_group_id=GroupId(str(row[0])),
            created_epoch=TimestampSec(int(row[1])),
        )

    def _insert_capture_group(
        self,
        connection: DbConnection,
        group_id: GroupId,
        created_epoch: TimestampSec,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO capture_groups (capture_group_id, created_epoch)
                    VALUES (?, ?);
                    """,
                    (str(group_id), int(created_epoch)),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO capture_groups (capture_group_id, created_epoch)
                        VALUES (%s, %s)
                        ON CONFLICT (capture_group_id) DO NOTHING;
                        """,
                        (str(group_id), int(created_epoch)),
                    )
                connection.commit()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

    def _fetch_capture_group_transaction(
        self, connection: DbConnection, group_id: GroupId, txn_id: TransactionId
    ) -> bool:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT 1 FROM capture_group_transactions
                    WHERE capture_group_id = ? AND transaction_id = ?;
                    """,
                    (str(group_id), str(txn_id)),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT 1 FROM capture_group_transactions
                        WHERE capture_group_id = %s AND transaction_id = %s;
                        """,
                        (str(group_id), str(txn_id)),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        return row is not None

    def _next_position(self, connection: DbConnection, group_id: GroupId) -> int:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT MAX(position) FROM capture_group_transactions
                    WHERE capture_group_id = ?;
                    """,
                    (str(group_id),),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT MAX(position) FROM capture_group_transactions
                        WHERE capture_group_id = %s;
                        """,
                        (str(group_id),),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if row is None or row[0] is None:
            return _POSITION_START
        return int(row[0]) + 1

    def _insert_capture_group_transaction(
        self,
        connection: DbConnection,
        group_id: GroupId,
        txn_id: TransactionId,
        position: int,
        created_epoch: TimestampSec,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO capture_group_transactions (
                        capture_group_id, transaction_id, position, added_epoch
                    )
                    VALUES (?, ?, ?, ?);
                    """,
                    (str(group_id), str(txn_id), int(position), int(created_epoch)),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO capture_group_transactions (
                            capture_group_id, transaction_id, position, added_epoch
                        )
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (capture_group_id, transaction_id) DO NOTHING;
                        """,
                        (str(group_id), str(txn_id), int(position), int(created_epoch)),
                    )
                connection.commit()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

    def _fetch_capture_group_transactions(
        self, connection: DbConnection, group_id: GroupId
    ) -> list[tuple[str]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT transaction_id FROM capture_group_transactions
                    WHERE capture_group_id = ?
                    ORDER BY position ASC, transaction_id ASC;
                    """,
                    (str(group_id),),
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT transaction_id FROM capture_group_transactions
                        WHERE capture_group_id = %s
                        ORDER BY position ASC, transaction_id ASC;
                        """,
                        (str(group_id),),
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [(str(row[0]),) for row in rows]

    def _fetch_capture_groups(self, connection: DbConnection) -> list[tuple[str]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT capture_group_id FROM capture_groups ORDER BY created_epoch ASC;"
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT capture_group_id FROM capture_groups ORDER BY created_epoch ASC;"
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [(str(row[0]),) for row in rows]


class OperationCaptureRepository:
    """
    Repository for operation_captures table.
    """

    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._schema_manager = DatabaseSchemaManager.from_overrides(
            backend, sqlite_path, postgres_dsn
        )
        self._operation_id_column: str | None = None
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def from_system_config(cls) -> OperationCaptureRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
        """
        return cls(
            SystemConfigSettings.database_backend(),
            SystemConfigSettings.database_sqlite_path(),
            SystemConfigSettings.database_postgres_dsn(),
        )

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> OperationCaptureRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def upsert_operation_capture(
        self,
        operation_id: OperationId | str,
        capture_group_id: GroupId | str,
        created_epoch: TimestampSec,
    ) -> None:
        """
        Insert or update an operation capture mapping.
        """
        op_id = OperationId(str(operation_id))
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        f"""
                        INSERT OR REPLACE INTO operation_captures (
                            {column}, capture_group_id, created_epoch
                        )
                        VALUES (?, ?, ?);
                        """,
                        (str(op_id), str(group_id), int(created_epoch)),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"""
                            INSERT INTO operation_captures (
                                {column}, capture_group_id, created_epoch
                            )
                            VALUES (%s, %s, %s)
                            ON CONFLICT ({column}) DO UPDATE SET
                                capture_group_id = EXCLUDED.capture_group_id,
                                created_epoch = EXCLUDED.created_epoch;
                            """,
                            (str(op_id), str(group_id), int(created_epoch)),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def get_capture_group_id(self, operation_id: OperationId | str) -> GroupId | None:
        """
        Resolve capture_group_id for the given operation_id.
        """
        op_id = OperationId(str(operation_id))
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        f"""
                        SELECT capture_group_id FROM operation_captures
                        WHERE {column} = ?;
                        """,
                        (str(op_id),),
                    )
                    row = cursor.fetchone()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"""
                            SELECT capture_group_id FROM operation_captures
                            WHERE {column} = %s;
                            """,
                            (str(op_id),),
                        )
                        row = cursor.fetchone()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

        if row is None:
            return None
        return GroupId(str(row[0]))

    def list_operation_ids(self) -> list[OperationId]:
        """
        List all operation IDs.
        """
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        f"SELECT {column} FROM operation_captures ORDER BY created_epoch ASC;"
                    )
                    rows = cursor.fetchall()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"SELECT {column} FROM operation_captures ORDER BY created_epoch ASC;"
                        )
                        rows = cursor.fetchall()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

        return [OperationId(str(row[0])) for row in rows]

    def _connect(self) -> DbConnection:
        return self._schema_manager.connect()

    def _resolve_operation_id_column(self, connection: DbConnection) -> str:
        if self._operation_id_column:
            return self._operation_id_column

        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute("PRAGMA table_info('operation_captures');")
                rows = cursor.fetchall()
                column_names = {str(row[1]) for row in rows}
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_name = 'operation_captures';
                        """
                    )
                    rows = cursor.fetchall()
                column_names = {str(row[0]) for row in rows}
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        if _OPERATION_ID_COLUMN in column_names:
            self._operation_id_column = _OPERATION_ID_COLUMN
        elif _LEGACY_OPERATION_ID_COLUMN in column_names:
            self._operation_id_column = _LEGACY_OPERATION_ID_COLUMN
        else:
            raise RuntimeError("operation_captures table has no operation id column")

        return self._operation_id_column

# FILE: src/pypnm/lib/db/db_schema_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, TypeAlias

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.model.db_health_model import DatabaseHealthModel
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath

if TYPE_CHECKING:
    from psycopg import Connection as PsycopgConnection
else:
    PsycopgConnection = object

DbConnection: TypeAlias = sqlite3.Connection | PsycopgConnection

SCHEMA_VERSION: int = 1
SCHEMA_META_ID: int = 1
UNKNOWN_SYSDESCR_HASH: str = "UNKNOWN"
DEFAULT_ARTIFACT_STORE_NAME: str = "default"
DEFAULT_ARTIFACT_STORE_ROOT: str = ".data/pnm"
SQLITE_JOURNAL_MODE: str = "WAL"
SQLITE_BUSY_TIMEOUT_MS: int = 5000

BEGIN_STATEMENT: str = "BEGIN"
COMMIT_STATEMENT: str = "COMMIT"

_SQLITE_DDL_FILE: str = "schema_sqlite.sql"
_POSTGRES_DDL_FILE: str = "schema_postgres.sql"

_REQUIRED_TABLES: tuple[str, ...] = (
    "schema_meta",
    "system_description_dim",
    "device_details",
    "transaction_records",
    "capture_groups",
    "capture_group_transactions",
    "operation_captures",
    "artifact_stores",
    "file_artifacts",
    "transaction_artifacts",
)


class DatabaseSchemaManager:
    """
    Initialize and validate the DB schema for the selected backend.
    """

    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._sqlite_path = sqlite_path
        self._postgres_dsn = postgres_dsn
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def from_system_config(cls) -> DatabaseSchemaManager:
        """
        Build a schema manager using SystemConfigSettings.
        """
        return cls(
            SystemConfigSettings.database_backend(),
            SystemConfigSettings.database_sqlite_path(),
            SystemConfigSettings.database_postgres_dsn(),
        )

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> DatabaseSchemaManager:
        """
        Build a schema manager using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def connect(self) -> DbConnection:
        """
        Open a DB connection for the configured backend.
        """
        match self._backend:
            case DatabaseBackend.SQLITE:
                return self._connect_sqlite()
            case DatabaseBackend.POSTGRES:
                return self._connect_postgres()
        raise ValueError(f"Unsupported Database backend: {self._backend}")

    def initialize_schema(self) -> None:
        """
        Apply schema DDL and seed required rows idempotently.
        """
        connection = self.connect()
        try:
            self._apply_schema(connection)
            self._seed_unknown_sysdescr(connection)
            self._seed_default_artifact_store(connection)
            self._ensure_schema_version(connection)
        finally:
            connection.close()

    def health_check(self) -> DatabaseHealthModel:
        """
        Run a schema health check and return a diagnostic model.
        """
        connection = self.connect()
        try:
            table_names = self._fetch_table_names(connection)
            missing_tables = [
                table for table in _REQUIRED_TABLES if table not in table_names
            ]
            schema_version = self._fetch_schema_version(connection)
            unknown_sysdescr_present = self._has_unknown_sysdescr(connection)
            default_store_present = self._has_default_artifact_store(connection)
            ok = (
                not missing_tables
                and schema_version == SCHEMA_VERSION
                and unknown_sysdescr_present
                and default_store_present
            )
            details = self._health_details(
                schema_version,
                missing_tables,
                unknown_sysdescr_present,
                default_store_present,
            )
            return DatabaseHealthModel(
                backend=self._backend,
                schema_version=schema_version,
                missing_tables=missing_tables,
                unknown_sysdescr_present=unknown_sysdescr_present,
                default_artifact_store_present=default_store_present,
                ok=ok,
                details=details,
            )
        finally:
            connection.close()

    def _connect_sqlite(self) -> sqlite3.Connection:
        db_path = self._resolve_sqlite_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(db_path)
        connection.execute(f"PRAGMA journal_mode = {SQLITE_JOURNAL_MODE};")
        connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS};")
        connection.execute("PRAGMA foreign_keys = ON;")
        return connection

    def _connect_postgres(self) -> PsycopgConnection:
        dsn = str(self._postgres_dsn).strip()
        if not dsn:
            raise ValueError("Database.postgres.dsn cannot be blank")
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError(
                "psycopg is required for Postgres backend support"
            ) from exc
        return psycopg.connect(dsn)

    def _apply_schema(self, connection: DbConnection) -> None:
        ddl_sql = self._load_schema_sql()
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.executescript(ddl_sql)
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                statements = self._split_sql_statements(ddl_sql)
                current_idx = 0
                try:
                    with pg_conn.cursor() as cursor:
                        for idx, statement in enumerate(statements, start=1):
                            current_idx = idx
                            if self._should_skip_statement(statement):
                                continue
                            cursor.execute(statement)
                    pg_conn.commit()
                except Exception as exc:
                    pg_conn.rollback()
                    raise RuntimeError(
                        f"Failed to apply Postgres schema at statement {current_idx}"
                    ) from exc

    def _seed_unknown_sysdescr(self, connection: DbConnection) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.execute(
                    """
                    INSERT OR IGNORE INTO system_description_dim (
                        hw_rev, vendor, bootr, sw_rev, model,
                        sysdescr_json, sysdescr_hash, is_unknown
                    )
                    VALUES (
                        'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
                        '{}', ?, 1
                    );
                    """,
                    (UNKNOWN_SYSDESCR_HASH,),
                )
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO system_description_dim (
                            hw_rev, vendor, bootr, sw_rev, model,
                            sysdescr_json, sysdescr_hash, is_unknown
                        )
                        VALUES (
                            'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
                            '{}'::jsonb, %s, TRUE
                        )
                        ON CONFLICT (sysdescr_hash) DO NOTHING;
                        """,
                        (UNKNOWN_SYSDESCR_HASH,),
                    )
                pg_conn.commit()

    def _seed_default_artifact_store(self, connection: DbConnection) -> None:
        root_path = self._normalize_root_path(SystemConfigSettings.pnm_dir())
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                sqlite_conn.execute(
                    """
                    INSERT OR IGNORE INTO artifact_stores (store_name, root_path)
                    VALUES (?, ?);
                    """,
                    (DEFAULT_ARTIFACT_STORE_NAME, root_path),
                )
                sqlite_conn.commit()
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO artifact_stores (store_name, root_path)
                        VALUES (%s, %s)
                        ON CONFLICT (store_name) DO NOTHING;
                        """,
                        (DEFAULT_ARTIFACT_STORE_NAME, root_path),
                    )
                pg_conn.commit()

    def _ensure_schema_version(self, connection: DbConnection) -> None:
        schema_version = self._fetch_schema_version(connection)
        if schema_version != SCHEMA_VERSION:
            raise RuntimeError(
                f"Unsupported schema_version={schema_version}; expected {SCHEMA_VERSION}"
            )

    def _fetch_table_names(self, connection: DbConnection) -> set[str]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table';"
                )
                return {row[0] for row in cursor.fetchall()}
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT table_name
                        FROM information_schema.tables
                        WHERE table_schema = 'public';
                        """
                    )
                    return {row[0] for row in cursor.fetchall()}
        return set()

    def _fetch_schema_version(self, connection: DbConnection) -> int:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT schema_version FROM schema_meta WHERE schema_meta_id = ?;",
                    (SCHEMA_META_ID,),
                )
                row = cursor.fetchone()
                if row:
                    return int(row[0])
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT schema_version FROM schema_meta WHERE schema_meta_id = %s;",
                        (SCHEMA_META_ID,),
                    )
                    row = cursor.fetchone()
                    if row:
                        return int(row[0])
        return 0

    def _has_unknown_sysdescr(self, connection: DbConnection) -> bool:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT 1 FROM system_description_dim WHERE sysdescr_hash = ?;",
                    (UNKNOWN_SYSDESCR_HASH,),
                )
                return cursor.fetchone() is not None
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT 1 FROM system_description_dim WHERE sysdescr_hash = %s;",
                        (UNKNOWN_SYSDESCR_HASH,),
                    )
                    return cursor.fetchone() is not None
        return False

    def _has_default_artifact_store(self, connection: DbConnection) -> bool:
        match self._backend:
            case DatabaseBackend.SQLITE:
                sqlite_conn = connection
                cursor = sqlite_conn.execute(
                    "SELECT 1 FROM artifact_stores WHERE store_name = ?;",
                    (DEFAULT_ARTIFACT_STORE_NAME,),
                )
                return cursor.fetchone() is not None
            case DatabaseBackend.POSTGRES:
                pg_conn = connection
                with pg_conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT 1 FROM artifact_stores WHERE store_name = %s;",
                        (DEFAULT_ARTIFACT_STORE_NAME,),
                    )
                    return cursor.fetchone() is not None
        return False

    def _health_details(
        self,
        schema_version: int,
        missing_tables: list[str],
        unknown_sysdescr_present: bool,
        default_store_present: bool,
    ) -> str:
        if missing_tables:
            return f"Missing tables: {', '.join(missing_tables)}"
        if schema_version != SCHEMA_VERSION:
            return f"Schema version mismatch: {schema_version}"
        if not unknown_sysdescr_present:
            return "Missing UNKNOWN sysDescr seed row"
        if not default_store_present:
            return "Missing default artifact store row"
        return "Schema healthy"

    def _resolve_sqlite_db_path(self) -> Path:
        path = Path(str(self._sqlite_path))
        if path.is_absolute():
            return path
        return self._resolve_app_root() / path

    def _normalize_root_path(self, root_path: str) -> str:
        path = Path(root_path)
        if not path.is_absolute():
            return root_path
        app_root = self._resolve_app_root()
        if app_root in path.parents:
            return str(path.relative_to(app_root))
        self.logger.warning(
            "Artifact store root_path is absolute; portable paths are recommended: %s",
            root_path,
        )
        return root_path

    def _load_schema_sql(self) -> str:
        ddl_dir = self._resolve_ddl_dir()
        ddl_file = (
            _SQLITE_DDL_FILE
            if self._backend == DatabaseBackend.SQLITE
            else _POSTGRES_DDL_FILE
        )
        ddl_path = ddl_dir / ddl_file
        return ddl_path.read_text(encoding="utf-8")

    @staticmethod
    def _split_sql_statements(sql: str) -> list[str]:
        statements: list[str] = []
        buffer: list[str] = []
        in_single = False
        in_double = False
        in_line_comment = False
        in_block_comment = False
        dollar_tag: str | None = None

        idx = 0
        length = len(sql)
        while idx < length:
            ch = sql[idx]
            nxt = sql[idx + 1] if idx + 1 < length else ""

            if in_line_comment:
                buffer.append(ch)
                if ch == "\n":
                    in_line_comment = False
                idx += 1
                continue

            if in_block_comment:
                buffer.append(ch)
                if ch == "*" and nxt == "/":
                    buffer.append(nxt)
                    idx += 2
                    in_block_comment = False
                    continue
                idx += 1
                continue

            if dollar_tag is not None:
                if ch == "$" and sql.startswith(dollar_tag, idx):
                    buffer.append(dollar_tag)
                    idx += len(dollar_tag)
                    dollar_tag = None
                    continue
                buffer.append(ch)
                idx += 1
                continue

            if not in_single and not in_double:
                if ch == "-" and nxt == "-":
                    buffer.append(ch)
                    buffer.append(nxt)
                    idx += 2
                    in_line_comment = True
                    continue
                if ch == "/" and nxt == "*":
                    buffer.append(ch)
                    buffer.append(nxt)
                    idx += 2
                    in_block_comment = True
                    continue

            if not in_single and not in_double and ch == "$":
                tag_end = sql.find("$", idx + 1)
                if tag_end != -1:
                    tag = sql[idx : tag_end + 1]
                    if DatabaseSchemaManager._is_valid_dollar_tag(tag):
                        closing_idx = sql.find(tag, tag_end + 1)
                        if closing_idx == -1:
                            buffer.append(ch)
                            idx += 1
                            continue
                        dollar_tag = tag
                        buffer.append(tag)
                        idx = tag_end + 1
                        continue

            if ch == "'" and not in_double:
                if in_single and nxt == "'":
                    buffer.append(ch)
                    buffer.append(nxt)
                    idx += 2
                    continue
                in_single = not in_single
                buffer.append(ch)
                idx += 1
                continue

            if ch == '"' and not in_single:
                in_double = not in_double
                buffer.append(ch)
                idx += 1
                continue

            if ch == ";" and not in_single and not in_double and dollar_tag is None:
                statement = "".join(buffer).strip()
                if statement:
                    statements.append(statement)
                buffer = []
                idx += 1
                continue

            buffer.append(ch)
            idx += 1

        tail = "".join(buffer).strip()
        if tail:
            statements.append(tail)
        return statements

    @staticmethod
    def _should_skip_statement(statement: str) -> bool:
        normalized = " ".join(statement.strip().strip(";").split()).upper()
        return normalized in (
            BEGIN_STATEMENT,
            "BEGIN TRANSACTION",
            COMMIT_STATEMENT,
            "COMMIT WORK",
            "ROLLBACK",
            "ROLLBACK WORK",
        )

    @staticmethod
    def _is_valid_dollar_tag(tag: str) -> bool:
        if len(tag) < 2 or not tag.startswith("$") or not tag.endswith("$"):
            return False
        body = tag[1:-1]
        return all(ch_token.isalnum() or ch_token == "_" for ch_token in body)

    def _resolve_ddl_dir(self) -> Path:
        candidates = [Path(__file__).resolve(), Path.cwd().resolve()]
        for candidate in candidates:
            for parent in [candidate] + list(candidate.parents):
                ddl_dir = parent / "docs" / "design" / "db"
                if ddl_dir.is_dir():
                    return ddl_dir
        raise FileNotFoundError("Unable to locate docs/design/db for DDL assets")

    def _resolve_app_root(self) -> Path:
        cwd = Path.cwd().resolve()
        for parent in [cwd] + list(cwd.parents):
            if (parent / "pyproject.toml").is_file():
                return parent
        return cwd


def initialize_database_schema() -> None:
    """
    Initialize and validate the database schema using system configuration.
    """
    manager = DatabaseSchemaManager.from_system_config()
    manager.initialize_schema()
    health = manager.health_check()
    if not health.ok:
        raise RuntimeError(f"Database schema health check failed: {health.details}")

# FILE: src/pypnm/lib/db/transaction_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.db.db_schema_manager import (
    UNKNOWN_SYSDESCR_HASH,
    DatabaseSchemaManager,
    DbConnection,
)
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    HashStr,
    MacAddressStr,
    TimestampSec,
    TransactionId,
)

_UNKNOWN_FIELD_VALUE: str = "UNKNOWN"
_EMPTY_JSON_OBJECT: str = "{}"


@dataclass(frozen=True)
class MacAddressDescriptorRow:
    mac_address: MacAddressStr
    system_description: dict[str, str] | None


@dataclass(frozen=True)
class TransactionRecordRow:
    transaction_id: TransactionId
    timestamp_epoch: TimestampSec
    mac_address: MacAddressStr
    pnm_test_type: str
    filename: FileName
    system_description: dict[str, str] | None


class _RepositoryBase:
    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._schema_manager = DatabaseSchemaManager.from_overrides(
            backend, sqlite_path, postgres_dsn
        )
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def _from_system_config(cls) -> _RepositoryBase:
        return cls(
            SystemConfigSettings.database_backend(),
            SystemConfigSettings.database_sqlite_path(),
            SystemConfigSettings.database_postgres_dsn(),
        )

    def _connect(self) -> DbConnection:
        return self._schema_manager.connect()

    @staticmethod
    def _canonical_json(data: dict[str, object]) -> str:
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _hash_json(data: dict[str, object]) -> HashStr:
        payload = _RepositoryBase._canonical_json(data).encode("utf-8")
        return HashStr(hashlib.sha256(payload).hexdigest())

    @staticmethod
    def _load_json_value(value: object) -> dict[str, object]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return {}
            if isinstance(parsed, dict):
                return parsed
        return {}


class SystemDescriptionRepository(_RepositoryBase):
    """
    Repository for the system_description_dim dimension table.
    """

    @classmethod
    def from_system_config(cls) -> SystemDescriptionRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
        """
        return cls._from_system_config()

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> SystemDescriptionRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def get_or_create_sysdescr_id(self, sysdescr_json: dict[str, str] | None) -> int:
        """
        Resolve or insert a sysDescr row and return its primary key.
        """
        normalized = self._normalize_sysdescr_json(sysdescr_json)
        is_unknown = not normalized
        if is_unknown:
            sysdescr_hash = UNKNOWN_SYSDESCR_HASH
            hw_rev = _UNKNOWN_FIELD_VALUE
            vendor = _UNKNOWN_FIELD_VALUE
            bootr = _UNKNOWN_FIELD_VALUE
            sw_rev = _UNKNOWN_FIELD_VALUE
            model = _UNKNOWN_FIELD_VALUE
            sysdescr_payload = _EMPTY_JSON_OBJECT
        else:
            sysdescr_hash = str(self._hash_json(normalized))
            hw_rev = normalized.get("HW_REV", "")
            vendor = normalized.get("VENDOR", "")
            bootr = normalized.get("BOOTR", "")
            sw_rev = normalized.get("SW_REV", "")
            model = normalized.get("MODEL", "")
            sysdescr_payload = self._canonical_json(normalized)

        connection = self._connect()
        try:
            existing = self._fetch_sysdescr_id(connection, sysdescr_hash)
            if existing is not None:
                return existing
            self._insert_sysdescr(
                connection,
                hw_rev,
                vendor,
                bootr,
                sw_rev,
                model,
                sysdescr_payload,
                sysdescr_hash,
                is_unknown,
            )
            fetched = self._fetch_sysdescr_id(connection, sysdescr_hash)
            if fetched is None:
                raise RuntimeError("Failed to resolve sysdescr_id after insert")
            return fetched
        finally:
            connection.close()

    @staticmethod
    def _normalize_sysdescr_json(
        sysdescr_json: dict[str, str] | None,
    ) -> dict[str, str]:
        if not sysdescr_json:
            return {}
        cleaned = {key: str(value) for key, value in sysdescr_json.items()}
        normalized = SystemDescriptor.load_from_dict(cleaned).to_dict()
        if not any(value.strip() for value in normalized.values()):
            return {}
        return normalized

    def _fetch_sysdescr_id(
        self, connection: DbConnection, sysdescr_hash: str
    ) -> int | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT sysdescr_id FROM system_description_dim WHERE sysdescr_hash = ?;",
                    (sysdescr_hash,),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT sysdescr_id FROM system_description_dim WHERE sysdescr_hash = %s;",
                        (sysdescr_hash,),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if not row:
            return None
        return int(row[0])

    def _insert_sysdescr(
        self,
        connection: DbConnection,
        hw_rev: str,
        vendor: str,
        bootr: str,
        sw_rev: str,
        model: str,
        sysdescr_json: str,
        sysdescr_hash: str,
        is_unknown: bool,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO system_description_dim (
                        hw_rev, vendor, bootr, sw_rev, model,
                        sysdescr_json, sysdescr_hash, is_unknown
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        hw_rev,
                        vendor,
                        bootr,
                        sw_rev,
                        model,
                        sysdescr_json,
                        sysdescr_hash,
                        1 if is_unknown else 0,
                    ),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO system_description_dim (
                            hw_rev, vendor, bootr, sw_rev, model,
                            sysdescr_json, sysdescr_hash, is_unknown
                        )
                        VALUES (%s, %s, %s, %s, %s, CAST(%s AS jsonb), %s, %s)
                        ON CONFLICT (sysdescr_hash) DO NOTHING;
                        """,
                        (
                            hw_rev,
                            vendor,
                            bootr,
                            sw_rev,
                            model,
                            sysdescr_json,
                            sysdescr_hash,
                            is_unknown,
                        ),
                    )
                connection.commit()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")


class DeviceDetailsRepository(_RepositoryBase):
    """
    Repository for the device_details dimension table.
    """

    @classmethod
    def from_system_config(cls) -> DeviceDetailsRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
        """
        return cls._from_system_config()

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> DeviceDetailsRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def get_or_create_device_detail_id(
        self, device_details_json: dict[str, object], sysdescr_id: int
    ) -> int:
        """
        Resolve or insert a device_details row and return its primary key.
        """
        payload = device_details_json or {}
        device_details_hash = str(self._hash_json(payload))
        payload_json = self._canonical_json(payload)

        connection = self._connect()
        try:
            existing = self._fetch_device_detail_id(connection, device_details_hash)
            if existing is not None:
                return existing
            self._insert_device_details(
                connection, sysdescr_id, payload_json, device_details_hash
            )
            fetched = self._fetch_device_detail_id(connection, device_details_hash)
            if fetched is None:
                raise RuntimeError("Failed to resolve device_detail_id after insert")
            return fetched
        finally:
            connection.close()

    def _fetch_device_detail_id(
        self, connection: DbConnection, device_details_hash: str
    ) -> int | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT device_detail_id FROM device_details WHERE device_details_hash = ?;",
                    (device_details_hash,),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT device_detail_id FROM device_details WHERE device_details_hash = %s;",
                        (device_details_hash,),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if not row:
            return None
        return int(row[0])

    def _insert_device_details(
        self,
        connection: DbConnection,
        sysdescr_id: int,
        device_details_json: str,
        device_details_hash: str,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO device_details (
                        sysdescr_id, device_details_json, device_details_hash
                    )
                    VALUES (?, ?, ?);
                    """,
                    (sysdescr_id, device_details_json, device_details_hash),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO device_details (
                            sysdescr_id, device_details_json, device_details_hash
                        )
                        VALUES (%s, CAST(%s AS jsonb), %s)
                        ON CONFLICT (device_details_hash) DO NOTHING;
                        """,
                        (sysdescr_id, device_details_json, device_details_hash),
                    )
                connection.commit()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")


class TransactionRepository(_RepositoryBase):
    """
    Repository for transaction_records and related queries.
    """

    @classmethod
    def from_system_config(cls) -> TransactionRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
        """
        return cls._from_system_config()

    @classmethod
    def from_overrides(
        cls,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> TransactionRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def insert_transaction(
        self,
        transaction_id: TransactionId,
        timestamp_epoch: TimestampSec,
        mac_address: MacAddress | MacAddressStr | str,
        pnm_test_type: str,
        filename: FileName | str,
        device_detail_id: int,
    ) -> None:
        """
        Insert a transaction record (idempotent on transaction_id).
        """
        mac_str = self._normalize_mac(mac_address)
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO transaction_records (
                            transaction_id, timestamp_epoch, mac_address,
                            pnm_test_type, filename, device_detail_id
                        )
                        VALUES (?, ?, ?, ?, ?, ?);
                        """,
                        (
                            str(transaction_id),
                            int(timestamp_epoch),
                            mac_str,
                            pnm_test_type,
                            str(filename),
                            device_detail_id,
                        ),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            """
                            INSERT INTO transaction_records (
                                transaction_id, timestamp_epoch, mac_address,
                                pnm_test_type, filename, device_detail_id
                            )
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (transaction_id) DO NOTHING;
                            """,
                            (
                                str(transaction_id),
                                int(timestamp_epoch),
                                mac_str,
                                pnm_test_type,
                                str(filename),
                                device_detail_id,
                            ),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def list_macs(self) -> list[MacAddressDescriptorRow]:
        """
        List distinct MAC addresses with best-effort system_description metadata.
        """
        connection = self._connect()
        try:
            rows = self._fetch_mac_rows(connection)
        finally:
            connection.close()

        latest_by_mac: dict[str, tuple[int, dict[str, str] | None]] = {}
        for mac_str, timestamp_epoch, device_details_json in rows:
            normalized_mac = str(mac_str).lower().strip()
            if not normalized_mac:
                continue
            system_description = self._extract_system_description(device_details_json)
            existing = latest_by_mac.get(normalized_mac)
            if existing is None:
                latest_by_mac[normalized_mac] = (timestamp_epoch, system_description)
                continue
            existing_ts, _existing_sd = existing
            if timestamp_epoch >= existing_ts:
                latest_by_mac[normalized_mac] = (timestamp_epoch, system_description)

        results: list[MacAddressDescriptorRow] = []
        for mac_str, (_ts, system_description) in sorted(
            latest_by_mac.items(), key=lambda item: item[0]
        ):
            results.append(
                MacAddressDescriptorRow(
                    mac_address=MacAddressStr(mac_str),
                    system_description=system_description,
                )
            )

        return results

    def list_transactions_for_mac(
        self, mac_address: MacAddress | MacAddressStr | str
    ) -> list[TransactionRecordRow]:
        """
        List all transactions for a MAC address ordered by timestamp.
        """
        mac_str = self._normalize_mac(mac_address)
        connection = self._connect()
        try:
            rows = self._fetch_transaction_rows_for_mac(connection, mac_str)
        finally:
            connection.close()
        return self._transaction_rows_from_query(rows)

    def list_all_transactions(self) -> list[TransactionRecordRow]:
        """
        List all transactions ordered by timestamp.
        """
        connection = self._connect()
        try:
            rows = self._fetch_all_transaction_rows(connection)
        finally:
            connection.close()
        return self._transaction_rows_from_query(rows)

    def get_transaction_record(
        self, transaction_id: TransactionId
    ) -> TransactionRecordRow | None:
        """
        Fetch a transaction record by identifier.
        """
        connection = self._connect()
        try:
            row = self._fetch_transaction_row_by_id(connection, str(transaction_id))
        finally:
            connection.close()

        if row is None:
            return None
        return self._transaction_row_from_tuple(row)

    def _fetch_mac_rows(
        self, connection: DbConnection
    ) -> list[tuple[str, int, object]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT t.mac_address, t.timestamp_epoch, d.device_details_json
                    FROM transaction_records t
                    JOIN device_details d ON t.device_detail_id = d.device_detail_id
                    ORDER BY t.timestamp_epoch DESC;
                    """
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT t.mac_address, t.timestamp_epoch, d.device_details_json
                        FROM transaction_records t
                        JOIN device_details d ON t.device_detail_id = d.device_detail_id
                        ORDER BY t.timestamp_epoch DESC;
                        """
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [(str(row[0]), int(row[1]), row[2]) for row in rows]

    def _fetch_transaction_rows_for_mac(
        self, connection: DbConnection, mac_address: str
    ) -> list[tuple[str, int, str, str, str, object]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                           t.pnm_test_type, t.filename, d.device_details_json
                    FROM transaction_records t
                    JOIN device_details d ON t.device_detail_id = d.device_detail_id
                    WHERE t.mac_address = ?
                    ORDER BY t.timestamp_epoch ASC, t.transaction_id ASC;
                    """,
                    (mac_address,),
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                               t.pnm_test_type, t.filename, d.device_details_json
                        FROM transaction_records t
                        JOIN device_details d ON t.device_detail_id = d.device_detail_id
                        WHERE t.mac_address = %s
                        ORDER BY t.timestamp_epoch ASC, t.transaction_id ASC;
                        """,
                        (mac_address,),
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [
            (
                str(row[0]),
                int(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                row[5],
            )
            for row in rows
        ]

    def _fetch_all_transaction_rows(
        self, connection: DbConnection
    ) -> list[tuple[str, int, str, str, str, object]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                           t.pnm_test_type, t.filename, d.device_details_json
                    FROM transaction_records t
                    JOIN device_details d ON t.device_detail_id = d.device_detail_id
                    ORDER BY t.timestamp_epoch ASC, t.transaction_id ASC;
                    """
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                               t.pnm_test_type, t.filename, d.device_details_json
                        FROM transaction_records t
                        JOIN device_details d ON t.device_detail_id = d.device_detail_id
                        ORDER BY t.timestamp_epoch ASC, t.transaction_id ASC;
                        """
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [
            (
                str(row[0]),
                int(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                row[5],
            )
            for row in rows
        ]

    def _fetch_transaction_row_by_id(
        self, connection: DbConnection, transaction_id: str
    ) -> tuple[str, int, str, str, str, object] | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                           t.pnm_test_type, t.filename, d.device_details_json
                    FROM transaction_records t
                    JOIN device_details d ON t.device_detail_id = d.device_detail_id
                    WHERE t.transaction_id = ?;
                    """,
                    (transaction_id,),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT t.transaction_id, t.timestamp_epoch, t.mac_address,
                               t.pnm_test_type, t.filename, d.device_details_json
                        FROM transaction_records t
                        JOIN device_details d ON t.device_detail_id = d.device_detail_id
                        WHERE t.transaction_id = %s;
                        """,
                        (transaction_id,),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        if row is None:
            return None
        return (
            str(row[0]),
            int(row[1]),
            str(row[2]),
            str(row[3]),
            str(row[4]),
            row[5],
        )

    @staticmethod
    def _normalize_mac(mac_address: MacAddress | MacAddressStr | str) -> str:
        if isinstance(mac_address, MacAddress):
            return mac_address.to_mac_format(MacAddressFormat.COLON).lower()
        normalized = MacAddress(mac_address).to_mac_format(MacAddressFormat.COLON)
        return str(normalized).lower()

    def _transaction_rows_from_query(
        self, rows: list[tuple[str, int, str, str, str, object]]
    ) -> list[TransactionRecordRow]:
        records: list[TransactionRecordRow] = []
        for row in rows:
            record = self._transaction_row_from_tuple(row)
            records.append(record)
        return records

    def _transaction_row_from_tuple(
        self, row: tuple[str, int, str, str, str, object]
    ) -> TransactionRecordRow:
        system_description = self._extract_system_description(row[5])
        return TransactionRecordRow(
            transaction_id=TransactionId(row[0]),
            timestamp_epoch=TimestampSec(int(row[1])),
            mac_address=MacAddressStr(row[2]),
            pnm_test_type=row[3],
            filename=FileName(row[4]),
            system_description=system_description,
        )

    def _extract_system_description(
        self, device_details_json: object
    ) -> dict[str, str] | None:
        payload = self._load_json_value(device_details_json)
        if not payload:
            return None
        sysdesc = payload.get("system_description")
        if not isinstance(sysdesc, dict):
            return None
        cleaned: dict[str, str] = {}
        for key, value in sysdesc.items():
            cleaned[str(key)] = str(value)
        return cleaned or None

# FILE: src/pypnm/startup/startup.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.common.extended.common_process_service import SystemConfigSettings
from pypnm.config.log_config import LoggerConfigurator
from pypnm.lib.db.db_schema_manager import initialize_database_schema


class StartUp:
    """
    Class to handle the startup process of the PyPNM application.
    It initializes the system configuration settings and prepares the environment.
    """

    @classmethod
    def initialize(cls) -> None:
        """
        Initialize the system configuration settings and set up logging.
        This method should be called at the start of the application.
        """
        SystemConfigSettings.initialize_directories()
        initialize_database_schema()

        LoggerConfigurator(
            SystemConfigSettings.log_dir(),
            SystemConfigSettings.log_filename(),
            SystemConfigSettings.log_level(),
        )

# FILE: tests/test_capture_group_empty_transaction.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    TimestampSec,
    TransactionId,
)

PNM_TEST_TYPE: str = "DS_RXMER"
DEFAULT_TIMESTAMP: int = 1
SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
}
DEVICE_DETAILS: dict[str, object] = {"system_description": SYS_DESCR}
DEFAULT_FILENAME = FileName("rxmer.bin")
DEFAULT_MAC = MacAddress("aa:bb:cc:dd:ee:ff")
TRANSACTION_ID: str = "txn-1"


def _configure_capture_group_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    db_path = tmp_path / "pypnm.sqlite3"
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(db_path))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()
    return db_path


def _insert_transaction(db_path: Path, transaction_id: str) -> None:
    sqlite_path = DatabasePath(str(db_path))
    postgres_dsn = DatabaseDsn("")
    sys_repo = SystemDescriptionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    device_repo = DeviceDetailsRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    txn_repo = TransactionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    sysdescr_id = sys_repo.get_or_create_sysdescr_id(SYS_DESCR)
    device_detail_id = device_repo.get_or_create_device_detail_id(
        DEVICE_DETAILS, sysdescr_id
    )
    txn_repo.insert_transaction(
        transaction_id=TransactionId(transaction_id),
        timestamp_epoch=TimestampSec(DEFAULT_TIMESTAMP),
        mac_address=DEFAULT_MAC,
        pnm_test_type=PNM_TEST_TYPE,
        filename=DEFAULT_FILENAME,
        device_detail_id=device_detail_id,
    )


def test_add_transaction_skips_empty_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _insert_transaction(db_path, TRANSACTION_ID)
    capture_group = CaptureGroup()
    group_id = capture_group.create_group()

    capture_group.add_transaction("")
    capture_group.add_transaction("   ")
    capture_group.add_transaction(TRANSACTION_ID)

    repo = CaptureGroupRepository.from_system_config()
    transactions = repo.list_transactions(group_id)
    assert transactions == [TransactionId(TRANSACTION_ID)]

# FILE: tests/test_capture_group_persistence_normalizes_transaction_id.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.api.routes.common.classes.file_capture.pnm_file_opearation import (
    OperationCaptureGroupResolver,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    GroupId,
    TimestampSec,
    TransactionId,
)

DEFAULT_CREATED_EPOCH: int = 1
DEFAULT_TIMESTAMP: int = 1
PNM_TEST_TYPE: str = "DS_RXMER"
SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
}
DEVICE_DETAILS: dict[str, object] = {"system_description": SYS_DESCR}
DEFAULT_FILENAME = FileName("rxmer.bin")
DEFAULT_MAC = MacAddress("aa:bb:cc:dd:ee:ff")


def _configure_capture_group_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    db_path = tmp_path / "pypnm.sqlite3"
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(db_path))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()
    return db_path


def _insert_transaction(db_path: Path, transaction_id: str) -> None:
    sqlite_path = DatabasePath(str(db_path))
    postgres_dsn = DatabaseDsn("")
    sys_repo = SystemDescriptionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    device_repo = DeviceDetailsRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    txn_repo = TransactionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    sysdescr_id = sys_repo.get_or_create_sysdescr_id(SYS_DESCR)
    device_detail_id = device_repo.get_or_create_device_detail_id(
        DEVICE_DETAILS, sysdescr_id
    )
    txn_repo.insert_transaction(
        transaction_id=TransactionId(transaction_id),
        timestamp_epoch=TimestampSec(DEFAULT_TIMESTAMP),
        mac_address=DEFAULT_MAC,
        pnm_test_type=PNM_TEST_TYPE,
        filename=DEFAULT_FILENAME,
        device_detail_id=device_detail_id,
    )


def test_capture_group_skips_whitespace_transaction_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_capture_group_db(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    group = CaptureGroup()
    group_id = group.create_group()

    group.add_transaction("   ")

    repo = CaptureGroupRepository.from_system_config()
    assert repo.list_transactions(group_id) == []
    assert "Skipping empty transaction_id persistence" in caplog.text


def test_resolver_filters_whitespace_transaction_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _insert_transaction(db_path, "txn123")
    group_id = GroupId("group-1")
    json_path = tmp_path / "capture_group.json"
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(json_path)),
    )
    payload = {
        str(group_id): {
            "created": DEFAULT_CREATED_EPOCH,
            "transactions": ["", "   ", "txn123"],
        }
    }
    json_path.write_text(json.dumps(payload), encoding="utf-8")

    resolver = OperationCaptureGroupResolver()
    txns = resolver.get_transaction_ids_for_capture_group(group_id)

    assert txns == [TransactionId("txn123")]
    repo = CaptureGroupRepository.from_system_config()
    assert repo.list_transactions(group_id) == [TransactionId("txn123")]


def test_resolver_prefers_db_transaction_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    group_id = GroupId("group-db")
    repo = CaptureGroupRepository.from_system_config()
    repo.get_or_create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    _insert_transaction(db_path, "txn-b")
    _insert_transaction(db_path, "txn-a")
    repo.add_transaction(group_id, TransactionId("txn-b"), TimestampSec(2))
    repo.add_transaction(group_id, TransactionId("txn-a"), TimestampSec(3))

    resolver = OperationCaptureGroupResolver()
    txns = resolver.get_transaction_ids_for_capture_group(group_id)

    assert txns == [TransactionId("txn-b"), TransactionId("txn-a")]

# FILE: tests/test_db_schema_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import cast

import pytest

from pypnm.lib.db.db_schema_manager import (
    BEGIN_STATEMENT,
    COMMIT_STATEMENT,
    DEFAULT_ARTIFACT_STORE_NAME,
    SCHEMA_VERSION,
    SQLITE_BUSY_TIMEOUT_MS,
    SQLITE_JOURNAL_MODE,
    UNKNOWN_SYSDESCR_HASH,
    DatabaseSchemaManager,
)
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath

SCHEMA_META_ID: int = 1
EXPECTED_UNKNOWN_COUNT: int = 1
EXPECTED_SCHEMA_STATEMENTS_MIN: int = 1
EXPECTED_SQLITE_JOURNAL_MODE: str = SQLITE_JOURNAL_MODE.lower()
UNSUPPORTED_SCHEMA_VERSION: int = SCHEMA_VERSION + 1


def test_sqlite_schema_init_and_health(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm_schema.sqlite3"
    sqlite_path = cast(DatabasePath, str(db_path))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )

    manager.initialize_schema()
    manager.initialize_schema()

    health = manager.health_check()
    assert health.ok is True
    assert health.schema_version == SCHEMA_VERSION
    assert health.missing_tables == []
    assert health.unknown_sysdescr_present is True
    assert health.default_artifact_store_present is True

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute(
            "SELECT schema_version FROM schema_meta WHERE schema_meta_id = ?;",
            (SCHEMA_META_ID,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == SCHEMA_VERSION

        cursor = connection.execute(
            "SELECT COUNT(1) FROM system_description_dim WHERE sysdescr_hash = ?;",
            (UNKNOWN_SYSDESCR_HASH,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == EXPECTED_UNKNOWN_COUNT

        cursor = connection.execute(
            "SELECT root_path FROM artifact_stores WHERE store_name = ?;",
            (DEFAULT_ARTIFACT_STORE_NAME,),
        )
        row = cursor.fetchone()
        assert row is not None
        assert str(row[0]).strip() != ""
    finally:
        connection.close()


def test_sqlite_pragmas_applied(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm_schema.sqlite3"
    sqlite_path = cast(DatabasePath, str(db_path))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )

    connection = manager.connect()
    try:
        cursor = connection.execute("PRAGMA journal_mode;")
        row = cursor.fetchone()
        assert row is not None
        assert str(row[0]).lower() == EXPECTED_SQLITE_JOURNAL_MODE

        cursor = connection.execute("PRAGMA busy_timeout;")
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == SQLITE_BUSY_TIMEOUT_MS
    finally:
        connection.close()


def test_schema_version_mismatch_raises(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm_schema.sqlite3"
    sqlite_path = cast(DatabasePath, str(db_path))
    postgres_dsn = cast(DatabaseDsn, "")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )

    manager.initialize_schema()

    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            "UPDATE schema_meta SET schema_version = ? WHERE schema_meta_id = ?;",
            (UNSUPPORTED_SCHEMA_VERSION, SCHEMA_META_ID),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="Unsupported schema_version"):
        manager.initialize_schema()


def test_split_sql_statements_handles_quotes_and_comments() -> None:
    sql = (
        "CREATE TABLE t (v text CHECK (v ~* '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'));\n"
        "-- Comment with ; should not split\n"
        "INSERT INTO t (v) VALUES ('{}'::jsonb);\n"
        "/* Block comment ; still in comment */\n"
        "SELECT $$a; b$$;\n"
    )
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    assert len(statements) == 3


def test_split_sql_statements_filters_begin_commit() -> None:
    sql = "BEGIN; CREATE TABLE demo (id int); COMMIT;"
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    normalized = {stmt.strip().strip(";").upper() for stmt in statements}
    assert BEGIN_STATEMENT in normalized
    assert COMMIT_STATEMENT in normalized
    assert "CREATE TABLE DEMO (ID INT)" in normalized
    assert DatabaseSchemaManager._should_skip_statement("BEGIN") is True
    assert DatabaseSchemaManager._should_skip_statement("BEGIN TRANSACTION") is True
    assert DatabaseSchemaManager._should_skip_statement("COMMIT") is True
    assert DatabaseSchemaManager._should_skip_statement("COMMIT WORK") is True
    assert DatabaseSchemaManager._should_skip_statement("ROLLBACK") is True
    assert DatabaseSchemaManager._should_skip_statement("ROLLBACK WORK") is True


def test_split_sql_statements_handles_escaped_single_quotes() -> None:
    sql = "INSERT INTO t (v) VALUES ('a''b; still string'); SELECT 1;"
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    assert len(statements) == 2


def test_split_sql_statements_handles_valid_dollar_tag() -> None:
    sql = "SELECT $tag$a; b$tag$; SELECT 2;"
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    assert len(statements) == 2


def test_split_sql_statements_rejects_invalid_dollar_tag() -> None:
    sql = "SELECT $a$b$; SELECT 2;"
    statements = DatabaseSchemaManager._split_sql_statements(sql)
    assert len(statements) == 2


def test_split_schema_postgres_contains_schema_meta() -> None:
    ddl_path = Path("docs/design/db/schema_postgres.sql")
    ddl_sql = ddl_path.read_text(encoding="utf-8")
    statements = DatabaseSchemaManager._split_sql_statements(ddl_sql)
    assert len(statements) >= EXPECTED_SCHEMA_STATEMENTS_MIN
    joined = "\n".join(statements)
    assert "CREATE TABLE IF NOT EXISTS schema_meta" in joined


def test_postgres_schema_init_optional() -> None:
    dsn = os.environ.get("PYPNM_DB_POSTGRES_DSN", "")
    if not dsn:
        pytest.skip("PYPNM_DB_POSTGRES_DSN not set")
    postgres_dsn = cast(DatabaseDsn, dsn)
    sqlite_path = cast(DatabasePath, ".data/db/pypnm.sqlite3")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    manager.initialize_schema()
    health = manager.health_check()
    assert health.ok is True

# FILE: tests/test_multi_channel_estimation_result.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.multi_ds_chan_est.router import router
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    OperationId,
    TimestampSec,
    TransactionId,
)


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


PNM_TEST_TYPE: str = "DS_OFDM_CHAN_EST_COEF"
DEFAULT_TIMESTAMP: int = 1
SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
}
DEVICE_DETAILS: dict[str, object] = {"system_description": SYS_DESCR}
DEFAULT_FILENAME = FileName("chan_est.bin")
DEFAULT_MAC = MacAddress("aa:bb:cc:dd:ee:ff")


class _DbFixture:
    @staticmethod
    def initialize(db_path: Path) -> None:
        sqlite_path = DatabasePath(str(db_path))
        postgres_dsn = DatabaseDsn("")
        manager = DatabaseSchemaManager.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        manager.initialize_schema()

    @staticmethod
    def insert_transaction(db_path: Path, transaction_id: str) -> None:
        sqlite_path = DatabasePath(str(db_path))
        postgres_dsn = DatabaseDsn("")
        sys_repo = SystemDescriptionRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        device_repo = DeviceDetailsRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        txn_repo = TransactionRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        sysdescr_id = sys_repo.get_or_create_sysdescr_id(SYS_DESCR)
        device_detail_id = device_repo.get_or_create_device_detail_id(
            DEVICE_DETAILS, sysdescr_id
        )
        txn_repo.insert_transaction(
            transaction_id=TransactionId(transaction_id),
            timestamp_epoch=TimestampSec(DEFAULT_TIMESTAMP),
            mac_address=DEFAULT_MAC,
            pnm_test_type=PNM_TEST_TYPE,
            filename=DEFAULT_FILENAME,
            device_detail_id=device_detail_id,
        )


def _configure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Path]:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"
    sqlite_db = db_dir / "pypnm.sqlite3"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(capture_group_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    _DbFixture.initialize(sqlite_db)

    return {
        "capture_group_db": capture_group_db,
        "operation_db": operation_db,
        "database_sqlite_path": sqlite_db,
    }


def _seed_operation(
    operation_id: OperationId, capture_group_id: str, paths: dict[str, Path]
) -> None:
    paths["operation_db"].write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group_id": capture_group_id,
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )


def _seed_transaction_db(transaction_id: str, paths: dict[str, Path]) -> None:
    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id)


def _seed_capture_group(
    capture_group_id: str, transaction_ids: list[str], paths: dict[str, Path]
) -> None:
    paths["capture_group_db"].write_text(
        json.dumps(
            {
                capture_group_id: {
                    "created": 1,
                    "transactions": transaction_ids,
                }
            }
        ),
        encoding="utf-8",
    )


def _complete_operation(operation_id: OperationId) -> None:
    store = OperationStore()
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )


def test_multi_channel_estimation_result_skips_missing_records_and_returns_200(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())
    caplog.set_level("WARNING")

    operation_id = OperationId("op-300")
    capture_group_id = "group-300"
    txn_ok = "txn-ok"
    txn_missing = "txn-missing"

    _seed_operation(operation_id, capture_group_id, paths)
    _seed_capture_group(capture_group_id, [txn_ok, txn_missing], paths)
    _seed_transaction_db(txn_ok, paths)
    _complete_operation(operation_id)

    response = client.post(
        "/advance/multiChannelEstimation/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert len(payload["transactions"]) == 1
    assert payload["transactions"][0]["transaction_id"] == txn_ok
    assert "Missing transaction record for transaction_id" in caplog.text


def test_multi_channel_estimation_result_returns_404_when_none_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-301")
    capture_group_id = "group-301"
    txn_missing = "txn-missing"

    _seed_operation(operation_id, capture_group_id, paths)
    _seed_capture_group(capture_group_id, [txn_missing], paths)
    # No transaction records seeded.
    _complete_operation(operation_id)

    response = client.post(
        "/advance/multiChannelEstimation/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 404
    assert "No transaction records found" in response.json()["detail"]


def test_multi_channel_estimation_result_accepts_legacy_capture_group_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-302")
    capture_group_id = "group-302"
    txn_ok = "txn-ok-302"

    paths["operation_db"].write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group": capture_group_id,
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )
    _seed_capture_group(capture_group_id, [txn_ok], paths)
    _seed_transaction_db(txn_ok, paths)
    _complete_operation(operation_id)

    response = client.post(
        "/advance/multiChannelEstimation/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert payload["transactions"][0]["transaction_id"] == txn_ok

# FILE: tests/test_multi_channel_estimation_start_and_analysis.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import pypnm.api.routes.advance.multi_ds_chan_est.router as ds_router
from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.multi_ds_chan_est.router import router
from pypnm.api.routes.advance.multi_ds_chan_est.service import (
    MultiChannelEstimationService,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath, OperationId

_TEST_TIME_REMAINING: int = 123


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _configure_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"
    sqlite_db = db_dir / "pypnm.sqlite3"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(capture_group_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()


def _start_request_payload() -> dict[str, object]:
    return {
        "cable_modem": {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "192.168.0.100",
            "pnm_parameters": {
                "tftp": {
                    "ipv4": None,
                    "ipv6": None,
                },
                "capture": {
                    "channel_ids": None,
                },
            },
            "snmp": {
                "snmp_v2c": {
                    "community": "public",
                }
            },
        },
        "capture": {
            "parameters": {
                "measurement_duration": 1,
                "sample_interval": 1,
            }
        },
    }


@pytest.mark.asyncio
async def test_start_returns_success_status_and_group_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    async def _fake_precheck(
        self: CableModemServicePreCheck,
    ) -> tuple[ServiceStatusCode, str]:
        return ServiceStatusCode.SUCCESS, "ok"

    async def _fake_capture(self: MultiChannelEstimationService) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])

    monkeypatch.setattr(CableModemServicePreCheck, "run_precheck", _fake_precheck)
    monkeypatch.setattr(
        MultiChannelEstimationService, "_capture_message_response", _fake_capture
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/start",
        json=_start_request_payload(),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.SUCCESS
    assert payload["operation_id"]
    assert payload["capture_group_id"]
    assert payload["group_id"] == payload["capture_group_id"]
    assert payload["operation_state"] == "running"
    OperationRegistry.unregister(OperationId(payload["operation_id"]))


def test_analysis_returns_capture_group_not_found_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    db_path = Path(SystemConfigSettings.operation_db())
    db_path.write_text(json.dumps({}), encoding="utf-8")

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/analysis",
        json={"operation_id": "op-missing"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND
    assert "No capture group found for operation" in payload["message"]


class _StubMac:
    mac_address = "aa:bb:cc:dd:ee:ff"


class _StubCm:
    get_mac_address = _StubMac()


class _StubService:
    def __init__(self) -> None:
        self.cm = _StubCm()
        self._state = "running"

    def status(self, operation_id: OperationId) -> dict[str, object]:
        return {
            "state": self._state,
            "collected": 0,
            "time_remaining": 0,
        }

    def stop(self, operation_id: OperationId) -> None:
        self._state = "stopped"


def test_status_endpoint_uses_service_status_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    stub = _StubService()
    monkeypatch.setattr(
        ds_router.MultiDsChanEstRouter,
        "getService",
        lambda self, operation_id: stub,
    )

    client = TestClient(_build_app())
    response = client.get("/advance/multiChannelEstimation/status/op-500")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.SUCCESS
    assert payload["operation"]["operation_id"] == "op-500"


def test_stop_endpoint_uses_service_status_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    stub = _StubService()
    monkeypatch.setattr(
        ds_router.MultiDsChanEstRouter,
        "getService",
        lambda self, operation_id: stub,
    )

    client = TestClient(_build_app())
    response = client.delete("/advance/multiChannelEstimation/stop/op-501")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.SUCCESS
    assert payload["operation"]["state"] == "stopped"


def test_registry_status_endpoint_returns_dual_status_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/status",
        json={"operation_id": "op-600"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS


def test_registry_status_endpoint_uses_service_time_remaining(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    class _StubService:
        def status(self, operation_id: OperationId) -> dict[str, int]:
            return {"time_remaining": _TEST_TIME_REMAINING}

    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )
    monkeypatch.setattr(
        OperationRegistry,
        "get",
        staticmethod(lambda operation_id: _StubService()),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/status",
        json={"operation_id": "op-602"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["time_remaining"] == _TEST_TIME_REMAINING


def test_registry_status_endpoint_uses_default_time_remaining_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )
    monkeypatch.setattr(
        OperationRegistry,
        "get",
        staticmethod(lambda operation_id: None),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/status",
        json={"operation_id": "op-603"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert (
        payload["time_remaining"]
        == ds_router.MultiDsChanEstRouter._DEFAULT_TIME_REMAINING
    )


def test_registry_cancel_endpoint_returns_dual_status_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    def _fake_cancel(
        operation_id: OperationId, service: object | None = None
    ) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "canceled",
            "created_ts": 1,
            "updated_ts": 2,
            "progress_current": 1,
            "progress_total": 1,
            "message": "Operation canceled",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "cancel",
        staticmethod(_fake_cancel),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/cancel",
        json={"operation_id": "op-601"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS

# FILE: tests/test_multi_rxmer_result_resolves_transactions.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.router import router
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    OperationId,
    TimestampSec,
    TransactionId,
)


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


PNM_TEST_TYPE: str = "DS_OFDM_RXMER_PER_SUBCAR"
DEFAULT_TIMESTAMP: int = 1
SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
}
DEVICE_DETAILS: dict[str, object] = {"system_description": SYS_DESCR}
DEFAULT_FILENAME = FileName("rxmer.bin")
DEFAULT_MAC = MacAddress("aa:bb:cc:dd:ee:ff")


class _DbFixture:
    @staticmethod
    def initialize(db_path: Path) -> None:
        sqlite_path = DatabasePath(str(db_path))
        postgres_dsn = DatabaseDsn("")
        manager = DatabaseSchemaManager.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        manager.initialize_schema()

    @staticmethod
    def insert_transaction(db_path: Path, transaction_id: str) -> None:
        sqlite_path = DatabasePath(str(db_path))
        postgres_dsn = DatabaseDsn("")
        sys_repo = SystemDescriptionRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        device_repo = DeviceDetailsRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        txn_repo = TransactionRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        sysdescr_id = sys_repo.get_or_create_sysdescr_id(SYS_DESCR)
        device_detail_id = device_repo.get_or_create_device_detail_id(
            DEVICE_DETAILS, sysdescr_id
        )
        txn_repo.insert_transaction(
            transaction_id=TransactionId(transaction_id),
            timestamp_epoch=TimestampSec(DEFAULT_TIMESTAMP),
            mac_address=DEFAULT_MAC,
            pnm_test_type=PNM_TEST_TYPE,
            filename=DEFAULT_FILENAME,
            device_detail_id=device_detail_id,
        )


def _configure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Path]:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"
    sqlite_db = db_dir / "pypnm.sqlite3"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(capture_group_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    _DbFixture.initialize(sqlite_db)

    return {
        "capture_group_db": capture_group_db,
        "operation_db": operation_db,
        "database_sqlite_path": sqlite_db,
    }


def test_result_resolves_transactions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())
    caplog.set_level("WARNING")

    operation_id = OperationId("op-123")
    capture_group_id = "group-123"
    transaction_id = "txn123"
    missing_transaction_id = "txn-missing"

    paths["operation_db"].write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group_id": capture_group_id,
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )
    paths["capture_group_db"].write_text(
        json.dumps(
            {
                capture_group_id: {
                    "created": 1,
                    "transactions": [transaction_id, missing_transaction_id],
                }
            }
        ),
        encoding="utf-8",
    )
    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id)

    store = OperationStore()
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )

    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert payload["transactions"]
    assert payload["transactions"][0]["transaction_id"] == transaction_id
    assert "Missing transaction record for transaction_id" in caplog.text
    OperationRegistry.unregister(operation_id)


def test_result_rejects_when_no_transactions_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-124")
    capture_group_id = "group-124"
    transaction_id = "txn-missing"

    paths["operation_db"].write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group_id": capture_group_id,
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )
    paths["capture_group_db"].write_text(
        json.dumps(
            {
                capture_group_id: {
                    "created": 1,
                    "transactions": [transaction_id],
                }
            }
        ),
        encoding="utf-8",
    )
    # No transaction records seeded.

    store = OperationStore()
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )

    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 404
    assert "No transaction records found" in response.json()["detail"]


def test_result_resolves_transactions_with_legacy_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-125")
    capture_group_id = "group-125"
    transaction_id = "txn125"

    paths["operation_db"].write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group": capture_group_id,
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )
    paths["capture_group_db"].write_text(
        json.dumps(
            {
                capture_group_id: {
                    "created": 1,
                    "transactions": [transaction_id],
                }
            }
        ),
        encoding="utf-8",
    )
    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id)

    store = OperationStore()
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )

    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert payload["transactions"][0]["transaction_id"] == transaction_id

# FILE: tests/test_multi_rxmer_start_returns_operation_and_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.router import router
from pypnm.api.routes.advance.multi_rxmer.service import MultiRxMerService
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath, OperationId


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _configure_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"
    sqlite_db = db_dir / "pypnm.sqlite3"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(capture_group_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()


@pytest.mark.asyncio
async def test_start_returns_operation_and_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    async def _fake_capture(self: MultiRxMerService) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])

    monkeypatch.setattr(MultiRxMerService, "_capture_message_response", _fake_capture)

    client = TestClient(_build_app())
    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/start",
        json={
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "192.168.0.100",
            "duration": 0,
            "interval": 0,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["operation_id"]
    assert payload["capture_group_id"]
    OperationRegistry.unregister(OperationId(payload["operation_id"]))

# FILE: tests/test_operation_manager_capture_group_id.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import OperationCaptureRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath


def _configure_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base_dir = tmp_path / ".data"
    db_dir = base_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"
    sqlite_db = db_dir / "pypnm.sqlite3"

    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(capture_group_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()

    return operation_db


def test_operation_manager_writes_capture_group_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    group = CaptureGroup()
    group_id = group.create_group()

    manager = OperationManager(capture_group_id=group_id)
    operation_id = manager.register()

    operation_repo = OperationCaptureRepository.from_system_config()
    resolved = operation_repo.get_capture_group_id(operation_id)
    assert resolved == group_id

# FILE: tests/test_operation_manager_get_capture_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import (
    CaptureGroupRepository,
    OperationCaptureRepository,
)
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    OperationId,
    TimestampSec,
)

DEFAULT_CREATED_EPOCH: int = 1


def _configure_operation_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base_dir = tmp_path / ".data"
    db_dir = base_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    operation_db = db_dir / "operation_capture.json"
    sqlite_db = db_dir / "pypnm.sqlite3"
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()
    return operation_db


def test_get_capture_group_prefers_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-199")
    capture_group_id = GroupId("group-199")

    capture_repo = CaptureGroupRepository.from_system_config()
    capture_repo.get_or_create_capture_group(
        capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )
    operation_repo = OperationCaptureRepository.from_system_config()
    operation_repo.upsert_operation_capture(
        operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id
    operation_repo = OperationCaptureRepository.from_system_config()
    assert operation_repo.get_capture_group_id(operation_id) == capture_group_id


def test_get_capture_group_returns_group_id_for_canonical_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_db = _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-200")
    capture_group_id = GroupId("group-200")

    operation_db.write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group_id": str(capture_group_id),
                    "created": DEFAULT_CREATED_EPOCH,
                }
            }
        ),
        encoding="utf-8",
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id
    operation_repo = OperationCaptureRepository.from_system_config()
    assert operation_repo.get_capture_group_id(operation_id) == capture_group_id


def test_get_capture_group_returns_group_id_for_legacy_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_db = _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-201")
    capture_group_id = GroupId("group-201")

    operation_db.write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group": str(capture_group_id),
                    "created": DEFAULT_CREATED_EPOCH,
                }
            }
        ),
        encoding="utf-8",
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id


def test_get_capture_group_returns_none_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-202")

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved is None

# FILE: tests/test_operation_workflow.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    MessageResponse,
    MessageResponseType,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath, OperationId


class _FakeCaptureService(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])


class _FakeCaptureServiceEmptyTxn(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        payload = [
            {
                "status": ServiceStatusCode.SUCCESS.name,
                "message_type": MessageResponseType.PNM_FILE_TRANSACTION.name,
                "message": {
                    "transaction_id": "",
                    "filename": "rxmer.bin",
                },
            }
        ]
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=payload)


class _FakeCaptureServiceWhitespaceTxn(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        payload = [
            {
                "status": ServiceStatusCode.SUCCESS.name,
                "message_type": MessageResponseType.PNM_FILE_TRANSACTION.name,
                "message": {
                    "transaction_id": "   ",
                    "filename": "rxmer.bin",
                },
            }
        ]
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=payload)


def _configure_operation_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"
    sqlite_db = db_dir / "pypnm.sqlite3"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(capture_group_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()


@pytest.mark.asyncio
async def test_start_creates_running_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    service = _FakeCaptureService(duration=0, interval=1)
    _, operation_id = await service.start()

    store = OperationStore()
    status = store.get_operation(operation_id)
    assert status is not None
    assert status.state == OperationExecutionState.RUNNING

    await asyncio.sleep(0)
    completed = store.get_operation(operation_id)
    assert completed is not None
    assert completed.state == OperationExecutionState.COMPLETED
    assert completed.progress_current >= 1


@pytest.mark.asyncio
async def test_cancel_marks_canceled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    service = _FakeCaptureService(duration=1, interval=0)
    _, operation_id = await service.start()

    canceled = OperationWorkflowService.cancel(operation_id, service)
    assert canceled.state == OperationExecutionState.CANCELED

    await asyncio.sleep(0)
    store = OperationStore()
    status = store.get_operation(operation_id)
    assert status is not None
    assert status.state == OperationExecutionState.CANCELED


def test_result_requires_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    store = OperationStore()
    operation_id = OperationId("op-test-1")
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.RUNNING,
        progress_current=0,
        progress_total=1,
        message="Operation running",
        error=None,
        artifact_paths=None,
    )

    with pytest.raises(ValueError):
        OperationWorkflowService.get_result(operation_id)

    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )
    status = OperationWorkflowService.get_result(operation_id)
    assert status.state == OperationExecutionState.COMPLETED


@pytest.mark.asyncio
async def test_capture_service_skips_empty_transaction_id_linking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    service = _FakeCaptureServiceEmptyTxn(duration=0, interval=0)
    group_id, _ = await service.start()

    await asyncio.sleep(0)

    repo = CaptureGroupRepository.from_system_config()
    assert repo.list_transactions(group_id) == []
    assert "Skipping capture_group link for empty transaction_id" in caplog.text


@pytest.mark.asyncio
async def test_capture_service_skips_whitespace_transaction_id_linking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    service = _FakeCaptureServiceWhitespaceTxn(duration=0, interval=0)
    group_id, _ = await service.start()

    await asyncio.sleep(0)

    repo = CaptureGroupRepository.from_system_config()
    assert repo.list_transactions(group_id) == []
    assert "Skipping capture_group link for empty transaction_id" in caplog.text

# FILE: tests/test_transaction_id_persistence_guards.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.session_group import SessionGroup
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


def _configure_transaction_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "pypnm.sqlite3"
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(db_path))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()
    return db_path


def _configure_session_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "session_group.json"
    monkeypatch.setattr(
        SystemConfigSettings,
        "session_group_db",
        classmethod(lambda cls: str(db_path)),
    )
    return db_path


def _empty_sha256() -> object:
    class _Hasher:
        def update(self, _data: bytes) -> None:
            return None

        def hexdigest(self) -> str:
            return ""

    return _Hasher()


def test_session_group_skips_empty_transaction_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = _configure_session_db(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    group = SessionGroup()
    session_id = group.create_session()

    group.add_transaction("")
    group.add_transaction("   ")
    group.add_transaction("txn-1")

    with db_path.open("r", encoding="utf-8") as handle:
        db = json.load(handle)
    assert db[session_id]["transactions"] == ["txn-1"]
    assert (
        "Skipping empty transaction_id persistence in session_group_db" in caplog.text
    )


def test_pnm_file_transaction_skips_empty_transaction_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = _configure_transaction_db(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    monkeypatch.setattr(
        "pypnm.api.routes.common.classes.file_capture.pnm_file_transaction.hashlib.sha256",
        lambda _data=None: _empty_sha256(),
    )

    txn_store = PnmFileTransaction()
    cm = CableModem(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        inet=Inet("192.168.0.100"),
        write_community="public",
    )
    txn_id = txn_store._insert_generic(
        mac_address=cm.get_mac_address,
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        filename="rxmer.bin",
    )

    assert str(txn_id) == ""
    assert "Skipping transaction insert for empty transaction_id" in caplog.text

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute("SELECT COUNT(1) FROM transaction_records;")
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == 0
    finally:
        connection.close()


def test_pnm_file_transaction_persists_valid_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_transaction_db(tmp_path, monkeypatch)
    txn_store = PnmFileTransaction()
    cm = CableModem(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        inet=Inet("192.168.0.100"),
        write_community="public",
    )
    txn_id = txn_store._insert_generic(
        mac_address=cm.get_mac_address,
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        filename="rxmer.bin",
    )

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute(
            "SELECT COUNT(1) FROM transaction_records WHERE transaction_id = ?;",
            (str(txn_id),),
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == 1
    finally:
        connection.close()

# FILE: tests/test_transaction_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import cast

from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    TimestampSec,
    TransactionId,
)

PNM_TEST_TYPE: str = "DS_RXMER"

SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "ACME",
    "BOOTR": "1.1",
    "SW_REV": "2.0.1",
    "MODEL": "ACME-123",
}

MAC_ONE = MacAddress("aa:bb:cc:dd:ee:ff")
MAC_TWO = MacAddress("11:22:33:44:55:66")

TRANSACTION_ONE = TransactionId("aaaaaaaaaaaaaaaa")
TRANSACTION_TWO = TransactionId("bbbbbbbbbbbbbbbb")
TRANSACTION_THREE = TransactionId("cccccccccccccccc")

FILENAME_ONE = FileName("rxmer_one.bin")
FILENAME_TWO = FileName("rxmer_two.bin")
FILENAME_THREE = FileName("rxmer_three.bin")

TIMESTAMP_ONE: int = 1700000000
TIMESTAMP_TWO: int = 1700000100

EXPECTED_SYS_DESCR_COUNT: int = 1
EXPECTED_DEVICE_DETAILS_COUNT: int = 1
EXPECTED_DISTINCT_MACS: int = 2


class _RepoFixture:
    @staticmethod
    def build(
        tmp_path: Path,
    ) -> tuple[
        SystemDescriptionRepository,
        DeviceDetailsRepository,
        TransactionRepository,
        Path,
    ]:
        db_path = tmp_path / "pypnm.sqlite3"
        sqlite_path = cast(DatabasePath, str(db_path))
        postgres_dsn = cast(DatabaseDsn, "")

        manager = DatabaseSchemaManager.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        manager.initialize_schema()

        sys_repo = SystemDescriptionRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        device_repo = DeviceDetailsRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        txn_repo = TransactionRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )

        return sys_repo, device_repo, txn_repo, db_path

    @staticmethod
    def insert_transaction(
        sys_repo: SystemDescriptionRepository,
        device_repo: DeviceDetailsRepository,
        txn_repo: TransactionRepository,
        transaction_id: TransactionId,
        timestamp_epoch: int,
        mac_address: MacAddress,
        filename: FileName,
        sysdescr: dict[str, str],
    ) -> None:
        sysdescr_id = sys_repo.get_or_create_sysdescr_id(sysdescr)
        device_details: dict[str, object] = {"system_description": sysdescr}
        device_detail_id = device_repo.get_or_create_device_detail_id(
            device_details, sysdescr_id
        )
        txn_repo.insert_transaction(
            transaction_id=transaction_id,
            timestamp_epoch=TimestampSec(timestamp_epoch),
            mac_address=mac_address,
            pnm_test_type=PNM_TEST_TYPE,
            filename=filename,
            device_detail_id=device_detail_id,
        )


def test_sysdescr_dedup(tmp_path: Path) -> None:
    sys_repo, device_repo, txn_repo, db_path = _RepoFixture.build(tmp_path)

    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_ONE,
        TIMESTAMP_ONE,
        MAC_ONE,
        FILENAME_ONE,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_TWO,
        TIMESTAMP_TWO,
        MAC_ONE,
        FILENAME_TWO,
        SYS_DESCR,
    )

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute(
            "SELECT COUNT(1) FROM system_description_dim WHERE is_unknown = 0;"
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == EXPECTED_SYS_DESCR_COUNT
    finally:
        connection.close()


def test_device_details_dedup(tmp_path: Path) -> None:
    sys_repo, device_repo, txn_repo, db_path = _RepoFixture.build(tmp_path)

    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_ONE,
        TIMESTAMP_ONE,
        MAC_ONE,
        FILENAME_ONE,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_TWO,
        TIMESTAMP_TWO,
        MAC_TWO,
        FILENAME_TWO,
        SYS_DESCR,
    )

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute("SELECT COUNT(1) FROM device_details;")
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == EXPECTED_DEVICE_DETAILS_COUNT
    finally:
        connection.close()


def test_list_macs_returns_distinct(tmp_path: Path) -> None:
    sys_repo, device_repo, txn_repo, _db_path = _RepoFixture.build(tmp_path)

    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_ONE,
        TIMESTAMP_ONE,
        MAC_ONE,
        FILENAME_ONE,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_TWO,
        TIMESTAMP_TWO,
        MAC_ONE,
        FILENAME_TWO,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_THREE,
        TIMESTAMP_TWO,
        MAC_TWO,
        FILENAME_THREE,
        SYS_DESCR,
    )

    mac_entries = txn_repo.list_macs()
    assert len(mac_entries) == EXPECTED_DISTINCT_MACS
    macs = {entry.mac_address for entry in mac_entries}
    assert str(MAC_ONE) in macs
    assert str(MAC_TWO) in macs


def test_list_transactions_for_mac_orders_by_timestamp(tmp_path: Path) -> None:
    sys_repo, device_repo, txn_repo, _db_path = _RepoFixture.build(tmp_path)

    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_ONE,
        TIMESTAMP_TWO,
        MAC_ONE,
        FILENAME_ONE,
        SYS_DESCR,
    )
    _RepoFixture.insert_transaction(
        sys_repo,
        device_repo,
        txn_repo,
        TRANSACTION_TWO,
        TIMESTAMP_ONE,
        MAC_ONE,
        FILENAME_TWO,
        SYS_DESCR,
    )

    records = txn_repo.list_transactions_for_mac(MAC_ONE)
    timestamps = [int(record.timestamp_epoch) for record in records]
    assert timestamps == [TIMESTAMP_ONE, TIMESTAMP_TWO]
