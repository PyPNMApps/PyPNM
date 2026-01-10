<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Maurice Garcia -->

# PyPNM DB Backend Refactor Burndown (With ToC)

## Table Of Contents

- [Overview](#overview)
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
- JSON ledgers are deprecated and removed from code and docs; migrator is optional and offline-only.

## Milestones

- M0: Repo safety and release hygiene complete
- M1: DB configuration and installer selection complete
- M2: Schema and DB abstraction complete
- M3: Transaction persistence migrated (replaces `transactions.json`)
- M4: Capture group and operation persistence migrated (replaces `capture_group.json`, `operation_capture.json`)
- M5: Artifact linkage migrated (DB is authoritative for path resolution)
- M6: Ledger JSON design removed (docs) and legacy ledger code paths removed
- M7: Pytest suite and GitHub Actions migrated to DB backends (SQLite required; Postgres validated)

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
- [ ] Document runtime DB location rules:
  - [ ] SQLite path under `.data/db/`
  - [ ] Postgres external (no local DB file)
- [ ] Add doc note: demo uses isolated root (`demo/`) and isolated DB.

### Acceptance Criteria

- Building sdist/wheel does not contain `.data/` or any DB files.
- Docker images do not contain `.data/` contents.
- Docs state the runtime DB location policy clearly.

## Phase 1 · Install-Time Backend Selection And Config Contract (M1)

### Goal

Make DB backend selection a first-class install-time choice owned by PyPNM and visible in docs.

### Tasks

- [ ] Extend `install.sh`:
  - [ ] Support `--db-install-postgres`
  - [ ] Support `--db-install-sqlite`
  - [ ] Add interactive prompt if no flag provided (default: SQLite)
  - [ ] Add install-time warning text:
    - [ ] SQLite is recommended for standalone PyPNM / single-writer
    - [ ] Postgres is recommended for PyPNM-CMTS and/or multi-worker/multi-process
  - [ ] Add a Postgres config prompt path when Postgres is selected:
    - [ ] Allow DSN entry OR discrete fields that render into a DSN
    - [ ] Host / port / database / user / password / ssl mode
    - [ ] Ensure password can be provided via env var override (no plaintext requirement in JSON)
- [ ] Add config keys to `settings/system.json.template` (and demo template if used):
  - [ ] `Database.backend` = `sqlite` | `postgres`
  - [ ] `Database.sqlite.path` default `.data/db/pypnm.sqlite3`
  - [ ] Postgres connection settings:
    - [ ] Support `Database.postgres.dsn`
    - [ ] Optional discrete settings for UX (installer can populate DSN)
  - [ ] Support environment variable overrides for secrets (do not require plaintext passwords in tracked JSON)
- [ ] Add `SystemConfigSettings` accessors for DB settings.
- [ ] Ensure docs explicitly describe:
  - [ ] Install-time backend selection mechanism
  - [ ] SQLite vs Postgres recommendation (single-writer vs multi-worker)
  - [ ] PyPNM-CMTS inherits backend (no separate selection)
- [ ] Add pytest coverage for config defaults and validation (missing/blank handling).

### Notes: Postgres Credentials Policy

- Development defaults like `pypnm/pypnm` are acceptable for local dev and CI only.
- Do not recommend these credentials for production.
- Prefer environment variables or a local `.env` file for passwords and DSNs.
- Do not commit `.env` or populated DB settings containing real credentials.

### Acceptance Criteria

- Fresh install can select backend via flag or prompt.
- Config settings are available via `SystemConfigSettings`.
- Tests cover selection and default behavior.

## Phase 2 · Schema Introduction And DB Abstraction Layer (M2)

### Goal

Introduce both schemas and a stable DB API that hides backend differences.

### Tasks

- [ ] Ensure schema assets exist and are treated as authoritative:
  - [ ] `docs/design/db/schema_postgres.sql`
  - [ ] `docs/design/db/schema_sqlite.sql`
- [ ] Implement DB connection layer in PyPNM:
  - [ ] SQLite connection opens with `PRAGMA foreign_keys = ON`
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
- [ ] Add pytest coverage:
  - [ ] SQLite: init creates tables and seed rows (pure unit test)
  - [ ] Postgres: wiring exists; integration is deferred to Phase 7 CI job

### Acceptance Criteria

- PyPNM can initialize DB schema for SQLite reliably.
- Postgres path is implemented and can be exercised with integration tests.
- `UNKNOWN` sysDescr exists after init.

## Phase 3 · Transactions Migration (Replace `transactions.json`) (M3)

### Goal

Replace JSON transactions ledger with DB-backed `transaction_records` plus de-dup dimensions, and update endpoint read paths.

### Tasks

- [ ] Implement repository/service layer:
  - [ ] `SystemDescriptionRepository` (upsert by hash)
  - [ ] `DeviceDetailsRepository` (upsert by hash, FK sysDescr)
  - [ ] `TransactionRepository` (insert/get/list/search)
- [ ] Enforce safeguards:
  - [ ] MAC normalization in app (lowercase)
  - [ ] Rely on DB CHECK constraints for MAC format enforcement
- [ ] Update transaction creation/read code to use DB:
  - [ ] Remove JSON file creation/reads for transactions ledger
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

- Captures produce DB rows instead of writing `transactions.json`.
- File manager flows can fetch transactions from DB.

## Phase 4 · Capture Group And Operation Migration (Replace `capture_group.json`, `operation_capture.json`) (M4)

### Goal

Move multi-capture and operation tracking to DB, updating operation-based endpoints.

### Tasks

- [ ] Implement `CaptureGroupRepository`:
  - [ ] Create capture group
  - [ ] Add ordered transaction membership (`position`)
  - [ ] Load capture group with ordered transactions
- [ ] Implement `OperationCaptureRepository`:
  - [ ] Create operation capture linking to capture group
  - [ ] Resolve operation capture -> capture group -> ordered transaction list
- [ ] Update existing grouping/operation services to use DB:
  - [ ] Stop reading/writing JSON ledgers
- [ ] Update file-manager endpoint behavior:
  - [ ] `download/operationID/{operation_id}` resolves op -> group -> ordered tx list
- [ ] Add pytest coverage:
  - [ ] Position uniqueness within group
  - [ ] Operation capture references group correctly
  - [ ] Endpoint path resolution uses DB (service-level tests)

### Acceptance Criteria

- Multi-capture workflows no longer use JSON ledger files.
- Operation workflows resolve through DB.

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

- Transactions resolve to binary files without legacy settings JSON linkage.
- Demo and prod are isolated by data root and DB.

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
- [ ] Documentation cleanup (explicit requirement):
  - [ ] Remove/replace all doc references to:
    - [ ] `.data/db/transactions.json`
    - [ ] `.data/db/capture_group.json`
    - [ ] `.data/db/operation_capture.json`
  - [ ] Update file-manager docs to state DB-backed persistence for transactions/groups/operations
  - [ ] Add DB backend sections:
    - [ ] Backend selection and install-time flags
    - [ ] Runtime DB location policy
    - [ ] Concurrency guidance (SQLite vs Postgres)
  - [ ] Add Mermaid diagrams/flows in docs where workflows are described
- [ ] MkDocs + tooling support for Mermaid:
  - [ ] Update `mkdocs.yml` to render Mermaid fences (Material: `pymdownx.superfences`)
  - [ ] Add the Mermaid plugin dependency to the docs extras in `pyproject.toml` (Codex selects the best fit for current repo)
- [ ] Final hygiene scan:
  - [ ] Ensure no `.data/` artifacts are tracked or packaged

### Acceptance Criteria

- No code path depends on JSON ledgers.
- Docs and examples reflect DB backend design (no ledger design remains as “current”).
- Release artifacts contain no DB data.

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
    - [ ] Postgres job (required; not “allowed failure”)
  - [ ] Postgres service container job:
    - [ ] Use `postgres` service with `POSTGRES_USER=pypnm`, `POSTGRES_PASSWORD=pypnm`, `POSTGRES_DB=pypnm`
    - [ ] Provide DSN via env var to tests (no committed secrets)
    - [ ] Apply schema during test setup (idempotent)
  - [ ] Ensure tests remain hermetic:
    - [ ] No external CMTS/SNMP dependencies in CI
- [ ] Developer documentation:
  - [ ] Document what backends CI validates
  - [ ] Document how to run Postgres tests locally (docker compose recommended)
  - [ ] Document DSN override via environment variables

### Acceptance Criteria

- `pytest` passes locally for SQLite.
- GitHub Actions passes with SQLite.
- Postgres path is validated in CI with a service container.

## Cross-Cutting Requirements

### PyPNM-CMTS Contract

- [ ] PyPNM-CMTS must not select a different backend than PyPNM.
- [ ] All DB interactions in PyPNM-CMTS must occur through PyPNM APIs only.

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
