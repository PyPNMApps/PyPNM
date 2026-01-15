# PyPNM DB Backend Refactor Burndown (With ToC)

## Table Of Contents

- [Overview](#overview)
- [Recent Status Update (2026-01-11)](#recent-status-update-2026-01-11)
- [Phase 7.7 Burndown Tracker (Updated 2026-01-11)](#phase-77-burndown-tracker-updated-2026-01-11)
- [Open Issues From Review Bundles (Updated 2026-01-11)](#open-issues-from-review-bundles-updated-2026-01-11)
- [Locked Decisions (Selection Summary)](#locked-decisions-selection-summary)
- [Milestones](#milestones)
- [Phase 0 · Guardrails And Release Hygiene (M0)](#phase-0--guardrails-and-release-hygiene-m0)
- [Phase 1 · Install-Time Backend Selection And Config Contract (M1)](#phase-1--install-time-backend-selection-and-config-contract-m1)
- [Phase 2 · Schema Introduction And DB Abstraction Layer (M2)](#phase-2--schema-introduction-and-db-abstraction-layer-m2)
- [Phase 3 · Transactions Migration (DB-Backed Transactions) (M3)](#phase-3--transactions-migration-db-backed-transactions-m3)
- [Phase 4 · Capture Group And Operation Migration (DB-Backed Capture Groups) (M4)](#phase-4--capture-group-and-operation-migration-db-backed-capture-groups-m4)
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

Work completed since the last burndown sync (per Agent Review Bundles and the current codebase snapshot):

- **M2 complete (schema init + DB abstraction layer):**
  - Schema assets maintained as authoritative:
    - `docs/design/db/schema_sqlite.sql`
    - `docs/design/db/schema_postgres.sql`
  - Schema apply/init is idempotent and invoked from startup.
  - Seeds `UNKNOWN` sysDescr row idempotently.
  - Seeds default `artifact_stores` rows idempotently (at least the primary/prod default).

- **M3 complete (transactions and JSON export artifacts are DB-backed; legacy ledgers removed from runtime):**
  - Introduced repository helpers for sysDescr/device_details dimensions and transaction_records.
  - Wired `PnmFileTransaction` reads/writes to DB while preserving legacy payload shapes.
  - Updated file manager reads (`search_files`, `get_mac_addresses`) to query DB-backed repositories.
  - Updated tests to seed DB transactions and added repository unit coverage for:
    - sysDescr de-duplication
    - device_details de-duplication
    - deterministic listing and ordering (timestamp + transaction_id tie-break)

- **M4 is now in progress (repositories exist; cutover tasks remain):**
  - DB repositories for capture groups and operation→capture group linkage exist.
  - A compatibility layer exists for legacy column naming differences (operation_id vs operation_capture_id).
  - Remaining work is primarily cutover enforcement: stop runtime reads/writes of the capture/operation JSON ledgers and shift remaining endpoints/services fully to DB.

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

## Open Issues From Review Bundles (Updated 2026-01-11)

These are implementation follow-ups that are not blocked by the milestone plan but should be addressed during M4/M5 hardening.

1) Potential bug in `PnmFileTransaction.insert()`
   - Risk: passing `cable_modem.get_mac_address` (callable) instead of invoking it.
   - Requirement: ensure an actual MAC value is used consistently (normalized to lowercase).

2) Transaction ID generation hardening (keep the 16-char prefix contract)
   - Current: sha256(filename + timestamp) with truncation.
   - Improve: add higher-resolution time (e.g., `time.time_ns()`), plus MAC and/or test type.

3) Magic-number cleanup
   - Example: DEFAULT_HEXDUMP_BYTES_PER_LINE = 16 defined inside a function.
   - Requirement: promote to a named constant.

4) Refactor long if/elif chains to `match/case`
   - Target: `PnmFileService.__get_analysis()` (behavior unchanged).

5) Strict typing improvement
   - Target: `_RepositoryBase._from_system_config` should return `Self` (or an equivalent strict typing approach).

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
- M2: Complete (DB schema init + backend-aware connection path landed; schema manager in use)
- M3: Complete (transactions and JSON export artifacts are DB-backed; legacy ledger paths are not used at runtime)
- M4: In progress (capture groups + operation linkage repositories exist; JSON ledger cutover and endpoint wiring still open)
- M5: Not started (artifact linkage; DB becomes authoritative for path resolution)
- M6: Not started (delete ledger code paths and ledger docs)
- M7: Partially done (Postgres CI job plumbing landed; full DB-backed test suite + ledger removal assertions pending)

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

- [x] Ensure schema assets exist and are treated as authoritative:
  - [x] `docs/design/db/schema_postgres.sql`
  - [x] `docs/design/db/schema_sqlite.sql`

- [x] Implement DB connection layer in PyPNM:
  - [x] SQLite connection opens with `PRAGMA foreign_keys = ON`
  - [x] SQLite enables WAL + sets a busy timeout (to reduce transient contention)
  - [x] Postgres connection opens via DSN (minimum) or discrete settings
  - [x] Minimal connection factory based on `Database.backend`

- [x] Implement schema apply/init (idempotent, using shipped DDL assets):
  - [x] Apply DDL idempotently on startup/install
  - [x] Seed canonical `UNKNOWN` sysDescr row idempotently
  - [x] Seed default `artifact_stores` row idempotently:
    - [x] prod store: `.data/pnm`
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

## Phase 3 · Transactions Migration (DB-Backed Transactions) (M3)

### Goal

Replace the legacy JSON transaction ledger with DB-backed `transaction_records` plus de-dup dimensions, and update endpoint read paths.

Cutover note:

- Runtime must stop writing and reading legacy JSON transaction ledgers once DB-backed transactions are enabled.
- Other legacy ledgers remain until M4.

### Tasks

- [x] Implement repository/service layer:
  - [x] `SystemDescriptionRepository` (upsert by hash)
  - [x] `DeviceDetailsRepository` (upsert by hash, FK sysDescr)
  - [x] `TransactionRepository` (insert/get/list/search)

- [x] Enforce safeguards:
  - [x] MAC normalization in app (lowercase)
  - [x] Rely on DB CHECK constraints for MAC format enforcement

- [x] Update transaction creation/read code to use DB:
  - [x] Stop writing legacy JSON transaction ledgers
  - [x] Preserve external API shapes as needed by current services/endpoints

- [x] Track JSON export artifacts in DB (file_artifacts + transaction_artifacts; no JSON ledger)

- [x] Update file-manager endpoints to query DB (no JSON ledger traversal):
  - [x] `getMacAddresses`
  - [x] `searchFiles/{mac_address}`
  - [x] `download/transactionID/{transaction_id}` resolves filename via DB record (artifact linkage becomes authoritative in M5)

- [x] Add pytest coverage:
  - [x] Insert transaction creates dims (sysDescr/device details)
  - [x] De-dup sysDescr across multiple transactions
  - [x] De-dup device details across multiple transactions
  - [x] Endpoint-compatible query behavior (service-level tests)

### Acceptance Criteria

- [x] Captures produce DB rows instead of writing legacy JSON ledgers.
- [x] File manager flows can fetch transactions from DB (no JSON ledger traversal for transactions).
- [x] There is no runtime write/read path that touches legacy JSON ledgers.
- [x] JSON export artifacts are tracked in DB without JSON ledger files.

## Phase 4 · Capture Group And Operation Migration (DB-Backed Capture Groups) (M4)

### Goal

Move multi-capture and operation tracking to DB, updating operation-based endpoints.

Cutover note:

- This phase stops runtime writes to capture-group and operation ledgers.
- Once complete, operation status/result endpoints must resolve via DB-backed repositories.

### Tasks

- [x] Implement `CaptureGroupRepository`:
  - [x] Create capture group
  - [x] Add ordered transaction membership (`position`)
  - [x] Load capture group with ordered transactions

- [x] Implement `OperationCaptureRepository`:
  - [x] Create operation capture linking to capture group
  - [x] Resolve operation capture -> capture group -> ordered transaction list
  - [x] Support legacy schema compatibility (`operation_id` vs `operation_capture_id`) without branching call sites

- [ ] Update existing grouping/operation services to use DB end-to-end:
  - [ ] Stop writing legacy capture-group ledgers
  - [ ] Stop writing legacy operation-capture ledgers
  - [ ] Stop reading capture/operation ledgers from runtime paths
  - [ ] Ensure multi-capture start/status/result endpoints resolve operation/group via DB only

- [ ] Update file-manager endpoint behavior:
  - [ ] `download/operationID/{operation_id}` resolves op -> group -> ordered tx list via DB

- [ ] Add pytest coverage:
  - [ ] Position uniqueness within group
  - [ ] Operation capture references group correctly
  - [ ] Endpoint path resolution uses DB (service-level tests)
  - [ ] Explicit assertion: no runtime read/write of capture/operation JSON ledgers

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
    - [ ] legacy JSON ledger paths for transactions, capture groups, and operations
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

## Phase 2 · Schema Introduction And DB Abstraction Layer (M2) Status Block

- Status: Complete (schema assets authoritative, startup idempotent schema init, connection factory, health check, seeds for UNKNOWN sysDescr and default artifact store)
- Verified gates: compileall, ruff check, ruff format --check, pytest all green in the latest bundle
- Known deltas: demo artifact store seeding only required if demo mode is actively supported; otherwise defer to M5/demo hardening
- Next dependencies: M4 cutover enforcement (eliminate capture/operation JSON ledger runtime usage), then M5 artifact linkage as the authoritative file resolver
