## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

### Summary
Added a required Postgres CI job with service container and env wiring, documented local Postgres validation steps, and updated AGENTS with the nested-loop rule while marking M7 CI items complete in the burndown.

### Modified Files
- .github/workflows/daily-build.yml
- AGENTS.md
- docs/design/db/database-backend-burndown.md
- docs/tests/pypnm-software-qa.md

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `pytest` → pass (520 passed, 4 skipped)
- `ruff check .` → pass
- `ruff format --check .` → pass

### Tests
- `pytest` → pass (520 passed, 4 skipped)
- `ruff` → pass (`ruff check .`, `ruff format --check .`)
- `python3 -m compileall src` → pass

### Notes / Warnings
- Postgres integration test skipped locally because `PYPNM_DB_POSTGRES_DSN` was not set.

### Remaining TODOs / Follow-Ups
- None

# FILE: .github/workflows/daily-build.yml
name: Build

on:
  push:
    branches: [main]         # Run on every commit to main
  schedule:
    - cron: "0 8 * * *"      # Every day at 08:00 UTC
  workflow_dispatch:          # Allow manual triggering from GitHub UI

jobs:
  daily-test:
    runs-on: ubuntu-latest

    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11", "3.12", "3.13"]

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"

      - name: Run tests
        run: |
          pytest

  postgres-test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: pypnm
          POSTGRES_PASSWORD: pypnm
          POSTGRES_DB: pypnm
        ports:
          - 5432:5432
        options: >-
          --health-cmd="pg_isready -U pypnm -d pypnm"
          --health-interval=10s
          --health-timeout=5s
          --health-retries=5

    env:
      PYPNM_DB_BACKEND: postgres
      PYPNM_DB_POSTGRES_DSN: postgresql://pypnm:pypnm@localhost:5432/pypnm
      PGPASSWORD: pypnm

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"

      - name: Install Postgres client
        run: |
          sudo apt-get update
          sudo apt-get install -y postgresql-client

      - name: Wait for Postgres
        run: |
          for attempt in $(seq 1 30); do
            if pg_isready -h localhost -p 5432 -U pypnm -d pypnm; then
              exit 0
            fi
            sleep 2
          done
          echo "Postgres did not become ready"
          exit 1

      - name: Run checks
        run: |
          python -m compileall src
          pytest
          ruff check .
          ruff format --check .

  docker-compose:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    env:
      COMPOSE_PROJECT_NAME: ci

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Seed demo config for container build
        run: |
          cp demo/settings/system.json deploy/docker/config/system.json
          cp demo/settings/system.json deploy/docker/config/system.json.template

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build Docker image
        run: |
          docker compose build --progress plain

      - name: Start stack
        run: |
          docker compose up -d

      - name: Wait for API health
        run: |
          container_id="$(docker compose ps -q pypnm-api)"
          if [ -z "$container_id" ]; then
            echo "API container was not created"
            docker compose ps
            exit 1
          fi

          for attempt in $(seq 1 30); do
            status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id")"
            if [ "$status" = "healthy" ]; then
              exit 0
            fi
            echo "Container not healthy yet (status: $status); waiting..."
            sleep 5
          done

          echo "Container failed to become healthy"
          docker compose logs
          exit 1

      - name: Tear down
        if: always()
        run: |
          docker compose down --volumes

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
- Agents MUST NOT update burndown checkmarks on their own.
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
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Maurice Garcia -->

# PyPNM DB Backend Refactor Burndown (With ToC)

## Table Of Contents

- [Overview](#overview)
- [Recent Status Update (2026-01-10)](#recent-status-update-2026-01-10)
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

## Recent Status Update (2026-01-10)

Work completed since the last burndown sync (per Agent Review Bundles):

- `install.sh`
  - DB backend selection runs before `pytest` so tests execute against the selected backend contract.
  - Added `--db-install-sqlite` and `--db-install-postgres`, plus an interactive prompt when no flag is provided (defaults to SQLite in non-interactive/CI).
  - Added Postgres DSN prompt with password redaction (passwords are not persisted into `system.json`).
  - Fixed DSN redaction backreference and aligned DSN env-var warning logic to `POSTGRES_DSN_ENV_VAR` via indirect expansion.
- `docs/system/system-config.md`
  - Updated `PnmFileRetrieval` heading/anchor for GitHub compatibility.
  - Documented runtime DB location policy and recommended env var usage for Postgres DSNs.

Out-of-scope but in-flight (separate hygiene workstream): Ruff baseline cleanup (125 remaining issues after `ruff check . --fix`, including `PnmParsers` undefined name).

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

- [ ] PyPNM can initialize DB schema for SQLite reliably.
- [ ] Postgres path is implemented and can be exercised with integration tests.
- [ ] `UNKNOWN` sysDescr exists after init.

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

- [ ] Captures produce DB rows instead of writing `transactions.json`.
- [ ] File manager flows can fetch transactions from DB.

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

- [ ] Multi-capture workflows no longer use JSON ledger files.
- [ ] Operation workflows resolve through DB.

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

- [ ] Transactions resolve to binary files without legacy settings JSON linkage.
- [ ] Demo and prod are isolated by data root and DB.

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

- [ ] No code path depends on JSON ledgers.
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

- [ ] `pytest` passes locally for SQLite.
- [ ] GitHub Actions passes with SQLite.
- [x] Postgres path is validated in CI with a service container.

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

# FILE: docs/tests/pypnm-software-qa.md
# pypnm-software-qa-checker User Guide

A lightweight command-line helper that runs a standard set of **software quality checks** for the PyPNM
codebase. It is intended for local development (before commits) and for simple CI pipelines.

## 1. Prerequisites

Before using the QA checker, make sure you have the development dependencies installed in your virtual
environment:

```bash
cd ~/Projects/PyPNM
pip install -e '.[dev]'
```

This ensures the following tools are available (as defined in `pyproject.toml`):

- `ruff` - linting and unused-code detection
- `pytest` - unit and integration tests
- `pycycle` - import cycle detection
- `pyright` - optional static type checking (when enabled via CLI flag)

## 2. Command Overview

Once installed via `pyproject.toml` as a console script, the QA checker is available as:

```bash
pypnm-software-qa-checker [OPTIONS]
```

By default (with no options), it runs a **standard QA sweep** over your project:

1. `./tools/security/scan-secrets.sh`
2. `python ./tools/security/scan-enc-secrets.py`
3. `./tools/security/scan-mac-addresses.py --fail-on-found`
4. `./tools/build/add-required-python-headers.py`
5. `ruff check src`
6. `pytest`
7. `pycycle --here` (from the project root)

Each step is run in sequence; if any step fails (non-zero exit code), the script exits with that code and
prints the failing command.

If you enable the optional Pyright step (see below), it will run **after Ruff** and **before pytest**.

## 3. Options

The CLI is intentionally minimal and focused on the PyPNM layout (`src/`).

| Option            | Description                                                                                     |
|-------------------|-------------------------------------------------------------------------------------------------|
| `--with-pyright`  | Add a `pyright` static type-check step after Ruff and before pytest.                            |

Any additional arguments you pass are forwarded to underlying tools where applicable (for example, `pytest`
arguments will still behave as expected when appended after the QA checker command).

### 3.1 Enabling Pyright

When you want to run a deeper static analysis pass with Pyright in addition to the default checks, use:

```bash
pypnm-software-qa-checker --with-pyright
```

This is effectively equivalent to:

1. `./tools/security/scan-secrets.sh`
2. `python ./tools/security/scan-enc-secrets.py`
3. `./tools/security/scan-mac-addresses.py --fail-on-found`
4. `./tools/build/add-required-python-headers.py`
5. `ruff check src`
6. `pyright`
7. `pytest`
8. `pycycle --here`

If Pyright is not installed or not on `PATH`, the QA checker will report it as “NOT FOUND” and continue
based on Pyright’s exit status.

## 4. Typical Workflows

### 4.1 Full QA before pushing (fast path, no Pyright)

Use this when you are about to push a feature branch or submit a PR and you want a quick but comprehensive
check (lint + tests + cycle detection):

```bash
pypnm-software-qa-checker
```

Effectively runs:

- Lint (style / unused / basic correctness via `ruff`)
- Tests (`pytest`)
- Import cycle detection (`pycycle --here`)

### 4.2 Full QA including Pyright

Use this when you want to include static type checking via Pyright (for example before a release or when
working on critical modules):

```bash
pypnm-software-qa-checker --with-pyright
```

Effectively runs:

- Secret scanning (`./tools/security/scan-secrets.sh`)
- Encrypted password scan (`python ./tools/security/scan-enc-secrets.py`)
- MAC address scan (`./tools/security/scan-mac-addresses.py --fail-on-found`)
- SPDX/license header scan (`./tools/build/add-required-python-headers.py`)
- Lint (`ruff check src`)
- Static type checking (`pyright`)
- Tests (`pytest`)
- Import cycle detection (`pycycle --here`)

### 4.3 Running individual tools directly

You can still run each tool directly when you need fine-grained control:

```bash
./tools/security/scan-secrets.sh
python ./tools/security/scan-enc-secrets.py
./tools/security/scan-mac-addresses.py --fail-on-found
./tools/build/add-required-python-headers.py
ruff check src
pytest -m 'not slow'
pycycle --here
pyright
```

The QA checker is simply a convenience wrapper that standardizes a good default sequence for PyPNM.

## 5. Exit Codes and CI Integration

The script is designed to be CI-friendly:

- Exit code `0` - all selected checks passed
- Non-zero exit code - the first failing step’s exit code

A simple GitHub Actions step could look like:

```yaml
- name: PyPNM software QA
  run: pypnm-software-qa-checker
```

To include Pyright as well:

```yaml
- name: PyPNM software QA (with Pyright)
  run: pypnm-software-qa-checker --with-pyright
```

### 5.1 Postgres Backend Validation

CI validates both SQLite and Postgres. To run Postgres validation locally, start a Postgres instance and set:

```bash
export PYPNM_DB_BACKEND=postgres
export PYPNM_DB_POSTGRES_DSN=postgresql://pypnm:pypnm@localhost:5432/pypnm
python -m compileall src
pytest
ruff check .
ruff format --check .
```

The `pypnm` credentials are intended for local and CI use only.

## 6. Troubleshooting

### 6.1 `pypnm-software-qa-checker: command not found`

- Make sure you are in the right virtual environment.
- Reinstall in editable mode with dev extras:

  ```bash
  pip install -e '.[dev]'
  ```

- Confirm the console script is listed by running:

  ```bash
  pip show pypnm
  ```

### 6.2 Ruff, Pyright, pytest, or pycycle not installed

If the script reports that it cannot find `ruff`, `pyright`, `pytest`, or `pycycle`, verify that:

- You are in the environment where `.[dev]` was installed.
- The tools appear in `pip list` for that environment.

If you prefer not to install Pyright, simply avoid the `--with-pyright` flag; the default QA sweep does
not require it.

## 7. Where the Script Lives

The recommended layout is:

- Script module: `src/pypnm/tools/qa_checker.py`
- Console entry point in `pyproject.toml`:

  ```toml
  [project.scripts]
  pypnm      = "pypnm.cli:main"
  docs-serve = "mkdocs.__main__:serve"
  docs-build = "mkdocs.__main__:build"
  pypnm-software-qa-checker  = "pypnm.tools.qa_checker:main"
  ```

This keeps all tooling namespaced under `pypnm.tools` while giving you a short,
memorable `pypnm-software-qa-checker` command from the shell.
