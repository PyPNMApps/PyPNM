## Agent Review Bundle Summary Template (Standard)

### Summary
Fixed QA regressions by enforcing safe MultiRxMer error handling, counting comprehensions in loop nesting checks, and aligning QA tooling/docs with updated header and MAC scanning behavior. Normalized SPDX years to 2025-2026 ranges across touched files and hardened the header updater to preserve ranges.

### Modified Files
- .github/workflows/daily-build.yml
- NOTICE
- docs/design/db/database-backend-burndown.md
- docs/system/system-config.md
- docs/tests/pypnm-software-qa.md
- pyproject.toml
- src/pypnm/api/routes/advance/analysis/signal_analysis/detection/anolamaly/heatmap_anomaly_detection.py
- src/pypnm/api/routes/advance/analysis/signal_analysis/multi_rxmer_signal_analysis.py
- src/pypnm/api/routes/advance/common/abstract/service.py
- src/pypnm/api/routes/advance/multi_ds_chan_est/router.py
- src/pypnm/api/routes/basic/fec_summary_analysis_rpt.py
- src/pypnm/api/routes/basic/modulation_profile_analysis_rpt.py
- src/pypnm/api/routes/common/classes/analysis/analysis.py
- src/pypnm/api/routes/common/classes/common_endpoint_classes/common_req_resp.py
- src/pypnm/api/routes/common/classes/common_endpoint_classes/schema/base_snmp.py
- src/pypnm/api/routes/common/classes/operation/cable_modem_precheck.py
- src/pypnm/api/routes/common/extended/common_measure_service.py
- src/pypnm/api/routes/docs/dev/service.py
- src/pypnm/api/routes/docs/fdd/diplexer/service.py
- src/pypnm/api/routes/docs/if30/ds/scqam/chan/stats/service.py
- src/pypnm/api/routes/docs/if31/us/ofdma/chan/stats/service.py
- src/pypnm/api/routes/docs/pnm/ds/histogram/router.py
- src/pypnm/api/routes/docs/pnm/ds/ofdm/chan_est_coeff/router.py
- src/pypnm/api/routes/docs/pnm/ds/ofdm/const_display/router.py
- src/pypnm/api/routes/docs/pnm/ds/ofdm/fec_summary/router.py
- src/pypnm/api/routes/docs/pnm/ds/ofdm/modulation_profile/router.py
- src/pypnm/api/routes/docs/pnm/ds/ofdm/rxmer/router.py
- src/pypnm/api/routes/docs/pnm/files/router.py
- src/pypnm/api/routes/docs/pnm/files/service.py
- src/pypnm/docsis/cm_snmp_operation.py
- src/pypnm/examples/common/common_cli.py
- src/pypnm/lib/secret/crypto_manager.py
- src/pypnm/tools/qa_checker.py
- src/pypnm/tools/system_config/__init__.py
- tests/test_complex_array_ops.py
- tests/test_docs_pnm_chan_est_entry_casts.py
- tests/test_docs_pnm_rxmer_entry_casts.py
- tests/test_echo_detector.py
- tests/test_fixed_point_decoder.py
- tests/test_ftp_connector.py
- tests/test_group_delay_calculator.py
- tests/test_heatmap_anomaly_detector.py
- tests/test_host_endpoint.py
- tests/test_ifft_echo_detector.py
- tests/test_ping.py
- tests/test_pnm_channel_estimation_parse.py
- tests/test_pnm_constellation_parse.py
- tests/test_pnm_factory_fetcher.py
- tests/test_pnm_fec_summary_parse.py
- tests/test_pnm_file_type_mapper.py
- tests/test_pnm_header_each_file.py
- tests/test_pnm_histogram_parse.py
- tests/test_pnm_modulation_profile_parse.py
- tests/test_pnm_parser_and_parameters.py
- tests/test_pnm_rxmer_parse.py
- tests/test_pnm_spectrum_analysis_parse.py
- tests/test_scalar_value_converters.py
- tests/test_shannon.py
- tests/test_shannon_series.py
- tests/test_signal_statistics.py
- tests/test_utils_time_stamp.py
- tools/maintenance/add-required-python-headers.py
- tools/release/check_version.py
- tools/security/scan-mac-addresses.py
- src/pypnm/lib/db/db_schema_manager.py
- src/pypnm/lib/db/model/db_health_model.py
- src/pypnm/tools/loop_nesting_checker.py
- tests/test_db_schema_manager.py
- tests/test_loop_nesting_checker.py

### Commands Executed And Results
- `python3 -m compileall src` -> pass
- `ruff check .` -> pass
- `ruff format --check .` -> pass (343 files already formatted)
- `pytest` -> pass (530 passed, 4 skipped)
- `pypnm-software-qa-checker` -> pass

### Tests
- `pytest` -> pass (530 passed, 4 skipped)
- `ruff` -> pass (`ruff check .`)
- `ruff format --check .` -> pass

### Notes / Warnings
- Loop nesting checker emits warnings for depth 2 (expected per policy).

### Remaining TODOs / Follow-Ups
- None
# FILE: .github/workflows/daily-build.yml
name: Build

on:
  push:
    branches: [main]         # Run on every commit to main
  pull_request:
    branches: [main]
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

      - name: Run checks
        run: |
          pypnm-software-qa-checker

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
          pip install "psycopg[binary]"

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
          pypnm-software-qa-checker

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
# FILE: NOTICE
PyPNM - Proactive Network Maintenance Toolkit
Copyright (c) 2025-2026 Maurice Garcia

This product includes software developed by Maurice Garcia for the PyPNM project.

Attribution requirement:
If you distribute this software in source or binary form, you must retain this NOTICE
file and the LICENSE file, and include the following acknowledgment in a location
appropriate for third-party notices (for example, in documentation, README, or UI credits):

  "PyPNM - Proactive Network Maintenance Toolkit"
# FILE: docs/design/db/database-backend-burndown.md
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2025-2026 Maurice Garcia -->

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
# FILE: docs/system/system-config.md
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2025-2026 Maurice Garcia -->

# System Configuration Reference

Canonical Structure And Field Semantics For `system.json`.

* **Config file**: [`src/pypnm/settings/system.json`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/settings/system.json)
* **ConfigManager class**: [`src/pypnm/config/config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/config_manager.py)
* **PnmConfigManager class**: [`src/pypnm/config/pnm_config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/pnm_config_manager.py)

## Table Of Contents

* [1. FastApiRequestDefault](#1-fastapirequestdefault)
* [2. SNMP](#2-snmp)
* [3. PnmBulkDataTransfer](#3-pnmbulkdatatransfer)
* [4. PnmFileRetrieval](#4-pnmfileretrieval)
* [5. Database](#5-database)
* [6. Logging](#6-logging)
* [7. TestMode](#7-testmode)
* [Loading Configuration](#loading-configuration)

## 1. FastApiRequestDefault

Default Parameters For REST Requests To The FastAPI Service.

```json
"FastApiRequestDefault": {
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.0.100"
}
```

| Field       | Type   | Description                       |
| ----------- | ------ | --------------------------------- |
| mac_address | string | Default device MAC address.       |
| ip_address  | string | Default device IP (IPv4 or IPv6). |

## 2. SNMP

Global SNMP Settings, Including Version-Specific Options.

```json
"SNMP": {
  "timeout": 2,
  "version": {
    "2c": {
      "enable": true,
      "retries": 3,
      "read_community": "public",
      "write_community": "private"
    },
    "3": {
      "enable": false,
      "retries": 3,
      "username": "user",
      "securityLevel": "authPriv",
      "authProtocol": "SHA",
      "authPassword": "pass",
      "privProtocol": "AES",
      "privPassword": "privpass"
    }
  }
}
```

**Top-Level**

| Field   | Type   | Description                                  |
| ------- | ------ | -------------------------------------------- |
| timeout | number | Per-request timeout (seconds).               |
| version | object | Container for v2c/v3 configuration versions. |

**SNMP v2c**

| Field           | Type    | Description                     |
| --------------- | ------- | ------------------------------- |
| enable          | boolean | Enable v2c operations.          |
| retries         | number  | Retry count on timeout/failure. |
| read_community  | string  | Community for GET/WALK.         |
| write_community | string  | Community for SET.              |

**SNMP v3**

| Field         | Type    | Description                                  |
| ------------- | ------- | -------------------------------------------- |
| enable        | boolean | Enable v3 operations.                        |
| retries       | number  | Retry count on timeout/failure.              |
| username      | string  | Security name.                               |
| securityLevel | string  | `noAuthNoPriv`, `authNoPriv`, or `authPriv`. |
| authProtocol  | string  | For example `MD5`, `SHA`.                    |
| authPassword  | string  | Required when `auth*` is used.               |
| privProtocol  | string  | For example `DES`, `AES`.                    |
| privPassword  | string  | Required when `*Priv` is used.               |

## 3. PnmBulkDataTransfer

Transport Parameters For CM-Generated Files (for example, RxMER, FEC Summary) Sent To A Server.

```json
"PnmBulkDataTransfer": {
  "method": "tftp",
  "tftp": {
    "ip_v4": "192.168.0.10",
    "ip_v6": "::1",
    "remote_dir": ""
  },
  "http": {
    "base_url": "http://files.example.com/",
    "port": 80
  },
  "https": {
    "base_url": "https://files.example.com/",
    "port": 443
  }
}
```

| Field   | Type   | Description                                                |
| ------- | ------ | ---------------------------------------------------------- |
| method  | string | Preferred bulk method: `tftp`, `http`, or `https`.         |
| tftp.*  | object | TFTP targets for IPv4/IPv6 plus optional remote directory. |
| http.*  | object | HTTP base URL and port for file delivery.                  |
| https.* | object | HTTPS base URL and port for file delivery.                 |

## 4. PnmFileRetrieval

Local Storage Layout And Remote Retrieval Methods.

Related Guide: [File Transfer Methods](pnm-file-retrieval/index.md)

Runtime DB location policy: SQLite DB files live under `.data/db/` (demo uses `demo/.data/db/`), while Postgres is external and does not create a local DB file.

```json
"PnmFileRetrieval": {
  "pnm_dir": ".data/pnm",
  "csv_dir": ".data/csv",
  "json_dir": ".data/json",
  "xlsx_dir": ".data/xlsx",
  "png_dir": ".data/png",
  "archive_dir": ".data/archive",
  "msg_rsp_dir": ".data/msg_rsp",
  "transaction_db": ".data/db/transactions.json",
  "capture_group_db": ".data/db/capture_group.json",
  "session_group_db": ".data/db/session_group.json",
  "operation_db": ".data/db/operation_capture.json",
  "json_transaction_db": ".data/db/json_transactions.json",
  "retries": 5,
  "retrieval_method": {
    "method": "local",
    "methods": {
      "local": {
        "src_dir": "/srv/tftp"
      },
      "tftp": {
        "host": "localhost",
        "port": 69,
        "timeout": 5,
        "remote_dir": ""
      },
      "ftp": {
        "host": "localhost",
        "port": 21,
        "tls": false,
        "timeout": 5,
        "user": "user",
        "password_enc": "",
        "remote_dir": "/srv/tftp"
      },
      "sftp": {
        "host": "localhost",
        "port": 22,
        "user": "user",
        "password_enc": "",
        "private_key_path": "",
        "remote_dir": "/srv/tftp"
      },
      "http": {
        "base_url": "http://STUB/",
        "port": 80
      },
      "https": {
        "base_url": "https://STUB/",
        "port": 443
      }
    }
  }
}
```

`password_enc` is the preferred password field for file retrieval methods. Plaintext `password` is supported only as a legacy fallback and is deprecated.

**Directories And Databases**

| Field               | Type   | Description                                  |
| ------------------- | ------ | -------------------------------------------- |
| pnm_dir             | string | Local storage for raw PNM binaries.          |
| csv_dir             | string | Local storage for derived CSVs.              |
| json_dir            | string | Local storage for derived JSON.              |
| xlsx_dir            | string | Local storage for Excel reports.             |
| png_dir             | string | Local storage for generated PNGs.            |
| archive_dir         | string | Local storage for analysis ZIP archives.     |
| msg_rsp_dir         | string | Local storage for message/response metadata. |
| transaction_db      | string | JSON ledger of file transactions.            |
| capture_group_db    | string | JSON map of grouped transactions.            |
| session_group_db    | string | JSON map of session groups.                  |
| operation_db        | string | JSON map of operation to capture group.      |
| json_transaction_db | string | JSON map of JSON transaction metadata.       |

**Retrieval Settings**

| Field                                  | Type   | Description                                                           |
| -------------------------------------- | ------ | --------------------------------------------------------------------- |
| retrieval_method.method                 | string | Active retrieval method: `local`, `tftp`, `ftp`, `sftp`, `http`, `https`. |
| retrieval_method.methods.local.src_dir  | string | Source directory to watch/copy from when using `local`.               |
| retrieval_method.methods.tftp.*         | object | TFTP host/port/timeout and remote directory.                          |
| retrieval_method.methods.ftp.*          | object | FTP connection, credentials, and remote directory.                    |
| retrieval_method.methods.sftp.*         | object | SFTP connection and remote directory.                                 |
| retrieval_method.methods.http.*         | object | HTTP base URL and port.                                               |
| retrieval_method.methods.https.*        | object | HTTPS base URL and port.                                              |
| retries                                | number | Max attempts per retrieval operation.                                 |

> The legacy key name `retrival_method` is accepted for backward compatibility.

## 5. Database

Database Backend Selection And Connection Settings.

```json
"Database": {
  "backend": "sqlite",
  "sqlite": {
    "path": ".data/db/pypnm.sqlite3"
  },
  "postgres": {
    "dsn": ""
  }
}
```

Backend selection is set at install time (SQLite default; Postgres recommended for multi-worker deployments). Set `PYPNM_DB_BACKEND` to override the backend selection (`sqlite` or `postgres`). SQLite stores its DB file under `.data/db/` (demo uses `demo/.data/db/`), while Postgres is external and does not create a local DB file. For Postgres, supply the DSN via `PYPNM_DB_POSTGRES_DSN` to avoid storing plaintext credentials in tracked JSON files. Blank strings for required values are invalid when the backend is active.

On startup, PyPNM applies the schema for the selected backend and seeds the canonical `UNKNOWN` sysDescr row and the default artifact store entry.

DB backend migration is in progress; legacy ledger keys remain until Phase M6.

## 6. Logging

Application Logging Options.

```json
"logging": {
  "log_level": "INFO",
  "log_dir": "logs",
  "log_filename": "pypnm.log"
}
```

| Field        | Type   | Description                                 |
| ------------ | ------ | ------------------------------------------- |
| log_level    | string | `DEBUG`, `INFO`, `WARN`, or `ERROR`.        |
| log_dir      | string | Directory for log files.                    |
| log_filename | string | Log filename (created under `log_dir`).     |

## 7. TestMode

Global And Class-Specific Test-Mode Controls.

```json
"TestMode": {
  "global": {
    "mode": {
      "enable": true
    }
  },
  "class_name": {
    "DsScQamChannelSpectrumAnalyzer": {
      "mode": {
        "enable": true
      }
    }
  }
}
```

| Field                          | Type    | Description                                            |
| ------------------------------ | ------- | ------------------------------------------------------ |
| global.mode.enable             | boolean | Enable or disable global test mode.                    |
| class_name.<Class>.mode.enable | boolean | Per-class override for test mode, keyed by class name. |

## Loading Configuration

Typical Access Pattern Using The Manager Abstractions.

```python
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_config_manager import PnmConfigManager

cfg = ConfigManager()

mac = cfg.get("FastApiRequestDefault", "mac_address")
ip  = cfg.get("FastApiRequestDefault", "ip_address")

pnm_cfg = PnmConfigManager()
tftp_v4 = pnm_cfg.get("PnmBulkDataTransfer", "tftp")["ip_v4"]
```
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
4. `python ./tools/maintenance/add-required-python-headers.py`
5. `ruff check src`
6. `python -m pypnm.tools.loop_nesting_checker src`
7. `pytest`

Each step is run in sequence; the checker continues through all steps and returns the first non-zero exit
code encountered. It prints the failing command(s) as they run.

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
4. `python ./tools/maintenance/add-required-python-headers.py`
5. `ruff check src`
6. `pyright`
7. `python -m pypnm.tools.loop_nesting_checker src`
8. `pytest`

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
- Loop nesting guard (`python -m pypnm.tools.loop_nesting_checker src`)
- Tests (`pytest`)

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
- SPDX/license header scan (`python ./tools/maintenance/add-required-python-headers.py`)
- Lint (`ruff check src`)
- Static type checking (`pyright`)
- Loop nesting guard (`python -m pypnm.tools.loop_nesting_checker src`)
- Tests (`pytest`)

### 4.3 Running individual tools directly

You can still run each tool directly when you need fine-grained control:

```bash
./tools/security/scan-secrets.sh
python ./tools/security/scan-enc-secrets.py
./tools/security/scan-mac-addresses.py --fail-on-found
python ./tools/maintenance/add-required-python-headers.py
ruff check src
python -m pypnm.tools.loop_nesting_checker src
pytest -m 'not slow'
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

CI validates both SQLite and Postgres. To run Postgres validation locally, start a Postgres instance (Docker is fine) and set:

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

### 6.2 Ruff, Pyright, or pytest not installed

If the script reports that it cannot find `ruff`, `pyright`, or `pytest`, verify that:

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
# FILE: pyproject.toml
# SPDX-License-Identifier: Apache-2.0

[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name            = "pypnm-docsis"
version         = "1.0.20.0"
description     = "DOCSIS 3.x/4.0 Proactive Network Maintenance Toolkit"
readme          = "README.md"
requires-python = ">=3.10"
license         = "Apache-2.0"

authors = [
  { name = "Maurice Garcia", email = "mgarcia01752@outlook.com" }
]

classifiers = [
  "Programming Language :: Python :: 3",
  "Programming Language :: Python :: 3 :: Only",
  "Programming Language :: Python :: 3.10",
  "Programming Language :: Python :: 3.11",
  "Programming Language :: Python :: 3.12",
  "Programming Language :: Python :: 3.13",
  "Operating System :: OS Independent",
  "Framework :: FastAPI",
  "Topic :: System :: Networking",
  "Typing :: Typed",
]

license-files = ["LICENSE", "NOTICE"]

dependencies = [
  "fastapi==0.115.12",
  "uvicorn[standard]==0.34.2",
  "python-multipart>=0.0.20",
  "numpy==2.2.6",
  "scipy==1.15.1",
  "pydantic>=2.12.4,<2.13",
  "pysmi==1.6.1",
  "pysnmp==7.1.17",
  "python-dotenv>=1.0.0",
  "psycopg[binary]==3.2.3",
  "requests==2.32.3",
  "pandas==2.2.3",
  "paramiko==3.5.1",
  "tftpy==0.8.5",
  "matplotlib==3.10.8",
  "typing-extensions>=4.10.0",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.0.0",
  "pytest-cov>=5.0.0",
  "pytest-asyncio>=0.23.5",
  "black>=24.0.0",
  "pydantic-settings>=2.6.0",
  "ruff>=0.14.7",
  "pycycle>=0.0.8",
  "pyright>=1.1.407",
  "pyyaml>=6.0.2",
]
docs = [
  "mkdocs>=1.6",
  "mkdocs-material>=9.5",
  "pymdown-extensions>=10.8",
]
reports = []

[project.urls]
Homepage    = "https://www.pypnm.io"
Repository  = "https://github.com/PyPNMApps/PyPNM"
Bug-Tracker = "https://github.com/PyPNMApps/PyPNM/issues"
Documentation = "https://www.pypnm.io"

[project.scripts]
pypnm      = "pypnm.cli:main"
docs-serve = "mkdocs.__main__:serve"
docs-build = "mkdocs.__main__:build"
pypnm-software-qa-checker  = "pypnm.tools.qa_checker:main"

[tool.setuptools]
package-dir = { "" = "src" }
include-package-data = true

[tool.setuptools.packages.find]
where   = ["src"]
include = ["pypnm*"]

[tool.setuptools.package-data]
"pypnm" = [
  "settings/*.json",
  "py.typed",
]

[tool.pytest.ini_options]
minversion   = "8.0"
pythonpath   = ["src"]
testpaths    = ["tests"]
addopts      = "-ra -q --strict-markers --tb=short -m 'not cm_it'"
asyncio_mode = "auto"
log_cli = true
log_cli_level = "INFO"
log_cli_format = "%(levelname)s %(name)s:%(lineno)d | %(message)s"
log_cli_date_format = "%H:%M:%S"
markers = [
  "asyncio: mark test as asyncio-based (requires pytest-asyncio)",
  "cm_it: cable modem integration tests (enable with -m cm_it)",
  "slow: slow tests",
  "net: network-required tests",
  "pnm: PNM file parsing tests",
]
filterwarnings = [
  "ignore:getReadersFromUrls is deprecated:DeprecationWarning:pysnmp",
  "ignore:smiV1Relaxed is deprecated:DeprecationWarning:pysnmp",
  "ignore:.*getReadersFromUrls.*:DeprecationWarning:pysmi.reader.url",
  "ignore:.*addSources.*:DeprecationWarning:pysnmp.smi.compiler",
  "ignore:.*addSearchers.*:DeprecationWarning:pysnmp.smi.compiler",
  "ignore:.*addBorrowers.*:DeprecationWarning:pysnmp.smi.compiler",
]

[tool.coverage.run]
branch = true
source = ["pypnm"]

[tool.coverage.report]
show_missing = true
skip_covered = true

[tool.black]
line-length = 100
target-version = ["py310"]

[tool.ruff]
src            = ["src"]
target-version = "py310"
exclude        = [
  "tools",
  "src/pypnm/lib/matplot/manager.py",
  "src/pypnm/lib/csv/manager.py",
  "src/pypnm/api/routes/common/extended/common_messaging_service.py",
  "src/pypnm/api/routes/common/extended/common_measure_service.py",
  "src/pypnm/examples/",
]

[tool.ruff.lint]
# Common, high-signal rulesets:
# F   = Pyflakes (real errors)
# E,W = pycodestyle
# I   = import sorting
# B   = flake8-bugbear
# UP  = pyupgrade
#
# Ignore:
# E501 - https://docs.astral.sh/ruff/rules/line-too-long/
# B006 - https://docs.astral.sh/ruff/rules/mutable-argument-default/
#
# ---------------------------------------------------------------------------
# Ruff Roadmap (do NOT enable by default; turn on gradually when ready)
# ---------------------------------------------------------------------------
# Phase 1 (current):
#   - Focus on correctness + core style only.
#   - Enabled rule families:
#       F, E, W, I, B, UP
#
# Phase 2 (optional): Naming rules
#   - Add N (pep8-naming) when public API naming is stable.
#   - This enforces conventional names for functions, classes, etc.
#   - Example change (for later, DO NOT UNCOMMENT YET):
#       select = ["F", "E", "W", "I", "B", "UP", "N"]
#
# Phase 3 (optional): Type-annotation rules
#   - Add ANN to enforce more consistent type hints once F/E/W noise is low.
#   - You can selectively ignore strict ANN codes if needed (e.g., ANN101/ANN102).
#   - Example (for later):
#       select = ["F", "E", "W", "I", "B", "UP", "ANN"]
#       ignore = ["E501", "B006", "ANN101", "ANN102"]
#
# Phase 4 (optional): Simplification & performance hints
#   - Enable SIM (flake8-simplify) to flag redundant or over-complicated logic.
#   - Enable PERF to catch obvious performance footguns in hot paths.
#   - Recommended approach:
#       - First, run ad-hoc from CLI without adding to select:
#           ruff check src --select SIM,PERF
#       - Fix only the diagnostics you agree with.
#   - If you like the results, you can later extend select:
#       select = ["F", "E", "W", "I", "B", "UP", "N", "ANN", "SIM", "PERF"]
#
# Packs to generally avoid for PyPNM (unless explicitly desired later):
#   - D (pydocstyle): conflicts with custom docstring rules.
#   - C90 / PL (mccabe / pylint families): very noisy, low signal for this project.

select = ["F", "E", "W", "I", "B", "UP", "ANN", "SIM", "PERF"]
ignore = [
  "E501",
  "B006"
]

[tool.pyright]
pythonVersion = "3.10"
pythonPlatform = "Linux"

include = ["src"]
exclude = [
  "tools",
  "src/pypnm/examples/",
  "**/__pycache__",
]

# VSCode + .env venv
venvPath = "."
venv = ".env"

reportMissingImports = "warning"
reportMissingTypeStubs = "warning"
typeCheckingMode = "basic"
# FILE: src/pypnm/api/routes/advance/analysis/signal_analysis/detection/anolamaly/heatmap_anomaly_detection.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

from collections.abc import Generator

import numpy as np


class HeatmapAnomalyDetector:
    """
    Detect anomalies in a 2D array via global z-score thresholding
    and extract bounding boxes around each connected component.

    Attributes:
        data (np.ndarray): 2D input array of measurements.
        threshold (float): z-score cutoff; defaults to 3.0.
        zmap (np.ndarray): computed z-score map.
        mask (np.ndarray): boolean mask where |z| > threshold.
        boxes (List[Tuple[int, int, int, int]]): list of
            (row_min, col_min, row_max, col_max) bounding boxes.
    """

    def __init__(self, data: np.ndarray, threshold: float = 3.0) -> None:
        self.data = np.asarray(data, dtype=float)
        if self.data.ndim != 2:
            raise ValueError("Input must be a 2-D array.")
        self.threshold: float = threshold
        self.zmap: np.ndarray = None  # will be computed
        self.mask: np.ndarray = None
        self.boxes: list[tuple[int, int, int, int]] = []

    def compute_zmap(self) -> np.ndarray:
        """
        Compute the z-score map of the input data.

        Returns:
            np.ndarray: z-score normalized array.
        """
        mu = self.data.mean()
        sigma = self.data.std()
        # Avoid division by zero
        if sigma == 0:
            self.zmap = np.zeros_like(self.data)
        else:
            self.zmap = (self.data - mu) / sigma
        return self.zmap

    def detect(self) -> np.ndarray:
        """
        Apply the threshold to form a boolean anomaly mask.

        Returns:
            np.ndarray: boolean mask where anomalies are True.
        """
        if self.zmap is None:
            self.compute_zmap()
        self.mask = np.abs(self.zmap) > self.threshold
        return self.mask

    def find_boxes(self) -> list[tuple[int, int, int, int]]:
        """
        Identify connected components in the anomaly mask (4-connectivity)
        and compute their bounding boxes.

        Returns:
            List[Tuple[int, int, int, int]]: list of bounding boxes
            as (row_min, col_min, row_max, col_max).
        """
        if self.mask is None:
            self.detect()

        visited = np.zeros_like(self.mask, dtype=bool)
        rows, cols = self.data.shape
        boxes: list[tuple[int, int, int, int]] = []

        boxes = [
            self._walk_component(i, j, visited)
            for i in range(rows)
            for j in range(cols)
            if self.mask[i, j] and not visited[i, j]
        ]

        self.boxes = boxes
        return boxes

    def to_json(self) -> dict[str, object]:
        """
        Convert the detected boxes into a JSON-friendly dictionary.

        Returns:
            Dict[str, Any]: dictionary with threshold and boxes list.
        """
        return {
            "threshold": self.threshold,
            "boxes": [
                {"row_min": r0, "col_min": c0, "row_max": r1, "col_max": c1}
                for r0, c0, r1, c1 in self.boxes
            ],
        }

    def _neighbors(
        self, row: int, col: int, rows: int, cols: int
    ) -> Generator[tuple[int, int], None, None]:
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = row + dr, col + dc
            if 0 <= nr < rows and 0 <= nc < cols:
                yield nr, nc

    def _walk_component(
        self, start_row: int, start_col: int, visited: np.ndarray
    ) -> tuple[int, int, int, int]:
        rmin = rmax = start_row
        cmin = cmax = start_col
        stack = [(start_row, start_col)]
        visited[start_row, start_col] = True
        rows, cols = self.data.shape

        while stack:
            row, col = stack.pop()
            rmin = min(rmin, row)
            rmax = max(rmax, row)
            cmin = min(cmin, col)
            cmax = max(cmax, col)
            for nr, nc in self._neighbors(row, col, rows, cols):
                if self.mask[nr, nc] and not visited[nr, nc]:
                    visited[nr, nc] = True
                    stack.append((nr, nc))

        return rmin, cmin, rmax, cmax
# FILE: src/pypnm/api/routes/advance/analysis/signal_analysis/multi_rxmer_signal_analysis.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, cast

import numpy as np
from pydantic import BaseModel, Field

from pypnm.api.routes.advance.analysis.report.multi_analysis_rpt import MultiAnalysisRpt
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.transactionsCollection import (
    TransactionCollectionModel,
)
from pypnm.api.routes.common.classes.analysis.model.schema import (
    DsModulationProfileAnalysisModel,
    ProfileAnalysisEntryModel,
)
from pypnm.api.routes.common.classes.collection.ds_modulation_profile_aggregator import (
    DsModulationProfileAggregator,
)
from pypnm.api.routes.common.classes.collection.ds_rxmer_aggregator import (
    DsRxMerAggregator,
)
from pypnm.api.routes.common.classes.collection.fec_summary_aggregator import (
    FecSummaryAggregator,
    FecSummaryTotalsModel,
)
from pypnm.lib.constants import INVALID_CAPTURE_TIME
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.signal_processing.shan.series import ShannonSeries
from pypnm.lib.types import (
    ArrayLike,
    CaptureTime,
    ChannelId,
    FloatSeries,
    FrequencySeriesHz,
    MacAddressStr,
    MagnitudeSeries,
    StringEnum,
    TimeStamp,
    TimestampSec,
)
from pypnm.pnm.lib.min_avg_max import MinAvgMax
from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.CmDsOfdmModulationProfile import (
    CmDsOfdmModulationProfile,
    ProfileId,
)
from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer, CmDsOfdmRxMerModel


class MultiRxMerAnalysisType(StringEnum):
    MIN_AVG_MAX = "min-avg-max"
    RXMER_HEAT_MAP = "rxmer-heat-map"
    OFDM_PROFILE_PERFORMANCE_1 = "ofdm-profile-performance-1"


class MultiRxMerAnalysisBaseModel(BaseModel):
    channel_id: ChannelId = Field(
        ..., description="OFDM channel identifier for this result set."
    )
    frequency: FrequencySeriesHz = Field(
        ..., description="Per-subcarrier frequency bins (Hz)."
    )


class MinAvgMaxAnalysisModel(MultiRxMerAnalysisBaseModel):
    min: FloatSeries = Field(..., description="Per-subcarrier minimum values.")
    avg: FloatSeries = Field(..., description="Per-subcarrier average values.")
    max: FloatSeries = Field(..., description="Per-subcarrier maximum values.")


class ProfileEntryModel(BaseModel):
    capture_time: CaptureTime = Field(..., description="Epoch capture timestamp.")
    profile_id: ProfileId = Field(
        ..., description="Modulation profile index for the capture."
    )
    profile_min_mer: FloatSeries = Field(
        ..., description="Per-subcarrier Shannon limits (bits/s/Hz) for the profile."
    )
    capacity_delta: FloatSeries = Field(
        ...,
        description="Average measured MER Subcarrier vs. Min Subcarrier Shannon MER",
    )
    fec_summary: FecSummaryTotalsModel = Field(..., description="")


class ChannelOfdmProfilePerf01Model(MultiRxMerAnalysisBaseModel):
    avg_mer: FloatSeries = Field(..., description="Per-subcarrier average MER (dB).")
    mer_shannon_limits: FloatSeries = Field(
        ..., description="Per-subcarrier Shannon limits derived from avg MER."
    )
    profiles: list[ProfileEntryModel] = Field(
        ..., description="Per-capture per-profile deltas/limits."
    )


class ChannelHeatMapModel(MultiRxMerAnalysisBaseModel):
    timestamps: list[TimestampSec] = Field(
        ..., description="Capture timestamps (epoch) for rows of the heatmap."
    )
    values: list[MagnitudeSeries] = Field(
        ..., description="Matrix: rows=captures, cols=subcarriers; MER values."
    )


MultiRxMerTemporalObjType = (
    CmDsOfdmRxMer | CmDsOfdmFecSummary | CmDsOfdmModulationProfile
)
TemporalMapping = tuple[CaptureTime, MultiRxMerTemporalObjType]

MinAvgMaxMap = dict[ChannelId, MinAvgMaxAnalysisModel]
OfdmProfilePerf01Map = dict[ChannelId, ChannelOfdmProfilePerf01Model]
HeatMapMap = dict[ChannelId, ChannelHeatMapModel]
MultiRxMerAnalysisMap = MinAvgMaxMap | OfdmProfilePerf01Map | HeatMapMap


class MultiRxMerAnalysisResult(BaseModel):
    mac_address: MacAddressStr = Field(
        ..., description="Cable modem MAC address associated with this analysis."
    )
    analysis_type: MultiRxMerAnalysisType = Field(
        ..., description="Type of multi-RxMER analysis performed."
    )
    data: MultiRxMerAnalysisMap = Field(
        ..., description="Analysis results mapping (per-channel model)."
    )
    error: str | None = Field(
        default="", description="Optional error message if analysis failed."
    )


# ---------------------------
# Analyzer (models built during processing; single CM)
# ---------------------------


class MultiRxMerSignalAnalysis(MultiAnalysisRpt):
    def __init__(
        self,
        capt_data_agg: CaptureDataAggregator,
        analysis_type: MultiRxMerAnalysisType,
    ) -> None:
        super().__init__(capt_data_agg)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.analysis_type = analysis_type
        self._model: MultiRxMerAnalysisResult | None = None
        self._mac: MacAddressStr | None = None

        self._sorted_temporal_mapping: list[TemporalMapping] = []
        self._analysis_map: MultiRxMerAnalysisMap = {}
        self._is_process: bool = False

    # -----------------------
    # Public API
    # -----------------------

    def to_model(self) -> MultiRxMerAnalysisResult:
        if not self._is_process:
            self._process()

        if self._model is not None:
            return self._model

        mac = self.getMacAddresses()

        if len(mac) > 1:
            self.logger.error(
                f"Found #({len(mac)}), Not Expection more than 1 MacAddress -> {mac}"
            )

        mac = mac[0].to_mac_format()

        try:
            data = self._dispatch_build()
            self._model = MultiRxMerAnalysisResult(
                mac_address=mac,
                analysis_type=self.analysis_type,
                data=data,
            )

        except Exception as e:
            self.logger.error(f"Unable to create MultiRxMerAnalysisResult, reason: {e}")
            self._model = MultiRxMerAnalysisResult(
                mac_address=mac,
                analysis_type=self.analysis_type,
                data={},
                error=str(e),
            )

        return self._model

    def to_dict(self) -> dict[str, Any]:
        return self.to_model().model_dump()

    # -----------------------
    # Internals
    # -----------------------

    def _get_temporal_pnm_data(self) -> list[TemporalMapping]:
        self.logger.debug(
            f"Temporal PNM Data - Record Count: [{len(self._sorted_temporal_mapping)}]"
        )
        return self._sorted_temporal_mapping

    def _get_capture_times(
        self, channel_id: ChannelId, obj_type: type
    ) -> list[TimestampSec]:
        capture_times: list[TimestampSec] = []

        for capture_time, obj in self._get_temporal_pnm_data():
            chan_id: ChannelId = cast(ChannelId, obj.to_model().channel_id)

            if channel_id == chan_id and isinstance(obj, obj_type):
                capture_times.append(cast(TimestampSec, capture_time))

        return capture_times

    def _dispatch_build(self) -> MultiRxMerAnalysisMap:
        if self.analysis_type == MultiRxMerAnalysisType.MIN_AVG_MAX:
            return self._analyze_min_avg_max_models()

        if self.analysis_type == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
            return self._analyze_ofdm_profile_perf_1_models()

        if self.analysis_type == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
            return self._analyze_rxmer_heat_map_models()

        raise ValueError(f"Unsupported analysis type: {self.analysis_type}")

    # --------------------------------------------------------------------------
    #               Analyses (single MAC; return channel->model)
    # --------------------------------------------------------------------------
    def _analyze_min_avg_max_models(self) -> MinAvgMaxMap:
        """
        Aggregate per-subcarrier RxMER across time (by channel) using CmDsOfdmRxMerModel.

        For each CmDsOfdmRxMer object in `self._sorted_temporal_mapping`, this:
        - Converts to CmDsOfdmRxMerModel (`obj.to_model()`),
        - Collects `values` (FloatSeries) per `channel_id`,
        - Applies MinAvgMax across captures to produce per-index min/avg/max arrays.

        Returns
        -------
        MinAvgMaxMap
            Mapping of ChannelId -> MinAvgMaxModel (min/avg/max lists per subcarrier index).
        """
        self.logger.debug("Building MinAvgMax Signal Analysis")

        chan_series: dict[ChannelId, list[MagnitudeSeries]] = {}
        chan_freq: dict[ChannelId, FrequencySeriesHz] = {}
        mamap: MinAvgMaxMap = {}

        for _, obj in self._get_temporal_pnm_data():
            if not isinstance(obj, CmDsOfdmRxMer):
                self.logger.debug("Not a CmDsOfdmRxMer Object, skipping")
                continue

            model: CmDsOfdmRxMerModel = obj.to_model()

            if model.channel_id not in chan_series:
                chan_series[model.channel_id] = []

            chan_series[model.channel_id].append(model.values)
            chan_freq[model.channel_id] = self._build_frequencies(model)

        for cid, series in chan_series.items():
            self.logger.debug(f"Building MinAvgMaxAnalysisModel for Channel: {cid}")
            frequencies = self._build_frequencies(chan_freq.get(cid))

            try:
                mam = MinAvgMax(series, precision=2)
                mam_model = mam.to_model()

                mamap[cid] = MinAvgMaxAnalysisModel(
                    channel_id=cid,
                    frequency=frequencies,
                    min=mam_model.min,
                    avg=mam_model.avg,
                    max=mam_model.max,
                )

            except ValueError as e:
                self.logger.warning(
                    "MinAvgMax failed for channel %s: %s", str(cid), str(e)
                )
                continue

        return mamap

    def _analyze_rxmer_heat_map_models(self) -> HeatMapMap:
        """
        Build RxMER HeatMap Signal Analysis by aggregating per-subcarrier MER values
        across all captures for each channel.

        Returns
        -------
        HeatMapMap
            Mapping of ChannelId -> ChannelHeatMapModel containing timestamps and MER matrix.
        """
        self.logger.info("Building RxMER HeatMap Signal Analysis")

        # Store per-channel temporal data
        channel_data: dict[ChannelId, list[MagnitudeSeries]] = {}
        channel_freqs: dict[ChannelId, FrequencySeriesHz] = {}
        heatmap_map: HeatMapMap = {}

        # Aggregate values for each capture per channel
        for _, obj in self._get_temporal_pnm_data():
            if not isinstance(obj, CmDsOfdmRxMer):
                self.logger.debug(
                    "Skipping non-CmDsOfdmRxMer object: %s", type(obj).__name__
                )
                continue

            model: CmDsOfdmRxMerModel = obj.to_model()
            ch_id = cast(ChannelId, model.channel_id)

            if ch_id not in channel_data:
                channel_data[ch_id] = []

            channel_data[ch_id].append(model.values)
            channel_freqs[ch_id] = self._build_frequencies(model)

        # Build final models
        for ch_id, magnitudes in channel_data.items():
            self.logger.debug("Building ChannelHeatMapModel for Channel: %s", ch_id)

            timestamps: list[TimestampSec] = self._get_capture_times(
                ch_id, CmDsOfdmRxMer
            )
            frequencies: FrequencySeriesHz = channel_freqs.get(ch_id, [])

            heatmap_map[ch_id] = ChannelHeatMapModel(
                channel_id=ch_id,
                frequency=frequencies,
                timestamps=timestamps,
                values=magnitudes,
            )

        return heatmap_map

    def _analyze_ofdm_profile_perf_1_models(self) -> OfdmProfilePerf01Map:
        """
        Perform OFDM Profile Performance Analysis (Type 1).

        Integrates data from RxMER, Modulation Profile, and FEC Summary aggregators.

        Steps
        -----
        1. Aggregate temporal PNM data by channel.
        2. For each channel:
            - Compute average RxMER and Shannon limits.
            - Retrieve modulation profile analysis results via `mod_pro_agg.basic_analysis()`.
            - Align FEC summary totals.
        3. Build and return structured per-channel performance results.

        Returns
        -------
        OfdmProfilePerf01Map
            Mapping of ChannelId → ChannelOfdmProfilePerf01Model.
        """
        self.logger.info("Running OFDM Profile Performance Analysis (Type 1)")

        rxmer_agg = DsRxMerAggregator()
        mod_pro_agg = DsModulationProfileAggregator()
        fec_sum_agg = FecSummaryAggregator()
        models: OfdmProfilePerf01Map = {}

        # Step 1: aggregate PNM objects
        for _, obj in self._get_temporal_pnm_data():
            if isinstance(obj, CmDsOfdmRxMer):
                rxmer_agg.add(obj)
            elif isinstance(obj, CmDsOfdmModulationProfile):
                mod_pro_agg.add(obj)
            elif isinstance(obj, CmDsOfdmFecSummary):
                fec_sum_agg.add(obj)

        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(f"RxMER Aggregator Count: {rxmer_agg.length()}")
            self.logger.info(
                f"Modulation Profile Aggregator Count: {mod_pro_agg.length()}"
            )
            self.logger.info(f"FEC Summary Aggregator Count: {fec_sum_agg.length()}")

        # Step 2: analyze per channel
        for ch_id in rxmer_agg.get_channel_ids():
            mam = rxmer_agg.get_min_avg_max(ch_id)
            shannon_model = ShannonSeries(mam.avg).to_model()
            frequencies = rxmer_agg.get_frequencies(ch_id)

            # Perform basic modulation profile analysis for this channel
            mod_analysis_map = mod_pro_agg.basic_analysis(ch_id)
            mod_analysis_list = mod_analysis_map.get(ch_id, [])
            if not mod_analysis_list:
                self.logger.warning(
                    "No modulation analysis results for channel %s", ch_id
                )
                continue

            capture_times = sorted(rxmer_agg.get_capture_times(ch_id))
            if not capture_times:
                self.logger.warning("No RxMER captures for channel %s", ch_id)
                continue

            start, stop = TimeStamp(capture_times[0]), TimeStamp(capture_times[-1])
            fec_summary = fec_sum_agg.get_summary_totals(ch_id, start, stop)

            profile_entries = self._build_profile_entries(
                mod_analysis_list=mod_analysis_list,
                mam=mam,
                start=start,
                fec_summary=fec_summary,
            )

            models[ch_id] = ChannelOfdmProfilePerf01Model(
                channel_id=ch_id,
                frequency=frequencies,
                avg_mer=mam.avg,
                mer_shannon_limits=cast(FloatSeries, shannon_model.snr_db_min),
                profiles=profile_entries,
            )

        return models

    def _build_profile_entries(
        self,
        mod_analysis_list: list[DsModulationProfileAnalysisModel],
        mam: MinAvgMax,
        start: TimeStamp,
        fec_summary: FecSummaryTotalsModel,
    ) -> list[ProfileEntryModel]:
        profile_entries: list[ProfileEntryModel] = []
        for mod_analysis in mod_analysis_list:
            capture_time = CaptureTime(getattr(mod_analysis, "capture_time", start))
            profile_entries.extend(
                self._build_profile_entries_for_analysis(
                    capture_time=capture_time,
                    profiles=mod_analysis.profiles,
                    mam=mam,
                    fec_summary=fec_summary,
                )
            )
        return profile_entries

    def _build_profile_entries_for_analysis(
        self,
        capture_time: CaptureTime,
        profiles: list[ProfileAnalysisEntryModel],
        mam: MinAvgMax,
        fec_summary: FecSummaryTotalsModel,
    ) -> list[ProfileEntryModel]:
        entries: list[ProfileEntryModel] = []
        for profile_entry in profiles:
            pid = profile_entry.profile_id
            shannon_min = profile_entry.carrier_values.shannon_min_mer
            capacity_delta = [
                float(a - b) for a, b in zip(mam.avg, shannon_min, strict=False)
            ]
            fec_entry = next(
                (p for p in fec_summary.summary if p.profile_id == pid), None
            )
            fec_payload = (
                fec_summary
                if fec_entry is None
                else FecSummaryTotalsModel(
                    start=fec_summary.start,
                    end=fec_summary.end,
                    channel_id=fec_summary.channel_id,
                    summary=[fec_entry],
                )
            )

            entries.append(
                ProfileEntryModel(
                    capture_time=capture_time,
                    profile_id=pid,
                    profile_min_mer=shannon_min,
                    capacity_delta=capacity_delta,
                    fec_summary=fec_payload,
                )
            )
        return entries

    """Abstract Required methods"""

    def _process(self) -> None:
        """
        Process transactions into typed PNM objects and build a time-indexed view.

        Steps
        -----
        1) Fetch all TransactionCollectionModel items from the current TransactionCollection.
        2) Attempt to decode each payload (bytes) as one of:
            - CmDsOfdmRxMer
            - CmDsOfdmFecSummary
            - CmDsOfdmModulationProfile
            In that order; on failure, fall through to the next type.
        3) Store each successfully decoded object in a temporal mapping keyed
        by its capture_time (or INVALID_CAPTURE_TIME if missing).
        4) Produce a list `self._sorted_temporal_mapping` of (capture_time, obj) tuples,
        sorted by ascending capture_time, for downstream iteration.
        """
        self._is_process = True
        self.logger.info("Processing Multi-RxMER Analysis Report")

        # Convert Transactions to PNM RxMER Data
        tc = self.getTransactionCollection()
        tcms: list[TransactionCollectionModel] = tc.getTransactionCollectionModel()
        temporal_mapping: dict[
            CaptureTime, CmDsOfdmRxMer | CmDsOfdmFecSummary | CmDsOfdmModulationProfile
        ] = {}

        self.logger.info(f"TransactionCollectionModel Count: {len(tcms)}")

        # Groom data for general use due to various Analysis that is performed
        for count, tcm in enumerate(tcms):
            try:
                dorm = CmDsOfdmRxMer(tcm.data)
                capture_time: CaptureTime = (
                    dorm.getPnmHeaderModel().pnm_header.capture_time
                    or INVALID_CAPTURE_TIME
                )
                temporal_mapping[capture_time] = dorm
                model = dorm.to_model()
                self.register_models_for_json_archive_files(
                    model, [str(model.channel_id), "CmDsOfdmRxMer"]
                )
                continue

            except Exception as e:
                self.logger.debug(
                    f"PNM file {count} is not compatible with CmDsOfdmRxMer, skipping: {e}"
                )

            try:
                dofs = CmDsOfdmFecSummary(tcm.data)
                capture_time: CaptureTime = (
                    dofs.getPnmHeaderModel().pnm_header.capture_time
                    or INVALID_CAPTURE_TIME
                )
                temporal_mapping[capture_time] = dofs
                model = dofs.to_model()
                self.register_models_for_json_archive_files(
                    model, [str(model.channel_id), "CmDsOfdmFecSummary"]
                )
                continue

            except Exception as e:
                self.logger.debug(
                    f"PNM file {count} is not compatible with CmDsOfdmFecSummary, skipping: {e}"
                )

            try:
                domp = CmDsOfdmModulationProfile(tcm.data)
                capture_time: CaptureTime = (
                    domp.getPnmHeaderModel().pnm_header.capture_time
                    or INVALID_CAPTURE_TIME
                )
                temporal_mapping[capture_time] = domp
                model = domp.to_model()
                self.register_models_for_json_archive_files(
                    model, [str(model.channel_id), "CmDsOfdmModulationProfile"]
                )
                continue

            except Exception as e:
                self.logger.debug(
                    f"PNM file {count} is not compatible with CmDsOfdmModulationProfile, skipping: {e}"
                )

        # Create a sorted list of tuples based on capture_time (ascending)
        self._sorted_temporal_mapping = sorted(
            temporal_mapping.items(), key=lambda x: x[0]
        )

        self.logger.debug(
            f"Temporal mapping size={len(temporal_mapping)}, sorted entries={len(self._sorted_temporal_mapping)}"
        )

        self._dispatch_build()

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Build CSV outputs for supported analysis types.
        Currently implemented for MIN_AVG_MAX only.
        """
        self.logger.debug("Processing Multi-RxMER Analysis CSV Report")
        out: list[CSVManager] = []
        model = self.to_model()

        if self.analysis_type == MultiRxMerAnalysisType.MIN_AVG_MAX:
            data = cast(MinAvgMaxMap, model.data)

            for ch_id, ch_model in data.items():
                csv_mgr: CSVManager = self.csv_manager_factory()

                # Convert frequency (Hz) → kHz for readability and to match labeling.
                freq_hz = ch_model.frequency
                freq_khz = [f / 1_000.0 for f in freq_hz]

                csv_mgr.set_header(["channel_id", "frequency_khz", "min", "avg", "max"])

                for idx, f_khz in enumerate(freq_khz):
                    # Defensive indexing (lists should match by construction)
                    mn = ch_model.min[idx] if idx < len(ch_model.min) else None
                    av = ch_model.avg[idx] if idx < len(ch_model.avg) else None
                    mx = ch_model.max[idx] if idx < len(ch_model.max) else None
                    csv_mgr.insert_row([ch_id, f_khz, mn, av, mx])

                csv_fname = self.create_csv_fname(
                    tags=["rxmer_min_avg_max", f"{ch_id}"]
                )
                csv_mgr.set_path_fname(csv_fname)

                out.append(csv_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
            data = cast(OfdmProfilePerf01Map, model.data)

            for ch_id, ch_model in data.items():
                ch_model = cast(ChannelOfdmProfilePerf01Model, ch_model)

                for profile_model in ch_model.profiles:
                    csv_mgr: CSVManager = self.csv_manager_factory()
                    header = [
                        "ProfileID",
                        "Frequency(Hz)",
                        "AvgMER(dB)",
                        "ProfileMin(dB)",
                        "CapacityDelta(Avg vs. ProfileMin)",
                        "FECTotal",
                        "FECCorrected",
                        "FECUncorrectable",
                    ]
                    csv_mgr.set_header(header)

                    pid = profile_model.profile_id
                    fec_e = (
                        profile_model.fec_summary.summary[0]
                        if profile_model.fec_summary.summary
                        else None
                    )
                    total = fec_e.summary.total_codewords if fec_e else 0
                    corr = fec_e.summary.corrected if fec_e else 0
                    uncor = fec_e.summary.uncorrectable if fec_e else 0

                    self._write_profile_perf_rows(
                        csv_mgr=csv_mgr,
                        profile_id=pid,
                        total=total,
                        corr=corr,
                        uncor=uncor,
                        frequencies=ch_model.frequency,
                        avg_mer=ch_model.avg_mer,
                        profile_min_mer=profile_model.profile_min_mer,
                        capacity_delta=profile_model.capacity_delta,
                    )

                    csv_fname = self.create_csv_fname(
                        tags=["ofdm_profile_perf_1", f"ch{ch_id}", f"pid{pid}"]
                    )
                    csv_mgr.set_path_fname(csv_fname)
                    out.append(csv_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
            data = cast(HeatMapMap, model.data)

            for ch_id, ch_model in data.items():
                ch_model = cast(ChannelHeatMapModel, ch_model)
                csv_mgr: CSVManager = self.csv_manager_factory()

                # Build header: first column is capture time index, then frequency (Hz → kHz)
                freq_khz = [f / 1_000.0 for f in ch_model.frequency]
                header = ["CaptureTime"] + [str(f) for f in freq_khz]
                csv_mgr.set_header(header)

                # Each row contains: capture time + MER values for that time
                for ts, mag_series in zip(
                    ch_model.timestamps, ch_model.values, strict=False
                ):
                    csv_mgr.insert_row([ts] + mag_series)

                # Assign CSV filename
                csv_fname = self.create_csv_fname(
                    tags=["rxmer_ofdm_heat_map", f"{ch_id}"]
                )
                csv_mgr.set_path_fname(csv_fname)

                out.append(csv_mgr)

        return out

    def _write_profile_perf_rows(
        self,
        csv_mgr: CSVManager,
        profile_id: ProfileId,
        total: int,
        corr: int,
        uncor: int,
        frequencies: FrequencySeriesHz,
        avg_mer: FloatSeries,
        profile_min_mer: FloatSeries,
        capacity_delta: FloatSeries,
    ) -> None:
        for freq, avg_value, prof_lim, delta in zip(
            frequencies,
            avg_mer,
            profile_min_mer,
            capacity_delta,
            strict=False,
        ):
            csv_mgr.insert_row(
                [profile_id, freq, avg_value, prof_lim, delta, total, corr, uncor]
            )

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """
        Build MatPlot PNG outputs for supported analysis types.
        Currently implemented for MIN_AVG_MAX only.
        """
        self.logger.debug("Processing Multi-RxMER Analysis MatPlot Report")
        out: list[MatplotManager] = []
        model = self.to_model()

        if self.analysis_type == MultiRxMerAnalysisType.MIN_AVG_MAX:
            data1 = cast(MinAvgMaxMap, model.data)

            for channel_id, ch_model in data1.items():
                freq_hz = cast(ArrayLike, ch_model.frequency)
                freq_khz = cast(ArrayLike, freq_hz)

                mn = cast(ArrayLike, ch_model.min)
                av = cast(ArrayLike, ch_model.avg)
                mx = cast(ArrayLike, ch_model.max)

                cfg = PlotConfig(
                    title=f"Min-Avg-Max RxMER · Channel: {channel_id}",
                    x=cast(ArrayLike, freq_khz),
                    y_multi=[mn, av, mx],
                    y_multi_label=["Min", "Avg", "Max"],
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    xlabel_base="Frequency",
                    ylabel="dB",
                    grid=True,
                    legend=True,
                    transparent=False,
                    line_colors=[
                        "#FF5733",
                        "#3357FF",
                        "#33FF57",
                    ],
                    theme="dark",
                )

                multi = self.create_png_fname(
                    tags=[str(channel_id), "rxmer_min_avg_max"]
                )
                self.logger.debug(
                    "Creating MatPlot: %s for channel: %s", multi, channel_id
                )

                mat_mgr = MatplotManager(default_cfg=cfg)
                mat_mgr.plot_multi_line(filename=multi)

                out.append(mat_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
            data2 = cast(HeatMapMap, model.data)

            for ch_id, ch_model in data2.items():
                ch_model = cast(ChannelHeatMapModel, ch_model)

                Z = np.asarray(ch_model.values, dtype=float)
                if Z.size == 0:
                    self.logger.warning(
                        "RXMER_HEAT_MAP: empty matrix for channel %s; skipping.", ch_id
                    )
                    continue

                x_hz = cast(ArrayLike, ch_model.frequency)
                y_ix = cast(ArrayLike, np.arange(Z.shape[0], dtype=float))

                try:
                    vmin = float(np.nanmin(Z))
                    vmax = float(np.nanmax(Z))
                except Exception:
                    vmin = None
                    vmax = None

                cfg = PlotConfig(
                    title=f"HeatMap RxMER · Channel: {ch_id}",
                    x=x_hz,
                    x_tick_mode="unit",
                    x_unit_from="hz",
                    x_unit_out="mhz",
                    x_tick_decimals=0,
                    xlabel_base="Frequency",
                    ylabel="Capture Index",
                    zlabel="MER (dB)",
                    grid=False,
                    legend=False,
                    transparent=False,
                    theme="dark",
                )

                png_name = self.create_png_fname(tags=[str(ch_id), "rxmer_heat_map"])

                mat_mgr = MatplotManager(default_cfg=cfg)
                mat_mgr.heatmap2d(
                    Z.tolist(),
                    png_name,
                    x=x_hz,
                    y=y_ix,
                    add_colorbar=True,
                    vmin=vmin,
                    vmax=vmax,
                )

                out.append(mat_mgr)

        elif self.analysis_type == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
            data3 = cast(OfdmProfilePerf01Map, model.data)

            for ch_id, ch_model in data3.items():
                ch_model = cast(ChannelOfdmProfilePerf01Model, ch_model)

                if not ch_model.profiles:
                    self.logger.warning(
                        "OFDM_PROFILE_PERFORMANCE_1: no profiles for channel %s; skipping.",
                        ch_id,
                    )
                    continue

                freq_hz = cast(ArrayLike, ch_model.frequency)
                avg_mer = cast(ArrayLike, ch_model.avg_mer)

                for profile_model in ch_model.profiles:
                    pid = profile_model.profile_id
                    pmin = cast(ArrayLike, profile_model.profile_min_mer)
                    fec_e = (
                        profile_model.fec_summary.summary[0]
                        if profile_model.fec_summary.summary
                        else None
                    )
                    total = getattr(fec_e.summary, "total_codewords", 0) if fec_e else 0
                    corr = getattr(fec_e.summary, "corrected", 0) if fec_e else 0
                    uncor = getattr(fec_e.summary, "uncorrectable", 0) if fec_e else 0
                    fec_l = f"FEC(Total={total}, Corr={corr}, Uncorr={uncor})"

                    cfg = PlotConfig(
                        title=f"OFDM PROFILE PERFORMANCE 1 · Channel: {ch_id} · Profile: {pid}",
                        x=freq_hz,
                        y_multi=[avg_mer, pmin],
                        y_multi_label=[f"AvgMER (dB) {fec_l}", "ProfileMin (dB)"],
                        x_tick_mode="unit",
                        x_unit_from="hz",
                        x_unit_out="mhz",
                        x_tick_decimals=0,
                        xlabel_base="Frequency",
                        ylabel="Average MER (dB)",
                        grid=True,
                        legend=True,
                        transparent=False,
                        line_colors=["#3357FF", "#33FF57"],
                        theme="dark",
                    )

                    fname = self.create_png_fname(
                        tags=[f"{ch_id}", f"profile_{pid}", "ofdm_profile_perf_1"]
                    )
                    plotmgr = MatplotManager(default_cfg=cfg)
                    plotmgr.plot_multi_line(filename=fname)
                    out.append(plotmgr)

        return out

    """Helpers"""

    def _parse_rxmer_heatmap_series(self) -> None:
        pass

    def _build_frequencies(
        self, model: CmDsOfdmRxMerModel | FrequencySeriesHz | None
    ) -> FrequencySeriesHz:
        """
        Build absolute subcarrier center frequencies (Hz) for the RxMER series.
        """
        if isinstance(model, list):
            return model
        if model is None:
            return []

        active_idx = model.first_active_subcarrier_index
        spacing = model.subcarrier_spacing
        freq_zero = model.subcarrier_zero_frequency
        num_idx = len(model.values)

        start_freq = freq_zero + (spacing * active_idx)

        freqs: FrequencySeriesHz = cast(
            FrequencySeriesHz, [start_freq + (i * spacing) for i in range(num_idx)]
        )
        return freqs
# FILE: src/pypnm/api/routes/advance/common/abstract/service.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import TypeVar

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.lib.types import GroupId, OperationId

T = TypeVar("T", bound=AbstractCaptureService)


class AbstractService:
    """
    Base router class managing the lifecycle of capture service instances.

    Responsibilities:
        - Instantiate and start capture services using load_service().
        - Store service instances keyed by operation ID in an internal registry.
        - Provide get_service() for retrieving active services in route handlers.

    Attributes:
        _service_store (Dict[str, AbstractCaptureService]):
            Registry mapping operation IDs to service instances.
    """

    # Maintain singleton mapping of operation_id to service instances
    __SERVICE_STORE: dict[OperationId, AbstractCaptureService] = {}

    def __init__(self) -> None:
        """
        Initialize the internal service registry.
        """
        self._service_store: dict[OperationId, AbstractCaptureService] = {}
        self.logger = logging.getLogger(self.__class__.__name__)

    async def updateServiceStore(
        self, operation_id: OperationId, service: AbstractCaptureService
    ) -> None:
        """
        Update the internal service registry with a new or modified service instance.

        Args:
            operation_id (OperationId): The unique ID of the operation.
            service (AbstractCaptureService): The service instance to register.

        Returns:
            None
        """
        self.__SERVICE_STORE[operation_id] = service

    async def loadService(
        self, service_cls: type[T], *args: object, **kwargs: object
    ) -> tuple[GroupId, OperationId]:
        """
        Instantiate, start, and register a capture service.

        Args:
            service_cls (Type[T]): Capture service class to instantiate.
            *args: Positional args for the service constructor.
            **kwargs: Keyword args for the service constructor.

        Returns:
            Tuple[GroupId, OperationId]: (group_id, operation_id) returned by service.start().

        Raises:
            Exception: Propagates errors from instantiation or startup.

        Supported Service Types:
            - MultiRxMerService
            - MultiChannelEstimationService
            - MultiRxMer_Ofdm_Performance_1_Service

        """
        service: T = service_cls(*args, **kwargs)
        group_id, operation_id = await service.start()
        self._service_store[operation_id] = service
        return group_id, operation_id

    def getService(self, operation_id: OperationId) -> AbstractCaptureService:
        """
        Retrieve a previously loaded service by its operation ID.

        Args:
            operation_id (str): The ID returned by load_service().

        Returns:
            AbstractCaptureService: The associated service instance.

        Raises:
            KeyError: If no service exists for the given operation ID.
        """
        try:
            return self._service_store[operation_id]
        except KeyError as err:
            raise KeyError(
                f"No service loaded for operation_id '{operation_id}'"
            ) from err

    def getActiveServices(self) -> dict[OperationId, AbstractCaptureService]:
        """
        Retrieve all currently active services.

        Returns:
            Dict[OperationId, AbstractCaptureService]: Mapping of operation IDs to service instances.
        """
        self.logger.info(
            f"Retrieving active services. Current store: {self._service_store.keys()}"
        )

        active_services: dict[OperationId, AbstractCaptureService] = {}

        for operation_id in self._service_store:
            self.logger.info(f"Active service: operation_id={operation_id}")
            if (
                self._service_store[operation_id].status()["state"]
                == OperationState.RUNNING
            ):
                self.logger.info(f"Service {operation_id} is running")
                active_services[operation_id] = self._service_store[operation_id]

        return active_services
# FILE: src/pypnm/api/routes/advance/multi_ds_chan_est/router.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import io
import logging
import os
import zipfile
from collections.abc import Callable
from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from pypnm.api.routes.advance.analysis.signal_analysis.multi_chan_est_singnal_analysis import (
    MultiChanEstAnalysisType,
    MultiChanEstimationSignalAnalysis,
)
from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.multi_ds_chan_est.schemas import (
    AnalysisDataModel,
    MultiChanEstAnalysisRequest,
    MultiChanEstimationAnalysisResponse,
    MultiChanEstimationResponseStatus,
    MultiChanEstimationStartResponse,
    MultiChanEstRequest,
    MultiChanEstStatusResponse,
)
from pypnm.api.routes.advance.multi_ds_chan_est.service import (
    MultiChannelEstimationService,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import GroupId, MacAddressStr, OperationId


class MultiDsChanEstRouter(AbstractService):
    """Router for handling Multi-DS-Channel-Estimation operations."""

    def __init__(self) -> None:
        super().__init__()
        self.router = APIRouter(
            prefix="/advance/multiChannelEstimation",
            tags=["PNM Operations - Multi-DS-Channel-Estimation"],
        )
        self.logger = logging.getLogger(self.__class__.__name__)
        self._add_routes()

    # ──────────────────────────────────────────────────────────
    # Routes
    # ──────────────────────────────────────────────────────────
    def _add_routes(self) -> None:
        @self.router.post(
            "/start",
            response_model=MultiChanEstimationStartResponse | SnmpResponse,
            summary="Start a multi-sample ChannelEstimation capture",
        )
        async def start_multi_chan_estimation(
            request: MultiChanEstRequest,
        ) -> MultiChanEstimationStartResponse | SnmpResponse:
            duration, interval = (
                request.capture.parameters.measurement_duration,
                request.capture.parameters.sample_interval,
            )
            mac_address: MacAddressStr = request.cable_modem.mac_address
            ip_address: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(
                request.cable_modem.snmp
            )
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(
                request.cable_modem.pnm_parameters.tftp
            )

            self.logger.info(
                f"[start] Multi-ChanEst for MAC={mac_address}, duration={duration}s interval={interval}s"
            )

            cm = CableModem(
                mac_address=MacAddress(mac_address),
                inet=Inet(ip_address),
                write_community=community,
            )

            # Pre-checks
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm, validate_ofdm_exist=True
            ).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(
                    f"[start] Precheck failed for MAC={mac_address}: {msg}"
                )
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)

            group_id, operation_id = await self.loadService(
                MultiChannelEstimationService,
                cm,
                tftp_servers,
                duration=duration,
                interval=interval,
            )
            return MultiChanEstimationStartResponse(
                mac_address=mac_address,
                status=OperationState.RUNNING,
                message=None,
                group_id=group_id,
                operation_id=operation_id,
            )

        @self.router.get(
            "/status/{operation_id}",
            response_model=MultiChanEstStatusResponse,
            summary="Get status of a multi-sample ChannelEstimation capture",
        )
        def get_status(operation_id: OperationId) -> MultiChanEstStatusResponse:
            try:
                service: MultiChannelEstimationService = cast(
                    MultiChannelEstimationService, self.getService(operation_id)
                )

            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err

            status = service.status(operation_id)
            return MultiChanEstStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                status="success",
                message=None,
                operation=MultiChanEstimationResponseStatus(
                    operation_id=operation_id,
                    state=status["state"],
                    collected=status["collected"],
                    time_remaining=status["time_remaining"],
                    message=None,
                ),
            )

        @self.router.get(
            "/results/{operation_id}",
            summary="Download a ZIP archive of all ChannelEstimation capture files",
            responses={
                200: {
                    "content": {"application/zip": {}},
                    "description": "ZIP archive of capture files",
                }
            },
        )
        def download_results_zip(operation_id: OperationId) -> StreamingResponse:
            svc: MultiChannelEstimationService = cast(
                MultiChannelEstimationService, self.getService(operation_id)
            )
            samples = svc.results(operation_id)
            pnm_dir, mac = (
                str(SystemConfigSettings.pnm_dir()),
                svc.cm.get_mac_address.mac_address,
            )
            buf = io.BytesIO()

            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for s in samples:
                    path = os.path.join(pnm_dir, s.filename)

                    try:
                        zf.write(path, arcname=os.path.basename(s.filename))

                    except FileNotFoundError:
                        self.logger.warning(f"[zip] Missing: {path}")

                    except Exception as e:
                        self.logger.warning(f"[zip] Skip {path}: {e}")

            buf.seek(0)
            headers = {
                "Content-Disposition": f"attachment; filename=multiChannelEstimation_{mac}_{operation_id}.zip"
            }
            return StreamingResponse(buf, media_type="application/zip", headers=headers)

        @self.router.delete(
            "/stop/{operation_id}",
            response_model=MultiChanEstStatusResponse,
            summary="Stop a running multi-sample ChannelEstimation capture early",
        )
        def stop_capture(operation_id: OperationId) -> MultiChanEstStatusResponse:
            """ """
            try:
                service: MultiChannelEstimationService = cast(
                    MultiChannelEstimationService, self.getService(operation_id)
                )

            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err

            service.stop(operation_id)
            status = service.status(operation_id)
            return MultiChanEstStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                status=OperationState.STOPPED,
                message=None,
                operation=MultiChanEstimationResponseStatus(
                    operation_id=operation_id,
                    state=status["state"],
                    collected=status["collected"],
                    time_remaining=status["time_remaining"],
                    message=None,
                ),
            )

        @self.router.post(
            "/analysis",
            response_model=MultiChanEstimationAnalysisResponse,
            summary="Perform signal analysis on a previously executed Multi-ChannelEstimation",
        )
        def analysis(
            request: MultiChanEstAnalysisRequest,
        ) -> MultiChanEstimationAnalysisResponse | FileResponse:
            """
            Perform post-capture analysis on Multi-ChannelEstimation measurement data.

            Supports:
            - MIN_AVG_MAX
            - GROUP_DELAY
            - LTE_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_IFFT
            """
            try:
                capture_group_id: GroupId = OperationManager.get_capture_group(
                    request.operation_id
                )
                self.logger.info(
                    f"[analysis] operation_id={request.operation_id} capture_group={capture_group_id}"
                )
            except KeyError:
                msg = f"No capture group found for operation {request.operation_id}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message=msg,
                    data=AnalysisDataModel(analysis_type="UNKNOWN", results=[]),
                )

            # Prepare data aggregator
            cda = CaptureDataAggregator(capture_group_id)

            # Parse analysis type
            try:
                atype = MultiChanEstAnalysisType(request.analysis.type)

            except ValueError:
                msg = f"Invalid analysis type: {request.analysis.type}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE,
                    message=msg,
                    data=AnalysisDataModel(analysis_type="UNKNOWN", results=[]),
                )

            # Dispatch map for type → analysis engine
            analysis_map: dict[
                MultiChanEstAnalysisType,
                Callable[[CaptureDataAggregator], MultiChanEstimationSignalAnalysis],
            ] = {
                MultiChanEstAnalysisType.MIN_AVG_MAX: lambda agg: MultiChanEstimationSignalAnalysis(
                    agg, MultiChanEstAnalysisType.MIN_AVG_MAX
                ),
                MultiChanEstAnalysisType.GROUP_DELAY: lambda agg: MultiChanEstimationSignalAnalysis(
                    agg, MultiChanEstAnalysisType.GROUP_DELAY
                ),
                MultiChanEstAnalysisType.LTE_DETECTION_PHASE_SLOPE: lambda agg: MultiChanEstimationSignalAnalysis(
                    agg, MultiChanEstAnalysisType.LTE_DETECTION_PHASE_SLOPE
                ),
                MultiChanEstAnalysisType.ECHO_DETECTION_IFFT: lambda agg: MultiChanEstimationSignalAnalysis(
                    agg, MultiChanEstAnalysisType.ECHO_DETECTION_IFFT
                ),
            }

            if atype not in analysis_map:
                msg = f"Unsupported analysis type: {atype}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE,
                    message=msg,
                    data=AnalysisDataModel(analysis_type="UNKNOWN", results=[]),
                )

            # Determine output type
            output_type: OutputType = request.analysis.output.type
            engine = analysis_map[atype](cda)
            analysis_result = engine.to_model()

            # Handle output formats
            if output_type == OutputType.JSON:
                err = analysis_result.error
                status = (
                    ServiceStatusCode.SUCCESS if not err else ServiceStatusCode.FAILURE
                )
                message = (
                    err
                    or f"Analysis {analysis_result.analysis_type} completed for group {capture_group_id}"
                )

                data_model = AnalysisDataModel(
                    analysis_type=analysis_result.analysis_type,
                    results=[r.model_dump() for r in analysis_result.results],
                )

                mac = engine.getMacAddresses()[0].mac_address
                self.logger.info(
                    f"[analysis] type={atype.name} mac={mac} status={status.name} group={capture_group_id}"
                )

                return MultiChanEstimationAnalysisResponse(
                    mac_address=mac, status=status, message=message, data=data_model
                )

            elif output_type == OutputType.ARCHIVE:
                try:
                    rpt = engine.build_report()
                    self.logger.info(
                        f"[analysis] Built archive report for group {capture_group_id}"
                    )
                    return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

                except Exception as e:
                    msg = f"Archive build failed: {e}"
                    self.logger.error(msg)
                    return MultiChanEstimationAnalysisResponse(
                        mac_address=MacAddress.null(),
                        status=ServiceStatusCode.FAILURE,
                        message=msg,
                        data=AnalysisDataModel(analysis_type=atype.name, results=[]),
                    )

            # Unsupported output type
            msg = f"Unsupported output type: {output_type}"
            self.logger.error(msg)
            return MultiChanEstimationAnalysisResponse(
                mac_address=MacAddress.null(),
                status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message=msg,
                data=AnalysisDataModel(analysis_type=atype.name, results=[]),
            )


# Auto-register
router = MultiDsChanEstRouter().router
# FILE: src/pypnm/api/routes/basic/fec_summary_analysis_rpt.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import cast

from pydantic import Field

from pypnm.api.routes.basic.abstract.analysis_report import (
    AnalysisReport,
    AnalysisRptMatplotConfig,
)
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.schema import (
    OfdmFecSummaryAnalysisModel,
)
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import ArrayLike, ChannelId, IntSeries, ScalarValue


class FecSummaryAnalysisRptModel(CommonAnalysis):
    """
    CommonAnalysis wrapper for OFDM FEC Summary outputs.

    Attributes
    ----------
    parameters : OfdmFecSummaryAnalysisModel
        Structured FEC summary model produced by the analysis layer.
    """

    parameters: OfdmFecSummaryAnalysisModel = Field(
        ...,
        description="Structured OFDM FEC summary model (per-channel, per-profile codeword time series).",
    )


class FecSummaryAnalysisReport(AnalysisReport):
    """
    Report generator for OFDM FEC Summary analysis.

    Responsibilities
    ----------------
    - Emit one CSV per channel/profile with time-series codeword counters.
    - Emit one PNG per channel/profile with Total/Corrected/Uncorrected curves.
    """

    FNAME_TAG: str = "FecSummary"

    def __init__(
        self,
        analysis: Analysis,
        analysis_matplot_config: AnalysisRptMatplotConfig | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize report generator and internal result registry."""
        if analysis_matplot_config is None:
            analysis_matplot_config = AnalysisRptMatplotConfig()
        super().__init__(analysis, analysis_matplot_config)
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self._results: dict[int, FecSummaryAnalysisRptModel] = {}

    @staticmethod
    def _as_seq(x: ScalarValue | Sequence[ScalarValue] | None) -> list[ScalarValue]:
        """
        Convert scalar or sequence of scalars into a list of ScalarValue.

        Notes
        -----
        - None         → []
        - list/tuple   → list(x)
        - other scalar → [x]
        """
        if x is None:
            return []
        if isinstance(x, (list, tuple)):
            return list(x)
        try:
            return list(x)
        except Exception:
            return [x]

    @staticmethod
    def _get(obj: object, *names: str) -> object | None:
        """
        Retrieve the first matching attribute or mapping key from a set of candidates.

        Parameters
        ----------
        obj : Any
            Source object or mapping.
        *names : str
            Candidate attribute or key names to probe in order.

        Returns
        -------
        Any
            Value of the first attribute/key found, otherwise None.
        """
        for n in names:
            if hasattr(obj, n):
                return getattr(obj, n)
            if isinstance(obj, Mapping) and n in obj:
                return obj[n]
        return None

    def _resolve_profile(self, profile_entry: object) -> str:
        """
        Resolve a human-readable profile identifier string.

        Parameters
        ----------
        profile_entry : Any
            Profile entry object or mapping with one of: profile, profile_id, id.

        Returns
        -------
        str
            Profile identifier coerced to string (integer string when possible).
        """
        p = self._get(profile_entry, "profile", "profile_id", "id")
        try:
            return str(int(p))
        except Exception:
            return str(p) if p is not None else "unknown"

    def _resolve_codewords(
        self,
        profile_entry: object,
    ) -> tuple[list[ScalarValue], IntSeries, IntSeries, IntSeries, dict[str, int]]:
        """
        Resolve timestamp and codeword counter series from schema variants.

        Parameters
        ----------
        profile_entry : Any
            Profile entry containing codeword time-series data in one of several
            supported field layouts.

        Returns
        -------
        Tuple[List[ScalarValue], IntSeries, IntSeries, IntSeries, Dict[str, int]]
            - List[ScalarValue] : Timestamps (epoch seconds or formatted labels).
            - IntSeries         : Total codewords per timestamp.
            - IntSeries         : Corrected codewords per timestamp.
            - IntSeries         : Uncorrected codewords per timestamp.
            - Dict[str, int]    : Shape summary for logging (keys: ts, tc, cc, uc).
        """
        cw = self._get(
            profile_entry, "codewords", "codeword_entries", "entries", "codeword"
        )
        shape: dict[str, int] = {}
        candidates = [cw, self._get(cw, "values"), self._get(cw, "data")]

        ts: list[ScalarValue] = []
        tc: IntSeries = []
        cc: IntSeries = []
        uc: IntSeries = []
        for node in candidates:
            if node is None:
                continue
            ts = self._as_seq(self._get(node, "timestamps", "timestamp"))
            tc = [
                int(v)
                for v in self._as_seq(
                    self._get(node, "total_codewords", "total", "totals")
                )
            ]
            cc = [int(v) for v in self._as_seq(self._get(node, "corrected"))]
            uc = [int(v) for v in self._as_seq(self._get(node, "uncorrected"))]
            if any((ts, tc, cc, uc)):
                break

        shape["ts"] = len(ts)
        shape["tc"] = len(tc)
        shape["cc"] = len(cc)
        shape["uc"] = len(uc)
        return ts, tc, cc, uc, shape

    def _log_preview(
        self,
        ch: ChannelId,
        profile: str,
        ts: Sequence[ScalarValue],
        tc: Sequence[int],
        cc: Sequence[int],
        uc: Sequence[int],
    ) -> None:
        """
        Log a short preview of the first few samples for a channel/profile series.

        Parameters
        ----------
        ch : ChannelId
            Channel identifier.
        profile : str
            Profile identifier.
        ts : Sequence[ScalarValue]
            Timestamp sequence.
        tc : Sequence[int]
            Total codeword counts.
        cc : Sequence[int]
            Corrected codeword counts.
        uc : Sequence[int]
            Uncorrected codeword counts.
        """

        def head(
            seq: Sequence[ScalarValue | int], k: int = 5
        ) -> list[ScalarValue | int]:
            return list(seq[:k])

        self.logger.debug(
            "Preview ch=%s prof=%s ts[:5]=%s total[:5]=%s corr[:5]=%s unc[:5]=%s",
            int(ch),
            profile,
            head(ts),
            head(tc),
            head(cc),
            head(uc),
        )

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Produce CSV files with per-timestamp codeword counters for each channel/profile.

        Returns
        -------
        list[CSVManager]
            Managers pointing at the generated CSV files.
        """
        mgr_out: list[CSVManager] = []
        for common_model in self.get_common_analysis_model():
            c_model = cast(FecSummaryAnalysisRptModel, common_model)
            channel_id: int = int(c_model.channel_id)
            analysis_model = c_model.parameters
            profiles = getattr(analysis_model, "profiles", []) or []

            for profile_entry in profiles:
                profile = self._resolve_profile(profile_entry)
                ts, tc, cc, uc, shape = self._resolve_codewords(profile_entry)
                n = min(len(ts), len(tc), len(cc), len(uc))
                self.logger.debug(
                    "CSV series lengths ch=%s prof=%s shape=%s n=%d",
                    channel_id,
                    profile,
                    shape,
                    n,
                )
                if n == 0:
                    self.logger.warning(
                        "No data for Channel %s, Profile %s (timestamps/counters empty).",
                        channel_id,
                        profile,
                    )
                    continue

                try:
                    csv_mgr: CSVManager = self.csv_manager_factory()
                    csv_mgr.set_header(
                        [
                            "ChannelID",
                            "Profile",
                            "Timestamp",
                            "TotalCodewords",
                            "Corrected",
                            "Uncorrected",
                        ]
                    )
                    csv_fname = self.create_csv_fname(
                        tags=[str(channel_id), profile, self.FNAME_TAG]
                    )
                    csv_mgr.set_path_fname(csv_fname)
                    self._append_csv_rows(
                        csv_mgr=csv_mgr,
                        channel_id=channel_id,
                        profile=profile,
                        ts=ts,
                        tc=tc,
                        cc=cc,
                        uc=uc,
                        count=n,
                    )
                    self._log_preview(channel_id, profile, ts, tc, cc, uc)
                    self.logger.debug(
                        "CSV created ch=%s prof=%s -> %s (rows=%d)",
                        channel_id,
                        profile,
                        csv_fname,
                        csv_mgr.get_row_count(),
                    )
                    mgr_out.append(csv_mgr)
                except Exception as exc:
                    self.logger.exception(
                        "Failed to create CSV for channel %s (profile %s): %s",
                        channel_id,
                        profile,
                        exc,
                    )
        return mgr_out

    def _append_csv_rows(
        self,
        csv_mgr: CSVManager,
        channel_id: int,
        profile: str,
        ts: Sequence[ScalarValue],
        tc: Sequence[int],
        cc: Sequence[int],
        uc: Sequence[int],
        count: int,
    ) -> None:
        for idx in range(count):
            csv_mgr.insert_row(
                [channel_id, profile, ts[idx], tc[idx], cc[idx], uc[idx]]
            )

    def create_matplot(self, **kwargs: object) -> list[MatplotManager]:
        """
        Produce PNG plots (Total/Corrected/Uncorrected) for each channel/profile.

        Notes
        -----
        - X axis ticks are hidden.
        - A single human-readable time range ("start → end") is used as the xlabel.

        Returns
        -------
        list[MatplotManager]
            Managers used to generate and reference plot outputs.
        """
        mgr_out: list[MatplotManager] = []
        for common_model in self.get_common_analysis_model():
            c_model = cast(FecSummaryAnalysisRptModel, common_model)
            ch_id: ChannelId = ChannelId(c_model.channel_id)
            analysis_model = c_model.parameters
            profiles = getattr(analysis_model, "profiles", []) or []

            for profile_entry in profiles:
                profile = self._resolve_profile(profile_entry)
                ts, tc, cc, uc, shape = self._resolve_codewords(profile_entry)
                n = min(len(ts), len(tc), len(cc), len(uc))
                self.logger.debug(
                    "Plot series lengths ch=%s prof=%s shape=%s n=%d",
                    int(ch_id),
                    profile,
                    shape,
                    n,
                )
                if n == 0:
                    self.logger.warning(
                        "No data for Channel %s, Profile %s (timestamps/counters empty).",
                        int(ch_id),
                        profile,
                    )
                    continue

                try:
                    cfg = PlotConfig(
                        title=f"FEC Summary · OFDM · Channel {int(ch_id)} · Profile ({profile})",
                        x=cast(ArrayLike, ts[:n]),
                        ylabel="Codeword Count",
                        y_multi=[
                            cast(ArrayLike, tc[:n]),
                            cast(ArrayLike, cc[:n]),
                            cast(ArrayLike, uc[:n]),
                        ],
                        y_multi_label=["Total", "Corrected", "Uncorrected"],
                        grid=True,
                        legend=True,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                        line_colors=["tab:blue", "tab:green", "tab:red"],
                        # ── X-axis time range label & tick suppression ──
                        x_ticks_visible=False,  # hide all x ticks/labels
                        x_time_labels="from_to",  # render "start → end" as xlabel
                        x_time_input_unit="s",  # timestamps are epoch seconds
                        x_time_format="%Y-%m-%d %H:%M",  # adjust as needed
                        xlabel_prefix="Time Range: ",  # optional prefix before start→end
                    )

                    mgr = MatplotManager(default_cfg=cfg)
                    png_path = self.create_png_fname(
                        tags=[str(int(ch_id)), profile, self.FNAME_TAG]
                    )
                    self._log_preview(ch_id, profile, ts, tc, cc, uc)
                    self.logger.debug(
                        "Creating MatPlot: %s ch=%s prof=%s",
                        png_path,
                        int(ch_id),
                        profile,
                    )
                    mgr.plot_multi_line(filename=png_path)
                    mgr_out.append(mgr)
                except Exception as exc:
                    self.logger.exception(
                        "Failed to create plot for channel %s (profile %s): %s",
                        int(ch_id),
                        profile,
                        exc,
                    )
        return mgr_out

    def _process(self) -> None:
        """
        Register CommonAnalysis wrappers for each OfdmFecSummaryAnalysisModel.

        Expected
        --------
        The analysis model list is `list[OfdmFecSummaryAnalysisModel]`.
        """
        models: list[OfdmFecSummaryAnalysisModel] = cast(
            list[OfdmFecSummaryAnalysisModel], self.get_analysis_model()
        )
        for model in models:
            channel_id: int = int(model.channel_id)
            a_model = FecSummaryAnalysisRptModel(
                channel_id=channel_id, parameters=model
            )
            self.register_common_analysis_model(channel_id, a_model)
# FILE: src/pypnm/api/routes/basic/modulation_profile_analysis_rpt.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field

from pypnm.api.routes.basic.abstract.analysis_report import (
    AnalysisReport,
    AnalysisRptMatplotConfig,
)
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.lib.constants import INVALID_CHANNEL_ID, INVALID_PROFILE_ID
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import (
    ArrayLike,
    ChannelId,
    FloatSeries,
    FrequencyHz,
    FrequencySeriesHz,
    ProfileId,
    StringArray,
)


class ModulationProfileRptModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    profile_id: int = Field(..., description="Profile identifier")
    modulation: list[str] = Field(
        default_factory=list,
        description="Per-carrier modulation label (e.g., 'QAM256')",
    )
    bits_per_symbol: list[int] = Field(
        default_factory=list,
        description="Per-carrier bits per symbol (derived or provided)",
    )
    shannon_min_mer: list[float] = Field(
        default_factory=list, description="Per-carrier minimum MER per Shannon (dB)"
    )


class ModulationProfileParametersAnalysisRpt(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    profiles: list[ModulationProfileRptModel] = Field(
        default_factory=list, description="All profiles for a channel"
    )


class ModulationProfileAnalysisRptModel(CommonAnalysis):
    parameters: ModulationProfileParametersAnalysisRpt = Field(
        ..., description="Modulation profile parameters"
    )


class ModulationProfileReport(AnalysisReport):
    FNAME_TAG: str = "modulationprofile"

    def __init__(
        self,
        analysis: Analysis,
        analysis_matplot_config: AnalysisRptMatplotConfig | None = None,
        **kwargs: object,
    ) -> None:
        if analysis_matplot_config is None:
            analysis_matplot_config = AnalysisRptMatplotConfig()
        super().__init__(analysis, analysis_matplot_config)
        self.logger = logging.getLogger("ModulationProfileReport")
        self._results: dict[int, ModulationProfileAnalysisRptModel] = {}

    def create_csv(self, **kwargs: object) -> list[CSVManager]:
        """
        Stream validated models into CSVs. Assumes `_process()` already enforced.
        Emits one CSV per channel/profile pair.
        """
        csv_mgr_list: list[CSVManager] = []
        any_models = False

        for common_model in self.get_common_analysis_model():
            any_models = True
            model = cast(ModulationProfileAnalysisRptModel, common_model)
            channel_id: int = int(model.channel_id)
            freq: FrequencySeriesHz = cast(FrequencySeriesHz, model.raw_x)

            if not freq:
                self.logger.warning(
                    f"Channel {channel_id} has empty frequency array; skipping CSV."
                )
                continue

            try:
                header: list[str] = [
                    "ChannelID",
                    "ProfileID",
                    "Frequency_Hz",
                    "Modulation",
                    "BitsPerSymbol",
                    "ShannonMinMER_dB",
                ]

                for profile in model.parameters.profiles:
                    csv_mgr: CSVManager = self.csv_manager_factory()
                    csv_mgr.set_header(header)

                    csv_fname = self.create_csv_fname(
                        tags=[str(channel_id), str(profile.profile_id), self.FNAME_TAG]
                    )
                    csv_mgr.set_path_fname(csv_fname)

                    n = len(freq)
                    mod = self._align_len(profile.modulation, n, fill="UNKNOWN")
                    bps = self._align_len(profile.bits_per_symbol, n, fill=0)
                    mer = self._align_len(profile.shannon_min_mer, n, fill=float("nan"))

                    rows_written = self._append_profile_rows(
                        csv_mgr=csv_mgr,
                        channel_id=channel_id,
                        profile_id=profile.profile_id,
                        freq=freq,
                        mod=mod,
                        bps=bps,
                        mer=mer,
                    )

                    self.logger.info(
                        f"CSV rows for channel {channel_id} profile {profile.profile_id}: {rows_written}"
                    )
                    self.logger.info(
                        f"CSV created for channel {channel_id}: {csv_fname} (rows={csv_mgr.get_row_count()})"
                    )

                    csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception(
                    f"Failed to create CSV for channel {channel_id}: {exc}",
                    exc_info=True,
                )

        if not any_models:
            self.logger.info("No analysis data available; no CSVs created.")

        return csv_mgr_list

    def create_matplot(self) -> list[MatplotManager]:
        """
        Generate per-channel plots, one set per profile:
        1) Bits-per-symbol vs. Frequency
        2) Shannon Min MER vs. Frequency
        3) Modulation vs. Frequency with a preloaded M-QAM scale (linear spacing via log₂(M) positions,
            tick labels shown as M values: 4, 8, 16, 32, …, 4096)

        Notes
        -----
        - Frequency axis is formatted by Matplot using unit scaling (Hz → MHz) and zero decimals.
        - Theme is taken from AnalysisRptMatplotConfig (e.g., "dark" or "light").
        - The M-QAM axis uses evenly spaced positions at log₂(M) to avoid visually "log-like" spacing,
        while the visible tick labels are the true QAM orders (M).
        """
        out: list[MatplotManager] = []

        for common_model in self.get_common_analysis_model():
            model = cast(ModulationProfileAnalysisRptModel, common_model)
            channel_id: ChannelId = ChannelId(model.channel_id)
            freq: FrequencySeriesHz = cast(FrequencySeriesHz, model.raw_x)

            if not freq:
                self.logger.warning(
                    f"Channel {channel_id} has empty frequency array; skipping plots."
                )
                continue

            for profile in model.parameters.profiles:
                profile_id: ProfileId = ProfileId(profile.profile_id)

                # Align inputs to frequency length
                try:
                    n = len(freq)
                    bpsym: FloatSeries = self._align_len(
                        profile.bits_per_symbol, n, fill=0
                    )
                    min_mer: FloatSeries = self._align_len(
                        profile.shannon_min_mer, n, fill=float("nan")
                    )
                    mod_lbls: StringArray = self._align_len(
                        profile.modulation, n, fill="UNKNOWN"
                    )
                    mod_order = self._derive_qam_orders(mod_lbls)
                except Exception as exc:
                    self.logger.exception(
                        f"Failed to align arrays for channel {channel_id} profile {profile_id}: {exc}",
                        exc_info=True,
                    )
                    continue

                # 1) Bits-per-symbol vs Frequency
                try:
                    bps_cfg = PlotConfig(
                        title=f"Bits-Per-Symbol vs Frequency — OFDM Ch {channel_id} · Profile {profile_id}",
                        x=cast(ArrayLike, freq),
                        y=cast(ArrayLike, bpsym),
                        ylabel="Bits per Symbol",
                        x_tick_mode="unit",
                        x_unit_from="hz",
                        x_unit_out="mhz",
                        x_tick_decimals=0,
                        xlabel_base="Frequency",
                        grid=True,
                        legend=False,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                    )

                    png_fname = self.create_png_fname(
                        tags=[str(channel_id), str(profile_id), "bps", self.FNAME_TAG]
                    )
                    self.logger.info(
                        f"Creating Bits-Per-Symbol plot: {png_fname} for channel: {channel_id}"
                    )
                    mplot_mgr = MatplotManager(default_cfg=bps_cfg)
                    mplot_mgr.plot_line(filename=png_fname)
                    out.append(mplot_mgr)
                except Exception as exc:
                    self.logger.exception(
                        f"Failed to create Bits-Per-Symbol plot for channel {channel_id} profile {profile_id}: {exc}",
                        exc_info=True,
                    )

                # 2) Shannon Min MER vs Frequency
                try:
                    mer_cfg = PlotConfig(
                        title=f"Shannon Min MER vs Frequency — OFDM Ch {channel_id} · Profile {profile_id}",
                        x=cast(ArrayLike, freq),
                        y=cast(ArrayLike, min_mer),
                        ylabel="Shannon Min MER (dB)",
                        x_tick_mode="unit",
                        x_unit_from="hz",
                        x_unit_out="mhz",
                        x_tick_decimals=0,
                        xlabel_base="Frequency",
                        grid=True,
                        legend=False,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                    )

                    png_fname = self.create_png_fname(
                        tags=[
                            str(channel_id),
                            str(profile_id),
                            "shannon",
                            self.FNAME_TAG,
                        ]
                    )
                    self.logger.info(
                        f"Creating Shannon Min MER plot: {png_fname} for channel: {channel_id}"
                    )
                    mplot_mgr = MatplotManager(default_cfg=mer_cfg)
                    mplot_mgr.plot_line(filename=png_fname)
                    out.append(mplot_mgr)
                except Exception as exc:
                    self.logger.exception(
                        f"Failed to create Shannon Min MER plot for channel {channel_id} profile {profile_id}: {exc}",
                        exc_info=True,
                    )

                # 3) Modulation vs Frequency with preloaded M-QAM scale (linear spacing via log₂(M), labels show M)
                try:
                    (
                        mod_bits,
                        y_ticks_bits,
                        y_labels_M,
                        max_bits_cap,
                    ) = self._build_modulation_plot_axes(mod_order)

                    mod_cfg = PlotConfig(
                        title=f"Modulation vs Frequency · OFDM · Channel ({channel_id}) · Profile ({profile_id})",
                        x=cast(ArrayLike, freq),
                        y=cast(ArrayLike, mod_bits),
                        ylabel="Modulation Order (M-QAM)",
                        x_tick_mode="unit",
                        x_unit_from="hz",
                        x_unit_out="mhz",
                        x_tick_decimals=0,
                        xlabel_base="Frequency",
                        y_ticks=y_ticks_bits,
                        y_tick_labels=y_labels_M,
                        ylim=(0.0, float(max_bits_cap)),
                        grid=True,
                        legend=False,
                        transparent=False,
                        theme=self.getAnalysisRptMatplotConfig().theme,
                    )

                    png_fname = self.create_png_fname(
                        tags=[
                            str(channel_id),
                            str(profile_id),
                            "modulation",
                            self.FNAME_TAG,
                        ]
                    )
                    self.logger.info(
                        f"Creating Modulation plot: {png_fname} for channel: {channel_id}"
                    )
                    mplot_mgr = MatplotManager(default_cfg=mod_cfg)
                    mplot_mgr.plot_line(filename=png_fname)
                    out.append(mplot_mgr)
                except Exception as exc:
                    self.logger.exception(
                        f"Failed to create Modulation plot for channel {channel_id} profile {profile_id}: {exc}",
                        exc_info=True,
                    )

        if not out:
            self.logger.info("No analysis data available; no plots created.")

        return out

    def _append_profile_rows(
        self,
        csv_mgr: CSVManager,
        channel_id: int,
        profile_id: int,
        freq: FrequencySeriesHz,
        mod: list[str],
        bps: FloatSeries,
        mer: FloatSeries,
    ) -> int:
        rows_written = 0
        for idx in range(len(freq)):
            csv_mgr.insert_row(
                [
                    channel_id,
                    profile_id,
                    freq[idx],
                    mod[idx],
                    int(bps[idx]),
                    float(mer[idx]),
                ]
            )
            rows_written += 1
        return rows_written

    def _derive_qam_orders(self, labels: StringArray) -> list[int]:
        return list(map(self._derive_qam_order, labels))

    def _derive_bits_per_symbol_list(self, mod: list[str]) -> list[int]:
        return list(map(self._derive_bits_per_symbol, mod))

    def _build_modulation_plot_axes(
        self, mod_order: list[int]
    ) -> tuple[list[int], list[int], list[str], int]:
        from math import isfinite, log2

        mod_bits: list[int] = []
        for value in mod_order:
            if value and value > 0:
                try:
                    bits = log2(value)
                    mod_bits.append(int(bits) if isfinite(bits) else 0)
                except Exception:
                    mod_bits.append(0)
            else:
                mod_bits.append(0)

        ladder_M = [4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
        ladder_bits = [int(log2(item)) for item in ladder_M]

        max_bits_seen = max(mod_bits) if mod_bits else 8
        max_bits_cap = max(2, min(max_bits_seen, ladder_bits[-1]))

        y_ticks_bits = [bits for bits in ladder_bits if bits <= max_bits_cap]
        y_labels_M = [str(2**bits) for bits in y_ticks_bits]

        return mod_bits, y_ticks_bits, y_labels_M, max_bits_cap

    def _process(self) -> None:
        """
        Expected per-item shape (keys are case-sensitive):

        {
          "device_details": {...},
          "pnm_header": {...},
          "mac_address": "...",
          "channel_id": int,
          "frequency_unit": "Hz",
          "shannon_limit_unit": "dB",
          "profiles": [
            {
              "profile_id": int,
              "carrier_values": {
                "frequency": [...],           # List[float] (Hz)
                "modulation": [...],          # List[str]  (e.g., 'QAM256')
                "bits_per_symbol": [...],     # Optional[List[int]]
                "shannon_min_mer": [...]      # List[float] (dB)
              }
            },
            ...
          ]
        }
        """
        data_list: list[dict[str, Any]] = self.get_analysis_data() or []

        try:
            for _idx, data in enumerate(data_list):
                channel_id = ChannelId(data.get("channel_id", INVALID_CHANNEL_ID))
                profiles_in: list[dict[str, Any]] = data.get("profiles", [])

                freq_array: FrequencySeriesHz = []
                profile_models: list[ModulationProfileRptModel] = []

                for profile_entry in profiles_in:
                    cv: dict[str, Any] = profile_entry.get("carrier_values", {})
                    profile_id: int = int(
                        profile_entry.get("profile_id", INVALID_PROFILE_ID)
                    )

                    freqs: FrequencySeriesHz = list(
                        map(FrequencyHz, cv.get("frequency", []) or [])
                    )
                    mod: list[str] = list(map(str, cv.get("modulation", []) or []))
                    bps: list[int] = list(map(int, cv.get("bits_per_symbol", []) or []))
                    mer: list[float] = list(
                        map(float, cv.get("shannon_min_mer", []) or [])
                    )

                    if not bps and mod:
                        bps = self._derive_bits_per_symbol_list(mod)

                    if not freq_array and freqs:
                        freq_array = freqs

                    n = len(freq_array) if freq_array else len(freqs)
                    if n:
                        mod = self._align_len(mod, n, fill="UNKNOWN")
                        bps = self._align_len(bps, n, fill=0)
                        mer = self._align_len(mer, n, fill=float("nan"))

                    profile_models.append(
                        ModulationProfileRptModel(
                            profile_id=profile_id,
                            modulation=mod,
                            bits_per_symbol=bps,
                            shannon_min_mer=mer,
                        )
                    )

                params = ModulationProfileParametersAnalysisRpt(profiles=profile_models)

                model = ModulationProfileAnalysisRptModel(
                    channel_id=channel_id,
                    raw_x=freq_array,
                    raw_y=[0.0],
                    parameters=params,
                )

                self.register_common_analysis_model(channel_id, model)

        except Exception as exc:
            self.logger.exception(
                f"Failed to process Modulation Profile data: {exc}", exc_info=True
            )

    T = TypeVar("T")

    @staticmethod
    def _align_len(seq: Iterable[T] | list[T], n: int, *, fill: T) -> list[T]:
        """
        Force a sequence to length n using truncation or padding with `fill`.
        """
        lst = list(seq) if not isinstance(seq, list) else seq
        if n <= 0:
            return []
        if len(lst) >= n:
            return lst[:n]
        return lst + [fill] * (n - len(lst))

    @staticmethod
    def _derive_bits_per_symbol(mod_label: str) -> int:
        """
        Best-effort mapping from modulation label to bits/symbol. Accepts forms like 'QAM256', 'QAM-256', '256QAM', 'qam1024', etc.
        """
        if not mod_label:
            return 0
        s = mod_label.strip().upper().replace("-", "").replace("_", "")
        digits = "".join(ch for ch in s if ch.isdigit())
        if not digits:
            return 0
        try:
            order = int(digits)
            from math import isfinite, log2

            val = log2(order)
            return int(val) if isfinite(val) else 0
        except Exception:
            return 0

    @staticmethod
    def _derive_qam_order(mod_label: str) -> int:
        """
        Parse modulation label to return QAM order M (e.g., 'QAM256' -> 256). If the label is missing digits, returns 0.
        """
        if not mod_label:
            return 0
        s = mod_label.strip().upper().replace("-", "").replace("_", "")
        digits = "".join(ch for ch in s if ch.isdigit())
        if not digits:
            return 0
        try:
            return int(digits)
        except Exception:
            return 0
# FILE: src/pypnm/api/routes/common/classes/analysis/analysis.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any, cast

import numpy as np

from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.echo_detector import (
    EchoDetector,
    EchoDetectorReport,
)
from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.type import (
    EchoDetectorType,
)
from pypnm.api.routes.common.classes.analysis.model.mod_profile_schema import (
    CarrierItemModel,
    CarrierValuesListModel,
    CarrierValuesModel,
    CarrierValuesSplitModel,
    ProfileAnalysisEntryModel,
)
from pypnm.api.routes.common.classes.analysis.model.process import (
    AnalysisProcessParameters,
)
from pypnm.api.routes.common.classes.analysis.model.schema import (
    BaseAnalysisModel,
    ChanEstCarrierModel,
    ConstellationDisplayAnalysisModel,
    DsChannelEstAnalysisModel,
    DsHistogramAnalysisModel,
    DsModulationProfileAnalysisModel,
    DsRxMerAnalysisModel,
    EchoDatasetModel,
    FecSummaryCodeWordModel,
    GrpDelayStatsModel,
    OfdmaUsPreEqCarrierModel,
    OfdmFecSummaryAnalysisModel,
    OfdmFecSummaryProfileModel,
    RegressionModel,
    RxMerCarrierValuesModel,
    UsOfdmaUsPreEqAnalysisModel,
)
from pypnm.api.routes.common.classes.analysis.model.spectrum_analyzer_schema import (
    DEFAULT_POINT_AVG,
    MagnitudeSeries,
    SpecAnaAnalysisResults,
    SpectrumAnalyzerAnalysisModel,
    WindowAverage,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import SpecAnCapturePara
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cm_snmp_operation import Generate
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.constants import (
    CABLE_VF,
    INVALID_CHANNEL_ID,
    INVALID_PROFILE_ID,
    INVALID_SCHEMA_TYPE,
    INVALID_START_VALUE,
    SPEED_OF_LIGHT,
    CableType,
)
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.log_files import LogFile
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.qam.lut_mgr import QamLutManager
from pypnm.lib.qam.types import QamModulation
from pypnm.lib.signal_processing.averager import MovingAverage
from pypnm.lib.signal_processing.butterworth import (
    DEFAULT_BUTTERWORTH_ORDER,
    MagnitudeButterworthFilter,
)
from pypnm.lib.signal_processing.complex_array_ops import ComplexArrayOps
from pypnm.lib.signal_processing.group_delay import GroupDelay
from pypnm.lib.signal_processing.linear_regression import LinearRegression1D
from pypnm.lib.signal_processing.shan.series import Shannon, ShannonSeries
from pypnm.lib.types import (
    ArrayLike,
    ChannelId,
    ComplexArray,
    FloatSeries,
    FrequencyHz,
    FrequencySeriesHz,
    IntSeries,
    MacAddressStr,
    ProfileId,
)
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import WindowFunction
from pypnm.pnm.data_type.DsOfdmModulationType import DsOfdmModulationType
from pypnm.pnm.lib.signal_statistics import SignalStatistics, SignalStatisticsModel
from pypnm.pnm.parser.CmDsOfdmModulationProfile import (
    CmDsOfdmModulationProfile,
    ModulationOrderType,
    RangeModulationProfileSchemaModel,
    SkipModulationProfileSchemaModel,
)
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


class RxMerCarrierType(Enum):
    """
    RxMER carrier classification labels.

    Members
    -------
    EXCLUSION : str
        "0". Subcarriers marked as excluded (e.g., guard bands, PLC gaps).
    CLIPPED : str
        "1". Values clipped/saturated (e.g., 0.0 dB or 63.5 dB).
    NORMAL : str
        "2". Valid, non-clipped RxMER readings.
    """

    EXCLUSION = "0"
    CLIPPED = "1"
    NORMAL = "2"


# RxMER special sentinel values used for classification:
RXMER_EXCLUSION = 63.75
RXMER_CLIPPED_LOW = 0.0
RXMER_CLIPPED_HIGH = 63.5

# Constants for Signal Processing
CHAN_EST_BW_CUTOFF_FRACTION: float = 0.25


class AnalysisType(Enum):
    """
    Analysis mode selector.

    Notes
    -----
    BASIC
        Provides (frequency, magnitude) and selected meta-data depending on the
        detected PNM file type. Additional per-type metrics may be included
        (e.g., group delay, Shannon limits, histogram counts).
    """

    BASIC = 0


class Analysis:
    """Core analysis runner.

    This orchestrator normalizes the payload's ``data`` into a list of
    measurement dictionaries and dispatches to the appropriate analysis
    routine based on the inferred PNM file type. For echo detection, the
    provided ``cable_type`` controls the velocity factor used to convert
    echo time delays to physical distances.

    Parameters
    ----------
    analysis_type : AnalysisType
        Selected analysis mode (e.g., ``AnalysisType.BASIC``).
    msg_response : MessageResponse
        Wrapped transport of the measurement payload; must expose
        ``payload_to_dict()`` with a top-level ``"data"`` entry.
    cable_type : CableType, default CableType.RG6
        Cable type used by echo-detection analysis to determine the
        propagation velocity factor for distance calculations.

    """

    def __init__(
        self,
        analysis_type: AnalysisType,
        msg_response: MessageResponse,
        cable_type: CableType = CableType.RG6,
        skip_automatic_process: bool = False,
    ) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.analysis_type: AnalysisType = analysis_type
        self.msg_response: MessageResponse = msg_response
        self._cable_type: CableType = cable_type
        payload: dict[int | str, Any] = msg_response.payload_to_dict() or {}
        _raw_data = payload.get("data", [])

        self._result_model: list[BaseAnalysisModel] = []
        self._processed_pnm_type: list[PnmFileType] = []
        self._skip_automatic_process = skip_automatic_process

        # Defining DataTypes
        self._analysis_para: AnalysisProcessParameters = AnalysisProcessParameters()

        if isinstance(_raw_data, Mapping):
            self.measurement_data: list[dict[str, Any]] = [dict(_raw_data)]
        elif isinstance(_raw_data, Sequence) and not isinstance(
            _raw_data, (str, bytes, bytearray)
        ):
            self.measurement_data = [dict(m) for m in _raw_data]
        else:
            self.measurement_data = []

        self._analysis_dict: list[dict[str, Any]] = []

        if self.logger.isEnabledFor(logging.DEBUG):
            self.save_message_response(self.msg_response)

        if not skip_automatic_process:
            self._process(self._analysis_para)

    def process(self, analysis_para: AnalysisProcessParameters) -> None:
        self._analysis_para = analysis_para
        self._process(analysis_para)

    def _process(self, analysis_para: AnalysisProcessParameters) -> None:
        """Iterate and dispatch analysis per measurement.

        For each normalized measurement, this method assembles the combined
        PNM file type string from the header fields and routes to the
        corresponding *basic* analysis handler.

        Notes
        -----
        Unknown or missing file types are logged; the measurement is
        serialized for troubleshooting via :class:`LogFile`.
        """

        for idx, measurement in enumerate(self.measurement_data):
            if (
                "pnm_file_type" in measurement
                and PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA.name
                in measurement["pnm_file_type"]
            ):
                self.logger.debug("Processing SNMP Spectrum Analysis Data")

                pnm_file_type = PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA.value
                if self.analysis_type == AnalysisType.BASIC:
                    self.logger.debug(
                        "Performing Basic Analysis on SNMP Spectrum Analysis Data"
                    )
                    self._basic_analysis(pnm_file_type, measurement, analysis_para)

                continue

            pnm_header: dict[str, Any] = measurement.get("pnm_header") or {}
            channel_id: int = measurement.get("channel_id", INVALID_CHANNEL_ID)

            self.logger.debug(f"PNM-HEADER[{idx}]: {pnm_header}")

            file_type = str(pnm_header.get("file_type", ""))
            file_ver = str(pnm_header.get("file_type_version", ""))
            pnm_file_type = f"{file_type}{file_ver}"

            if not pnm_file_type:
                self.logger.error("PNM FileType not Found")
                LogFile.write(
                    fname=f"unknown-pnm-filetype-{Generate.time_stamp()}.dict",
                    data=measurement,
                )
                pass

            if self.analysis_type == AnalysisType.BASIC:
                self.logger.debug(
                    f"Performing Basic Analysis on PNM: {pnm_file_type} on Channel: {channel_id}"
                )
                self._basic_analysis(pnm_file_type, measurement, analysis_para)

            else:
                self.logger.error(f"Unknown AnalysisType: {self.analysis_type}")
                raise

    def _basic_analysis(
        self,
        pnm_file_type: str,
        measurement: dict[str, Any],
        analysis_para: AnalysisProcessParameters,
    ) -> None:
        """
        Route to the appropriate BASIC analysis handler.

        Parameters
        ----------
        pnm_file_type : str
            Concatenated PNM file type identifier, e.g.
            ``PnmFileType.RECEIVE_MODULATION_ERROR_RATIO.value``.
        measurement : dict
            Single measurement dictionary. Expected keys vary by file type,
            but generally include:
                - ``pnm_header`` : dict with ``file_type`` and version
                - ``channel_id`` : int
                - ``device_details`` : dict
                - per-type fields such as subcarrier spacing, values, profiles, etc.

        Notes
        -----
        This method only dispatches. See the specific handlers for field
        expectations and returned structures:

        """
        # TODO: unify return type?
        # model:BaseAnalysisModel

        if pnm_file_type == PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT.value:
            self.logger.debug("Processing: OFDM_CHANNEL_ESTIMATE_COEFFICIENT")
            model = self.basic_analysis_ds_chan_est(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT)

        elif pnm_file_type == PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY.value:
            self.logger.debug("Processing: DOWNSTREAM_CONSTELLATION_DISPLAY")
            model = self.basic_analysis_ds_constellation_display(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY)

        elif pnm_file_type == PnmFileType.RECEIVE_MODULATION_ERROR_RATIO.value:
            self.logger.debug("Processing: RECEIVE_MODULATION_ERROR_RATIO")
            model = self.basic_analysis_rxmer(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.RECEIVE_MODULATION_ERROR_RATIO)

        elif pnm_file_type == PnmFileType.DOWNSTREAM_HISTOGRAM.value:
            self.logger.debug("Processing: DOWNSTREAM_HISTOGRAM")
            model = self.basic_analysis_ds_histogram(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.DOWNSTREAM_HISTOGRAM)

        elif pnm_file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS.value:
            self.logger.debug("Processing: UPSTREAM_PRE_EQUALIZER_COEFFICIENTS")
            model = self.basic_analysis_us_ofdma_pre_equalization(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS)

        elif (
            pnm_file_type
            == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE.value
        ):
            self.logger.debug(
                "Processing: UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE"
            )
            model = self.basic_analysis_us_ofdma_pre_equalization(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(
                PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE
            )

        elif pnm_file_type == PnmFileType.OFDM_FEC_SUMMARY.value:
            self.logger.debug("Processing: OFDM_FEC_SUMMARY")
            model = self.basic_analysis_ds_ofdm_fec_summary(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.OFDM_FEC_SUMMARY)

        elif pnm_file_type == PnmFileType.SPECTRUM_ANALYSIS.value:
            self.logger.debug("Processing: SPECTRUM_ANALYSIS")
            model = self.basic_analysis_spectrum_analyzer(measurement, analysis_para)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.SPECTRUM_ANALYSIS)

        elif pnm_file_type == PnmFileType.OFDM_MODULATION_PROFILE.value:
            self.logger.debug("Processing: OFDM_MODULATION_PROFILE")
            model = self.basic_analysis_ds_modulation_profile(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.OFDM_MODULATION_PROFILE)

        elif pnm_file_type == PnmFileType.LATENCY_REPORT.value:
            self.logger.warning("Stub: Processing: LATENCY_REPORT")
            self.__add_pnmType(PnmFileType.LATENCY_REPORT)
            pass

        elif pnm_file_type == PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA.value:
            self.logger.debug(
                "Processing: Basic Analysis -> CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA"
            )
            model = self.basic_analysis_spectrum_analyzer_snmp(
                measurement, analysis_para
            )
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA)

        else:
            self.logger.error(f"Unknown PNM file type: ({pnm_file_type})")

    def get_pnm_type(self) -> list[PnmFileType]:
        return self._processed_pnm_type

    def get_results(
        self, full_dict: bool = True
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """
        Return accumulated analysis results.

        Behavior
        --------
        - full_dict=True  -> always: {"analysis": [dict, dict, ...]}
        - full_dict=False -> if exactly one result: dict
                            else: {"analysis": [dict, dict, ...]}
        """
        results: list[dict[str, Any]] = self._analysis_dict

        if full_dict:
            return {"analysis": results}

        if len(results) == 1 and isinstance(results[0], dict):
            return results[0]

        return {"analysis": results}

    def get_model(self) -> BaseAnalysisModel | list[BaseAnalysisModel]:
        """Get the accumulated analysis results (typed models).

        Returns
        -------
        BaseAnalysisModel or list of BaseAnalysisModel
            The collected Pydantic models for analyses that produce them.
        """
        return self._result_model

    def get_dicts(self) -> list[dict[str, Any]]:
        return self._analysis_dict

    def save_message_response(self, msg_response: MessageResponse) -> None:
        """Persist the raw message response (debug aid).

        Parameters
        ----------
        msg_response : MessageResponse
            Source container that will be serialized to disk. The filename
            includes the MAC address (if present) and a timestamp.
        """
        msg_rsp_dict: dict[Any, Any] = msg_response.payload_to_dict()
        mac = msg_rsp_dict.get("mac_address")
        fname = f"{SystemConfigSettings().message_response_dir()}/{mac}_{Generate.time_stamp()}.msg"
        self.logger.debug(f"Saving Message Response: {fname}")

        fp = FileProcessor(fname)
        fp.write_file(msg_rsp_dict)
        fp.close()

    def __update_result_model(self, model: BaseAnalysisModel) -> None:
        """Append a typed analysis model to the results cache.

        Parameters
        ----------
        model : BaseAnalysisModel
            The model instance to record.
        """
        self._result_model.append(model)

    def __update_result_dict(self, model_dict: dict[str, Any]) -> None:
        """Append a plain-dict analysis result to the results cache.

        Parameters
        ----------
        model : dict
            The dictionary result to record.
        """
        self._analysis_dict.append(model_dict)

    def __add_pnmType(self, pft: PnmFileType) -> None:
        self._processed_pnm_type.append(pft)

    @classmethod
    def get_analysis_from_model(
        cls,
        model: BaseAnalysisModel,
        analysis_type: AnalysisType = AnalysisType.BASIC,
        cable_type: CableType = CableType.RG6,
    ) -> Analysis:
        """
        Construct an Analysis instance from an existing analysis model.

        The returned Analysis is equivalent to an already-processed BASIC analysis
        for a single measurement. The internal result caches are populated so that
        get_model(), get_results(), and get_dicts() can be used directly.

        Parameters
        ----------
        model : BaseAnalysisModel
            A concrete analysis model instance such as
            DsRxMerAnalysisModel, DsChannelEstAnalysisModel, etc.
        analysis_type : AnalysisType, default AnalysisType.BASIC
            Logical analysis mode to tag on the Analysis instance.
        cable_type : CableType, default CableType.RG6
            Cable type metadata retained on the Analysis instance.

        Returns
        -------
        Analysis
            An Analysis object whose result caches are populated from `model`.
        """
        # Infer the corresponding PNM file type from the model class
        pnm_type: PnmFileType | None
        if isinstance(model, DsChannelEstAnalysisModel):
            pnm_type = PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT
        elif isinstance(model, ConstellationDisplayAnalysisModel):
            pnm_type = PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY
        elif isinstance(model, DsRxMerAnalysisModel):
            pnm_type = PnmFileType.RECEIVE_MODULATION_ERROR_RATIO
        elif isinstance(model, DsHistogramAnalysisModel):
            pnm_type = PnmFileType.DOWNSTREAM_HISTOGRAM
        elif isinstance(model, UsOfdmaUsPreEqAnalysisModel):
            pnm_type = PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS
        elif isinstance(model, OfdmFecSummaryAnalysisModel):
            pnm_type = PnmFileType.OFDM_FEC_SUMMARY
        elif isinstance(model, DsModulationProfileAnalysisModel):
            pnm_type = PnmFileType.OFDM_MODULATION_PROFILE
        else:
            pnm_type = None

        # Bypass __init__ so we don't need a MessageResponse; populate internals manually.
        analysis = object.__new__(cls)  # type: ignore[call-arg]

        analysis.logger = logging.getLogger(f"{cls.__name__}")
        analysis.analysis_type = analysis_type
        analysis.msg_response = None
        analysis._cable_type = cable_type
        analysis._skip_automatic_process = True
        analysis._analysis_para = AnalysisProcessParameters()

        # No raw measurement data when constructed from a model
        analysis.measurement_data = []

        # Populate result caches from the provided model
        analysis._result_model = [model]
        analysis._analysis_dict = (
            [model.model_dump()] if hasattr(model, "model_dump") else [dict(model)]
        )

        analysis._processed_pnm_type = [pnm_type] if pnm_type is not None else []

        return analysis

    # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

    @classmethod
    def basic_analysis_rxmer(cls, measurement: dict[str, Any]) -> DsRxMerAnalysisModel:
        """
        Perform basic RxMER (Receive Modulation Error Ratio) analysis.

        Computes frequency per subcarrier, propagates magnitudes, and assigns a
        carrier status classification for each element (``EXCLUSION``, ``CLIPPED``,
        or ``NORMAL``). Also provides a simple regression line over the magnitudes
        and Shannon-series metadata.

        Parameters
        ----------
        measurement : dict
            Expected keys (subset):
                - ``channel_id`` : int
                - ``pnm_header`` : dict
                - ``device_details`` : dict
                - ``mac_address`` : str
                - ``subcarrier_spacing`` : int (Hz)
                - ``first_active_subcarrier_index`` : int
                - ``subcarrier_zero_frequency`` : int (Hz)
                - ``values`` : List[float] (RxMER in dB)

        Returns
        -------
        DsRxMerAnalysisModel
            Typed model with ``carrier_values.frequency``, ``carrier_values.magnitude``,
            and ``carrier_values.carrier_status`` aligned by index, plus regression
            and modulation statistics.

        Raises
        ------
        ValueError
            If required parameters are missing/negative, or lengths mismatch.
        """
        out: DsRxMerAnalysisModel

        channel_id: ChannelId = measurement.get("channel_id", INVALID_CHANNEL_ID)
        pnm_header = measurement.get("pnm_header", {})
        device_details = measurement.get("device_details", {})
        mac_address: MacAddressStr = measurement.get("mac_address", MacAddress.null())
        subcarrier_spacing: int = measurement.get("subcarrier_spacing", -1)
        first_active_subcarrier_index: int = measurement.get(
            "first_active_subcarrier_index", -1
        )
        subcarrier_zero_frequency: int = measurement.get(
            "subcarrier_zero_frequency", -1
        )
        values = measurement.get("values", [])

        if (
            first_active_subcarrier_index < 0
            or subcarrier_zero_frequency < 0
            or subcarrier_spacing < 0
        ):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} ALL must be non-negative"
            )

        if not values:
            raise ValueError("No RxMER values provided in measurement.")

        base_freq = (
            subcarrier_spacing * first_active_subcarrier_index
        ) + subcarrier_zero_frequency
        freqs: FloatSeries = [
            base_freq + (i * subcarrier_spacing) for i in range(len(values))
        ]
        magnitudes: FloatSeries = values

        def classify(v: int) -> int:
            if v == RXMER_EXCLUSION:
                return int(RxMerCarrierType.EXCLUSION.value)
            elif v in (RXMER_CLIPPED_LOW, RXMER_CLIPPED_HIGH):
                return int(RxMerCarrierType.CLIPPED.value)
            else:
                return int(RxMerCarrierType.NORMAL.value)

        # carrier_status will be List[int]
        carrier_status: list[int] = [classify(v) for v in values]

        if not (len(freqs) == len(magnitudes) == len(carrier_status)):
            raise ValueError(
                f"Length mismatch detected: frequencies({len(freqs)}), "
                f"magnitudes({len(magnitudes)}), carrier_status({len(carrier_status)})"
            )

        ss = ShannonSeries(magnitudes)

        regession_model = RegressionModel(
            slope=cast(
                FloatSeries,
                LinearRegression1D(
                    cast(ArrayLike, magnitudes), cast(ArrayLike, freqs)
                ).regression_line(),
            )
        )

        csm: dict[str, Any] = {
            RxMerCarrierType.EXCLUSION.name.lower(): RxMerCarrierType.EXCLUSION.value,
            RxMerCarrierType.CLIPPED.name.lower(): RxMerCarrierType.CLIPPED.value,
            RxMerCarrierType.NORMAL.name.lower(): RxMerCarrierType.NORMAL.value,
        }

        cv = RxMerCarrierValuesModel(
            carrier_status_map=csm,
            carrier_count=len(freqs),
            magnitude=magnitudes,
            frequency=freqs,
            carrier_status=carrier_status,
        )

        out = DsRxMerAnalysisModel(
            device_details=device_details,
            pnm_header=pnm_header,
            channel_id=channel_id,
            mac_address=mac_address,
            subcarrier_spacing=subcarrier_spacing,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            carrier_values=cv,
            regression=regession_model,
            modulation_statistics=ss.to_model(),
        )

        return out

    @classmethod
    def basic_analysis_ds_chan_est(
        cls, measurement: dict[str, Any], cable_type: CableType = CableType.RG6
    ) -> DsChannelEstAnalysisModel:
        """
        Perform downstream channel-estimation analysis.

        Computes:
        - Per-subcarrier frequency axis (Hz)
        - Magnitude sequence (dB) from complex coefficients
        - Group delay (µs) from phase slope across subcarriers
        - Echo detection via IFFT of H(f) → h(t) with conservative thresholds

        Expected Keys (subset) in `measurement`
        ---------------------------------------
        channel_id : int
            Downstream channel ID.
        subcarrier_spacing : int
            Δf in Hz between subcarriers.
        first_active_subcarrier_index : int
            Index of the first active subcarrier relative to subcarrier 0.
        subcarrier_zero_frequency : int
            Frequency (Hz) of subcarrier 0.
        occupied_channel_bandwidth : int
            Occupied bandwidth for metadata.
        values : ComplexArray
            List of complex-like samples for H(f). [(re, im), ...] or [complex, ...].

        Returns
        -------
        DsChannelEstAnalysisModel
            Typed model with carrier values, signal statistics, and echo results.
        """
        log = logging.getLogger(f"{cls.__name__}")

        channel_id: ChannelId = measurement.get("channel_id", INVALID_CHANNEL_ID)
        subcarrier_spacing: FrequencyHz = measurement.get(
            "subcarrier_spacing", INVALID_START_VALUE
        )
        first_active_subcarrier_index: int = measurement.get(
            "first_active_subcarrier_index", INVALID_START_VALUE
        )
        subcarrier_zero_frequency: FrequencyHz = measurement.get(
            "subcarrier_zero_frequency", INVALID_START_VALUE
        )
        occupied_channel_bandwidth: FrequencyHz = measurement.get(
            "occupied_channel_bandwidth", INVALID_START_VALUE
        )

        if (
            (first_active_subcarrier_index < 0)
            or (subcarrier_zero_frequency < 0)
            or (subcarrier_spacing <= 0)
        ):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        values: ComplexArray = measurement.get("values", [])
        if not values:
            raise ValueError(
                "No complex channel estimation values provided in measurement."
            )

        start_freq: FrequencyHz = cast(
            FrequencyHz,
            (subcarrier_spacing * first_active_subcarrier_index)
            + subcarrier_zero_frequency,
        )
        freqs: FrequencySeriesHz = cast(
            FrequencySeriesHz,
            [start_freq + (i * subcarrier_spacing) for i in range(len(values))],
        )

        gd = GroupDelay.from_channel_estimate(
            Hhat=values, df_hz=subcarrier_spacing, f0_hz=start_freq
        )
        gd_results = gd.to_result()

        cao = ComplexArrayOps(values)
        magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

        complex_arr = np.asarray(
            [
                complex(v[0], v[1])
                if not isinstance(v, complex)
                and isinstance(v, (list, tuple))
                and len(v) == 2
                else complex(v)
                for v in values
            ],
            dtype=np.complex128,
        )

        try:
            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(subcarrier_spacing) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz=FrequencyHz(subcarrier_spacing),
                cutoff_hz=cutoff_hz,
                order=DEFAULT_BUTTERWORTH_ORDER,
                zero_phase=True,
            )

            mag_result = mag_filter.apply(
                np.asarray(magnitudes_db_raw, dtype=np.float64)
            )
            magnitudes_db: FloatSeries = mag_result.filtered_values.tolist()
        except Exception:
            magnitudes_db = magnitudes_db_raw

        signal_stats_model: SignalStatisticsModel = SignalStatistics(
            magnitudes_db
        ).compute()

        group_delay_stats: GrpDelayStatsModel = GrpDelayStatsModel(
            group_delay_unit="microsecond",
            magnitude=ComplexArrayOps.to_list(gd_results.group_delay_us),
        )

        magn_linear = np.power(10.0, np.asarray(magnitudes_db, dtype=np.float64) / 20.0)
        phases = np.angle(complex_arr)
        H_smooth = magn_linear * np.exp(1j * phases)

        N = len(values)
        n_fft = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        fs = float(N) * float(subcarrier_spacing)
        max_delay_s = 3.5e-6

        v = SPEED_OF_LIGHT * CABLE_VF.get(cable_type.name, 0.87)
        max_dist_m = 0.5 * v * max_delay_s
        i_stop = int(max_delay_s * fs)
        log.debug(
            "EchoDetector window: fs=%.3f Hz, n_fft=%d, i_stop=%d bins, max_delay=%.2fus, max_dist≈%.1f m",
            fs,
            n_fft,
            i_stop,
            max_delay_s * 1e6,
            max_dist_m,
        )

        det = EchoDetector(
            freq_data=H_smooth.tolist(),
            subcarrier_spacing_hz=float(subcarrier_spacing),
            n_fft=4096,
            cable_type=cable_type.name,
            channel_id=channel_id,
        )

        max_delay_s_used = 3.5e-6
        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode="db_down",
            threshold_db_down=60.0,
            normalize_power=True,
            guard_bins=16,
            min_separation_s=8.0 / det.fs,
            max_delay_s=max_delay_s_used,
            max_peaks=3,
            include_time_response=False,
            direct_at_zero=True,
            window="hann",
        )

        i_stop = int(np.ceil(max_delay_s_used * det.fs))
        edge_guard = 8
        if echo_report.echoes:
            echo_report.echoes = [
                e for e in echo_report.echoes if (e.bin_index < (i_stop - edge_guard))
            ]

        echo_rpt = EchoDatasetModel(type=EchoDetectorType.IFFT, report=echo_report)

        carrier_values: ChanEstCarrierModel = ChanEstCarrierModel(
            carrier_count=len(freqs),
            frequency_unit="Hz",
            frequency=freqs,
            complex=values,
            complex_dimension=int(complex_arr.ndim),
            magnitudes=magnitudes_db,
            group_delay=group_delay_stats,
            occupied_channel_bandwidth=occupied_channel_bandwidth,
        )

        result_model: DsChannelEstAnalysisModel = DsChannelEstAnalysisModel(
            device_details=measurement.get("device_details", {}),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=measurement.get("mac_address", ""),
            channel_id=ChannelId(measurement.get("channel_id", INVALID_START_VALUE)),
            subcarrier_spacing=subcarrier_spacing,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            carrier_values=carrier_values,
            signal_statistics=signal_stats_model,
            echo=echo_rpt,
        )

        return result_model

    @classmethod
    def basic_analysis_ds_modulation_profile(
        cls, measurement: Mapping[str, Any], split_carriers: bool = True
    ) -> DsModulationProfileAnalysisModel:
        """
        Analyze the Downstream OFDM Modulation Profile and return a typed model.

        Parameters
        ----------
        measurement : Mapping[str, Any]
            Expected keys (subset):
            - subcarrier_spacing : int (Hz)
            - first_active_subcarrier_index : int
            - subcarrier_zero_frequency : int (Hz)
            - mac_address : str
            - channel_id : int
            - device_details : Mapping[str, Any] (optional passthrough)
            - pnm_header : Mapping[str, Any] (optional passthrough)
            - profiles : list of dicts:
                    {
                        "profile_id": int,
                        "schemes": list[SchemeModel-like]
                    }

            Each scheme item is one of:
            - schema_type = 0 (range):
                    {
                        "schema_type": 0,
                        "modulation_order": "qam_256" | "plc" | "exclusion" | "continuous_pilot" | ...,
                        "num_subcarriers": int
                    }
            - schema_type = 1 (skip):
                    {
                        "schema_type": 1,
                        "main_modulation_order": "...",
                        "skip_modulation_order": "...",
                        "num_subcarriers": int
                    }

        split_carriers : bool, default True
            Controls how per-carrier results are represented in the output:

            * True  → **split layout** (compact parallel arrays). Best for fast analytics,
                    vectorized ops, plotting, and storage efficiency.
            * False → **list layout** (verbose per-carrier records). Best for inspection/logging.

        Returns
        -------
        DsModulationProfileAnalysisModel

        Raises
        ------
        ValueError
            If spacing/indices/frequencies are invalid.
        """
        spacing: FrequencyHz = FrequencyHz(
            measurement.get("subcarrier_spacing", INVALID_START_VALUE)
        )
        active_index: int = int(
            measurement.get("first_active_subcarrier_index", INVALID_START_VALUE)
        )
        zero_freq: FrequencyHz = FrequencyHz(
            measurement.get("subcarrier_zero_frequency", INVALID_START_VALUE)
        )

        if active_index < 0 or zero_freq < 0 or spacing <= 0:
            raise ValueError(
                f"Invalid parameters: spacing={spacing}, active_index={active_index}, zero_freq={zero_freq}"
            )

        # Calculate Start Frequency
        start_freq = zero_freq + spacing * active_index

        out = DsModulationProfileAnalysisModel(
            device_details=measurement.get("device_details", {}),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=MacAddressStr(
                measurement.get("mac_address", MacAddress.null())
            ),
            channel_id=ChannelId(measurement.get("channel_id", INVALID_CHANNEL_ID)),
            frequency_unit="Hz",
            shannon_min_unit="dB",
            profiles=[],
        )

        for profile in measurement.get("profiles", []) or []:
            profile_id = ProfileId(profile.get("profile_id", INVALID_PROFILE_ID))
            schemes = profile.get("schemes", []) or []

            carrier_values = cls._build_carrier_values_from_mapping(
                schemes=schemes,
                start_freq=start_freq,
                spacing=spacing,
                split_carriers=split_carriers,
            )

            out.profiles.append(
                ProfileAnalysisEntryModel(
                    profile_id=profile_id,
                    carrier_values=carrier_values,
                )
            )

        return out

    @classmethod
    def _build_carrier_values_from_mapping(
        cls,
        schemes: list[dict[str, Any]],
        start_freq: FrequencyHz,
        spacing: FrequencyHz,
        split_carriers: bool,
    ) -> CarrierValuesModel:
        freq_list: FrequencySeriesHz = []
        mod_list: list[str] = []
        shan_list: list[float] = []
        carrier_items: list[CarrierItemModel] = []

        freq_ptr = start_freq
        for scheme in schemes:
            schema_type = int(scheme.get("schema_type", INVALID_SCHEMA_TYPE))

            if schema_type == CmDsOfdmModulationProfile.RANGE_MODULATION:
                mod_name: str = str(scheme.get("modulation_order"))
                count: int = int(scheme.get("num_subcarriers", 0))
            elif schema_type == CmDsOfdmModulationProfile.SKIP_MODULATION:
                mod_name = str(scheme.get("main_modulation_order"))
                count = int(scheme.get("num_subcarriers", 0))
            else:
                logging.warning(
                    f"basic_analysis_ds_modulation_profile() -> Unknown Schema: {schema_type}"
                )
                continue

            freq_ptr = cls._append_carriers(
                freq_ptr=freq_ptr,
                spacing=spacing,
                mod_name=mod_name,
                count=count,
                split_carriers=split_carriers,
                freq_list=freq_list,
                mod_list=mod_list,
                shan_list=shan_list,
                carrier_items=carrier_items,
            )

        return cls._build_carrier_values(
            split_carriers=split_carriers,
            freq_list=freq_list,
            mod_list=mod_list,
            shan_list=shan_list,
            carrier_items=carrier_items,
        )

    @classmethod
    def basic_analysis_us_ofdma_pre_equalization(
        cls, measurement: dict[str, Any]
    ) -> UsOfdmaUsPreEqAnalysisModel:
        """
        Perform Upstream OFDMA Pre-Equalization Analysis.

        Computes:
        - Per-subcarrier frequency axis (Hz)
        - Magnitude sequence (dB) from complex coefficients
        - Group delay (µs) from phase slope across subcarriers
        - IFFT-based echo detection over a constrained delay window
        - Complex samples passthrough
        - Signal statistics over the magnitude sequence

        Expected Keys (subset) in `measurement`
        ---------------------------------------
        channel_id : int
            Upstream OFDMA channel ID.
        subcarrier_spacing : int
            Δf in Hz between subcarriers.
        first_active_subcarrier_index : int
            Index of the first active subcarrier relative to subcarrier 0.
        subcarrier_zero_frequency : int
            Frequency (Hz) of subcarrier 0.
        occupied_channel_bandwidth : int
            Occupied bandwidth for metadata.
        values : ComplexArray
            List of complex-like samples for H(f). [(re, im), ...] or [complex, ...].

        Returns
        -------
        UsOfdmaUsPreEqAnalysisModel
            Typed model with carrier values, signal statistics, and echo results.
        """
        log = logging.getLogger(f"{cls.__name__}")

        channel_id: ChannelId = measurement.get("channel_id", INVALID_CHANNEL_ID)
        subcarrier_spacing: FrequencyHz = measurement.get(
            "subcarrier_spacing", INVALID_START_VALUE
        )
        first_active_subcarrier_index: int = measurement.get(
            "first_active_subcarrier_index", INVALID_START_VALUE
        )
        subcarrier_zero_frequency: FrequencyHz = measurement.get(
            "subcarrier_zero_frequency", INVALID_START_VALUE
        )
        occupied_channel_bandwidth: FrequencyHz = measurement.get(
            "occupied_channel_bandwidth", INVALID_START_VALUE
        )

        if (
            (first_active_subcarrier_index < 0)
            or (subcarrier_zero_frequency < 0)
            or (subcarrier_spacing <= 0)
        ):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        values: ComplexArray = measurement.get("values", [])
        if not values:
            raise ValueError(
                "No complex pre-equalization values provided in measurement."
            )

        start_freq: FrequencyHz = cast(
            FrequencyHz,
            (subcarrier_spacing * first_active_subcarrier_index)
            + subcarrier_zero_frequency,
        )
        freqs: FrequencySeriesHz = cast(
            FrequencySeriesHz,
            [start_freq + (i * subcarrier_spacing) for i in range(len(values))],
        )

        gd = GroupDelay.from_channel_estimate(
            Hhat=values, df_hz=subcarrier_spacing, f0_hz=start_freq
        )
        gd_results = gd.to_result()

        cao = ComplexArrayOps(values)
        magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

        complex_arr = np.asarray(
            [
                complex(v[0], v[1])
                if (not isinstance(v, complex))
                and isinstance(v, (list, tuple))
                and len(v) == 2
                else complex(v)
                for v in values
            ],
            dtype=np.complex128,
        )

        try:
            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(subcarrier_spacing) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz=FrequencyHz(subcarrier_spacing),
                cutoff_hz=cutoff_hz,
                order=DEFAULT_BUTTERWORTH_ORDER,
                zero_phase=True,
            )

            mag_result = mag_filter.apply(
                np.asarray(magnitudes_db_raw, dtype=np.float64)
            )
            magnitudes_db: FloatSeries = mag_result.filtered_values.tolist()
        except Exception:
            magnitudes_db = magnitudes_db_raw

        signal_stats_model: SignalStatisticsModel = SignalStatistics(
            magnitudes_db
        ).compute()

        group_delay_stats: GrpDelayStatsModel = GrpDelayStatsModel(
            group_delay_unit="microsecond",
            magnitude=ComplexArrayOps.to_list(gd_results.group_delay_us),
        )

        magn_linear = np.power(10.0, np.asarray(magnitudes_db, dtype=np.float64) / 20.0)
        phases = np.angle(complex_arr)
        H_smooth = magn_linear * np.exp(1j * phases)

        N = len(values)
        n_fft = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        fs = float(N) * float(subcarrier_spacing)
        max_delay_s_used = 3.5e-6

        cable_type_name = "RG6"
        v = SPEED_OF_LIGHT * CABLE_VF.get(cable_type_name, 0.87)
        max_dist_m = 0.5 * v * max_delay_s_used
        i_stop = int(max_delay_s_used * fs)
        log.debug(
            "US OFDMA Pre-Eq EchoDetector window: fs=%.3f Hz, n_fft=%d, i_stop=%d bins, "
            "max_delay=%.2fus, max_dist≈%.1f m",
            fs,
            n_fft,
            i_stop,
            max_delay_s_used * 1e6,
            max_dist_m,
        )

        det = EchoDetector(
            freq_data=H_smooth.tolist(),
            subcarrier_spacing_hz=float(subcarrier_spacing),
            n_fft=4096,
            cable_type=cable_type_name,
            channel_id=channel_id,
        )

        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode="db_down",
            threshold_db_down=60.0,
            normalize_power=True,
            guard_bins=16,
            min_separation_s=8.0 / det.fs,
            max_delay_s=max_delay_s_used,
            max_peaks=3,
            include_time_response=False,
            direct_at_zero=True,
            window="hann",
        )

        i_stop = int(np.ceil(max_delay_s_used * det.fs))
        edge_guard = 8
        if echo_report.echoes:
            echo_report.echoes = [
                e for e in echo_report.echoes if (e.bin_index < (i_stop - edge_guard))
            ]

        echo_rpt = EchoDatasetModel(
            type=EchoDetectorType.IFFT,
            report=echo_report,
        )

        carrier_values: OfdmaUsPreEqCarrierModel = OfdmaUsPreEqCarrierModel(
            carrier_count=len(freqs),
            frequency_unit="Hz",
            frequency=freqs,
            complex=values,
            complex_dimension=int(complex_arr.ndim),
            magnitudes=magnitudes_db,
            group_delay=group_delay_stats,
            occupied_channel_bandwidth=occupied_channel_bandwidth,
        )

        result_model: UsOfdmaUsPreEqAnalysisModel = UsOfdmaUsPreEqAnalysisModel(
            device_details=measurement.get("device_details", {}),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=MacAddressStr(measurement.get("mac_address", "")),
            channel_id=ChannelId(channel_id),
            subcarrier_spacing=subcarrier_spacing,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            carrier_values=carrier_values,
            signal_statistics=signal_stats_model,
            echo=echo_rpt,
        )

        if log.isEnabledFor(logging.DEBUG):
            LogFile.write(
                f"UsOfdmaUsPreEqAnalysisModel_{result_model.mac_address}_{result_model.channel_id}.log",
                result_model,
            )

        return result_model

    @classmethod
    def basic_analysis_ds_constellation_display(
        cls, measurement: dict[str, Any]
    ) -> ConstellationDisplayAnalysisModel:
        """
        Build a minimal constellation analysis payload from a downstream OFDM
        measurement dictionary.

        CM Output Assumption
        --------------------
        The DOCSIS spec states the constellation display samples are provided as
        s2.13 **soft decisions scaled to ~unit average power** at the slicer input.
        Because your LUT hard points are likewise normalized, **do not rescale**
        the CM-provided soft points here.

        Parameters
        ----------
        measurement : dict
            Expected keys (subset):
            - ``samples`` : ComplexArray (list of [real, imag]) — required
            - ``pnm_header`` : dict
            - ``mac_address`` : str
            - ``channel_id`` : int
            - ``num_sample_symbols`` : int (defaults to len(samples))
            - ``actual_modulation_order`` : int | str (e.g., 256 or "QAM-256")

        Returns
        -------
        ConstellationDisplayAnalysisModel
            Typed model carrying device/header info, inferred QAM order,
            **hard** constellation points from the LUT, and the **unscaled soft**
            decision coordinates provided by the CM.

        Raises
        ------
        ValueError
            If ``samples`` is missing or empty.
        """
        samples: ComplexArray = measurement.get("samples") or []
        if not samples:
            raise ValueError(
                "measurement['samples'] is required and must be a non-empty ComplexArray."
            )

        # Map actual modulation order → QamModulation
        amo: int | str = measurement.get(
            "actual_modulation_order", DsOfdmModulationType.UNKNOWN
        )
        qm: QamModulation = QamModulation.from_DsOfdmModulationType(amo)

        # Hard points come from LUT (already normalized)
        hard = QamLutManager().get_hard_decisions(qm)

        # IMPORTANT: Do NOT rescale the CM soft decisions; they are already unit-power normalized (s2.13).
        soft = samples

        return ConstellationDisplayAnalysisModel(
            device_details=measurement.get("device_details", SystemDescriptor.empty()),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=measurement.get("mac_address", MacAddress.null()),
            channel_id=measurement.get("channel_id", INVALID_CHANNEL_ID),
            num_sample_symbols=measurement.get("num_sample_symbols", len(samples)),
            modulation_order=qm,  # QamModulation
            hard=hard,  # LUT hard points (normalized)
            soft=soft,  # CM soft decisions (already normalized) ← changed
        )

    @classmethod
    def basic_analysis_ds_histogram(
        cls, measurement: dict[str, Any]
    ) -> DsHistogramAnalysisModel:
        """
        Build a :class:`DsHistogramAnalysisModel` from a downstream histogram payload.

        Parameters
        ----------
        measurement : dict
            Expected keys (subset):
                - ``device_details`` : dict
                - ``pnm_header`` : dict
                - ``mac_address`` : str
                - ``channel_id`` : int
                - ``symmetry`` : int
                - ``dwell_count`` : int
                - ``hit_counts`` : List[int]

        Returns
        -------
        DsHistogramAnalysisModel
            Typed model with histogram metrics and metadata.
        """
        return DsHistogramAnalysisModel(
            device_details=measurement.get("device_details", SystemDescriptor.empty()),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=measurement.get("mac_address", MacAddress.null()),
            channel_id=measurement.get("channel_id", INVALID_CHANNEL_ID),
            symmetry=measurement.get("symmetry", -1),
            dwell_counts=measurement.get("dwell_count_values", []),
            hit_counts=measurement.get("hit_count_values", []),
        )

    @classmethod
    def basic_analysis_ds_ofdm_fec_summary(
        cls, measurement: dict[str, Any]
    ) -> OfdmFecSummaryAnalysisModel:
        """
        Build an OfdmFecSummaryAnalysisModel from a DS OFDM FEC summary payload.

        Accepts EITHER:
        - parser shape:   fec_summary_data[*].codeword_entries.{timestamp,total_codewords,corrected,uncorrectable}
        - analysis shape: profiles[*].codewords.{timestamps,total_codewords,corrected,uncorrected}

        Truncates to the shortest parallel length per profile and logs length issues.
        """
        log = logging.getLogger(getattr(cls, "__name__", "OfdmFecSummaryAnalysis"))

        # Prefer parser shape; fall back to analysis shape.
        raw_profiles = measurement.get("fec_summary_data")
        alt_profiles = measurement.get("profiles")

        profiles_src = (
            "fec_summary_data"
            if raw_profiles
            else ("profiles" if alt_profiles else None)
        )
        prof_iter = raw_profiles if raw_profiles is not None else (alt_profiles or [])

        if profiles_src is None:
            log.warning(
                "FEC Summary: no 'fec_summary_data' or 'profiles' in measurement; returning empty model."
            )
            return OfdmFecSummaryAnalysisModel(
                device_details=measurement.get("device_details", {}),
                pnm_header=measurement.get("pnm_header", {}),
                mac_address=measurement.get("mac_address", MacAddress.null()),
                channel_id=ChannelId(measurement.get("channel_id", INVALID_CHANNEL_ID)),
                profiles=[],
            )

        out_profiles: list[OfdmFecSummaryProfileModel] = []

        for idx, prof in enumerate(prof_iter):
            # Profile id + declared sets field name differs per shape.
            profile_id = ProfileId(
                prof.get("profile_id", prof.get("profile", INVALID_CHANNEL_ID))
            )
            declared_sets = int(prof.get("number_of_sets", 0))

            # Choose inner block by shape:
            # - parser shape:   codeword_entries.{timestamp, total_codewords, corrected, uncorrectable}
            # - analysis shape: codewords.{timestamps, total_codewords, corrected, uncorrected}
            cwe = prof.get("codeword_entries")
            if cwe is None:
                cwe = prof.get("codewords") or {}

            # Try both key spellings for timestamps
            ts_raw = cwe.get("timestamp")
            if ts_raw is None:
                ts_raw = cwe.get("timestamps")

            # Coerce to ints; be tolerant of None/empty lists
            ts_list = [int(x) for x in (ts_raw or [])]
            tot_list = [int(x) for x in (cwe.get("total_codewords") or [])]
            cor_list = [int(x) for x in (cwe.get("corrected") or [])]
            unc_list = [int(x) for x in (cwe.get("uncorrectable") or [])]

            n = (
                min(len(ts_list), len(tot_list), len(cor_list), len(unc_list))
                if any((ts_list, tot_list, cor_list, unc_list))
                else 0
            )

            if n and any(
                len(lst) != n for lst in (ts_list, tot_list, cor_list, unc_list)
            ):
                log.warning(
                    "FEC Summary: profile=%s (%s[%d]) series mismatch; truncating to %d "
                    "(ts=%d, total=%d, corrected=%d, uncorrectable=%d)",
                    profile_id,
                    profiles_src,
                    idx,
                    n,
                    len(ts_list),
                    len(tot_list),
                    len(cor_list),
                    len(unc_list),
                )
                ts_list, tot_list, cor_list, unc_list = (
                    ts_list[:n],
                    tot_list[:n],
                    cor_list[:n],
                    unc_list[:n],
                )

            if declared_sets and declared_sets != n:
                log.debug(
                    "FEC Summary: profile=%s declared number_of_sets=%d, computed=%d; using computed.",
                    profile_id,
                    declared_sets,
                    n,
                )

            # Helpful debug when n == 0 so you can see the shape that arrived
            if n == 0:
                log.debug(
                    "FEC Summary: profile=%s has no aligned data (src=%s[%d]); "
                    "lens ts/total/corr/unc = %d/%d/%d/%d; keys=%s",
                    profile_id,
                    profiles_src,
                    idx,
                    len(ts_list),
                    len(tot_list),
                    len(cor_list),
                    len(unc_list),
                    list(cwe.keys()),
                )

            cw = FecSummaryCodeWordModel(
                timestamps=ts_list,
                total_codewords=tot_list,
                corrected=cor_list,
                uncorrected=unc_list,
            )

            out_profiles.append(
                OfdmFecSummaryProfileModel(
                    profile=profile_id,
                    number_of_sets=n,
                    codewords=cw,
                )
            )

        # Optional top-level sanity
        declared_num_profiles = int(measurement.get("num_profiles", len(out_profiles)))
        if declared_num_profiles != len(out_profiles):
            log.debug(
                "FEC Summary: num_profiles declared=%d, parsed=%d",
                declared_num_profiles,
                len(out_profiles),
            )

        return OfdmFecSummaryAnalysisModel(
            device_details=measurement.get("device_details", {}),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=measurement.get("mac_address", MacAddress.null()),
            channel_id=ChannelId(measurement.get("channel_id", INVALID_CHANNEL_ID)),
            profiles=out_profiles,
        )

    @classmethod
    def basic_analysis_spectrum_analyzer(
        cls,
        measurement: dict[str, Any],
        analysis_parameters: AnalysisProcessParameters | None,
    ) -> SpectrumAnalyzerAnalysisModel:
        """
        Build SpectrumAnalyzerAnalysisModel from converted PNM measurement:
        """
        log = logging.getLogger(f"{cls.__name__}")
        # --- core params ---
        first_seg_cf = int(measurement.get("first_segment_center_frequency", 0))
        last_seg_cf = int(measurement.get("last_segment_center_frequency", 0))
        seg_span_hz = int(measurement.get("segment_frequency_span", 0))
        bins_per_seg = int(measurement.get("num_bins_per_segment", 0))
        enbw_hz = float(measurement.get("equivalent_noise_bandwidth", 0.0))
        noise_bw_khz = int(round(enbw_hz / 1_000.0)) if enbw_hz > 0.0 else 0

        wf_raw = int(measurement.get("window_function", WindowFunction.HANN.value))
        try:
            wf_enum: WindowFunction = WindowFunction(wf_raw)
        except Exception:
            wf_enum = WindowFunction.HANN

        bin_bw = int(measurement.get("bin_frequency_spacing", 0))
        if bin_bw <= 0 and seg_span_hz > 0 and bins_per_seg > 0:
            bin_bw = max(1, seg_span_hz // bins_per_seg)

        # --- segments & magnitudes ---
        segments = measurement.get("amplitude_bin_segments_float", [])
        num_segments = len(segments)
        if bins_per_seg <= 0 and num_segments:
            bins_per_seg = len(segments[0])

        # Normalize each segment length to bins_per_seg (clip/pad NaN)
        norm_segments: list[list[float]] = []
        for s in segments:
            if len(s) >= bins_per_seg:
                norm_segments.append([float(x) for x in s[:bins_per_seg]])
            else:
                pad = [float("nan")] * (bins_per_seg - len(s))
                norm_segments.append([float(x) for x in s] + pad)

        magnitudes: MagnitudeSeries = [x for seg in norm_segments for x in seg]

        # --- compute frequency axis across segments ---
        frequencies: FrequencySeriesHz = []
        if (
            num_segments > 0
            and bins_per_seg > 0
            and seg_span_hz > 0
            and bin_bw > 0
            and first_seg_cf > 0
        ):
            seg_step_hz = (
                (last_seg_cf - first_seg_cf) // (num_segments - 1)
                if num_segments > 1
                else 0
            )
            # start at center - span/2, align to bin center with +bin_bw/2
            seg0_start = first_seg_cf - (seg_span_hz // 2) + (bin_bw // 2)

            freqs: FrequencySeriesHz = []
            for s_idx in range(num_segments):
                start_hz = seg0_start + s_idx * seg_step_hz
                freqs.extend(int(start_hz + i * bin_bw) for i in range(bins_per_seg))
            frequencies = freqs

        # --- align lengths (trim to shortest) ---
        if frequencies and magnitudes and len(frequencies) != len(magnitudes):
            n = min(len(frequencies), len(magnitudes))
            frequencies = frequencies[:n]
            magnitudes = magnitudes[:n]
        if not frequencies or not magnitudes:
            frequencies, magnitudes = [], []

        # --- windowed average (same length) ---
        # TODO: Need to clean this up, need to move the DEFAULT to the Model in a better way
        if analysis_parameters:
            log.debug(
                "Spectrum Analyzer: applying moving average with parameters: %s",
                analysis_parameters,
            )
            window_points = analysis_parameters.moving_average.points
        else:
            log.warning(
                "Spectrum Analyzer: applying DEFAULT moving average: %s",
                DEFAULT_POINT_AVG,
            )
            window_points = DEFAULT_POINT_AVG

        try:
            ma = MovingAverage(max(1, window_points), mode="reflect")
            smoothed = ma.apply(magnitudes) if magnitudes else []
        except Exception:
            smoothed = list(magnitudes)

        if len(smoothed) != len(frequencies):
            smoothed = smoothed[: len(frequencies)]

        window_avg = WindowAverage(points=max(1, window_points), magnitudes=smoothed)

        results = SpecAnaAnalysisResults(
            bin_bandwidth=bin_bw,
            segment_length=bins_per_seg,
            frequencies=frequencies,
            magnitudes=magnitudes,
            window_average=window_avg,
        )

        capture_parameters: SpecAnCapturePara = SpecAnCapturePara(
            first_segment_center_freq=FrequencyHz(first_seg_cf),
            last_segment_center_freq=FrequencyHz(last_seg_cf),
            segment_freq_span=FrequencyHz(seg_span_hz),
            num_bins_per_segment=bins_per_seg,
            noise_bw=noise_bw_khz,
            window_function=wf_enum,
        )

        return SpectrumAnalyzerAnalysisModel(
            device_details=measurement.get("device_details", SystemDescriptor.empty()),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=measurement.get("mac_address", MacAddress.null()),
            channel_id=ChannelId(measurement.get("channel_id", 0)),
            capture_parameters=capture_parameters,
            signal_analysis=results,
        )

    @classmethod
    def basic_analysis_spectrum_analyzer_snmp(
        cls,
        measurement: dict[str, Any],
        analysis_parameters: AnalysisProcessParameters | None = None,
    ) -> SpectrumAnalyzerAnalysisModel:
        log = logging.getLogger(f"{cls.__name__}")

        freqs: FrequencySeriesHz = list(measurement.get("frequency", []) or [])
        mags: MagnitudeSeries = [
            float(x) for x in (measurement.get("amplitude", []) or [])
        ]

        if not freqs or not mags:
            raise ValueError(
                "Spectrum Analyzer (SNMP): 'frequency' and 'amplitude' must be non-empty."
            )
        if len(freqs) != len(mags):
            n = min(len(freqs), len(mags))
            log.warning(
                "Spectrum Analyzer (SNMP): len mismatch freq=%d amp=%d; truncating to %d",
                len(freqs),
                len(mags),
                n,
            )
            freqs, mags = freqs[:n], mags[:n]

        # Infer bin bandwidth from median positive Δf (robust to occasional glitches)
        try:
            if len(freqs) >= 2:
                diffs = np.diff(np.asarray(freqs, dtype=np.int64))
                pos_diffs = diffs[diffs > 0]
                bin_bw = int(np.median(pos_diffs)) if pos_diffs.size else int(diffs[0])
            else:
                bin_bw = 0
        except Exception:
            bin_bw = 0

        first_hz: int = int(freqs[0])
        last_hz: int = int(freqs[-1])
        span_hz: int = abs(last_hz - first_hz)
        bins: int = len(freqs)

        # Moving-average (windowed) smoothing
        if analysis_parameters:
            window_points = int(max(1, analysis_parameters.moving_average.points))
        else:
            window_points = int(max(1, DEFAULT_POINT_AVG))

        try:
            ma = MovingAverage(window_points, mode="reflect")
            smoothed = ma.apply(mags) if mags else []
        except Exception:
            smoothed = list(mags)

        if len(smoothed) != len(freqs):
            smoothed = smoothed[: len(freqs)]

        window_avg = WindowAverage(points=window_points, magnitudes=smoothed)

        # Build results (single-sweep flattened to one "segment")
        results = SpecAnaAnalysisResults(
            bin_bandwidth=bin_bw,
            segment_length=bins,
            frequencies=freqs,
            magnitudes=mags,
            window_average=window_avg,
        )

        # Endpoints only; no center calculation
        enbw_hz = float(measurement.get("equivalent_noise_bandwidth", 0.0))
        noise_bw_khz = int(round(enbw_hz / 1_000.0)) if enbw_hz > 0.0 else 0

        capture_parameters: SpecAnCapturePara = SpecAnCapturePara(
            first_segment_center_freq=FrequencyHz(first_hz),
            last_segment_center_freq=FrequencyHz(last_hz),
            segment_freq_span=FrequencyHz(span_hz),
            num_bins_per_segment=bins,
            noise_bw=noise_bw_khz,
            window_function=WindowFunction.HANN,
        )

        return SpectrumAnalyzerAnalysisModel(
            device_details=measurement.get("device_details", SystemDescriptor.empty()),
            pnm_header=measurement.get("pnm_header", {}),
            mac_address=measurement.get("mac_address", MacAddress.null()),
            channel_id=ChannelId(measurement.get("channel_id", 0)),
            capture_parameters=capture_parameters,
            signal_analysis=results,
        )

    # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

    @classmethod
    def basic_analysis_rxmer_from_model(
        cls, model: CmDsOfdmRxMerModel
    ) -> DsRxMerAnalysisModel:
        """
        Perform basic RxMER analysis from a parsed :class:`CmDsOfdmRxMerModel`.

        This is the model-based counterpart to ``basic_analysis_rxmer(...)`` and builds
        a :class:`DsRxMerAnalysisModel` using typed fields instead of a raw measurement
        dictionary. It re-derives the frequency axis, carrier status classification, and
        regression line, while reusing metadata already normalized into the model.
        """
        channel_id: ChannelId = model.channel_id
        subcarrier_spacing: FrequencyHz = model.subcarrier_spacing
        first_active_subcarrier_index: int = model.first_active_subcarrier_index
        subcarrier_zero_frequency: FrequencyHz = model.subcarrier_zero_frequency

        if (
            (first_active_subcarrier_index < 0)
            or (subcarrier_zero_frequency < 0)
            or (subcarrier_spacing <= 0)
        ):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        magnitudes: FloatSeries = model.values
        if not magnitudes:
            raise ValueError("No RxMER values provided in model.")

        base_freq: FrequencyHz = FrequencyHz(
            (subcarrier_spacing * first_active_subcarrier_index)
            + subcarrier_zero_frequency
        )
        freqs: FrequencySeriesHz = [
            FrequencyHz(base_freq + (i * subcarrier_spacing))
            for i in range(len(magnitudes))
        ]

        def classify(v: float) -> int:
            if v == RXMER_EXCLUSION:
                return int(RxMerCarrierType.EXCLUSION.value)
            if v in (RXMER_CLIPPED_LOW, RXMER_CLIPPED_HIGH):
                return int(RxMerCarrierType.CLIPPED.value)
            return int(RxMerCarrierType.NORMAL.value)

        carrier_status: IntSeries = [classify(v) for v in magnitudes]

        if not (len(freqs) == len(magnitudes) == len(carrier_status)):
            raise ValueError(
                f"Length mismatch detected: frequencies({len(freqs)}), "
                f"magnitudes({len(magnitudes)}), carrier_status({len(carrier_status)})"
            )

        regession_model = RegressionModel(
            slope=cast(
                FloatSeries,
                LinearRegression1D(
                    cast(ArrayLike, magnitudes), cast(ArrayLike, freqs)
                ).regression_line(),
            )
        )

        csm: dict[str, Any] = {
            RxMerCarrierType.EXCLUSION.name.lower(): RxMerCarrierType.EXCLUSION.value,
            RxMerCarrierType.CLIPPED.name.lower(): RxMerCarrierType.CLIPPED.value,
            RxMerCarrierType.NORMAL.name.lower(): RxMerCarrierType.NORMAL.value,
        }

        carrier_values = RxMerCarrierValuesModel(
            carrier_status_map=csm,
            carrier_count=len(freqs),
            magnitude=magnitudes,
            frequency=freqs,
            carrier_status=carrier_status,
        )

        return DsRxMerAnalysisModel(
            device_details=getattr(model, "device_details", {}),
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else getattr(model, "pnm_header", {}),
            mac_address=MacAddressStr(getattr(model, "mac_address", MacAddress.null())),
            channel_id=channel_id,
            subcarrier_spacing=subcarrier_spacing,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            carrier_values=carrier_values,
            regression=regession_model,
            modulation_statistics=model.modulation_statistics,
        )

    @classmethod
    def basic_analysis_ds_chan_est_from_model(
        cls,
        model: CmDsOfdmChanEstimateCoefModel,
        cable_type: CableType = CableType.RG6,
    ) -> DsChannelEstAnalysisModel:
        """
        Model-based variant of downstream channel-estimation analysis.

        Mirrors `basic_analysis_ds_chan_est()` but accepts a parsed
        `CmDsOfdmChanEstimateCoefModel` instead of a raw measurement dict.

        Computes:
        - Per-subcarrier frequency axis (Hz)
        - Magnitude sequence (dB) from complex coefficients, with optional
          Butterworth low-pass smoothing across subcarriers
        - Group delay (µs) from phase slope across subcarriers
        - IFFT-based echo detection over a constrained delay window
        - Complex samples passthrough
        - Signal statistics over the (smoothed) magnitude sequence
        """
        log = logging.getLogger(f"{cls.__name__}")

        subcarrier_spacing: FrequencyHz = FrequencyHz(
            int(getattr(model, "subcarrier_spacing", INVALID_START_VALUE))
        )
        first_active_subcarrier_index: int = int(
            getattr(model, "first_active_subcarrier_index", INVALID_START_VALUE)
        )
        subcarrier_zero_frequency: FrequencyHz = cast(
            FrequencyHz,
            int(getattr(model, "subcarrier_zero_frequency", INVALID_START_VALUE)),
        )
        occupied_channel_bandwidth: FrequencyHz = cast(
            FrequencyHz, int(getattr(model, "occupied_channel_bandwidth", 0))
        )

        if (
            (first_active_subcarrier_index < 0)
            or (subcarrier_zero_frequency < 0)
            or (subcarrier_spacing <= 0)
        ):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        values: ComplexArray = cast(ComplexArray, getattr(model, "values", []))
        if not values:
            raise ValueError("No complex channel estimation values provided in model.")

        start_freq: FrequencyHz = cast(
            FrequencyHz,
            (subcarrier_spacing * first_active_subcarrier_index)
            + subcarrier_zero_frequency,
        )
        freqs: FrequencySeriesHz = cast(
            FrequencySeriesHz,
            [start_freq + (i * subcarrier_spacing) for i in range(len(values))],
        )

        gd = GroupDelay.from_channel_estimate(
            Hhat=values, df_hz=subcarrier_spacing, f0_hz=start_freq
        )
        gd_results = gd.to_result()

        cao = ComplexArrayOps(values)
        magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

        complex_arr = np.asarray(
            [
                complex(v[0], v[1])
                if not isinstance(v, complex)
                and isinstance(v, (list, tuple))
                and len(v) == 2
                else complex(v)
                for v in values
            ],
            dtype=np.complex128,
        )

        try:
            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(subcarrier_spacing) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz=FrequencyHz(int(subcarrier_spacing)),
                cutoff_hz=cutoff_hz,
                order=DEFAULT_BUTTERWORTH_ORDER,
                zero_phase=True,
            )

            mag_result = mag_filter.apply(
                np.asarray(magnitudes_db_raw, dtype=np.float64)
            )
            magnitudes_db: FloatSeries = mag_result.filtered_values.tolist()
        except Exception:
            magnitudes_db = magnitudes_db_raw

        signal_stats_model: SignalStatisticsModel = SignalStatistics(
            magnitudes_db
        ).compute()

        group_delay_stats: GrpDelayStatsModel = GrpDelayStatsModel(
            group_delay_unit="microsecond",
            magnitude=ComplexArrayOps.to_list(gd_results.group_delay_us),
        )

        magn_linear = np.power(10.0, np.asarray(magnitudes_db, dtype=np.float64) / 20.0)
        phases = np.angle(complex_arr)
        H_smooth = magn_linear * np.exp(1j * phases)

        N = len(values)
        n_fft = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        fs = float(N) * float(subcarrier_spacing)
        max_delay_s_used = 3.5e-6

        v = SPEED_OF_LIGHT * CABLE_VF.get(cable_type.name, 0.87)
        max_dist_m = 0.5 * v * max_delay_s_used
        i_stop = int(max_delay_s_used * fs)
        log.debug(
            "DS ChanEst (model) EchoDetector window: fs=%.3f Hz, n_fft=%d, i_stop=%d bins, "
            "max_delay=%.2fus, max_dist≈%.1f m, cable_type=%s",
            fs,
            n_fft,
            i_stop,
            max_delay_s_used * 1e6,
            max_dist_m,
            cable_type.name,
        )

        det = EchoDetector(
            freq_data=H_smooth.tolist(),
            subcarrier_spacing_hz=float(subcarrier_spacing),
            n_fft=4096,
            cable_type=cable_type.name,
            channel_id=cast(
                ChannelId, int(getattr(model, "channel_id", INVALID_CHANNEL_ID))
            ),
        )

        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode="db_down",
            threshold_db_down=60.0,
            normalize_power=True,
            guard_bins=16,
            min_separation_s=8.0 / det.fs,
            max_delay_s=max_delay_s_used,
            max_peaks=3,
            include_time_response=False,
            direct_at_zero=True,
            window="hann",
        )

        i_stop = int(np.ceil(max_delay_s_used * det.fs))
        edge_guard = 8
        if echo_report.echoes:
            echo_report.echoes = [
                e for e in echo_report.echoes if (e.bin_index < (i_stop - edge_guard))
            ]

        echo_rpt = EchoDatasetModel(type=EchoDetectorType.IFFT, report=echo_report)

        carrier_values: ChanEstCarrierModel = ChanEstCarrierModel(
            carrier_count=len(freqs),
            frequency_unit="Hz",
            frequency=freqs,
            complex=values,
            complex_dimension=int(complex_arr.ndim),
            magnitudes=magnitudes_db,
            group_delay=group_delay_stats,
            occupied_channel_bandwidth=occupied_channel_bandwidth,
        )

        result_model: DsChannelEstAnalysisModel = DsChannelEstAnalysisModel(
            device_details=getattr(model, "device_details", {}),
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else {},
            mac_address=cast(MacAddressStr, getattr(model, "mac_address", "")),
            channel_id=cast(
                ChannelId, int(getattr(model, "channel_id", INVALID_START_VALUE))
            ),
            subcarrier_spacing=subcarrier_spacing,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            carrier_values=carrier_values,
            signal_statistics=signal_stats_model,
            echo=echo_rpt,
        )

        return result_model

    @classmethod
    def basic_analysis_ds_modulation_profile_from_model(
        cls, model: CmDsOfdmModulationProfileModel, split_carriers: bool = True
    ) -> DsModulationProfileAnalysisModel:
        """
        Analyze a Downstream OFDM Modulation Profile using a parsed model
        from :class:`CmDsOfdmModulationProfile`.
        """
        spacing: int = int(model.subcarrier_spacing)
        active_index: int = int(model.first_active_subcarrier_index)
        zero_freq: int = int(model.subcarrier_zero_frequency)

        if active_index < 0 or zero_freq < 0 or spacing <= 0:
            raise ValueError(
                f"Invalid parameters: spacing={spacing}, active_index={active_index}, zero_freq={zero_freq}"
            )

        start_freq = zero_freq + spacing * active_index

        result = DsModulationProfileAnalysisModel(
            device_details={},
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else {},
            mac_address=model.mac_address,
            channel_id=model.channel_id,
            frequency_unit="Hz",
            shannon_min_unit="dB",
            profiles=[],
        )

        for profile in model.profiles:
            profile_id = int(profile.profile_id)
            carrier_values = cls._build_carrier_values_from_models(
                schemes=profile.schemes,
                start_freq=start_freq,
                spacing=FrequencyHz(spacing),
                split_carriers=split_carriers,
            )

            result.profiles.append(
                ProfileAnalysisEntryModel(
                    profile_id=profile_id,
                    carrier_values=carrier_values,
                )
            )

        return result

    @classmethod
    def _build_carrier_values_from_models(
        cls,
        schemes: list[
            RangeModulationProfileSchemaModel | SkipModulationProfileSchemaModel
        ],
        start_freq: FrequencyHz,
        spacing: FrequencyHz,
        split_carriers: bool,
    ) -> CarrierValuesModel:
        freq_list: FrequencySeriesHz = []
        mod_list: list[str] = []
        shan_list: list[float] = []
        carrier_items: list[CarrierItemModel] = []

        freq_ptr = start_freq
        for scheme in schemes:
            if isinstance(scheme, RangeModulationProfileSchemaModel):
                mod_name = str(scheme.modulation_order)
                count = int(scheme.num_subcarriers)
            elif isinstance(scheme, SkipModulationProfileSchemaModel):
                mod_name = str(scheme.main_modulation_order)
                count = int(scheme.num_subcarriers)
            else:
                logging.warning(
                    f"Unknown modulation profile schema type: {getattr(scheme, 'schema_type', '?')}"
                )
                continue

            freq_ptr = cls._append_carriers(
                freq_ptr=freq_ptr,
                spacing=spacing,
                mod_name=mod_name,
                count=count,
                split_carriers=split_carriers,
                freq_list=freq_list,
                mod_list=mod_list,
                shan_list=shan_list,
                carrier_items=carrier_items,
            )

        return cls._build_carrier_values(
            split_carriers=split_carriers,
            freq_list=freq_list,
            mod_list=mod_list,
            shan_list=shan_list,
            carrier_items=carrier_items,
        )

    @classmethod
    def _append_carriers(
        cls,
        freq_ptr: FrequencyHz,
        spacing: FrequencyHz,
        mod_name: str,
        count: int,
        split_carriers: bool,
        freq_list: FrequencySeriesHz,
        mod_list: list[str],
        shan_list: list[float],
        carrier_items: list[CarrierItemModel],
    ) -> FrequencyHz:
        for _ in range(count):
            s_min = cls._resolve_shannon_min(mod_name)
            f_val = int(freq_ptr)

            if split_carriers:
                freq_list.append(f_val)
                mod_list.append(mod_name)
                shan_list.append(s_min)
            else:
                carrier_items.append(
                    CarrierItemModel(
                        frequency=f_val,
                        modulation=mod_name,
                        shannon_min_mer=s_min,
                    )
                )

            freq_ptr += spacing
        return freq_ptr

    @classmethod
    def _resolve_shannon_min(cls, mod_name: str) -> float:
        if mod_name in (
            ModulationOrderType.continuous_pilot.name,
            ModulationOrderType.exclusion.name,
        ):
            return 0.0
        if mod_name == ModulationOrderType.plc.name:
            return round(float(Shannon.bits_to_snr(4)), 2)
        return round(float(Shannon.snr_from_modulation(mod_name)), 2)

    @classmethod
    def _build_carrier_values(
        cls,
        split_carriers: bool,
        freq_list: FrequencySeriesHz,
        mod_list: list[str],
        shan_list: list[float],
        carrier_items: list[CarrierItemModel],
    ) -> CarrierValuesModel:
        if split_carriers:
            return CarrierValuesSplitModel(
                layout="split",
                frequency=freq_list,
                modulation=mod_list,
                shannon_min_mer=shan_list,
            )

        return CarrierValuesListModel(
            layout="list",
            carriers=carrier_items,
        )

    @classmethod
    def basic_analysis_ds_constellation_display_from_model(
        cls, model: CmDsConstDispMeasModel
    ) -> ConstellationDisplayAnalysisModel:
        """
        Build a constellation analysis payload from a parsed :class:`CmDsConstDispMeasModel`.

        This is the model-based counterpart to ``basic_analysis_ds_constellation_display(...)``.
        It interprets the parsed constellation capture (soft decisions, modulation order,
        and metadata) and returns a fully-typed :class:`ConstellationDisplayAnalysisModel`.

        CM Output Assumption
        --------------------
        DOCSIS defines the constellation display samples as s2.13 soft decisions that
        are already scaled to approximately unit average power at the slicer input.
        Because the LUT hard points are normalized in the same way, **no additional
        scaling is applied** to the soft samples here.

        Parameters
        ----------
        model : CmDsConstDispMeasModel
            Parsed constellation display measurement, including:
            - ``samples``                : ComplexArray of soft decisions
            - ``actual_modulation_order``: int modulation order (e.g., 256)
            - ``num_sample_symbols``     : number of captured symbols
            - common PNM header fields   : ``pnm_header``, ``mac_address``, ``channel_id``.

        Returns
        -------
        ConstellationDisplayAnalysisModel
            Typed model carrying device/header info, inferred QAM order, LUT-hard
            constellation points, and CM-provided soft decisions.

        Raises
        ------
        ValueError
            If ``model.samples`` is empty.
        """
        samples: ComplexArray = model.samples or []
        if not samples:
            raise ValueError(
                "CmDsConstDispMeasModel.samples must be a non-empty ComplexArray."
            )

        amo: int = int(getattr(model, "actual_modulation_order", 0))
        qm: QamModulation = QamModulation.from_DsOfdmModulationType(amo)

        hard: ComplexArray = QamLutManager().get_hard_decisions(qm)
        soft: ComplexArray = samples

        return ConstellationDisplayAnalysisModel(
            device_details=getattr(
                model, "device_details", SystemDescriptor.empty().to_dict()
            ),
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else getattr(model, "pnm_header", {}),
            mac_address=MacAddressStr(getattr(model, "mac_address", MacAddress.null())),
            channel_id=ChannelId(getattr(model, "channel_id", INVALID_CHANNEL_ID)),
            num_sample_symbols=int(getattr(model, "num_sample_symbols", len(samples))),
            modulation_order=qm,
            hard=hard,
            soft=soft,
        )

    @classmethod
    def basic_analysis_ds_histogram_from_model(
        cls, model: CmDsHistModel
    ) -> DsHistogramAnalysisModel:
        """
        Build a :class:`DsHistogramAnalysisModel` from a parsed :class:`CmDsHistModel`.

        This is the model-based counterpart to ``basic_analysis_ds_histogram(...)``.
        It preserves the parsed symmetry flag, dwell counts, and hit counts, while
        normalizing PNM header and MAC/channel metadata into the canonical analysis
        model used by the API layer.

        Parameters
        ----------
        model : CmDsHistModel
            Parsed downstream histogram PNM payload, including:
            - ``pnm_header``               : :class:`PnmHeaderParameters`
            - ``mac_address``              : MAC address string
            - ``symmetry``                 : histogram symmetry indicator
            - ``dwell_count_values_length``: declared dwell-count length
            - ``dwell_count_values``       : dwell-count series
            - ``hit_count_values_length``  : declared hit-count length
            - ``hit_count_values``         : hit-count series

        Returns
        -------
        DsHistogramAnalysisModel
            Typed histogram analysis payload suitable for downstream consumers.
        """
        log = logging.getLogger(f"{cls.__name__}")

        dwell_counts = list(model.dwell_count_values or [])
        hit_counts = list(model.hit_count_values or [])

        if model.dwell_count_values_length and model.dwell_count_values_length != len(
            dwell_counts
        ):
            new_len = min(model.dwell_count_values_length, len(dwell_counts))
            log.warning(
                "DsHistogram: dwell_count length mismatch; declared=%d, actual=%d, truncating to %d",
                model.dwell_count_values_length,
                len(dwell_counts),
                new_len,
            )
            dwell_counts = dwell_counts[:new_len]

        if model.hit_count_values_length and model.hit_count_values_length != len(
            hit_counts
        ):
            new_len = min(model.hit_count_values_length, len(hit_counts))
            log.warning(
                "DsHistogram: hit_count length mismatch; declared=%d, actual=%d, truncating to %d",
                model.hit_count_values_length,
                len(hit_counts),
                new_len,
            )
            hit_counts = hit_counts[:new_len]

        return DsHistogramAnalysisModel(
            device_details=getattr(model, "device_details", {}),
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else model.pnm_header,
            mac_address=model.mac_address or MacAddress.null(),
            channel_id=ChannelId(getattr(model, "channel_id", INVALID_CHANNEL_ID)),
            symmetry=model.symmetry,
            dwell_counts=dwell_counts,
            hit_counts=hit_counts,
        )

    @classmethod
    def basic_analysis_ds_ofdm_fec_summary_from_model(
        cls, model: CmDsOfdmFecSummaryModel
    ) -> OfdmFecSummaryAnalysisModel:
        """
        Build an :class:`OfdmFecSummaryAnalysisModel` from a parsed
        :class:`CmDsOfdmFecSummaryModel`.

        This is the model-based counterpart to ``basic_analysis_ds_ofdm_fec_summary(...)``.
        It maps the parser-facing structures:

        * :class:`OfdmFecSumDataModel`          → :class:`OfdmFecSummaryProfileModel`
        * :class:`OfdmFecSumCodeWordEntryModel` → :class:`FecSummaryCodeWordModel`

        while carrying forward common analysis metadata from ``CmDsOfdmFecSummaryModel``.

        Parameters
        ----------
        model : CmDsOfdmFecSummaryModel
            Canonical DOCSIS downstream OFDM FEC summary model, including:
            - ``pnm_header``       : :class:`PnmHeaderParameters`
            - ``channel_id``       : ChannelId
            - ``mac_address``      : MAC address string
            - ``summary_type``     : CM-OSSI summary type enum
            - ``num_profiles``     : declared profile count
            - ``fec_summary_data`` : list of :class:`OfdmFecSumDataModel` entries

        Returns
        -------
        OfdmFecSummaryAnalysisModel
            Normalized FEC summary analysis payload used by the API/plotting layers.
        """
        log = logging.getLogger(f"{cls.__name__}")

        profiles: list[OfdmFecSummaryProfileModel] = []

        for _idx, prof in enumerate(model.fec_summary_data or []):
            cwe = prof.codeword_entries

            cw = FecSummaryCodeWordModel(
                timestamps=list(cwe.timestamp),
                total_codewords=list(cwe.total_codewords),
                corrected=list(cwe.corrected),
                uncorrected=list(cwe.uncorrectable),
            )

            profiles.append(
                OfdmFecSummaryProfileModel(
                    profile=ProfileId(prof.profile_id),
                    number_of_sets=int(prof.number_of_sets),
                    codewords=cw,
                )
            )

        declared_num_profiles = int(model.num_profiles)
        if declared_num_profiles != len(profiles):
            log.debug(
                "FEC Summary (model): num_profiles declared=%d, parsed=%d",
                declared_num_profiles,
                len(profiles),
            )

        return OfdmFecSummaryAnalysisModel(
            device_details={},
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else model.pnm_header,
            mac_address=MacAddressStr(model.mac_address or MacAddress.null()),
            channel_id=ChannelId(
                model.channel_id if model.channel_id is not None else INVALID_CHANNEL_ID
            ),
            profiles=profiles,
        )

    @classmethod
    def basic_analysis_us_ofdma_pre_equalization_from_model(
        cls, model: CmUsOfdmaPreEqModel
    ) -> UsOfdmaUsPreEqAnalysisModel:
        """
        Model-based variant of Upstream OFDMA Pre-Equalization Analysis.

        Mirrors `basic_analysis_us_ofdma_pre_equalization()` but accepts a parsed
        :class:`CmUsOfdmaPreEqModel` instead of a raw measurement dict.

        Computes:
        - Per-subcarrier frequency axis (Hz)
        - Magnitude sequence (dB) from complex coefficients, with optional
          Butterworth low-pass smoothing across subcarriers
        - Group delay (µs) from phase slope across subcarriers
        - IFFT-based echo detection over a constrained delay window
        - Complex samples passthrough
        - Signal statistics over the (smoothed) magnitude sequence
        """
        log = logging.getLogger(f"{cls.__name__}")

        subcarrier_spacing: FrequencyHz = FrequencyHz(
            int(getattr(model, "subcarrier_spacing", INVALID_START_VALUE))
        )
        first_active_subcarrier_index: int = int(
            getattr(model, "first_active_subcarrier_index", INVALID_START_VALUE)
        )
        subcarrier_zero_frequency: FrequencyHz = FrequencyHz(
            int(getattr(model, "subcarrier_zero_frequency", INVALID_START_VALUE))
        )
        occupied_channel_bandwidth: FrequencyHz = FrequencyHz(
            int(getattr(model, "occupied_channel_bandwidth", 0))
        )

        if (
            (first_active_subcarrier_index < 0)
            or (subcarrier_zero_frequency < 0)
            or (subcarrier_spacing <= 0)
        ):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        values: ComplexArray = cast(ComplexArray, getattr(model, "values", []))
        if not values:
            raise ValueError("No complex pre-equalization values provided in model.")

        start_freq: FrequencyHz = FrequencyHz(
            (subcarrier_spacing * first_active_subcarrier_index)
            + subcarrier_zero_frequency
        )
        freqs: FrequencySeriesHz = cast(
            FrequencySeriesHz,
            [start_freq + (i * subcarrier_spacing) for i in range(len(values))],
        )

        gd = GroupDelay.from_channel_estimate(
            Hhat=values, df_hz=subcarrier_spacing, f0_hz=start_freq
        )
        gd_results = gd.to_result()

        cao = ComplexArrayOps(values)
        magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

        complex_arr = np.asarray(
            [
                complex(v[0], v[1])
                if (not isinstance(v, complex))
                and isinstance(v, (list, tuple))
                and len(v) == 2
                else complex(v)
                for v in values
            ],
            dtype=np.complex128,
        )

        try:
            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(subcarrier_spacing) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz=FrequencyHz(int(subcarrier_spacing)),
                cutoff_hz=cutoff_hz,
                order=DEFAULT_BUTTERWORTH_ORDER,
                zero_phase=True,
            )

            mag_result = mag_filter.apply(
                np.asarray(magnitudes_db_raw, dtype=np.float64)
            )
            magnitudes_db: FloatSeries = mag_result.filtered_values.tolist()
        except Exception:
            magnitudes_db = magnitudes_db_raw

        signal_stats_model: SignalStatisticsModel = SignalStatistics(
            magnitudes_db
        ).compute()

        group_delay_stats: GrpDelayStatsModel = GrpDelayStatsModel(
            group_delay_unit="microsecond",
            magnitude=ComplexArrayOps.to_list(gd_results.group_delay_us),
        )

        magn_linear = np.power(10.0, np.asarray(magnitudes_db, dtype=np.float64) / 20.0)
        phases = np.angle(complex_arr)
        H_smooth = magn_linear * np.exp(1j * phases)

        N = len(values)
        n_fft = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        fs = float(N) * float(subcarrier_spacing)
        max_delay_s_used = 3.5e-6

        cable_type_name = "RG6"
        v = SPEED_OF_LIGHT * CABLE_VF.get(cable_type_name, 0.87)
        max_dist_m = 0.5 * v * max_delay_s_used
        i_stop = int(max_delay_s_used * fs)
        log.debug(
            "US OFDMA Pre-Eq (model) EchoDetector window: fs=%.3f Hz, n_fft=%d, i_stop=%d bins, "
            "max_delay=%.2fus, max_dist≈%.1f m",
            fs,
            n_fft,
            i_stop,
            max_delay_s_used * 1e6,
            max_dist_m,
        )

        det = EchoDetector(
            freq_data=H_smooth.tolist(),
            subcarrier_spacing_hz=float(subcarrier_spacing),
            n_fft=4096,
            cable_type=cable_type_name,
            channel_id=ChannelId(getattr(model, "channel_id", INVALID_CHANNEL_ID)),
        )

        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode="db_down",
            threshold_db_down=60.0,
            normalize_power=True,
            guard_bins=16,
            min_separation_s=8.0 / det.fs,
            max_delay_s=max_delay_s_used,
            max_peaks=3,
            include_time_response=False,
            direct_at_zero=True,
            window="hann",
        )

        i_stop = int(np.ceil(max_delay_s_used * det.fs))
        edge_guard = 8
        if echo_report.echoes:
            echo_report.echoes = [
                e for e in echo_report.echoes if (e.bin_index < (i_stop - edge_guard))
            ]

        echo_rpt = EchoDatasetModel(
            type=EchoDetectorType.IFFT,
            report=echo_report,
        )

        carrier_values: OfdmaUsPreEqCarrierModel = OfdmaUsPreEqCarrierModel(
            carrier_count=len(freqs),
            frequency_unit="Hz",
            frequency=freqs,
            complex=values,
            complex_dimension=int(complex_arr.ndim),
            magnitudes=magnitudes_db,
            group_delay=group_delay_stats,
            occupied_channel_bandwidth=occupied_channel_bandwidth,
        )

        result_model: UsOfdmaUsPreEqAnalysisModel = UsOfdmaUsPreEqAnalysisModel(
            device_details=getattr(model, "device_details", {}),
            pnm_header=model.pnm_header.model_dump()
            if hasattr(model.pnm_header, "model_dump")
            else getattr(model, "pnm_header", {}),
            mac_address=MacAddressStr(getattr(model, "mac_address", MacAddress.null())),
            channel_id=ChannelId(getattr(model, "channel_id", INVALID_CHANNEL_ID)),
            subcarrier_spacing=subcarrier_spacing,
            first_active_subcarrier_index=first_active_subcarrier_index,
            subcarrier_zero_frequency=subcarrier_zero_frequency,
            carrier_values=carrier_values,
            signal_statistics=signal_stats_model,
            echo=echo_rpt,
        )

        if log.isEnabledFor(logging.DEBUG):
            LogFile.write(
                f"UsOfdmaUsPreEqAnalysisModel_{result_model.mac_address}_{result_model.channel_id}.log",
                result_model,
            )

        return result_model

    @classmethod
    def basic_analysis_echo_detection_ifft(
        cls,
        model: CmDsOfdmChanEstimateCoefModel,
        cable_type: CableType = CableType.RG6,
    ) -> EchoDetectorReport:
        """
        Run FFT/IFFT-based echo detection from a single Channel-Estimation snapshot.

        Overview
        --------
        Builds a time response h(t) from the complex channel-estimation spectrum H(f),
        identifies the direct path, then scans for echo peaks subject to a conservative
        threshold, guard region, and optional time-response attachment.

        Inputs (from model)
        -------------------
        values : ComplexArray
            List of complex-like samples for H(f). Accepted shapes:
            - [(re, im), ...] pairs or
            - [complex, ...]
        subcarrier_spacing : float
            Δf in Hz between OFDM subcarriers.
        channel_id : int
            Downstream channel ID, used for metadata only.

        Parameters
        ----------
        cable_type : CableType, default CableType.RG6
            Cable type to derive the velocity factor for distance conversion.

        Returns
        -------
        EchoDetectorReport
            Structured result including dataset metadata, direct-path info, an array
            of detected echoes (if any), and optional time-response block.

        Notes
        -----
        - n_fft is chosen as the next power of two ≥ N (min 1024) for finer time sampling.
        - Thresholding defaults to “dB-down” mode (70 dB below direct peak), with an
          automatic fallback to 80 dB if nothing is found.
        - Magnitude smoothing uses the same Butterworth pipeline as
          `basic_analysis_ds_chan_est()`, applied to |H(f)| before echo detection.
        """
        log = logging.getLogger(f"{cls.__name__}")

        values = cast(Sequence[complex | Sequence[float]], getattr(model, "values", []))
        if not values:
            raise ValueError(
                "Echo detection requires non-empty channel-estimation values."
            )

        df_hz = float(getattr(model, "subcarrier_spacing", 0.0))
        if df_hz <= 0.0:
            raise ValueError("Invalid subcarrier spacing for echo detection.")

        channel_id = cast(ChannelId, getattr(model, "channel_id", INVALID_CHANNEL_ID))

        # ── Optional Butterworth smoothing over |H(f)| in dB (same pattern as ds_chan_est) ──
        H = np.asarray(values, dtype=complex)
        freq_data_for_detector: Sequence[complex]

        try:
            cao = ComplexArrayOps(values)
            magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(df_hz) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz=FrequencyHz(int(df_hz)),
                cutoff_hz=cutoff_hz,
            )

            mag_result = mag_filter.apply(
                np.asarray(magnitudes_db_raw, dtype=np.float64)
            )
            magnitudes_db_smooth = mag_result.filtered_values

            mag_lin = np.power(10.0, magnitudes_db_smooth / 20.0)
            H_phase = np.exp(1j * np.angle(H))
            H_filtered = mag_lin * H_phase

            freq_data_for_detector = H_filtered.tolist()

            log.debug(
                "Echo IFFT: applied Butterworth smoothing (df=%.3f Hz, cutoff=%.3f Hz, N=%d)",
                df_hz,
                float(cutoff_hz),
                H.shape[0],
            )
        except Exception as exc:
            log.debug(
                "Echo IFFT: Butterworth smoothing skipped due to error: %s; using raw values.",
                exc,
            )
            freq_data_for_detector = list(map(complex, H))

        # Choose IFFT length for finer time resolution
        N = len(freq_data_for_detector)
        n_fft = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        # Detector
        det = EchoDetector(
            freq_data=freq_data_for_detector,
            subcarrier_spacing_hz=df_hz,
            n_fft=n_fft,
            cable_type=cable_type.name,
            channel_id=ChannelId(channel_id),
        )

        log.debug(
            "Init EchoDetector: N=%d, Δf=%.3f Hz, fs=%.3f Hz, n_fft=%d, cable=%s, chan=%s",
            N,
            df_hz,
            N * df_hz,
            n_fft,
            cable_type.name,
            str(channel_id),
        )

        # Conservative defaults, with auto-fallback if nothing exceeds threshold
        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode="db_down",  # primary threshold strategy
            threshold_db_down=70.0,  # 70 dB below the direct path
            guard_bins=8,  # keep away from main-lobe skirt
            min_separation_s=0.0,  # allow closely spaced echoes if present
            max_delay_s=7.7e-6,  # ~1 km one-way at VF≈0.87
            max_peaks=5,  # cap number of echoes returned
            include_time_response=False,  # keep payload small by default
            direct_at_zero=True,  # recenter direct path to t=0
            window="hann",  # reduce sidelobes before IFFT
        )

        return echo_report
# FILE: src/pypnm/api/routes/common/classes/common_endpoint_classes/common_req_resp.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field, ValidationInfo, field_validator

from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    AnalysisType,
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_validation import (
    RequestListNormalizer,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPConfig,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.matplot.manager import ThemeType
from pypnm.lib.types import ChannelId, InetAddressStr, IPv4Str, IPv6Str, MacAddressStr

default_mac: MacAddressStr = SystemConfigSettings.default_mac_address()
default_ip: InetAddressStr = SystemConfigSettings.default_ip_address()
TFTP_IPV4_DEFAULT_DESC = "null uses system.json PnmBulkDataTransfer.tftp.ip_v4"
TFTP_IPV6_DEFAULT_DESC = "null uses system.json PnmBulkDataTransfer.tftp.ip_v6"
ERROR_TFTP_BLANK = "tftp.{field} must be null or a valid IP address"


class CommonOutput(BaseModel):
    type: OutputType = Field(
        default=OutputType.JSON, description="Desired output type for analysis results"
    )


class TftpConfig(BaseModel):
    ipv4: IPv4Str | None = Field(
        ..., description=f"TFTP server IPv4 address ({TFTP_IPV4_DEFAULT_DESC})"
    )
    ipv6: IPv6Str | None = Field(
        ..., description=f"TFTP server IPv6 address ({TFTP_IPV6_DEFAULT_DESC})"
    )

    @field_validator("ipv4", "ipv6", mode="before")
    def _reject_blank(cls, v: object, info: ValidationInfo) -> object:
        if v is None:
            return v
        if isinstance(v, str) and v.strip() == "":
            raise ValueError(ERROR_TFTP_BLANK.format(field=info.field_name))
        return v


class PnmCaptureConfig(BaseModel):
    channel_ids: list[ChannelId] | None = Field(
        default=None,
        description="Optional channel id list for targeted captures (empty or missing means all channels).",
    )

    @field_validator("channel_ids", mode="after")
    def _dedupe_channel_ids(cls, v: list[ChannelId] | None) -> list[ChannelId] | None:
        return RequestListNormalizer.dedupe_preserve_order(v)


class PnmParameters(BaseModel):
    tftp: TftpConfig = Field(..., description="TFTP configuration")
    capture: PnmCaptureConfig = Field(
        default_factory=PnmCaptureConfig, description="Capture parameters"
    )


class CableModemPnmConfig(BaseModel):
    mac_address: MacAddressStr = Field(
        default=default_mac, description="MAC address of the cable modem"
    )
    ip_address: InetAddressStr = Field(
        default=default_ip, description="Inet address of the cable modem"
    )
    pnm_parameters: PnmParameters = Field(
        description="PNM parameters such as TFTP server configuration"
    )
    snmp: SNMPConfig = Field(description="SNMP configuration")

    @field_validator("mac_address")
    def validate_mac(cls, v: str) -> MacAddressStr:
        try:
            return MacAddress(v).mac_address
        except Exception as e:
            raise ValueError(f"Invalid MAC address: {v}, reason: ({e})") from e


class CommonMatPlotUiConfig(BaseModel):
    theme: ThemeType = Field(
        default="dark", description="Matplotlib theme selection for plot rendering"
    )


class CommonMatPlotConfigRequest(BaseModel):
    ui: CommonMatPlotUiConfig = Field(
        default=CommonMatPlotUiConfig(),
        description="Matplotlib UI configuration for plot generation",
    )


class CommonFileSearchRequest(BaseModel):
    mac_address: MacAddressStr = Field(description="MAC address of the cable modem")

    @field_validator("mac_address")
    def validate_mac(cls, v: MacAddressStr) -> MacAddressStr:
        try:
            return MacAddress(v).to_mac_format(MacAddressFormat.COLON)
        except Exception as e:
            raise ValueError(f"Invalid MAC address: {v}, reason: ({e})") from e


class CommonRequest(BaseModel):
    cable_modem: CableModemPnmConfig = Field(
        description="Cable modem configuration for basic PNM operations"
    )


class CommonAnalysisType(BaseModel):
    type: int = Field(
        description="Analysis type to perform, implementation-specific integer value"
    )


class CommonMultiAnalysisRequest(BaseModel):
    cable_modem: CableModemPnmConfig = Field(description="Cable modem configuration")
    analysis: CommonAnalysisType = Field(description="Analysis type to perform")


class CommonAnalysisRequest(BaseModel):
    cable_modem: CableModemPnmConfig = Field(description="Cable modem configuration")
    analysis: CommonAnalysisType = Field(description="Analysis type or mode to perform")
    output: CommonOutput = Field(description="Output type control: JSON or archive")


class CommonSingleCaptureAnalysisType(BaseModel):
    type: AnalysisType = Field(
        default=AnalysisType.BASIC, description="Analysis type to perform"
    )
    output: CommonOutput = Field(
        description="Output format selection for single capture analysis"
    )
    plot: CommonMatPlotConfigRequest = Field(
        description="Plot configuration for single capture analysis"
    )


class CommonSingleCaptureAnalysisRequest(BaseModel):
    cable_modem: CableModemPnmConfig = Field(description="Cable modem configuration")
    analysis: CommonSingleCaptureAnalysisType = Field(
        description="Single capture analysis configuration"
    )


class CommonResponse(BaseModel):
    mac_address: MacAddressStr = Field(
        default=default_mac, description="MAC address of the cable modem"
    )
    status: ServiceStatusCode | OperationState | str | None = Field(
        default="success", description="Operation status code or state"
    )
    message: str | None = Field(
        default=None, description="Additional information or error details"
    )

    @field_validator("mac_address")
    def validate_mac(cls, v: str) -> MacAddressStr:
        try:
            return MacAddress(v).mac_address
        except Exception as e:
            raise ValueError(f"Invalid MAC address: {v}, reason: ({e})") from e


class CommonAnalysisResponse(CommonResponse):
    """Basic analysis response model."""

    pass
# FILE: src/pypnm/api/routes/common/classes/common_endpoint_classes/schema/base_snmp.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

"""
Module: common_endpoint_classes.schema.base_snmp
Defines SNMP configuration models for v2c and v3 settings.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel

from pypnm.config.system_config_settings import SystemConfigSettings as SCSC


class SNMPv2c(BaseModel):
    """
    SNMP v2c settings model.

    Attributes:
        community (str): Write community string. Must not be blank.
    """

    community: str | None = Field(
        ...,
        description=f"Write community string (null uses {SCSC.snmp_write_community()})",
    )

    @field_validator("community")
    def community_not_blank(cls, v: str | None) -> str | None:
        """
        Validate that the community string is not blank.
        """
        if v is None:
            return v
        if not v.strip():
            raise ValueError("SNMPv2c.community must not be blank")
        return v


class SNMPv3(BaseModel):
    """
    SNMP v3 settings model.

    Attributes:
        username (Optional[str]): Username; if omitted, system default is used.
        securityLevel (Literal["noAuthNoPriv","authNoPriv","authPriv"]): Required SNMPv3 security level.
        authProtocol (Optional[Literal["MD5","SHA"]]): Authentication protocol.
        authPassword (Optional[str]): Authentication password.
        privProtocol (Optional[Literal["DES","AES"]]): Privacy protocol.
        privPassword (Optional[str]): Privacy password.
    """

    username: str | None = Field(
        default=None, description="Username; if omitted, system default is used"
    )
    securityLevel: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] = Field(
        default="noAuthNoPriv", description="SNMPv3 security level"
    )
    authProtocol: Literal["MD5", "SHA"] | None = Field(
        default="SHA", description="Authentication protocol"
    )
    authPassword: str | None = Field(
        default="password", description="Authentication password"
    )
    privProtocol: Literal["DES", "AES"] | None = Field(
        default="AES", description="Privacy protocol"
    )
    privPassword: str | None = Field(default="password", description="Privacy password")

    @model_validator(mode="after")
    def check_v3_fields(self) -> SNMPv3:
        """
        Ensure that authentication and privacy fields are present based on securityLevel.
        """
        lvl = self.securityLevel
        if lvl in ("authNoPriv", "authPriv") and (
            not self.authProtocol or not self.authPassword
        ):
            raise ValueError("authProtocol & authPassword are required for auth levels")
        if lvl == "authPriv" and (not self.privProtocol or not self.privPassword):
            raise ValueError(
                "privProtocol & privPassword are required for privacy level"
            )
        return self


class SNMPConfig(BaseModel):
    """
    SNMP configuration model supporting both v2c and optional v3 settings.
    """

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)
    snmp_v2c: SNMPv2c = Field(..., description="SNMP v2c settings")

    if SCSC.snmp_v3_enable():
        snmp_v3: SNMPv3 = Field(default_factory=SNMPv3, description="SNMP v3 settings")
# FILE: src/pypnm/api/routes/common/classes/operation/cable_modem_precheck.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Iterable

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPConfig,
    SNMPv2c,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import DocsPnmCmCtlStatus
from pypnm.docsis.data_type.ClabsDocsisVersion import ClabsDocsisVersion
from pypnm.docsis.data_type.InterfaceStats import DocsisIfType
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr

PreCheckStatus = tuple[ServiceStatusCode, str]


class CableModemServicePreCheck:
    """
    Performs preliminary connectivity and validation checks against a DOCSIS Cable Modem.

    This service supports:
    - ICMP ping reachability check
    - SNMP reachability check
    - MAC address verification
    - Optional DOCSIS version compatibility validation
    - Optional validation that OFDM (DS) and/or OFDMA (US) channels exist

    Initialization methods:
    - Provide a pre-constructed `CableModem` object
    - Or specify a `mac_address` and `ip_address` pair

    Parameters allow flexible diagnostics for network readiness prior to performing
    PNM measurements or control operations.
    """

    def __init__(
        self,
        cable_modem: CableModem | None = None,
        mac_address: MacAddressStr | None = None,
        ip_address: InetAddressStr | None = None,
        snmp_config: SNMPConfig | None = None,
        check_docsis_version: list[ClabsDocsisVersion] = None,
        validate_ofdm_exist: bool = False,
        validate_ofdma_exist: bool = False,
        validate_scqam_exist: bool = False,
        validate_atdma_exist: bool = False,
        validate_pnm_ready_status: bool = True,
        ignore_mac_address_check: bool = False,
    ) -> None:
        """
        Initialize the pre-check service.

        Args:
            cable_modem: An existing CableModem instance to use for queries (optional).
            mac_address: MAC address of the target cable modem (optional).
            ip_address: IP address of the target cable modem (optional).
            check_docsis_version: Optional list of acceptable DOCSIS versions to validate.
            validate_ofdm_exist: If True, verifies that one or more downstream OFDM channels exist.
            validate_ofdma_exist: If True, verifies that one or more upstream OFDMA channels exist.

        Raises:
            ValueError: If neither a `CableModem` object nor both `mac_address` and `ip_address` are provided.
        """
        if check_docsis_version is None:
            check_docsis_version = []
        self.logger = logging.getLogger(self.__class__.__name__)

        if cable_modem:
            self.cm = cable_modem
        elif mac_address and ip_address:
            if snmp_config is None:
                self.logger.debug("No SNMPConfig provided, using default settings")
                snmp_config = SNMPConfig(snmp_v2c=SNMPv2c(community=None))

            self.cm = CableModem(
                mac_address=MacAddress(mac_address),
                inet=Inet(ip_address),
                write_community=snmp_config.snmp_v2c.community,
            )
        else:
            raise ValueError(
                "Must provide either `cable_modem` or both `mac_address` and `ip_address`."
            )

        if check_docsis_version:
            if isinstance(check_docsis_version, ClabsDocsisVersion):
                self.check_docsis_version = [check_docsis_version]
            elif isinstance(check_docsis_version, Iterable):
                self.check_docsis_version = list(check_docsis_version)
            else:
                self.check_docsis_version = [check_docsis_version]
        else:
            self.check_docsis_version = []

        self._validate_ofdma_exist = validate_ofdma_exist
        self._validate_ofdm_exist = validate_ofdm_exist
        self._validate_scqam_exist = validate_scqam_exist
        self._validate_atdma_exist = validate_atdma_exist
        self._validate_pnm_ready_stat = validate_pnm_ready_status
        self._ignore_mac_address_check = ignore_mac_address_check

    async def run_precheck(self) -> tuple[ServiceStatusCode, str]:
        """
        Run full pre-check routine:
          1. Ping modem
          2. Perform SNMP check
          3. Does Mac Match CableModem Mac
          4. Validate DOCSIS version (optional)

        Returns:
            Tuple[ServiceStatusCode, str]: Status and message.
        """
        self.logger.debug(f"Starting pre-check for CableModem: {self.cm}")

        status = self.ping_reachable()
        if status != ServiceStatusCode.SUCCESS:
            msg = f"Ping check failed: {status}"
            self.logger.error(msg)
            return status, msg

        status = await self.snmp_reachable()
        if status != ServiceStatusCode.SUCCESS:
            msg = f"SNMP check failed: {status}"
            self.logger.error(msg)
            return status, msg

        if not self._ignore_mac_address_check:
            status = await self.isMacCorrect()
            if status != ServiceStatusCode.SUCCESS:
                try:
                    mac = await self.getRealMacAddress()
                except Exception as e:
                    self.logger.error(
                        f"Error retrieving real MAC address: {e}", exc_info=True
                    )
                    mac = "Unknown"

                msg = f"Found: {mac} MAC address CableModem Mac check failed: {status}"
                self.logger.error(msg)
                return status, msg

        if self.check_docsis_version:
            status, msg = await self.validate_docsis_version()
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        if self._validate_ofdm_exist:
            status, msg = await self.validate_ofdm_channel_exist()
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        if self._validate_ofdma_exist:
            status, msg = await self.validate_ofdma_channel_exist()
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        if self._validate_scqam_exist:
            status, msg = await self.validate_scqam_channel_exist()
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        if self._validate_atdma_exist:
            status, msg = await self.validate_atdma_channel_exist()
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        if self._validate_pnm_ready_stat:
            status, msg = await self.validate_pnm_ready_status()
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        msg = "Pre-check successful: CableModem reachable via ping and SNMP"
        self.logger.debug(msg)
        return ServiceStatusCode.SUCCESS, msg

    def ping_reachable(self) -> ServiceStatusCode:
        """
        Perform an ICMP ping test.

        Returns:
            SUCCESS if reachable, else PING_FAILED.
        """
        try:
            if self.cm.is_ping_reachable():
                self.logger.debug("Ping check passed")
                return ServiceStatusCode.SUCCESS
            self.logger.debug("Ping check failed")
            return ServiceStatusCode.PING_FAILED
        except Exception as e:
            self.logger.error(f"Ping check exception: {e}", exc_info=True)
            return ServiceStatusCode.PING_FAILED

    async def snmp_reachable(self) -> ServiceStatusCode:
        """
        Perform SNMP reachability check.

        Returns:
            SUCCESS if SNMP response received, else UNREACHABLE_SNMP.
        """
        try:
            if await self.cm.is_snmp_reachable():
                self.logger.debug("SNMP check passed")
                return ServiceStatusCode.SUCCESS
            self.logger.debug("SNMP check failed")
            return ServiceStatusCode.UNREACHABLE_SNMP

        except Exception as e:
            self.logger.error(f"SNMP check exception: {e}", exc_info=True)
            return ServiceStatusCode.UNREACHABLE_SNMP

    async def isMacCorrect(self) -> ServiceStatusCode:
        """
        Check if the cable modem's MAC address is correct.
        """
        try:
            if await self.cm.isCableModemMacCorrect():
                self.logger.debug("MAC address check passed")
                return ServiceStatusCode.SUCCESS
            self.logger.debug("MAC address check failed")
            return ServiceStatusCode.CM_MAC_DOES_MATCH_MATCH
        except Exception as e:
            self.logger.error(f"MAC address check exception: {e}", exc_info=True)
            return ServiceStatusCode.UNREACHABLE_SNMP

    async def getRealMacAddress(self) -> MacAddress:
        """
        Retrieve the real MAC address from the cable modem via SNMP.

        Returns:
            MacAddress: The MAC address retrieved from the cable modem.
        """
        try:
            mac = await self.cm.getIfPhysAddress()
            self.logger.debug(f"Retrieved MAC address: {mac}")
            return mac
        except Exception as e:
            self.logger.error(f"Error retrieving MAC address: {e}", exc_info=True)
            raise

    async def validate_docsis_version(self) -> tuple[ServiceStatusCode, str]:
        """
        Check if the modem's DOCSIS version is in the accepted list.

        Returns:
            SUCCESS if version is allowed, else INVALID_DOCSIS_VERSION.
        """
        try:
            base_cap: ClabsDocsisVersion = await self.cm.getDocsisBaseCapability()
            if base_cap not in self.check_docsis_version:
                msg = f"Invalid DOCSIS Version: {base_cap.name}"
                self.logger.error(msg)
                return ServiceStatusCode.INVALID_DOCSIS_VERSION, msg

            self.logger.debug(f"DOCSIS version check passed: {base_cap.name}")
            return ServiceStatusCode.SUCCESS, "Valid DOCSIS version"

        except Exception as e:
            msg = f"Error checking DOCSIS version: {e}"
            self.logger.error(msg, exc_info=True)
            return ServiceStatusCode.INVALID_DOCSIS_VERSION, msg

    async def validate_ofdm_channel_exist(self) -> tuple[ServiceStatusCode, str]:
        """
        Checks whether any OFDM downstream channels are present on the cable modem.

        This method queries the cable modem for the DOCSIS 3.1 upstream OFDMA channel
        index stack. If no indices are found, it returns a failure status.

        Returns:
            Tuple[ServiceStatusCode, str]: A tuple containing the status code and an explanatory message.
                - ServiceStatusCode.SUCCESS if channels are found
                - ServiceStatusCode.NO_OFDMA_CHANNELS_EXIST if no channels are detected
        """
        idx_chan_stack = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()

        if not idx_chan_stack:
            msg = "No OFDM channels found on the cable modem."
            return ServiceStatusCode.NO_OFDMA_CHANNELS_EXIST, msg

        return ServiceStatusCode.SUCCESS, "OFDMA upstream channels detected."

    async def validate_ofdma_channel_exist(self) -> tuple[ServiceStatusCode, str]:
        """
        Checks whether any OFDMA upstream channels are present on the cable modem.

        This method queries the cable modem for the DOCSIS 3.1 upstream OFDMA channel
        index stack. If no indices are found, it returns a failure status.

        Returns:
            Tuple[ServiceStatusCode, str]: A tuple containing the status code and an explanatory message.
                - ServiceStatusCode.SUCCESS if channels are found
                - ServiceStatusCode.NO_OFDMA_CHANNELS_EXIST if no channels are detected
        """
        idx_chan_stack = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()

        if not idx_chan_stack:
            msg = "No OFDMA channels found on the cable modem."
            return ServiceStatusCode.NO_OFDMA_CHANNELS_EXIST, msg

        return ServiceStatusCode.SUCCESS, "OFDMA upstream channels detected."

    async def validate_scqam_channel_exist(self) -> tuple[ServiceStatusCode, str]:
        """
        Checks whether any SC-QAM downstream channels are present on the cable modem.

        This method queries the cable modem for the DOCSIS 3.0 SC-QAM downstream channel
        index stack. If no indices are found, it returns a failure status.

        Returns:
            Tuple[ServiceStatusCode, str]: A tuple containing the status code and an explanatory message.
                - ServiceStatusCode.SUCCESS if channels are found
                - ServiceStatusCode.NO_SCQAM_CHAN_ID_INDEX_FOUND if no channels are detected
        """
        scqam_idx_list = await self.cm.getIfTypeIndex(DocsisIfType.docsCableDownstream)

        if not scqam_idx_list:
            msg = "No SC-QAM channels found on the cable modem."
            return ServiceStatusCode.NO_SCQAM_CHAN_ID_INDEX_FOUND, msg

        return ServiceStatusCode.SUCCESS, "SC-QAM downstream channels detected."

    async def validate_atdma_channel_exist(self) -> tuple[ServiceStatusCode, str]:
        """
        Checks whether any ATDMA upstream channels are present on the cable modem.

        This method queries the cable modem for the DOCSIS 3.0 ATDMA upstream channel
        index stack. If no indices are found, it returns a failure status.

        Returns:
            Tuple[ServiceStatusCode, str]: A tuple containing the status code and an explanatory message.
                - ServiceStatusCode.SUCCESS if channels are found
                - ServiceStatusCode.NO_ATDMA_CHAN_ID_INDEX_FOUND if no channels are detected
        """
        atdma_idx_list = await self.cm.getIfTypeIndex(DocsisIfType.docsCableUpstream)

        if not atdma_idx_list:
            msg = "No ATDMA channels found on the cable modem."
            return ServiceStatusCode.NO_ATDMA_CHAN_ID_INDEX_FOUND, msg

        return ServiceStatusCode.SUCCESS, "ATDMA upstream channels detected."

    async def validate_pnm_ready_status(self) -> PreCheckStatus:
        out: PreCheckStatus = (ServiceStatusCode.SUCCESS, DocsPnmCmCtlStatus.READY.name)

        rst: DocsPnmCmCtlStatus = await self.cm.getDocsPnmCmCtlStatus()

        if rst != DocsPnmCmCtlStatus.READY:
            return ServiceStatusCode.SUCCESS, rst.name

        return out
# FILE: src/pypnm/api/routes/common/extended/common_measure_service.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
import math
import os
import shutil
import time
from enum import Enum, auto
from pathlib import Path
from typing import TypeAlias, cast

from pypnm.api.routes.common.classes.analysis.analysis import SpecAnCapturePara
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
    UpstreamOfdmaParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    CommonMessagingService,
    MessageResponse,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_config_manager import PnmConfigManager
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import (
    DocsPnmBulkFileUploadStatus,
    DocsPnmCmCtlStatus,
    FecSummaryType,
)
from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsConstDispMeasEntry import (
    DocsPnmCmDsConstDispMeasEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsHistEntry import DocsPnmCmDsHistEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmFecEntry import DocsPnmCmDsOfdmFecEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmModProfEntry import (
    DocsPnmCmDsOfdmModProfEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmRxMerEntry import (
    DocsPnmCmDsOfdmRxMerEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmOfdmChanEstCoefEntry import (
    DocsPnmCmOfdmChanEstCoefEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmUsPreEqEntry import DocsPnmCmUsPreEqEntry
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.ftp.ftp_connector import FTPConnector
from pypnm.lib.host_endpoint import HostEndpoint
from pypnm.lib.inet import Inet
from pypnm.lib.ping import Ping
from pypnm.lib.ssh.ssh_connector import SSHConnector
from pypnm.lib.tftp.tftp_connector import TFTPConnector
from pypnm.lib.types import ChannelId, FileNameStr, InterfaceIndex, TransactionId, HostNameStr
from pypnm.lib.utils import Generate
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import (
    DocsIf3CmSpectrumAnalysisCtrlCmd,
    SpectrumRetrievalType,
    WindowFunction,
)
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.snmp.modules import DocsisIfType
from pypnm.snmp.snmp_v2c import Snmp_v2c


class MeasureServiceReturnTypes(Enum):
    BASE_MODEL = auto()
    DICT = auto()

MeasurementEntry: TypeAlias =   DocsPnmCmOfdmChanEstCoefEntry   | \
                                DocsPnmCmDsConstDispMeasEntry   | \
                                DocsPnmCmDsOfdmRxMerEntry       | \
                                DocsPnmCmUsPreEqEntry           | \
                                DocsPnmCmDsHistEntry            | \
                                DocsPnmCmDsOfdmFecEntry         | \
                                DocsPnmCmDsOfdmModProfEntry     | \
                                DocsIf3CmSpectrumAnalysisEntry

class CommonMeasureService(CommonMessagingService):
    """
    Base service class for executing common Proactive Network Maintenance (PNM) measurement tests.

    Parameters:
        pnm_test_type (DocsPnmCmCtlTest): The type of PNM test to execute.
        cable_modem (CableModem): The cable modem instance used for the test.
        tftp_servers (Inet,Inet): (IPv4,IPv6)
        tftp_path (str, optional): The path on the TFTP server where test result files are stored. Default is an empty string.
        snmp_write_community (str, optional): The SNMP community string for write access. Default is "private".
        **extra_options (dict, optional): Additional keyword arguments specific to the test type, such as:
            - fec_summary_type (FecSummaryType): Required for tests involving FEC summary metrics.
            - Other parameters based on the test type.

    Notes:
        This class serves as a base for test-specific measurement operations. Subclasses should implement
        specific tests such as:
        - Downstream OFDM codeword error rate
        - RXMER per subcarrier
        - FEC statistics, etc.

        It is expected that subclasses will extend this service and provide the necessary implementations for
        executing and processing PNM measurements based on the test type and parameters.
    """
    def __init__(self, pnm_test_type:DocsPnmCmCtlTest,
                 cable_modem: CableModem,
                 tftp_servers: tuple[Inet,Inet],
                 tftp_path: str = "",
                 snmp_write_community: str = "private",
                 **extra_options) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.propagate = True

        self.pnm_filename:list[str]

        self._transactionId_pnmFile: dict[str, str] = {}
        self.pnm_test_type:DocsPnmCmCtlTest         = pnm_test_type
        self.cm:CableModem                          = cable_modem
        self.tftp_servers:tuple[Inet,Inet]          = tftp_servers
        self.tftp_path:str                          = tftp_path
        self.snmp_write_community:str               = snmp_write_community
        self.extra_options                          = extra_options
        self.config_mgr:ConfigManager               = ConfigManager()
        self.log_prefix:str                         = f"MAC: {self.cm.get_mac_address} - INET: {self.cm.get_inet_address}"
        self.pnm_dir                                = PnmConfigManager.get_save_dir()
        self.pnm_local_dir                          = SystemConfigSettings.pnm_dir
        self._capture_parameter:SpecAnCapturePara   = SpecAnCapturePara()

        # Initialize default spectrum capture parameters
        self._capture_parameter.spectrum_retrieval_type = SpectrumRetrievalType.UNKNOWN

        if self.extra_options:
            self.logger.info(f"{self.log_prefix} - OPTIONS: {self.extra_options}")
            self._preload_interface_parameters()

        self._precheck()

    def _precheck(self) -> None:
        """
        Perform pre-check and ensure the save directory exists.
        """
        self.logger.debug(f'PreCheck: SaveDir: {self.pnm_dir}')
        save_path = Path(self.pnm_dir)
        save_path.mkdir(parents=True, exist_ok=True)

    def _preload_interface_parameters(self) -> None:
        """
        Load optional interface parameters from extra_options dictionary.
        If not present, sets interface_parameters to None.
        """
        self.interface_parameters = self.extra_options.get("interface_parameters", None)

    def setSpectrumCaptureParameters(self, capture_parameter:SpecAnCapturePara) -> None:
        """
        Set the spectrum capture parameters for the measurement.

        TODO: This method may be deprecated in favor of passing parameters directly during initialization.

        Args:
            capture_parameter (SpecAnCapturePara): The spectrum capture parameters.
        """
        self._capture_parameter = capture_parameter

    def getSpectrumCaptureParameters(self) -> SpecAnCapturePara:
        """
        Get the current spectrum capture parameters.

        Returns:
            SpecAnCapturePara: The current spectrum capture parameters.
        """
        return self._capture_parameter

    async def set_and_go(self, interface_parameters: DownstreamOfdmParameters | UpstreamOfdmaParameters | None = None ,
                         max_wait_count: int = 5,) -> MessageResponse:
        """
        Trigger PNM file capture and retrieval based on direction-specific parameters.

        Args:
            interface_parameters (InterfaceParameters, optional):
                The configuration specifying the direction of capture:
                - `DownstreamOfdmParameters`: For OFDM downstream channels.
                - `UpstreamOfdmaParameters`: For OFDMA upstream channels.
                If `None` (default), all channels will be captured.

            max_wait_count (int, optional):
                Maximum seconds to wait for measurement readiness. Default is 5.

        Returns:
            MessageResponse: Result indicating success or failure of the operation.
        """

        ##########################################################
        # Verify that we can connect to the CM via Ping and SNMP
        ##########################################################

        if not self.is_ping_reachable():
            self.logger.error(f"{self.log_prefix} - Unreachable via PING")
            return self.build_send_msg(ServiceStatusCode.UNREACHABLE_PING)

        if not await self.is_snmp_ready():
            self.logger.error(f"{self.log_prefix} - Unreachable via SNMP")
            return self.build_send_msg(ServiceStatusCode.UNREACHABLE_SNMP)

        #########################################################################
        #                   Spectrum Analysis SNMP Return                       #
        #########################################################################

        if self.getSpectrumCaptureParameters().spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.debug(f"{self.log_prefix} - Performing Spectrum Analysis SNMP Amplitude Data")

            #Set Spectrum Analyzer
            __status = await self._generic_spectrum_analyzer_operation()

            if __status[0] != ServiceStatusCode.SUCCESS:
               self.logger.error(f"{self.log_prefix} - Unable to set Spectrum Analyzer Settings")
               return self.build_send_msg(ServiceStatusCode.SPEC_ANALYZER_SET_CONFIG_ERROR)

            # This is a blocking method, it will return SUCCESS or wait till timeout to return an ERROR
            status = await self._check_spectrum_amplitude_data_status()

            if status == ServiceStatusCode.SUCCESS:
                self.logger.info(f"{self.log_prefix} - Spectrum Amplitude Data is READY, collecting amplitude data, may take a while...")
                amp_data: bytes = await self.cm.getSpectrumAmplitudeData()
                self.logger.info(f"{self.log_prefix} - Spectrum Amplitude Data collection COMPLETE, total bytes: {len(amp_data)}.")
                #################################################################################################
                # Build binary filename and save file - START
                #################################################################################################
                filename = await self._pnm_file_generator(DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA)
                tx_id = self._get_transaction_id_by_filename(filename)
                if not tx_id:
                    self.logger.error(f"{self.log_prefix} - Unable to find Transaction ID for PNM filename: {filename}")
                    return self.build_send_msg(ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND)

                pnm_dir = SystemConfigSettings.pnm_dir()
                fpath = f"{pnm_dir}/{filename}"
                self.logger.debug(f'SpectrumAmplitudeData: - FNAME: {filename} - Length:{len(amp_data)} - TransactionID: {tx_id}')

                FileProcessor(fpath).write_file(amp_data)
                #################################################################################################
                # Build binary filename and save file - END
                #################################################################################################

                self.build_transaction_msg(tx_id, filename)

            return self.build_send_msg(status)

        #########################################################################
        # Ensure CM Inet and TFTP server address use the same IP version
        #
        # The TFTP server address must match the IP version (IPv4 or IPv6) used
        # by the Cable Modem (CM). By default, we assume IPv4.
        #
        # If the CM's IP address is IPv6 and matches the version of the
        # secondary TFTP server entry, we switch to using the IPv6 TFTP server.
        #
        # TODO: Enhance this logic to support dual-stack (dual-home) cable modems,
        # where both IPv4 and IPv6 may be valid simultaneously.
        #########################################################################

        self.logger.info(f'{self.log_prefix} - TFTP-SERVERS: ({self.tftp_servers[0]} | {self.tftp_servers[1].inet})')

        # Default to using the IPv4 TFTP server
        tftp_server: Inet = self.tftp_servers[0]

        # Switch to IPv6 TFTP server if CM uses IPv6
        if self.cm.same_inet_version(self.tftp_servers[1]):
            tftp_server = self.tftp_servers[1]

        # Attempt to configure the CM with the selected TFTP server and path
        if not await self.cm.setDocsPnmBulk(tftp_server.inet, self.tftp_path):
            self.logger.error(
                f"{self.log_prefix} - Unable to set TFTP server {tftp_server.inet} "
                f"or TFTP path: {self.tftp_path}")
            return self.build_send_msg(ServiceStatusCode.TFTP_SERVER_PATH_SET_FAIL)

        ##############################################################################################
        # This section is determine by the direction due to which interface and type we are accessing
        ##############################################################################################

        status_index_channelId = await self._get_indexes_via_pnm_test_type(interface_parameters)
        self.logger.info(f'{self.log_prefix} - Index/ChannelID List: {status_index_channelId[1]}')
        if status_index_channelId[0] != ServiceStatusCode.SUCCESS or status_index_channelId[1] is None:
            self.logger.error(f'{self.log_prefix} - Unable to aquire index from ChannelID, reason: {status_index_channelId[0]}')
            return self.build_send_msg(status_index_channelId[0])

        ##############################################################################################
        # This section runs through all the indexes, build PNM file, run measurement and check status
        ##############################################################################################
        index_channelId: list[tuple[InterfaceIndex, ChannelId]] = status_index_channelId[1]
        return self.build_send_msg(await self._pnm_measure_status_and_pnm_file_transfer(index_channelId, max_wait_count))

    def getInterfaceParameters(self,
        interface_type: DocsisIfType) -> DownstreamOfdmParameters | UpstreamOfdmaParameters:
        """
        Instantiate and return the PNM test parameters for the specified DOCSIS interface.

        Args:
            interface_type (DocsisIfType):
                The DOCSIS interface type:
                - `DocsisIfType.docsOfdmDownstream` → returns DownstreamOfdmParameters
                - `DocsisIfType.docsOfdmaUpstream`  → returns UpstreamOfdmaParameters

        Returns:
            Union[DownstreamOfdmParameters, UpstreamOfdmaParameters]:
                A parameters object tailored to the requested interface.

        Raises:
            ValueError: If `interface_type` is not OFDM downstream or OFDMA upstream.
        """
        if interface_type == DocsisIfType.docsOfdmDownstream:
            return DownstreamOfdmParameters()
        if interface_type == DocsisIfType.docsOfdmaUpstream:
            return UpstreamOfdmaParameters()

        raise ValueError(
            f"Unsupported interface type: {interface_type!r}. "
            "Expected docsOfdmDownstream or docsOfdmaUpstream."
        )

    def is_ping_reachable(self) -> bool:
        """
        Check if the cable modem is reachable via ICMP ping.

        Returns:
            bool: True if the modem responds to ping, False otherwise.
        """
        return self.cm.is_ping_reachable()

    async def is_snmp_ready(self) -> bool:
        """
        Asynchronously check if the cable modem is accessible via SNMP.

        Returns:
            bool: True if the modem responds to SNMP queries, False otherwise.
        """
        return await self.cm.is_snmp_reachable()

    async def _filter_measurement_entries(
        self,
        entries: list[MeasurementEntry],
        channel_ids: list[ChannelId] | None,
    ) -> list[MeasurementEntry]:
        if not channel_ids:
            return entries

        channel_id_set = {int(channel_id) for channel_id in channel_ids}
        index_set: set[int] = set()

        if self.pnm_test_type in (
            DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
            DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF,
            DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
            DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
            DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        ):
            idx_channel_id = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()
            index_set = {int(idx) for idx, channel_id in idx_channel_id if int(channel_id) in channel_id_set}

        elif self.pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:
            idx_channel_id = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
            index_set = {int(idx) for idx, channel_id in idx_channel_id if int(channel_id) in channel_id_set}

        filtered: list[MeasurementEntry] = []
        for entry in entries:
            if isinstance(entry, (DocsPnmCmDsHistEntry, DocsIf3CmSpectrumAnalysisEntry)):
                continue
            if index_set:
                if int(entry.index) in index_set:
                    filtered.append(entry)
                continue
            if not hasattr(entry, "channel_id"):
                continue
            if int(entry.channel_id) in channel_id_set:
                filtered.append(entry)
        return filtered

    async def getPnmMeasurementStatistics(
        self,
        channel_ids: list[ChannelId] | None = None,
    ) -> list[MeasurementEntry]:
        """
        Retrieve PNM measurement entries for the currently configured `pnm_test_type`.

        Returns
        -------
        List[MeasurementEntry]
            A (possibly empty) list of model instances corresponding to the active
            test type:

            - DS_OFDM_CHAN_EST_COEF             → List[DocsPnmCmOfdmChanEstCoefEntry]
            - DS_CONSTELLATION_DISP             → List[DocsPnmCmDsConstDispMeasEntry]
            - DS_OFDM_RXMER_PER_SUBCAR          → List[DocsPnmCmDsOfdmRxMerEntry]
            - US_PRE_EQUALIZER_COEF             → List[DocsPnmCmUsPreEqEntry]
            - DS_HISTOGRAM                      → List[DocsPnmCmDsHistEntry]
            - DS_OFDM_FEC_SUMMARY               → List[DocsPnmCmDsOfdmFecEntry]
            - DS_OFDM_MODULATION_PROFILE        → List[DocsPnmCmDsOfdmModProfEntry]
            - SPECTRUM_ANALYZER                 → List[DocsIf3CmSpectrumAnalysisEntry]
            - SPECTRUM_ANALYZER_SNMP_AMP_DATA   → List[DocsIf3CmSpectrumAnalysisEntry]

            For other (stub/unsupported) test types, an empty list is returned.

        Notes
        -----
        - This method performs no aggregation; it returns the raw per-entry models
          fetched from the cable modem for the selected measurement type.
        - For strict typing, concrete lists are cast to `List[MeasurementEntry]`
          at return points (because `List` is invariant in the type system).
        - If `channel_ids` is provided and not empty, results are filtered to only
          include entries whose `channel_id` is in the list.
        """
        entries: list[MeasurementEntry] = []

        if self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            self.logger.debug(f"{self.log_prefix} - Running SPECTRUM_ANALYZER")
            concrete = await self.cm.getDocsIf3CmSpectrumAnalysisEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF:
            self.logger.debug(f"{self.log_prefix} - Running OFDM Channel Estimation Coefficient collection")
            concrete = await self.cm.getDocsPnmCmOfdmChanEstCoefEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP:
            self.logger.debug(f"{self.log_prefix} - Running OFDM Constellation Display collection")
            concrete = await self.cm.getDocsPnmCmDsConstDispMeasEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR:
            self.logger.debug(f"{self.log_prefix} - Running RXMER entry collection")
            concrete = await self.cm.getDocsPnmCmDsOfdmRxMerEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE:
            self.logger.debug(f"{self.log_prefix} - Running DS_OFDM_CODEWORD_ERROR_RATE")
            concrete = await self.cm.getDocsPnmCmDsOfdmFecEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM:
            self.logger.debug(f"{self.log_prefix} - Running DS_HISTOGRAM")
            concrete = await self.cm.getDocsPnmCmDsHistEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:
            self.logger.debug(f"{self.log_prefix} - Running Upstream Pre-Equalization entry collection")
            concrete = await self.cm.getDocsPnmCmUsPreEqEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE:
            self.logger.debug(f"{self.log_prefix} - Running DS_OFDM_MODULATION_PROFILE")
            concrete = await self.cm.getDocsPnmCmDsOfdmModProfEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA:
            self.logger.debug(f"{self.log_prefix} - Running SPECTRUM_ANALYZER_SNMP_AMP_DATA")
            concrete = await self.cm.getDocsIf3CmSpectrumAnalysisEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_SYMBOL_CAPTURE:
            self.logger.warning(f"{self.log_prefix} - Stub handler: DS_OFDM_SYMBOL_CAPTURE")

        elif self.pnm_test_type == DocsPnmCmCtlTest.LATENCY_REPORT:
            self.logger.warning(f"{self.log_prefix} - Stub handler: LATENCY_REPORT")

        else:
            self.logger.warning(f"{self.log_prefix} - Unknown PNM test type: {self.pnm_test_type}")

        return entries

    ###################
    # Private Methods #
    ###################

    async def _get_and_move_pnm_file(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Retrieves and moves the specified PNM file based on the configured retrieval method.

        This method delegates the file retrieval operation to a protocol-specific handler method
        depending on the configuration defined under `PnmFileRetrieval.method`. 
        Supported methods include: "local", "tftp", "sftp"
        # TODO: Need to implement, not sure if we need to: "ftp", "http", and "https".

        Configuration keys used:
            - PnmFileRetrieval.method: The file retrieval method to use (e.g., "local", "tftp", etc.).
            - PnmFileRetrieval.retries: Optional number of retries for retrieval attempts (currently unused here).

        Args:
            pnm_file_name (str): The name of the file to retrieve and move.

        Returns:
            bool: True if the file was successfully retrieved and moved; False otherwise.
        """
        method = SystemConfigSettings.retrieval_method()
        self.logger.info(f"{self.log_prefix} - Retrieval method: {method}")

        try:
            if method == "local":
                return await self._handle_local_fetch(pnm_file_name)
            elif method == "tftp":
                return self._handle_tftp_fetch(pnm_file_name)
            elif method == "ftp":
                return self._handle_ftp_fetch(pnm_file_name)
            elif method == "sftp":
                return self._handle_sftp_fetch(pnm_file_name)
            elif method == "http":
                return self._handle_http_fetch(pnm_file_name)
            elif method == "https":
                return self._handle_https_fetch(pnm_file_name)
            else:
                self.logger.error(f"{self.log_prefix} - Unsupported retrieval method: {method}")
                return ServiceStatusCode.FILE_RETRIEVAL_TYPE_INVALID

        except Exception as e:
            self.logger.exception(f"{self.log_prefix} - File retrieval failed: {e}")
            return ServiceStatusCode.PNM_FILE_RETRIEVAL_ERROR

    async def _get_indexes_via_pnm_test_type(self, ifParameters: DownstreamOfdmParameters | UpstreamOfdmaParameters | None = None
                                             ) -> tuple[ServiceStatusCode, list[tuple[InterfaceIndex, ChannelId]] | None]:
        """
        Determines the appropriate interface indexes and channel IDs to target for a given PNM test type.

        Depending on the configured PNM test type, this method selects the relevant interface and filters the index/ChannelID
        tuples based on user-specified parameters.

        Args:
            interface_parameters (Optional[InterfaceParameters]): Parameters specifying interface type ("ofdm" or "ofdma")
                and optionally a list of channel IDs to filter. If not provided, default parameters are selected based on test type.

        Returns:
            Tuple[ServiceStatusCode, Optional[List[Tuple[int, int]]]]:
                A status code indicating success or reason for failure, and a list of (index, channelId) tuples.
        """

        if ifParameters is None:
            ifParameters = DownstreamOfdmParameters()

        if not ifParameters:
            ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmDownstream)

        if self.pnm_test_type in (DocsPnmCmCtlTest.DS_HISTOGRAM, DocsPnmCmCtlTest.LATENCY_REPORT):
            idx:list[InterfaceIndex] = await self.cm.getIfTypeIndex(DocsisIfType.docsCableMaclayer)
            return ServiceStatusCode.SUCCESS, [(idx[0], ChannelId(0))]

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            return ServiceStatusCode.SUCCESS, [(InterfaceIndex(0), ChannelId(0))]

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA:
            return ServiceStatusCode.SUCCESS, [(InterfaceIndex(0), ChannelId(0))]

        elif self.pnm_test_type in (DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
                                    DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF,
                                    DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
                                    DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
                                    DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR):

            if not ifParameters:
                ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmDownstream)

        elif self.pnm_test_type in (DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF,):
            ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmaUpstream)
            self.logger.info(f'{DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF} Measurement - IfParameters: {ifParameters.model_dump()}')

        '''
        There is redundant code, but incase I may need to change due to
        change of requiments depending on Downstream vs. Upstream

        TODO: lol, I am sure I will not revisit, but OK for now.
        '''
        if ifParameters.type == "ofdm":
            channel_id_list = ifParameters.channel_id
            idx_channelId = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()

            if not idx_channelId:
                self.logger.warning("No OFDM channel data found.")
                return ServiceStatusCode.NO_OFDMA_CHAN_ID_INDEX_FOUND, []

            if channel_id_list:
                filtered = [tpl for tpl in idx_channelId if tpl[1] in channel_id_list]
                self.logger.info(f'Downstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
                return ServiceStatusCode.SUCCESS, filtered

            self.logger.info(f'Downstream: {ifParameters.type} -> IDX,CHAN_ID: {idx_channelId}')

            return ServiceStatusCode.SUCCESS, idx_channelId

        elif ifParameters.type == "ofdma":
            channel_id_list = ifParameters.channel_id
            idx_channelId = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
            if not idx_channelId:
                self.logger.warning("No OFDMA channel found.")
                return ServiceStatusCode.NO_OFDMA_CHAN_ID_INDEX_FOUND, []

            if channel_id_list:
                filtered = [tpl for tpl in idx_channelId if tpl[1] in channel_id_list]
                self.logger.info(f'Upstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
                return ServiceStatusCode.SUCCESS, filtered

            self.logger.info(f'Upstream: {ifParameters.type} -> IDX,CHAN_ID: {idx_channelId}')

        return ServiceStatusCode.SUCCESS, idx_channelId

    async def _pnm_measure_status_and_pnm_file_transfer(self, idx_channelId:list[tuple[InterfaceIndex, ChannelId]], max_wait_count:int) -> ServiceStatusCode:
        """
        Set and monitor the OFDM measurement test for specified (index, PLC) tuples.

        For each (index, PLC) pair:
            - Initiates the PNM test using SNMP.
            - Waits for the test status to reach READY.
            - Monitors for the measurement status to become SAMPLE_READY.
            - Retrieves the resulting PNM file and stores it locally.

        Args:
            idx_channelId (Tuple[int, int]): A list of tuples where each tuple consists of
                the SNMP interface index and the corresponding PLC (center frequency).
            max_wait_count (int): Maximum number of seconds to wait for SAMPLE_READY status.

        Returns:
            ServiceStatusCode: SUCCESS if all steps completed successfully,
                otherwise a specific error status (e.g., if the file couldn't be retrieved
                or the measurement status did not become SAMPLE_READY).
        """
        for interface_index, channel_id in idx_channelId:

            #######################################################################
            # This sets the Measurement Table/Row for the specific PNM Measurement
            #######################################################################
            ctl_measure_status:tuple[ServiceStatusCode, list[FileNameStr]] = \
                await self._setDocsPnmCmMeasureTest(self.pnm_test_type, interface_index, channel_id)
            
            if ctl_measure_status[0] != ServiceStatusCode.SUCCESS:
                return ctl_measure_status[0]

            pnm_filenames = ctl_measure_status[1]
            self.logger.info(f'{self.log_prefix} - PNM File(s) -> {pnm_filenames}')

            count=1
            while True:
                cm_ctl_status:DocsPnmCmCtlStatus = await self.cm.getDocsPnmCmCtlStatus()
                self.logger.info(f"{self.log_prefix} - PNM status: {str(cm_ctl_status).upper()} - count: {count}")
                if cm_ctl_status == DocsPnmCmCtlStatus.TEST_IN_PROGRESS:
                    count += 1
                    await asyncio.sleep(1)
                    continue

                if cm_ctl_status == DocsPnmCmCtlStatus.READY:
                    break

                if cm_ctl_status == DocsPnmCmCtlStatus.TEMP_REJECT:
                    break

                if cm_ctl_status == DocsPnmCmCtlStatus.SNMP_ERROR:
                    break

            self.logger.debug(f"{self.log_prefix} - Checking Measurement Status for {self.pnm_test_type} @ IDX: {interface_index}")

            wait_count = 0
            def extract_idx(idx):
                return idx[0] if isinstance(idx, list) and idx else idx

            while wait_count < max_wait_count:
                meas_status = await self.cm.getPnmMeasurementStatus(self.pnm_test_type, extract_idx(interface_index))
                self.logger.info(f"{self.log_prefix} - MeasureStatus: {meas_status.name}")
                if meas_status == MeasStatusType.SAMPLE_READY:
                    break
                await asyncio.sleep(1)
                wait_count += 1

            else:
                self.logger.error(f"{self.log_prefix} - SAMPLE_READY not reached for ChannelID {channel_id}")
                return ServiceStatusCode.NOT_READY_AFTER_FILE_CAPTURE

            #Multiple PNM files for special cases
            for pnm_fname in pnm_filenames:

                status:ServiceStatusCode = await self._check_and_wait_for_tftp_upload(FileNameStr(pnm_fname))

                if status != ServiceStatusCode.SUCCESS:
                    self.logger.error(f"{self.log_prefix} - Unable to Upload PNM File to TFTP({status})")
                    return status

                # Get and copy PNM file to local data directory
                retrieval_status = await self._get_and_move_pnm_file(FileNameStr(pnm_fname))
                if retrieval_status != ServiceStatusCode.SUCCESS:
                    self.logger.error(
                        f"{self.log_prefix} - Unable to copy PNM file to local {self.pnm_dir} dir "
                        f"(status={retrieval_status})")
                    return retrieval_status

                # Find Transaction ID via filename
                trans_id = self._get_transaction_id_by_filename(pnm_fname)
                if not trans_id:
                    self.logger.error(f"{self.log_prefix} - Unable to find Transaction ID for PNM filename: {pnm_fname}")
                    return ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND
                
                self.logger.debug(f'{self.log_prefix} - TransID: {trans_id} -> Filename: {pnm_fname}')
                self.build_transaction_msg(trans_id, pnm_fname)

        return ServiceStatusCode.SUCCESS

    async def _check_and_wait_for_tftp_upload(self, filename: str, max_wait_count: int = 5) -> ServiceStatusCode:
        """
        Waits for a PNM file to be uploaded via TFTP by polling the upload status.

        Args:
            filename (str): The name of the file being uploaded.
            max_wait_count (int): Maximum number of seconds to wait before timing out.

        Returns:
            ServiceStatusCode: SUCCESS if upload completed, failure code otherwise.
        """
        wait_count = 0

        while wait_count < max_wait_count:
            try:
                status = await self.cm.getBulkFileUploadStatus(filename)
            except Exception as e:
                self.logger.error(f"{self.log_prefix} - Error checking upload status for '{filename}': {e}")
                return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

            if status == DocsPnmBulkFileUploadStatus.UPLOAD_COMPLETED:
                self.logger.info(f"{self.log_prefix} - File '{filename}' uploaded successfully.")
                return ServiceStatusCode.SUCCESS

            if status == DocsPnmBulkFileUploadStatus.ERROR:
                self.logger.error(f"{self.log_prefix} - Device reported ERROR for file upload '{filename}'.")
                return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

            self.logger.debug(
                f"{self.log_prefix} - Waiting for file '{filename}' to upload "
                f"(status={status.name}, wait_count={wait_count})"
            )

            await asyncio.sleep(1)
            wait_count += 1

        self.logger.error(f"{self.log_prefix} - TFTP file '{filename}' upload timed out after {max_wait_count} seconds.")
        return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

    async def _setDocsPnmCmMeasureTest(self, pnm_test_type:DocsPnmCmCtlTest,
                                       interface_index:int, channel_id:ChannelId) -> tuple[ServiceStatusCode, list[FileNameStr]]:
        """
        Configure and trigger a specific PNM (Proactive Network Maintenance) measurement
        test on a cable modem based on the test type.

        Depending on the `pnm_test_type`, this method:
        - Generates appropriate output file names.
        - Uses SNMP to set the modem to collect specific diagnostic data.
        - Handles various DOCSIS downstream and upstream tests, including:
            - US Pre-Equalizer Coefficients (requires two files per interface: pre-eq and last pre-eq)
            - DS OFDM RxMER per Subcarrier
            - DS OFDM Codeword Error Rate
            - DS OFDM Channel Estimation Coefficients
            - DS Constellation Display
            - DS Histogram
            - DS OFDM Modulation Profile
            - Spectrum Analyzer Scan

        Parameters:
            pnm_test_type (DocsPnmCmCtlTest): Enum value indicating the PNM test to perform.
            interface_index (int): The SNMP index for the OFDM channel (usually the interface index).
            channel_id (int): The channel ID associated with the modem interface.

        Returns:
            Tuple[ServiceStatusCode, List[str]]: Status of the operation and list of generated file names.
        """
        pnm_files: list[FileNameStr] = []

        if pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:

            # Pre-Eq and Last Pre-EQ (2 files)
            pre_eq_filename         = await self._pnm_file_generator(self.pnm_test_type, str(channel_id))
            last_pre_eq_filename    = await self._pnm_file_generator(self.pnm_test_type, f'last_pre-eq_{str(channel_id)}')

            self.logger.info(f'{self.log_prefix} - Setting {self.pnm_test_type} for ChannelID: {channel_id} "'
                             f'@ IDX: {interface_index} -> FN(): {pre_eq_filename}, FN(last): {last_pre_eq_filename}')

            self.logger.info(f'{self.log_prefix} - Performing US_PRE_EQUALIZER_COEF measurement on IDX: ({interface_index})')
            if not await self.cm.setDocsPnmCmUsPreEq(ofdma_idx              =   interface_index,
                                                     filename               =   pre_eq_filename,
                                                     last_pre_eq_filename   =   last_pre_eq_filename):
                self.logger.error(f"{self.log_prefix} - Upstream OFDMA Pre-Equalization is Not Avalaible")
                return ServiceStatusCode.FILE_SET_FAIL, []

            #Append files for later fetching
            pnm_files.extend([pre_eq_filename, last_pre_eq_filename])

        else:
            #The remaining PNM Measuresurement are single PNM file
            pnm_filename = await self._pnm_file_generator(self.pnm_test_type, str(channel_id))
            self.logger.debug(f'{self.log_prefix} - Setting {self.pnm_test_type} for ChannelID: {channel_id} @ IDX: {interface_index} -> FN: {pnm_filename}')
            pnm_files.append(pnm_filename)

            if pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR:

                if not await self.cm.setDocsPnmCmDsOfdmRxMer(ofdm_idx=interface_index, rxmer_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE:

                fst = self.extra_options.get("fec_summary_type", FecSummaryType.TEN_MIN)

                if not await self.cm.setDocsPnmCmDsOfdmFecSum(ofdm_idx=interface_index, fec_sum_file_name=pnm_filename, fec_sum_type=fst):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF:

                if not await self.cm.setDocsPnmCmOfdmChEstCoef(ofdm_idx=interface_index, chan_est_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP:
                # OFDM Downstream Constellation Display setup
                # Extra SNMP options may include:
                #   - modulation_offset: Optional[int]
                #   - num_sample_symb: Optional[int]
                if not await self.cm.setDocsPnmCmDsConstDisp(
                    ofdm_idx                =   interface_index,
                    const_disp_name         =   pnm_filename,
                    modulation_order_offset =   self.extra_options.get('modulation_order_offset', 0),
                    number_sample_symbol    =   self.extra_options.get('number_sample_symbol', 0)
                ):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM:
                sample_duration = self.extra_options.get("histogram_sample_duration", 10)
                if not await self.cm.setDocsPnmCmDsHist(ds_histogram_file_name=pnm_filename, timeout=sample_duration):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE:

                if not await self.cm.setDocsPnmCmDsOfdmModProf(ofdm_idx=interface_index, mod_prof_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
                #Created generic to be used for PNM File and SNMP Return data
                 __status = await self._generic_spectrum_analyzer_operation(filename=pnm_filename)
                 if __status[0] != ServiceStatusCode.SUCCESS:
                    return __status

        return ServiceStatusCode.SUCCESS, pnm_files

    async def _check_spectrum_amplitude_data_status(self, timeout_seconds: int = 300) -> ServiceStatusCode:
        """
        Polls the cable modem for spectrum amplitude data availability within a timeout period.

        This method repeatedly checks if `docsIf3CmSpectrumAnalysisMeasAmplitudeData` is present
        on the modem, and returns a success or timeout status accordingly.

        Args:
            timeout_seconds (int): Maximum number of seconds to wait before timing out. Default is 300.

        Returns:
            ServiceStatusCode:
                - SUCCESS if data becomes available within the timeout period.
                - SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT if the timeout is exceeded.
        """
        t_start = time.time()

        while True:
            if await self.cm.isAmplitudeDataPresent():
                return ServiceStatusCode.SUCCESS
            now:int = math.floor(time.time() - t_start)

            if now >= timeout_seconds:
                self.logger.warning(f'{self.log_prefix} - Timeout for Amplitude Data ({now} of {timeout_seconds} seconds)')
                return ServiceStatusCode.SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT

            self.logger.info(f'{self.log_prefix} - Waiting for Amplitude Data ({now} of {timeout_seconds})')

            await asyncio.sleep(1)

    async def _handle_local_fetch(self, pnm_file_name: str) -> ServiceStatusCode:
        """
        Handles copying a specified PNM file from a local source directory to a configured save directory.

        This method looks up the source and destination paths from the application's system configuration
        (under the "PnmFileRetrieval" section) and attempts to copy the file named `pnm_file_name`
        from the source directory to the save directory.

        Configuration keys used:
            - PnmFileRetrieval.local.src_dir: Source directory where the PNM file resides.
            - PnmFileRetrieval.save_dir: Destination directory where the file should be saved.

        Args:
            pnm_file_name (str): The name of the file to copy.

        Returns:
            bool: True if the file was successfully copied; False otherwise.
        """

        src_dir = SystemConfigSettings.local_src_dir()

        self.logger.info(
            f'{self.log_prefix} - Local Copy - SRC: {src_dir} - SAVE: {self.pnm_dir} - FN: {pnm_file_name}'
        )

        if not os.path.isdir(src_dir) or not os.path.isdir(self.pnm_dir):
            self.logger.error(f"{self.log_prefix} - Invalid source or destination directory")
            return ServiceStatusCode.LOCAL_FETCH_FAILURE

        while True:
            await asyncio.sleep(1)
            file_found = False
            for filename in os.listdir(src_dir):
                if filename == pnm_file_name:
                    file_found = True
                    src_path = os.path.join(src_dir, filename)
                    dest_path = os.path.join(self.pnm_dir, filename)
                    try:
                        shutil.copy2(src_path, dest_path)
                        self.logger.debug(f"{self.log_prefix} - Copied {filename} to {self.pnm_dir}")
                        return ServiceStatusCode.SUCCESS
                    except Exception as e:
                        self.logger.error(f"{self.log_prefix} - Copy failed for {filename}: {e}")
                        return ServiceStatusCode.LOCAL_FETCH_FAILURE

            if not file_found:
                self.logger.warning(f"{self.log_prefix} - File not found in source directory: {pnm_file_name}")

            return ServiceStatusCode.LOCAL_FETCH_FAILURE

    def _handle_sftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch a file from remote SFTP server.

        Args:
            pnm_file_name: Name of the file to fetch from remote server

        Returns:
            bool: True if file transfer successful, False otherwise
        """
        sys_config = SystemConfigSettings()

        self.logger.debug(f"{self.log_prefix} - SFTP: Connecting to: {sys_config.sftp_host()}")

        if self._ping_pnm_file_server(HostNameStr(sys_config.sftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for SFTP host: {sys_config.sftp_host()}")
            return ServiceStatusCode.SFTP_HOST_UNREACHABLE

        sftp = SSHConnector(
            hostname        =   sys_config.sftp_host(),
            username        =   sys_config.sftp_user(),
            port            =   sys_config.sftp_port())

        password_enc     = sys_config.sftp_password()
        private_key_path = sys_config.sftp_private_key_path()

        try:
            if not sftp.connect(password_enc     =   password_enc,
                                private_key_path =   private_key_path):
                self.logger.error(f'{self.log_prefix} - SFTP Connect Failure: Host: {sys_config.sftp_host()}')
                return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

            remote_file_path = f'{sys_config.sftp_remote_dir()}/{pnm_file_name}'
            if not sftp.receive_file(remote_path =   remote_file_path,
                                     local_path  =   sys_config.pnm_dir()):
                self.logger.error(
                    f'{self.log_prefix} - SFTP Receive File Error '
                    f'(SRC:{remote_file_path} DST: {sys_config.pnm_dir()})'
                )
                return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

            self.logger.info(f'{self.log_prefix} - Successfully fetched file: {pnm_file_name}')
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f'{self.log_prefix} - SFTP Fetch Exception: {e}')
            return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

        finally:
            sftp.disconnect()

    def _handle_tftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch the specified PNM file via TFTP.

        Assumes the following attributes on self:
        - self.pnm_local_dir (str)    # local directory to save the downloaded file
        - self.log_prefix (str)       # used for consistent logging

        TFTP settings are read from SystemConfigCommonSettings:
        - tftp_host (str)
        - tftp_port (int)
        - tftp_timeout (int)
        - tftp_remote_dir (str)   # remote directory where PNM files live (if applicable)
        """

        if self._ping_pnm_file_server(HostNameStr(SystemConfigSettings.tftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for TFTP host: {SystemConfigSettings.tftp_host()}")
            return ServiceStatusCode.TFTP_HOST_UNREACHABLE  

        try:
            connector = TFTPConnector(
                host    =   Inet(SystemConfigSettings.tftp_host()),
                port    =   int(str(SystemConfigSettings.tftp_port())))

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during TFTP connecting: {e}")
            return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

        try:

            self.logger.info(
                f"{self.log_prefix} - Starting TFTP download from "
                f"{SystemConfigSettings.tftp_host()}:{SystemConfigSettings.tftp_port()}"
            )

            # Build remote filename (some tftp servers require just the basename)
            remote_name = (
                f"{SystemConfigSettings.tftp_remote_dir().rstrip('/')}/{pnm_file_name}"
                if SystemConfigSettings.tftp_remote_dir() else
                pnm_file_name
            )
            local_path = os.path.join(SystemConfigSettings.pnm_dir(), pnm_file_name)

            success = connector.download_file(remote_name, local_path)

            if not success:
                self.logger.error(
                    f"{self.log_prefix} - TFTP download failed for '{remote_name}'"
                )
                return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

            self.logger.info(
                f"{self.log_prefix} - Successfully fetched '{pnm_file_name}' via TFTP"
            )
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during TFTP downloading: {e}")
            return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

    def _handle_ftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch the specified PNM file via FTP.

        Assumes the following attributes exist on self:
        - self.pnm_local_dir (str)    # local directory to save the downloaded file
        - self.log_prefix (str)       # used for consistent logging

        All FTP-specific settings are read from SystemConfigCommonSettings:
        - ftp_host (str)
        - ftp_port (int)
        - ftp_user (str)
        - ftp_password (str)
        - ftp_use_tls (bool)
        - ftp_timeout (int)
        - ftp_remote_dir (str)   # remote directory where PNM files live
        """
        sys_config = SystemConfigSettings()

        if self._ping_pnm_file_server(HostNameStr(SystemConfigSettings.ftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for FTP host: {SystemConfigSettings.ftp_host()}")
            return ServiceStatusCode.FTP_HOST_UNREACHABLE  

        try:
            connector = FTPConnector(
                host        =   str(sys_config.ftp_host()),
                port        =   int(str(sys_config.ftp_port())),
                username    =   str(sys_config.ftp_user()),
                password    =   str(sys_config.ftp_password()),
                use_tls     =   bool(sys_config.ftp_use_tls()),
                timeout     =   int(str(sys_config.ftp_timeout()))
            )

            self.logger.debug(
                f"{self.log_prefix} - Connecting to FTP server "
                f"{sys_config.ftp_host}:{sys_config.ftp_port}"
            )
            if not connector.connect():
                self.logger.error(f"{self.log_prefix} - FTP connection failed")
                return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

            # Build remote and local paths
            remote_base = sys_config.ftp_remote_dir.rstrip("/") if sys_config.ftp_remote_dir else ""
            remote_path = f"{remote_base}/{pnm_file_name}" if remote_base else pnm_file_name

            local_path = os.path.join(self.pnm_local_dir, pnm_file_name)

            self.logger.debug(
                f"{self.log_prefix} - Downloading '{remote_path}' to '{local_path}'"
            )
            success = connector.download_file(remote_path, local_path)
            connector.disconnect()

            if not success:
                self.logger.error(
                    f"{self.log_prefix} - FTP download failed for '{remote_path}'"
                )
                return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

            self.logger.info(
                f"{self.log_prefix} - Successfully fetched '{pnm_file_name}' via FTP"
            )
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during FTP fetch: {e}")
            return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

    def _handle_http_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        # TODO: implement HTTP file fetch logic
        self.logger.debug(f"{self.log_prefix} - HTTP fetch not yet implemented")
        return ServiceStatusCode.HTTP_PNM_FILE_FETCH_ERROR

    def _handle_https_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        # TODO: implement HTTPS file fetch logic
        self.logger.debug(f"{self.log_prefix} - HTTPS fetch not yet implemented")
        return ServiceStatusCode.SHTTP_PNM_FILE_FETCH_ERROR
    
    async def _pnm_file_generator(self, test_type: DocsPnmCmCtlTest, suffix: str = "", ext: str = ".bin") -> FileNameStr:
        """
        Generates the PNM file name based on the provided DocsPnmCmCtlTest, with optional suffix and extension.

        Args:
            test_type (DocsPnmCmCtlTest): The type of the test to generate the prefix.
            suffix (str, optional): A suffix added to the file name. Defaults to an empty string.
            ext (str, optional): The file extension. Defaults to ".bin".

        Returns:
            str: The generated PNM file name.
        """
        test_prefix = test_type.name.lower()

        if suffix:
            suffix = f'_{suffix}'

        file_name:FileNameStr = FileNameStr(f"{test_prefix}_{self.cm.get_mac_address.to_mac_format()}{suffix}_{Generate.time_stamp()}{ext}")

        transaction_id = await PnmFileTransaction().insert(self.cm, test_type, file_name)

        self.logger.debug(f"Generated PNM file name: {file_name} -> TransID: {transaction_id}")

        self._transactionId_pnmFile[transaction_id] = file_name

        return file_name

    def _get_transaction_id_by_filename(self, file_name: str) -> TransactionId | None:
        """
        Return the transaction ID associated with the given file name.
        Assumes file names are unique. Returns None if not found.
        """
        for transaction_id, name in self._transactionId_pnmFile.items():
            if name == file_name:
                return TransactionId(transaction_id)
        return None

    async def _generic_spectrum_analyzer_operation(self, filename:str="") -> tuple[ServiceStatusCode, list[str]]:
        """
        Perform a generic spectrum-analyzer operation on the cable modem, supporting two retrieval modes:
        1. SNMP-based amplitude data return (AmplitudeData textual convention)
        2. PNM file return (download via TFTP once the CM writes the file)

        The same set of control parameters (frequency range, bin count, windowing, etc.) is used
        in both cases—avoiding duplicate “control-command” logic (DRY). Downstream, a separate helper
        method is called based on `spectrum_retrieval_type`.

        Extra options (from self.extra_options):
            • inactivity_timeout             (int, default=100)
                - Maximum seconds to wait for the CM to complete the measurement
            • first_segment_center_freq      (int, default=300_000_000)
                - Starting center frequency in Hz
            • last_segment_center_freq       (int, default=900_000_000)
                - Ending center frequency in Hz
            • segment_freq_span              (int, default=7_500_000)
                - Frequency span per segment in Hz
            • num_bins_per_segment           (int, default=256)
                - Number of bins (samples) per segment
            • noise_bw                       (int, default=110)
                - Equivalent noise bandwidth in Hz
            • window_function                (WindowFunction, default=WindowFunction.HANN)
                - Window function to apply to each segment
            • num_averages                   (int, default=1)
                - Number of averages to take
            • spectrum_retrieval_type        (SpectrumRetrievalType, default=SpectrumRetrievalType.FILE)
                - FILE: write to PNM file via TFTP (requires pnm_filename)
                - SNMP: return amplitude data directly via SNMP (no file write)

        Returns:
            Tuple[ServiceStatusCode, List[str]]:
                • On success: (ServiceStatusCode.SUCCESS, [<PNM filename>]) for FILE mode,
                  or (ServiceStatusCode.SUCCESS, []) for SNMP mode.
                • On failure: (ServiceStatusCode.SPEC_ANALYZER_NOT_AVAILABLE, []).

        Raises:
            None directly—errors are mapped to a failure status code.
        """
        self.logger.info(f"{self.log_prefix} - Entering into SPECTRUM-ANALYZER Mode (filename: {filename})")

        # Default: only SNMP control-command, no file write
        ctl_cmd_filename = Snmp_v2c.TRUE

        if (self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER or \
            self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA) and \
            (not self.getSpectrumCaptureParameters()):

            self.logger.error('No Spectrum Parameters Found, did you set: setSpectrumCaptureParameters()')

            return  ServiceStatusCode.NO_SPECTRUM_CAPTURE_PARAMETERS, []

        capture_parameter = self.getSpectrumCaptureParameters()

        if not capture_parameter:

            capture_parameter = SpecAnCapturePara (
                inactivity_timeout          = self.extra_options.get("inactivity_timeout", 100),
                first_segment_center_freq   = self.extra_options.get("first_segment_center_freq", 300_000_000),
                last_segment_center_freq    = self.extra_options.get("last_segment_center_freq", 993_000_000),
                segment_freq_span           = self.extra_options.get("segment_freq_span", 1_000_000),
                num_bins_per_segment        = self.extra_options.get("num_bins_per_segment", 256),
                noise_bw                    = self.extra_options.get("noise_bw", 110),
                window_function             = self.extra_options.get("window_function", WindowFunction.HANN),
                num_averages                = self.extra_options.get("num_averages", 1),
                spectrum_retrieval_type     = self.extra_options.get("spectrum_retrieval_type",SpectrumRetrievalType.FILE),
            )

        if capture_parameter.spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.info(f"{self.log_prefix} - SPECTRUM-ANALYZER - SNMP-AMPLITUDE-DATA-RETURN")
            ctl_cmd_filename = Snmp_v2c.FALSE

        else:
            if not filename:
                self.logger.error(f"{self.log_prefix} - Missing 'filename' for FILE retrieval mode")
                return ServiceStatusCode.MISSING_PNM_FILENAME, []

        spectrum_cmd = DocsIf3CmSpectrumAnalysisCtrlCmd(
            docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout           =   capture_parameter.inactivity_timeout,
            docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency =   capture_parameter.first_segment_center_freq,
            docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency  =   capture_parameter.last_segment_center_freq,
            docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan        =   capture_parameter.segment_freq_span,
            docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment           =   capture_parameter.num_bins_per_segment,
            docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth    =   capture_parameter.noise_bw,
            docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction              =   capture_parameter.window_function,
            docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages            =   capture_parameter.num_averages,
            docsIf3CmSpectrumAnalysisCtrlCmdEnable                      =   Snmp_v2c.TRUE,
            docsIf3CmSpectrumAnalysisCtrlCmdFileName                    =   filename,
            docsIf3CmSpectrumAnalysisCtrlCmdFileEnable                  =   ctl_cmd_filename,)

        # Issue the SNMP SET for the control-command. The downstream logic
        # (not shown here) will branch to either:
        #   • SNMP:  set FileEnable = FALSE → wait for measurement → walk AmplitudeData
        #   • FILE:  set FileEnable = TRUE  → wait for measurement status → TFTP download
        if not await self.cm.setDocsIf3CmSpectrumAnalysisCtrlCmd(spectrum_cmd,
                                                                 capture_parameter.spectrum_retrieval_type):
            self.logger.error(f"{self.log_prefix} - Spectrum Analyzer is Not Available")
            return ServiceStatusCode.SPEC_ANALYZER_NOT_AVAILABLE, []

        # On success, return the filename (if FILE mode) or an empty list (SNMP mode)
        if capture_parameter.spectrum_retrieval_type == SpectrumRetrievalType.FILE:
            return ServiceStatusCode.SUCCESS, [filename]
        else:
            return ServiceStatusCode.SUCCESS, []

    def _ping_pnm_file_server(self, host: HostNameStr) -> ServiceStatusCode:
        """
        Ping The PNM File Server To Check Its Availability.

        This helper first attempts DNS resolution of the host. If the host
        resolves only to loopback addresses (for example "127.0.0.1" or "::1"),
        ICMP ping is bypassed and the host is treated as reachable so that
        local SCP/SFTP/TFTP retrieval is not blocked by loopback
        misconfiguration.

        If DNS resolution fails entirely, the ping pre-check is skipped and the
        method returns SUCCESS while logging the condition at debug level,
        allowing the subsequent transfer step to provide a more precise error.

        For non-loopback addresses that resolve successfully, a standard ICMP
        ping is issued via HostEndpoint. If the ping fails, PING_FAILED is
        returned.
        """
        endpoint  = HostEndpoint(host)
        addresses = endpoint.resolve()

        if not addresses:
            self.logger.debug(
                f"{self.log_prefix} - DNS lookup failed for host: {host}; "
                "skipping ping pre-check"
            )
            return ServiceStatusCode.SUCCESS

        for addr in addresses:
            if addr.startswith("127.") or addr == "::1":
                self.logger.debug(
                    f"{self.log_prefix} - Host {host} resolved to loopback ({addr}); "
                    "skipping ping pre-check"
                )
                return ServiceStatusCode.SUCCESS

        if endpoint.ping():
            return ServiceStatusCode.SUCCESS

        self.logger.debug(f"{self.log_prefix} - Ping failed for host: {host}")
        return ServiceStatusCode.PING_FAILED
# FILE: src/pypnm/api/routes/docs/dev/service.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging

from fastapi import HTTPException

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    SNMPConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPv2c,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import PnmResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.dev.schemas import EventLogEntry
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr

logger = logging.getLogger(__name__)


class CmDocsDevService:
    def __init__(
        self,
        mac_address: MacAddressStr,
        ip_address: InetAddressStr,
        snmp_config: SNMPConfig | None = None,
    ) -> None:
        if snmp_config is None:
            snmp_config = SNMPConfig(snmp_v2c=SNMPv2c(community=None))
        self._mac = MacAddress(mac_address)
        self._ip = Inet(ip_address)
        self._cm = CableModem(
            mac_address=self._mac,
            inet=self._ip,
            write_community=snmp_config.snmp_v2c.community,
        )

    def get_mac_address(self) -> MacAddressStr:
        return self._mac.mac_address

    async def fetch_event_log(self) -> list[EventLogEntry]:
        """
        Fetch DOCSIS event log entries and return a list of structured models.
        """
        raw_entries: list[dict] = await self._cm.getDocsDevEventEntry(to_dict=True)

        log_entries = []
        for raw in raw_entries:
            if not isinstance(raw, dict) or not raw:
                continue

            try:
                _, event_data = next(iter(raw.items()))
                log_entries.append(
                    EventLogEntry(
                        docsDevEvFirstTime=event_data.get("docsDevEvFirstTime", ""),
                        docsDevEvLastTime=event_data.get("docsDevEvLastTime", ""),
                        docsDevEvCounts=event_data.get("docsDevEvCounts", 0),
                        docsDevEvLevel=event_data.get("docsDevEvLevel", 0),
                        docsDevEvId=event_data.get("docsDevEvId", 0),
                        docsDevEvText=event_data.get("docsDevEvText", ""),
                    )
                )
            except Exception:
                continue

        return log_entries

    async def reset_cable_modem(self) -> PnmResponse:
        try:
            if not await self._cm.setDocsDevResetNow():
                return PnmResponse(
                    mac_address=self._mac.mac_address,
                    status=ServiceStatusCode.RESET_NOW_FAILED,
                    message=f"Reset command to cable modem at {self._ip} failed.",
                )

            return PnmResponse(
                mac_address=self._mac.mac_address,
                status=ServiceStatusCode.SUCCESS,
                message=f"Reset command sent to cable modem at {self._ip} successfully.",
            )

        except Exception as e:
            logger.exception("Failed to reset cable modem")
            raise HTTPException(status_code=500, detail=str(e)) from e

    async def ping_cable_modem(self) -> PnmResponse:
        try:
            if not self._cm.is_ping_reachable():
                return PnmResponse(
                    mac_address=self._mac.mac_address,
                    status=ServiceStatusCode.PING_FAILED,
                    message=f"Ping to {self._ip} failed.",
                )

            return PnmResponse(
                mac_address=self._mac.mac_address,
                status=ServiceStatusCode.SUCCESS,
                message=f"Ping to cable modem at {self._ip} succeeded.",
            )

        except Exception as e:
            logger.exception("Failed to send ping to cable modem")
            raise HTTPException(status_code=500, detail=str(e)) from e
# FILE: src/pypnm/api/routes/docs/fdd/diplexer/service.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    SNMPConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPv2c,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.ClabsDocsisVersion import ClabsDocsisVersion
from pypnm.docsis.data_type.DocsFddCmFddCapabilities import (
    DocsFddCmFddBandEdgeCapabilities,
)
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress, MacAddressStr
from pypnm.lib.types import InetAddressStr


class FddDiplexerBandEdgeCapabilityService:
    """
    Service class for retrieving the diplexer band edge capabilities of a DOCSIS 4.0
    cable modem operating in FDD mode.

    This service fetches the following capabilities via SNMP:
    - Upstream upper band edge capability
    - Downstream lower band edge capability
    - Downstream upper band edge capability

    These values indicate the supported extended frequency spectrum limits as reported
    in the modem's SNMP MIBs (e.g., `docsFddDiplexerUsUpperBandEdgeCapability`, etc.).
    """

    def __init__(
        self,
        mac_address: MacAddressStr,
        ip_address: InetAddressStr,
        snmp_config: SNMPConfig | None = None,
    ) -> None:
        """
        Initialize the service using a modem's MAC and IP address.

        Args:
            mac_address (str): The MAC address of the target cable modem.
            ip_address (str): The IP address of the target cable modem.
        """

        if snmp_config is None:
            snmp_config = SNMPConfig(snmp_v2c=SNMPv2c(community=None))

        self.cm = CableModem(
            mac_address=MacAddress(mac_address),
            inet=Inet(ip_address),
            write_community=snmp_config.snmp_v2c.community,
        )

    def isDocsis40(self) -> bool:
        return self.cm.getDocsisBaseCapability() == ClabsDocsisVersion.DOCSIS_40

    async def getFddDiplexerBandEdgeCapabilityEntries(self) -> list[dict]:
        """
        Retrieve and populate the FDD diplexer band edge capabilities from the modem.

        This method:
        1. Walks the SNMP capability tables to obtain valid indices.
        2. Constructs DocsFddCmFddBandEdgeCapabilities objects for each.
        3. Starts SNMP population of each capability instance.
        4. Returns the structured results as a list of dictionaries.

        Returns:
            List[Dict]: A list of populated band edge capability entries.
        """
        fdd_band_edge_list: (
            list[DocsFddCmFddBandEdgeCapabilities] | None
        ) = await self.cm.getDocsFddCmFddBandEdgeCapabilities(create_and_start=False)

        if fdd_band_edge_list is None:
            return []

        entries = [
            fdd_band_edge.to_dict()
            for fdd_band_edge in fdd_band_edge_list
            if await fdd_band_edge.start()
        ]

        return entries
# FILE: src/pypnm/api/routes/docs/if30/ds/scqam/chan/stats/service.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import logging

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    SNMPConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPv2c,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.DocsIfDownstreamChannel import DocsIfDownstreamChannelEntry
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class DsScQamChannelService:
    """
    Service class for retrieving SC-QAM (Single Carrier Quadrature Amplitude Modulation)
    downstream channel entries from a DOCSIS cable modem.

    This class encapsulates logic to interact with a cable modem using its MAC and IP address,
    and extract downstream channel metrics such as frequency, power, SNR, and modulation type.
    """

    def __init__(
        self,
        mac_address: MacAddressStr,
        ip_address: InetAddressStr,
        snmp_config: SNMPConfig | None = None,
    ) -> None:
        """
        Initialize the service with a target cable modem's MAC and IP address.

        Args:
            mac_address (str): MAC address of the cable modem.
            ip_address (str): IP address of the cable modem.
            snmp_config (SNMPConfig, optional): SNMP configuration. Defaults to None.
        """
        if snmp_config is None:
            snmp_config = SNMPConfig(snmp_v2c=SNMPv2c(community=None))
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cm = CableModem(
            mac_address=MacAddress(mac_address),
            inet=Inet(ip_address),
            write_community=snmp_config.snmp_v2c.community,
        )

    async def get_scqam_chan_entries(self) -> list[dict]:
        """
        Retrieve and process DOCSIS SC-QAM downstream channel entries.

        Returns:
            List[Dict]: A list of dictionaries representing successfully retrieved
                        and populated SC-QAM downstream channel entries.
        """
        entries: list[
            DocsIfDownstreamChannelEntry
        ] = await self.cm.getDocsIfDownstreamChannel()
        return [entry.model_dump() for entry in entries]

    async def get_scqam_chan_codeword_error_rate(
        self, time_elapse: float = 5
    ) -> list[dict]:
        """
        Retrieve codeword error rate for all downstream SC-QAM channels.
        Args:
            time_elapse (float): Time interval in seconds to wait between two SNMP snapshots.
                                 Default is 5 seconds.
        Returns:
            List[Dict]: A list of dictionaries containing codeword error rate entries for each channel.
        """
        cw_error_rate = await self.cm.getDocsIfDownstreamChannelCwErrorRate(time_elapse)

        self.logger.info(
            f"Retrieved [{len(cw_error_rate)}] SC-QAM channel codeword error rate entries over a sampling interval of {time_elapse} seconds."
        )

        if isinstance(cw_error_rate, list):
            return [entry.model_dump() for entry in cw_error_rate]

        elif isinstance(cw_error_rate, dict):
            return cw_error_rate.get("entries", [])

        else:
            return []
# FILE: src/pypnm/api/routes/docs/if31/us/ofdma/chan/stats/service.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    SNMPConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPv2c,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.DocsIf31CmUsOfdmaChanEntry import DocsIf31CmUsOfdmaChanEntry
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class UsOfdmChannelService:
    def __init__(
        self,
        mac_address: MacAddressStr,
        ip_address: InetAddressStr,
        snmp_config: SNMPConfig | None = None,
    ) -> None:
        if snmp_config is None:
            snmp_config = SNMPConfig(snmp_v2c=SNMPv2c(community=None))
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cm = CableModem(
            mac_address=MacAddress(mac_address),
            inet=Inet(ip_address),
            write_community=snmp_config.snmp_v2c.community,
        )

    async def get_ofdma_chan_entries(self) -> list[dict]:
        """
        Retrieves and populates all OFDMA upstream channel entries.

        Returns:
            List[dict]: List of dictionaries with `index`, `channel_id`, and `entry` keys.
        """
        entries: list[
            DocsIf31CmUsOfdmaChanEntry
        ] = await self.cm.getDocsIf31CmUsOfdmaChanEntry()

        result = []
        try:
            for entry in entries:
                result.append(entry.model_dump())
        except Exception as e:
            self.logger.warning(f"Skipping invalid entry at index {entry.index}: {e}")

        return result
# FILE: src/pypnm/api/routes/docs/pnm/ds/histogram/router.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisRptMatplotConfig
from pypnm.api.routes.basic.histrogram_analysis_rpt import DsHistrogramReport
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.histogram.schemas import PnmHistogramAnalysisRequest
from pypnm.api.routes.docs.pnm.ds.histogram.service import CmDsHistogramService
from pypnm.api.routes.docs.pnm.files.service import FileType, PnmFileService
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.pnm.DocsPnmCmDsHistEntry import DocsPnmCmDsHistEntry
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class DsHistogramRouter:
    """
    Router for DOCSIS Downstream Histogram operations following the RxMER design pattern.

    A single endpoint `/getCapture` performs the capture and, based on `request.analysis.output.type`,
    returns either a JSON payload with processed results or an archive (ZIP) report.
    """

    def __init__(self) -> None:
        prefix = "/docs/pnm/ds"
        self.base_endpoint = "/histogram"
        self.router = APIRouter(
            prefix=prefix, tags=["PNM Operations - Downstream Histogram"]
        )
        self.logger = logging.getLogger(
            f"DsHistogramRouter.{self.base_endpoint.strip('/')}"
        )
        self.__routes()

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get Downstream Histogram PNM Capture",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_capture(
            request: PnmHistogramAnalysisRequest,
        ) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture DOCSIS Downstream Histogram and return results as JSON or archive.

            The endpoint triggers a histogram capture on the cable modem using SNMP

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/histogram.md)
            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(
                request.cable_modem.snmp
            )
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(
                request.cable_modem.pnm_parameters.tftp
            )

            sample_duration: int = request.capture_settings.sample_duration

            self.logger.info(
                f"Starting Histogram measurement for MAC: {mac}, IP: {ip}, "
                f"Sample Duration: {request.capture_settings.sample_duration}"
            )

            cm = CableModem(
                mac_address=MacAddress(mac), inet=Inet(ip), write_community=community
            )

            status, msg = await CableModemServicePreCheck(cable_modem=cm).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service = CmDsHistogramService(
                cable_modem=cm,
                sample_duration=sample_duration,
                tftp_servers=tftp_servers,
            )

            msg_rsp: MessageResponse = await service.set_and_go()

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Histogram measurement."
                self.logger.error(err)
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            measurement_stats: list[DocsPnmCmDsHistEntry] = cast(
                list[DocsPnmCmDsHistEntry],
                await service.getPnmMeasurementStatistics(channel_ids=channel_ids),
            )

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())
                DictGenerate.pop_keys_recursive(payload, ["channel_id"])
                payload.update(
                    DictGenerate.models_to_nested_dict(
                        measurement_stats,
                        "measurement_stats",
                    )
                )

                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.SUCCESS,
                    data=payload,
                )

            elif request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme=theme)
                analysis_rpt = DsHistrogramReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    data={},
                )


# Required for dynamic auto-registration
router = DsHistogramRouter().router
# FILE: src/pypnm/api/routes/docs/pnm/ds/ofdm/chan_est_coeff/router.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.channel_estimation_analysis_rpt import ChanEstimationReport
from pypnm.api.routes.basic.rxmer_analysis_rpt import AnalysisRptMatplotConfig
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
    PnmSingleCaptureRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.chan_est_coeff.service import (
    CmDsOfdmChanEstCoefService,
)
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.pnm.DocsPnmCmOfdmChanEstCoefEntry import (
    DocsPnmCmOfdmChanEstCoefEntry,
)
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class ChannelEstimationCoefficientRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/ds/ofdm"
        self.base_endpoint = "/channelEstCoeff"
        self.router = APIRouter(
            prefix=prefix,
            tags=["PNM Operations - Downstream OFDM Channel Estimation Coefficients"],
        )
        self.logger = logging.getLogger(
            f"ChannelEstimationCoefficientRouter.{self.base_endpoint.strip('/')}"
        )
        self.__routes()

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get Channel Estimation Coefficients PNM Capture File",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_capture(
            request: PnmSingleCaptureRequest,
        ) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture Downstream OFDM Channel Estimation Coefficients.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/ofdm/channel-estimation.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(
                request.cable_modem.snmp
            )
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(
                request.cable_modem.pnm_parameters.tftp
            )

            self.logger.info(
                f"Starting Channel Estimation Coefficients measurement for MAC: {mac}, IP: {ip}"
            )

            cm = CableModem(
                mac_address=MacAddress(mac), inet=Inet(ip), write_community=community
            )

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm, validate_ofdm_exist=True
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service: CmDsOfdmChanEstCoefService = CmDsOfdmChanEstCoefService(
                cm, tftp_servers=tftp_servers
            )
            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            interface_parameters = None
            if channel_ids:
                interface_parameters = DownstreamOfdmParameters(
                    channel_id=list(channel_ids)
                )

            msg_rsp: MessageResponse = await service.set_and_go(
                interface_parameters=interface_parameters
            )

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Channel Estimation Coefficients measurement."
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            measurement_stats: list[DocsPnmCmOfdmChanEstCoefEntry] = cast(
                list[DocsPnmCmOfdmChanEstCoefEntry],
                await service.getPnmMeasurementStatistics(channel_ids=channel_ids),
            )

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())

                # Clean up payload by removing unneeded or redundant sections
                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "complex"])
                primative = msg_rsp.payload_to_dict("primative")
                DictGenerate.pop_keys_recursive(primative, ["device_details"])
                payload.update({str(k): v for k, v in primative.items()})
                payload.update(
                    DictGenerate.models_to_nested_dict(
                        measurement_stats,
                        "measurement_stats",
                    )
                )

                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.SUCCESS,
                    data=payload,
                )

            elif request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme=theme)
                analysis_rpt = ChanEstimationReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    data={},
                )


# Required for dynamic auto-registration
router = ChannelEstimationCoefficientRouter().router
# FILE: src/pypnm/api/routes/docs/pnm/ds/ofdm/const_display/router.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.abstract.analysis_report import Analysis
from pypnm.api.routes.basic.constellation_display_analysis_rpt import (
    ConstDisplayAnalysisRptMatplotConfig,
    ConstellationDisplayReport,
)
from pypnm.api.routes.common.classes.analysis.analysis import AnalysisType
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.const_display.schemas import (
    PnmConstellationDisplayAnalysisRequest,
)
from pypnm.api.routes.docs.pnm.ds.ofdm.const_display.service import (
    CmDsOfdmConstDisplayService,
)
from pypnm.api.routes.docs.pnm.files.service import FileType, PnmFileService
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.pnm.DocsPnmCmDsConstDispMeasEntry import (
    DocsPnmCmDsConstDispMeasEntry,
)
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class ConstellationDisplayRouter:
    """
    FastAPI router for Downstream OFDM Constellation Display.

    [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/documentation/api/fast-api/single/ds/ofdm/constellation-display.md)

    """

    def __init__(self) -> None:
        """
        Initialize router with consistent prefix/tags and register routes.
        """
        prefix: str = "/docs/pnm/ds/ofdm"
        self.base_endpoint: str = "/constellationDisplay"
        self.router: APIRouter = APIRouter(
            prefix=prefix,
            tags=["PNM Operations - Downstream OFDM Constellation Display"],
        )
        self.logger: logging.Logger = logging.getLogger(
            f"ConstellationDisplayRouter.{self.base_endpoint.strip('/')}"
        )
        self.__routes()

    def __routes(self) -> None:
        """
        Register FastAPI routes for this router.
        """

        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get Constellation Display PNM Capture File",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_capture(
            request: PnmConstellationDisplayAnalysisRequest,
        ) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture Downstream OFDM Constellation Display Samples And Return Analysis Results.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/ofdm/constellation-display.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(
                request.cable_modem.snmp
            )
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(
                request.cable_modem.pnm_parameters.tftp
            )

            self.logger.info(
                f"Starting Constellation Display capture for MAC: {mac}, IP: {ip}"
            )

            cm = CableModem(
                mac_address=MacAddress(mac), inet=Inet(ip), write_community=community
            )

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm, validate_ofdm_exist=True
            ).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            modulation_order_offset: int = (
                request.capture_settings.modulation_order_offset
            )
            number_sample_symbol: int = request.capture_settings.number_sample_symbol

            service: CmDsOfdmConstDisplayService = CmDsOfdmConstDisplayService(
                cable_modem=cm,
                tftp_servers=tftp_servers,
                modulation_order_offset=modulation_order_offset,
                number_sample_symbol=number_sample_symbol,
            )

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            interface_parameters = None
            if channel_ids:
                interface_parameters = DownstreamOfdmParameters(
                    channel_id=list(channel_ids)
                )

            msg_rsp: MessageResponse = await service.set_and_go(
                interface_parameters=interface_parameters
            )
            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Constellation Display capture."
                self.logger.error(err)
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            measurement_stats: list[DocsPnmCmDsConstDispMeasEntry] = cast(
                list[DocsPnmCmDsConstDispMeasEntry],
                await service.getPnmMeasurementStatistics(channel_ids=channel_ids),
            )

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())
                payload.update(
                    {
                        k: v
                        for k, v in msg_rsp.payload_to_dict().items()
                        if isinstance(k, str)
                    }
                )

                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "data"])
                primative = msg_rsp.payload_to_dict("primative")
                DictGenerate.pop_keys_recursive(primative, ["device_details"])
                payload.update(
                    {k: v for k, v in primative.items() if isinstance(k, str)}
                )
                payload.update(
                    DictGenerate.models_to_nested_dict(
                        measurement_stats,
                        "measurement_stats",
                    )
                )

                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.SUCCESS,
                    data=payload,
                )

            elif request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                crosshair = request.analysis.plot.options.display_cross_hair
                plot_config = ConstDisplayAnalysisRptMatplotConfig(
                    theme=theme, display_crosshair=crosshair
                )
                analysis_rpt = ConstellationDisplayReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    data={},
                )


# Required for dynamic auto-registration
router = ConstellationDisplayRouter().router
# FILE: src/pypnm/api/routes/docs/pnm/ds/ofdm/fec_summary/router.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisRptMatplotConfig
from pypnm.api.routes.basic.fec_summary_analysis_rpt import FecSummaryAnalysisReport
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.fec_summary.schemas import (
    PnmFecSummaryAnalysisRequest,
)
from pypnm.api.routes.docs.pnm.ds.ofdm.fec_summary.service import (
    CmDsOfdmFecSummaryService,
)
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import FecSummaryType
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmFecEntry import DocsPnmCmDsOfdmFecEntry
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class FecSummaryRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/ds/ofdm"
        self.base_endpoint = "/fecSummary"
        self.router = APIRouter(
            prefix=prefix, tags=["PNM Operations - Downstream OFDM FEC Summary"]
        )
        self.logger = logging.getLogger(
            f"FecSummaryRouter.{self.base_endpoint.strip('/')}"
        )
        self.__routes()

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get FEC Summary PNM Capture",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_capture(
            request: PnmFecSummaryAnalysisRequest,
        ) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture Downstream OFDM FEC Summary Statistics.

            Retrieves corrected/uncorrectable codeword counters for the selected FEC
            summary interval (e.g., 10-minute or 24-hour) across active OFDM profiles.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/ofdm/fec-summary.md)
            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(
                request.cable_modem.snmp
            )
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(
                request.cable_modem.pnm_parameters.tftp
            )
            self.logger.info(f"Starting FEC Summary capture for MAC: {mac}, IP: {ip}")

            cm = CableModem(
                mac_address=MacAddress(mac), inet=Inet(ip), write_community=community
            )

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm, validate_ofdm_exist=True
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            fec_type: FecSummaryType = request.capture_settings.fec_summary_type
            service = CmDsOfdmFecSummaryService(
                cable_modem=cm, fec_summary_type=fec_type, tftp_servers=tftp_servers
            )

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            interface_parameters = None
            if channel_ids:
                interface_parameters = DownstreamOfdmParameters(
                    channel_id=list(channel_ids)
                )

            msg_rsp: MessageResponse = await service.set_and_go(
                interface_parameters=interface_parameters
            )

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete FEC Summary capture."
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            measurement_stats: list[DocsPnmCmDsOfdmFecEntry] = cast(
                list[DocsPnmCmDsOfdmFecEntry],
                await service.getPnmMeasurementStatistics(channel_ids=channel_ids),
            )

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())
                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "mac_address"])

                primative = msg_rsp.payload_to_dict("primative")
                DictGenerate.pop_keys_recursive(primative, ["device_details"])
                payload.update(
                    cast(dict[str, Any], msg_rsp.payload_to_dict("primative"))
                )

                payload.update(
                    DictGenerate.models_to_nested_dict(
                        measurement_stats,
                        "measurement_stats",
                    )
                )

                return PnmAnalysisResponse(
                    mac_address=mac, status=ServiceStatusCode.SUCCESS, data=payload
                )

            elif request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme=theme)
                analysis_rpt = FecSummaryAnalysisReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    data={},
                )


# Required for dynamic auto-registration
router = FecSummaryRouter().router
# FILE: src/pypnm/api/routes/docs/pnm/ds/ofdm/modulation_profile/router.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisRptMatplotConfig
from pypnm.api.routes.basic.modulation_profile_analysis_rpt import (
    ModulationProfileReport,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
    PnmSingleCaptureRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.modulation_profile.service import (
    CmDsOfdmModProfileService,
)
from pypnm.api.routes.docs.pnm.files.service import (
    FileResponse,
    FileType,
    PnmFileService,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmModProfEntry import (
    DocsPnmCmDsOfdmModProfEntry,
)
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class ModulationProfileRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/ds/ofdm"
        self.base_endpoint = "/modulationProfile"
        self.router = APIRouter(
            prefix=prefix, tags=["PNM Operations - Downstream OFDM Modulation Profile"]
        )
        self.logger = logging.getLogger(
            f"ModulationProfileRouter.{self.base_endpoint.strip('/')}"
        )
        self.__routes()

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            response_model=None,
            summary="Get Modulation Profile PNM Capture File",
            responses=FAST_API_RESPONSE,
        )
        async def get_capture(
            request: PnmSingleCaptureRequest,
        ) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture Downstream OFDM Modulation Profile.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/ofdm/modulation-profile.md)
            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(
                request.cable_modem.snmp
            )
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(
                request.cable_modem.pnm_parameters.tftp
            )

            self.logger.info(
                f"Starting Modulation Profile measurement for MAC: {mac}, IP: {ip}"
            )

            cm = CableModem(
                mac_address=MacAddress(mac), inet=Inet(ip), write_community=community
            )

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm, validate_ofdm_exist=True
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service: CmDsOfdmModProfileService = CmDsOfdmModProfileService(
                cm, tftp_servers
            )
            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            interface_parameters = None
            if channel_ids:
                interface_parameters = DownstreamOfdmParameters(
                    channel_id=list(channel_ids)
                )

            msg_rsp: MessageResponse = await service.set_and_go(
                interface_parameters=interface_parameters
            )

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Modulation Profile measurement."
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            measurement_stats: list[DocsPnmCmDsOfdmModProfEntry] = cast(
                list[DocsPnmCmDsOfdmModProfEntry],
                await service.getPnmMeasurementStatistics(channel_ids=channel_ids),
            )

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())

                primative = cast(dict[str, Any], msg_rsp.payload_to_dict("primative"))
                DictGenerate.pop_keys_recursive(
                    primative, ["device_details", "modulation_statistics"]
                )
                payload.update(primative)
                payload.update(
                    DictGenerate.models_to_nested_dict(
                        measurement_stats, "measurement_stats"
                    )
                )

                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.SUCCESS,
                    data=payload,
                )

            elif request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme=theme)
                analysis_rpt = ModulationProfileReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return SnmpResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                )


# Required for dynamic auto-registration
router = ModulationProfileRouter().router
# FILE: src/pypnm/api/routes/docs/pnm/ds/ofdm/rxmer/router.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.rxmer_analysis_rpt import (
    AnalysisRptMatplotConfig,
    RxMerAnalysisReport,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
    PnmSingleCaptureRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.rxmer.service import CmDsOfdmRxMerService
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import DocsPnmCmDsOfdmRxMerEntry
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, InetAddressStr, MacAddressStr


class RxMerRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/ds/ofdm"
        self.base_endpoint = "/rxMer"
        self.router = APIRouter(
            prefix=prefix, tags=["PNM Operations - Downstream OFDM RxMER"]
        )
        self.logger = logging.getLogger(f"RxMerRouter.{self.base_endpoint.strip('/')}")
        self.__routes()

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get RxMER PNM Capture File",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_capture(
            request: PnmSingleCaptureRequest,
        ) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture Downstream OFDM RxMER Per-Subcarrier Values.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/ofdm/rxmer.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(
                request.cable_modem.snmp
            )
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(
                request.cable_modem.pnm_parameters.tftp
            )

            self.logger.info(f"Starting RxMER measurement for MAC: {mac}, IP: {ip}")

            cm = CableModem(
                mac_address=MacAddress(mac), inet=Inet(ip), write_community=community
            )

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm, validate_ofdm_exist=True
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service: CmDsOfdmRxMerService = CmDsOfdmRxMerService(cm, tftp_servers)
            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            interface_parameters = self._resolve_interface_parameters(channel_ids)
            msg_rsp: MessageResponse = await service.set_and_go(
                interface_parameters=interface_parameters
            )

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete RxMER measurement."
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            measurement_stats: list[DocsPnmCmDsOfdmRxMerEntry] = cast(
                list[DocsPnmCmDsOfdmRxMerEntry],
                await service.getPnmMeasurementStatistics(channel_ids=channel_ids),
            )

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())

                # Clean up payload by removing unneeded or redundant sections
                DictGenerate.pop_keys_recursive(
                    payload, ["pnm_header", "modulations", "snr_db_values"]
                )
                primative = msg_rsp.payload_to_dict("primative")
                DictGenerate.pop_keys_recursive(
                    primative, ["device_details", "modulation_statistics"]
                )
                payload.update({str(k): v for k, v in primative.items()})
                payload.update(
                    DictGenerate.models_to_nested_dict(
                        measurement_stats,
                        "measurement_stats",
                    )
                )

                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.SUCCESS,
                    data=payload,
                )

            elif request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme=theme)
                analysis_rpt = RxMerAnalysisReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    data={},
                )

    @staticmethod
    def _resolve_interface_parameters(
        channel_ids: list[ChannelId] | None,
    ) -> DownstreamOfdmParameters | None:
        if not channel_ids:
            return None
        return DownstreamOfdmParameters(channel_id=list(channel_ids))


# Required for dynamic auto-registration
router = RxMerRouter().router
# FILE: src/pypnm/api/routes/docs/pnm/files/router.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import cast

from fastapi import APIRouter, File, Path, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.docs.pnm.files.schemas import (
    AnalysisJsonResponse,
    FileAnalysisRequest,
    FileQueryRequest,
    FileQueryResponse,
    HexDumpResponse,
    MacAddressSystemDescriptorResponse,
    UploadFileResponse,
)
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.types import FileName, MacAddressStr, OperationId, TransactionId


class PnmFileManager:
    """
    REST API router for managing PNM test files.

    Endpoints:
    - Search files by MAC or criteria
    - Push/upload new test file
    - Analyze an uploaded or retrieved file
    """

    DEFAULT_HEXDUMP_BYTES_PER_LINE = 16

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"PnmFileManager.{self.__class__.__name__}")
        self.router = APIRouter(
            prefix="/docs/pnm/files",
            tags=["PNM File Manager"],
        )
        self._add_routes()

    def _add_routes(self) -> None:
        default_mac_address = (
            MacAddress(SystemConfigSettings.default_mac_address())
            .to_mac_format(fmt=MacAddressFormat.COLON)
            .lower()
        )

        @self.router.get(
            "/getMacAddresses/",
            response_model=MacAddressSystemDescriptorResponse,
            summary="Get All Registered MAC Addresses With PNM Files",
            responses=FAST_API_RESPONSE,
        )
        def get_mac_addresses() -> MacAddressSystemDescriptorResponse:  # noqa: B008
            """
            **Retrieve All Registered MAC Addresses With Uploaded PNM Files**

            Returns a list of all DOCSIS cable modem MAC addresses that have associated
            telemetry capture files stored in the PyPNM transaction database.

            Each MAC address represents a unique cable modem that has undergone
            telemetry data collection.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#1-get-all-registered-mac-addresses-with-pnm-files)
            """
            return PnmFileService().get_mac_addresses()

        search_files_mac_param = Path(
            description=(
                f"MAC address of the cable modem, default: **{default_mac_address}**"
            ),
        )

        @self.router.get(
            "/searchFiles/{mac_address}",
            response_model=FileQueryResponse,
            summary="Search For PNM Files Via Mac Address",
            responses=FAST_API_RESPONSE,
        )
        def search_files(
            mac_address: MacAddressStr = search_files_mac_param,
        ) -> FileQueryResponse:  # noqa: B008
            """
            **Search Uploaded PNM Files By MAC Address**

            Returns all registered telemetry capture files associated with a given DOCSIS cable modem.

            Each file represents a measurement such as RxMER, constellation, pre-equalization taps,
            or spectrum scan, and can be downloaded or analyzed via other endpoints.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#1-search-files-by-mac-address)
            """
            request = FileQueryRequest(mac_address=mac_address)
            result = PnmFileService().search_files(request)
            return result

        download_transaction_id_param = Path(
            description="Transaction ID of the file to download"
        )

        @self.router.get(
            "/download/transactionID/{transaction_id}",
            response_class=FileResponse,
            summary="Download A PNM File By Transaction ID",
            responses=FAST_API_RESPONSE,
        )
        def download_file_via_transaction_id(
            transaction_id: TransactionId = download_transaction_id_param,
        ) -> FileResponse:  # noqa: B008
            """
            **Download PNM Measurement File By Transaction ID**

            Retrieves the raw binary file generated during a telemetry capture session.
            Used for offline inspection, reprocessing, or historical archiving.

            Note:
            Depending on your browser and SwaggerUI behavior, the file may either download
            automatically or require clicking the returned link.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#2-download-file-by-transaction-id)
            """
            return PnmFileService().get_file_by_transaction_id(transaction_id)

        download_mac_param = Path(
            ..., description="MAC address of the file to download"
        )

        @self.router.get(
            "/download/macAddress/{mac_address}",
            response_class=FileResponse,
            summary="Download A PNM File By MAC Address",
            responses=FAST_API_RESPONSE,
        )
        def download_file_via_mac_address(
            mac_address: MacAddressStr = download_mac_param,
        ) -> FileResponse:  # noqa: B008
            """
            **Download PNM Measurement File By Transaction ID**

            Retrieves the raw binary file generated during a telemetry capture session.
            Used for offline inspection, reprocessing, or historical archiving.

            Note:
            Depending on your browser and SwaggerUI behavior, the file may either download
            automatically or require clicking the returned link.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#3-download-files-by-mac-address-zip-archive)
            """
            return PnmFileService().get_file_by_mac_address(mac_address)

        download_operation_id_param = Path(
            ..., description="Operation ID of the file to download"
        )

        @self.router.get(
            "/download/operationID/{operation_id}",
            response_class=FileResponse,
            summary="Download A PNM File By Operation ID",
            responses=FAST_API_RESPONSE,
        )
        def download_file_via_operationID(
            operation_id: OperationId = download_operation_id_param,
        ) -> FileResponse:  # noqa: B008
            """
            **Download PNM Measurement File By Operation ID**

            Retrieves the raw binary file generated during a telemetry capture session.
            Used for offline inspection, reprocessing, or historical archiving.

            Note:
            Depending on your browser and SwaggerUI behavior, the file may either download
            automatically or require clicking the returned link.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#4-download-files-by-operation-id-zip-archive)
            """
            return PnmFileService().get_file_by_operation_id(operation_id)

        upload_file_param = File(
            description="Raw PNM capture file (e.g., RxMER, constellation, histogram, spectrum)",
        )

        @self.router.post(
            "/upload",
            response_model=UploadFileResponse,
            summary="Upload A PNM File",
            responses=FAST_API_RESPONSE,
        )
        async def upload_file(
            file: UploadFile = upload_file_param,
        ) -> JSONResponse:  # noqa: B008
            """
            **Upload A PNM Binary File Into The PyPNM Transaction Database**

            This endpoint accepts a PNM capture file as multipart/form-data and stores
            it under a new transaction record.

            The server will:
            - Persist the file to the configured PNM directory.
            - Inspect the PNM header to identify the file type.
            - Map the file type to a logical PNM test (DocsPnmCmCtlTest).
            - Register a transaction entry with a placeholder null MAC address
              (to be backfilled later from the file contents).

            The response returns the generated transaction_id and echoes the stored filename.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#5-upload-pnm-file)

            """
            content = await file.read()
            result = PnmFileService().upload_file(
                filename=cast(FileName, file.filename), data=content
            )
            return JSONResponse(content=result.model_dump())

        @self.router.post(
            "/getAnalysis",
            response_model=AnalysisJsonResponse,
            summary="Analyze a PNM File Via Transaction ID",
            responses=FAST_API_RESPONSE,
        )
        def get_analysis_via_transaction_id(
            request: FileAnalysisRequest,
        ) -> AnalysisJsonResponse | FileResponse | JSONResponse:
            """
            **Analysis Of A PNM File**

            Launches an analysis routine based on the specified transactionID and requested
            analysis type. The backend will resolve the PNM file associated with the transactionID,
            inspect its header, and route it to the appropriate analysis pipeline.

            Supported Uploaded PNM File Types:
            - RxMER per subcarrier
            - Channel Estimation Coefficients
            - Constellation Diagram
            - Downstream Histogram
            - OFDMA Pre-equalization
            - Fec Summary
            - Modulation Profile

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#6-analyze-pnm-file-via-transaction-id)
            """
            PnmFileService().get_analysis(request)

            output_type = request.analysis.output.type

            if output_type == OutputType.JSON:
                analysis_result, file_type = PnmFileService().get_analysis(request)
                return AnalysisJsonResponse(
                    mac_address=analysis_result.mac_address,
                    pnm_file_type=file_type.name,
                    status="success",
                    analysis=analysis_result.model_dump(),
                )

            elif output_type == OutputType.ARCHIVE:
                return PnmFileService().get_archive(request)

            return JSONResponse(content="Not implemented yet")

        hexdump_transaction_id_param = Path(
            ..., description="Transaction ID of the PNM file to hexdump"
        )

        @self.router.get(
            "/getHexdump/transactionID/{transaction_id}",
            response_model=HexDumpResponse,
            summary="Hexdump Of A PNM File By Transaction ID",
            responses=FAST_API_RESPONSE,
        )
        def get_hexdump_via_transaction_id(
            transaction_id: TransactionId = hexdump_transaction_id_param,  # noqa: B008
            bytes_per_line: int | None = Query(
                default=None,
                description="Optional bytes-per-line for hexdump; if omitted, the service default is used.",
            ),
        ) -> HexDumpResponse:
            """
            **Hexdump Of A PNM File**

            Generates a hexadecimal dump of the raw binary contents of a PNM file
            associated with the specified transactionID.

            This is useful for low-level inspection, debugging, or forensic analysis
            of the file structure and data.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/file-manager/file-manager-api.md#7-hexdump-of-a-pnm-file-via-transaction-id)
            """
            hexdump_result = PnmFileService().get_hexdump_by_transaction_id(
                transaction_id=transaction_id,
                bytes_per_line=bytes_per_line if bytes_per_line is not None else 0,
            )
            return hexdump_result


# Required for auto-discovery via dynamic router loading
router = PnmFileManager().router
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
        records = PnmFileTransaction().get_all_record_models()
        if not records:
            return MacAddressSystemDescriptorResponse(mac_addresses=[])

        latest_by_mac: dict[str, tuple[int, dict[str, str] | None]] = {}

        for rec in records:
            mac_value = getattr(rec, "mac_address", "")
            mac_str = str(mac_value).lower().strip()
            if not mac_str:
                continue

            ts_value = getattr(rec, "timestamp", 0)
            try:
                ts_int = int(ts_value)
            except Exception:
                ts_int = 0

            system_description: dict[str, str] | None = None

            device_details = getattr(rec, "device_details", None)
            if device_details is not None:
                if hasattr(device_details, "system_description"):
                    sd_value = getattr(device_details, "system_description", None)
                    if sd_value is not None:
                        if hasattr(sd_value, "model_dump"):
                            system_description = sd_value.model_dump()
                        elif isinstance(sd_value, dict):
                            system_description = sd_value

                elif hasattr(device_details, "model_dump"):
                    dd_dump = device_details.model_dump()
                    if isinstance(dd_dump, dict):
                        sd_value = dd_dump.get("system_description")
                        if isinstance(sd_value, dict):
                            system_description = sd_value

                elif isinstance(device_details, dict):
                    sd_value = device_details.get("system_description")
                    if isinstance(sd_value, dict):
                        system_description = sd_value

            existing = latest_by_mac.get(mac_str)
            if existing is None:
                latest_by_mac[mac_str] = (ts_int, system_description)
                continue

            existing_ts, _existing_sd = existing
            if ts_int >= existing_ts:
                latest_by_mac[mac_str] = (ts_int, system_description)

        entries: list[MacAddressSystemDescriptorEntry] = []
        for mac_str, (_ts, sd) in sorted(latest_by_mac.items(), key=lambda x: x[0]):
            entries.append(
                MacAddressSystemDescriptorEntry(
                    mac_address=mac_str,
                    system_description=sd,
                )
            )

        return MacAddressSystemDescriptorResponse(mac_addresses=entries)
# FILE: src/pypnm/docsis/cm_snmp_operation.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
import time
from enum import Enum, IntEnum
from typing import Any, cast

from pysnmp.proto.rfc1902 import Gauge32, Integer32, OctetString

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.docsis.data_type.ClabsDocsisVersion import ClabsDocsisVersion
from pypnm.docsis.data_type.DocsDevEventEntry import DocsDevEventEntry
from pypnm.docsis.data_type.DocsFddCmFddCapabilities import (
    DocsFddCmFddBandEdgeCapabilities,
)
from pypnm.docsis.data_type.DocsFddCmFddSystemCfgState import DocsFddCmFddSystemCfgState
from pypnm.docsis.data_type.DocsIf31CmDsOfdmChanEntry import (
    DocsIf31CmDsOfdmChanChannelEntry,
    DocsIf31CmDsOfdmChanEntry,
)
from pypnm.docsis.data_type.DocsIf31CmDsOfdmProfileStatsEntry import (
    DocsIf31CmDsOfdmProfileStatsEntry,
)
from pypnm.docsis.data_type.DocsIf31CmSystemCfgState import (
    DocsIf31CmSystemCfgDiplexState,
)
from pypnm.docsis.data_type.DocsIf31CmUsOfdmaChanEntry import DocsIf31CmUsOfdmaChanEntry
from pypnm.docsis.data_type.DocsIfDownstreamChannel import DocsIfDownstreamChannelEntry
from pypnm.docsis.data_type.DocsIfDownstreamChannelCwErrorRate import (
    DocsIfDownstreamChannelCwErrorRate,
    DocsIfDownstreamCwErrorRateEntry,
)
from pypnm.docsis.data_type.DocsIfSignalQualityEntry import DocsIfSignalQuality
from pypnm.docsis.data_type.DocsIfUpstreamChannelEntry import DocsIfUpstreamChannelEntry
from pypnm.docsis.data_type.DsCmConstDisplay import CmDsConstellationDisplayConst
from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.docsis.data_type.InterfaceStats import InterfaceStats
from pypnm.docsis.data_type.OfdmProfiles import OfdmProfiles
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsConstDispMeasEntry import (
    DocsPnmCmDsConstDispMeasEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsHistEntry import DocsPnmCmDsHistEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmFecEntry import DocsPnmCmDsOfdmFecEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmMerMarEntry import (
    DocsPnmCmDsOfdmMerMarEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmModProfEntry import (
    DocsPnmCmDsOfdmModProfEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmRxMerEntry import (
    DocsPnmCmDsOfdmRxMerEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmOfdmChanEstCoefEntry import (
    DocsPnmCmOfdmChanEstCoefEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmUsPreEqEntry import DocsPnmCmUsPreEqEntry
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.docsis.lib.pnm_bulk_data import DocsPnmBulkDataGroup
from pypnm.lib.constants import DEFAULT_SPECTRUM_ANALYZER_INDICES
from pypnm.lib.format_string import Format
from pypnm.lib.inet import Inet
from pypnm.lib.inet_utils import InetGenerate
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, EntryIndex, FrequencyHz, InterfaceIndex
from pypnm.lib.utils import Generate
from pypnm.pnm.data_type.DocsEqualizerData import DocsEqualizerData
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import (
    DocsIf3CmSpectrumAnalysisCtrlCmd,
    SpectrumRetrievalType,
)
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.snmp.compiled_oids import COMPILED_OIDS
from pypnm.snmp.modules import DocsisIfType, DocsPnmBulkUploadControl
from pypnm.snmp.snmp_v2c import Snmp_v2c
from pypnm.snmp.snmp_v3 import Snmp_v3


class DocsPnmBulkFileUploadStatus(Enum):
    """Represents the upload status of a DOCSIS PNM bulk data file."""

    OTHER = 1
    AVAILABLE_FOR_UPLOAD = 2
    UPLOAD_IN_PROGRESS = 3
    UPLOAD_COMPLETED = 4
    UPLOAD_PENDING = 5
    UPLOAD_CANCELLED = 6
    ERROR = 7

    def describe(self) -> str:
        """Returns a human-readable description of the enum value."""
        return {
            self.OTHER: "Other: unspecified condition",
            self.AVAILABLE_FOR_UPLOAD: "Available: ready for upload",
            self.UPLOAD_IN_PROGRESS: "In progress: upload ongoing",
            self.UPLOAD_COMPLETED: "Completed: upload successful",
            self.UPLOAD_PENDING: "Pending: blocked until conditions clear",
            self.UPLOAD_CANCELLED: "Cancelled: upload was stopped",
            self.ERROR: "Error: upload failed",
        }.get(self, "Unknown status")

    def to_dict(self) -> dict:
        """Serializes the status for API or JSON usage."""
        return {"name": self.name, "value": self.value, "description": self.describe()}

    def __str__(self) -> str:
        return super().__str__()


class DocsPnmCmCtlStatus(Enum):
    """
    Enum representing the overall status of the PNM test platform.

    Based on the SNMP object `docsPnmCmCtlStatus`, this enum is used to manage
    test initiation constraints on the Cable Modem (CM).
    """

    OTHER = 1
    READY = 2
    TEST_IN_PROGRESS = 3
    TEMP_REJECT = 4
    SNMP_ERROR = 255

    def __str__(self) -> str:
        return self.name.lower()


class FecSummaryType(Enum):
    """
    Enum for FEC Summary Type used in DOCSIS PNM SNMP operations.
    """

    TEN_MIN = 2
    TWENTY_FOUR_HOUR = 3

    @classmethod
    def choices(cls) -> dict[str, int]:
        """Returns a dictionary [key,value] of enum names and their corresponding values."""
        return {e.name: e.value for e in cls}

    @classmethod
    def from_value(cls, value: int) -> FecSummaryType:
        try:
            return cls(value)
        except ValueError as err:
            raise ValueError(f"Invalid FEC Summary Type value: {value}") from err


class CmSnmpOperation:
    """
    Cable Modem SNMP Operation Handler.

    This class provides methods to perform SNMP operations
    (GET, WALK, etc.) specifically for Cable Modems.

    Attributes:
        _inet (str): IP address of the Cable Modem.
        _community (str): SNMP community string used for authentication.
        _port (int): SNMP port (default: 161).
        _snmp (Snmp_v2c): SNMP client instance for communication.
        logger (logging.Logger): Logger instance for this class.
    """

    class SnmpVersion(IntEnum):
        _SNMPv2C = 0
        _SNMPv3 = 1

    def __init__(
        self, inet: Inet, write_community: str, port: int = Snmp_v2c.SNMP_PORT
    ) -> None:
        """
        Initialize a CmSnmpOperation instance.

        Args:
            inet (str): IP address of the Cable Modem.
            write_community (str): SNMP community string (usually 'private' for read/write access).
            port (int, optional): SNMP port number. Defaults to standard SNMP port 161.

        """
        self.logger = logging.getLogger(self.__class__.__name__)

        if not isinstance(inet, Inet):
            self.logger.error(
                f"CmSnmpOperation() inet is of an Invalid Type: {type(inet)} , expecting Inet"
            )
            exit(1)

        self._inet: Inet = inet
        self._community = write_community
        self._port = port
        self._snmp = self.__load_snmp_version()

    def __load_snmp_version(self) -> Snmp_v2c | Snmp_v3:
        """
        Select and instantiate the appropriate SNMP client.

        Precedence:
        1) If SNMPv3 is explicitly enabled and parameters are valid -> return Snmp_v3
        2) Else if SNMPv2c is enabled -> return Snmp_v2c
        3) Else -> error
        """

        if SystemConfigSettings.snmp_v3_enable():
            """
            self.logger.debug("SNMPv3 enabled in configuration; validating parameters...")
            try:
                p = PnmConfigManager.get_snmp_v3_params()
            except Exception as e:
                self.logger.error(f"Failed to load SNMPv3 parameters: {e}. Falling back to SNMPv2c.")
                p = None

            # Minimal required fields for a usable v3 session
            required = ("user", "auth_key", "priv_key", "auth_protocol", "priv_protocol")
            if p and all(p.get(k) for k in required):
                self.logger.debug("Using SNMPv3")
                return Snmp_v3(
                    host=self._inet,
                    user=p["user"],
                    auth_key=p["auth_key"],
                    priv_key=p["priv_key"],
                    auth_protocol=p["auth_protocol"],
                    priv_protocol=p["priv_protocol"],
                    port=self._port,
                )
            else:
                self.logger.warning(
                    "SNMPv3 is enabled but parameters are incomplete or invalid; "
                    "falling back to SNMPv2c."
                )
            """
            # Keep the implementation stubbed for now.
            # Force an explicit failure instead of silently falling back.
            raise NotImplementedError(
                "SNMPv3 is enabled in configuration, but the SNMPv3 client is not implemented yet. "
                "Disable SNMPv3 to use SNMPv2c."
            )

        if SystemConfigSettings.snmp_enable():
            self.logger.debug("Using SNMPv2c")
            return Snmp_v2c(host=self._inet, community=self._community, port=self._port)

        # Neither protocol is usable
        msg = "No SNMP protocol enabled or properly configured (v3 disabled/invalid and v2c disabled)."
        self.logger.error(msg)
        raise ValueError(msg)

    async def _get_value(
        self, oid_suffix: str, value_type: type | str = str
    ) -> str | bytes | int | None:
        """
        Retrieves a value from SNMP for the given OID suffix, processes the value based on the expected type,
        and handles any error cases that may arise during the process.

        Parameters:
        - oid_suffix (str): The suffix of the OID to query.
        - value_type (type or str): The type to which the value should be converted. Defaults to `str`.

        Returns:
        - Optional[Union[str, bytes, int]]: The value retrieved from SNMP, converted to the specified type,
          or `None` if there was an error or no value could be obtained.
        """
        result = await self._snmp.get(f"{oid_suffix}.0")

        if result is None:
            logging.warning(f"Failed to get value for {oid_suffix}")
            return None

        val = Snmp_v2c.snmp_get_result_value(result)[0]
        logging.debug(f"get_value() -> Val:{val}")

        # Check if the result is an error message, and return None if it is
        if (
            isinstance(val, str)
            and "No Such Instance currently exists at this OID" in val
        ):
            logging.warning(f"SNMP error for {oid_suffix}: {val}")
            return None

        # Handle string and bytes conversions explicitly
        if value_type is str:
            if isinstance(val, bytes):  # if val is bytes, decode it
                return val.decode(
                    "utf-8", errors="ignore"
                )  # or replace with appropriate encoding
            return str(val)

        if value_type is bytes:
            if isinstance(val, str):  # if val is a string, convert to bytes
                # Remove any '0x' prefix or spaces before converting
                val = val.strip().lower()
                if val.startswith("0x"):
                    val = val[2:]  # Remove '0x' prefix

                # Ensure the string is a valid hex format
                try:
                    return bytes.fromhex(val)  # convert the cleaned hex string to bytes
                except ValueError as e:
                    logging.error(f"Invalid hex string: {val}. Error: {e}")
                    return None
            return val  # assuming it's already in bytes

        # Default case (int conversion)
        try:
            return value_type(val)
        except ValueError as e:
            logging.error(
                f"Failed to convert value for {oid_suffix}: {val}. Error: {e}"
            )
            return None

    ######################
    # SNMP Get Operation #
    ######################

    def getWriteCommunity(self) -> str:
        return self._community

    async def getIfTypeIndex(self, doc_if_type: DocsisIfType) -> list[InterfaceIndex]:
        """
        Retrieve interface indexes that match the specified DOCSIS IANA ifType.

        Args:
            doc_if_type (DocsisIfType): The DOCSIS interface type to filter by.

        Returns:
            List[int]: A list of interface indexes matching the given ifType.
        """
        self.logger.debug(f"Starting getIfTypeIndex for ifType: {doc_if_type}")

        indexes: list[int] = []

        # Perform SNMP walk
        results = await self._snmp.walk("ifType")

        if not results:
            self.logger.warning("No results found during SNMP walk for ifType.")
            return indexes

        # Iterate through results and filter by the specified DOCSIS interface type
        ifType_name = doc_if_type.name
        ifType_value = doc_if_type.value

        try:
            for result in results:
                # Compare ifType value with the result value
                if ifType_value == int(result[1]):
                    self.logger.debug(
                        f"ifType-Name: ({ifType_name}) -> ifType-Value: ({ifType_value}) -> Found: {result}"
                    )

                    # Extract index using a helper method (ensure it returns a valid index)
                    index = Snmp_v2c.get_oid_index(str(result[0]))
                    if index is not None:
                        indexes.append(index)
                    else:
                        self.logger.warning(f"Invalid OID index for result: {result}")
        except Exception as e:
            self.logger.error(f"Error processing results: {e}")

        # Return the list of found indexes
        return indexes

    async def getSysDescr(
        self, timeout: int | None = None, retries: int | None = None
    ) -> SystemDescriptor:
        """
        Retrieves and parses the sysDescr SNMP value into a SysDescr dataclass.

        Returns:
            SysDescr if successful, otherwise empty SysDescr.empty().
        """
        timeout = timeout if timeout is not None else self._snmp._timeout
        retries = retries if retries is not None else self._snmp._retries

        self.logger.debug(
            f"Retrieving sysDescr for {self._inet}, timeout: {timeout}, retries: {retries}"
        )

        try:
            result = await self._snmp.get(
                f"{'sysDescr'}.0", timeout=timeout, retries=retries
            )
        except Exception as e:
            self.logger.error(f"Error occurred while retrieving sysDescr: {e}")
            return SystemDescriptor.empty()

        if not result:
            self.logger.warning("SNMP get failed or returned empty for sysDescr.")
            return SystemDescriptor.empty()

        self.logger.debug(f"SysDescr Results: {result} before get_result_value")
        values = Snmp_v2c.get_result_value(result)

        if not values:
            self.logger.warning("No sysDescr value parsed.")
            return SystemDescriptor.empty()

        if not result:
            self.logger.warning("SNMP get failed or returned empty for sysDescr.")
            return SystemDescriptor.empty()

        values = Snmp_v2c.get_result_value(result)

        if not values:
            self.logger.warning("No sysDescr value parsed.")
            return SystemDescriptor.empty()

        self.logger.debug(f"SysDescr: {values}")

        try:
            parsed = SystemDescriptor.parse(values)
            self.logger.debug(f"Successfully parsed sysDescr: {parsed}")
            return parsed

        except ValueError as e:
            self.logger.error(f"Failed to parse sysDescr: {values}. Error: {e}")
            return SystemDescriptor.empty()

    async def getDocsPnmBulkDataGroup(self) -> DocsPnmBulkDataGroup:
        """
        Retrieves the current DocsPnmBulkDataGroup SNMP configuration from the device.

        Returns:
            DocsPnmBulkDataGroup: A dataclass populated with SNMP values.
        """

        return DocsPnmBulkDataGroup(
            docsPnmBulkDestIpAddrType=await self._get_value(
                "docsPnmBulkDestIpAddrType", int
            ),
            docsPnmBulkDestIpAddr=InetGenerate.binary_to_inet(
                await self._get_value("docsPnmBulkDestIpAddr", bytes)
            ),
            docsPnmBulkDestPath=await self._get_value("docsPnmBulkDestPath", str),
            docsPnmBulkUploadControl=await self._get_value(
                "docsPnmBulkUploadControl", int
            ),
        )

    async def getDocsPnmCmCtlStatus(self, max_retry: int = 1) -> DocsPnmCmCtlStatus:
        """
        Fetches the current Docs PNM CmCtlStatus.

        This method retrieves the Docs PNM CmCtlStatus and retries up to a specified number of times
        if the response is not valid. The possible statuses are:
        - 1: other
        - 2: ready
        - 3: testInProgress
        - 4: tempReject

        Parameters:
        - max_retry (int, optional): The maximum number of retries to obtain the status (default is 1).

        Returns:
        - DocsPnmCmCtlStatus: The Docs PNM CmCtlStatus as an enum value. Possible values:
        - DocsPnmCmCtlStatus.OTHER
        - DocsPnmCmCtlStatus.READY
        - DocsPnmCmCtlStatus.TEST_IN_PROGRESS
        - DocsPnmCmCtlStatus.TEMP_REJECT

        If the status cannot be retrieved after the specified retries, the method will return `DocsPnmCmCtlStatus.TEMP_REJECT`.
        """
        count = 1
        while True:
            result = await self._snmp.get(f"{'docsPnmCmCtlStatus'}.0")

            if result is None:
                time.sleep(2)
                self.logger.warning(
                    f"Not getting a proper docsPnmCmCtlStatus response, retrying: ({count} of {max_retry})"
                )

                if count >= max_retry:
                    self.logger.error(f"Reached max retries: ({max_retry})")
                    return DocsPnmCmCtlStatus.TEMP_REJECT

                count += 1
                continue
            else:
                break

        if not result:
            self.logger.error(
                f"No results found for docsPnmCmCtlStatus: {DocsPnmCmCtlStatus.SNMP_ERROR}"
            )
            return DocsPnmCmCtlStatus.SNMP_ERROR

        status_value = int(Snmp_v2c.snmp_get_result_value(result)[0])

        return DocsPnmCmCtlStatus(status_value)

    async def getIfPhysAddress(
        self, if_type: DocsisIfType = DocsisIfType.docsCableMaclayer
    ) -> MacAddress:
        """
        Retrieve the physical (MAC) address of the specified interface type.
        Args:
            if_type (DocsisIfType): The DOCSIS interface type to query. Defaults to docsCableMaclayer.
        Returns:
            MacAddress: The MAC address of the interface.
        Raises:
            RuntimeError: If no interfaces are found or SNMP get fails.
            ValueError: If the retrieved MAC address is invalid.
        """
        self.logger.debug(f"Getting ifPhysAddress for ifType: {if_type.name}")

        if_indexes = await self.getIfTypeIndex(if_type)
        self.logger.debug(f"{if_type.name} -> {if_indexes}")
        if not if_indexes:
            raise RuntimeError(f"No interfaces found for {if_type.name}")

        idx = if_indexes[0]
        resp = await self._snmp.get(f"ifPhysAddress.{idx}")
        self.logger.debug(f"getIfPhysAddress() -> {resp}")
        if not resp:
            raise RuntimeError(f"SNMP get failed for ifPhysAddress.{idx}")

        # Prefer grabbing raw bytes directly from the varbind
        try:
            varbind = resp[0]
            value = varbind[1]  # should be OctetString
            if isinstance(value, (OctetString, bytes, bytearray)):
                mac_bytes = bytes(value)
            else:
                # Fallback: use helper and try to coerce
                raw = Snmp_v2c.snmp_get_result_value(resp)[0]
                if isinstance(raw, (bytes, bytearray)):
                    mac_bytes = bytes(raw)
                elif isinstance(raw, str):
                    s = raw.strip().lower()
                    if s.startswith("0x"):
                        s = s[2:]
                    s = s.replace(":", "").replace("-", "").replace(" ", "")
                    mac_bytes = bytes.fromhex(s)
                else:
                    raise ValueError(f"Unsupported ifPhysAddress type: {type(raw)}")
        except Exception as e:
            # Log and rethrow with context
            self.logger.error(f"Failed to parse ifPhysAddress.{idx}: {e}")
            raise

        if len(mac_bytes) != 6:
            raise ValueError(
                f"Invalid MAC length {len(mac_bytes)} from ifPhysAddress.{idx}"
            )

        mac_hex = mac_bytes.hex()
        return MacAddress(mac_hex)

    async def getDocsIfCmDsScQamChanChannelIdIndex(self) -> list[InterfaceIndex]:
        """
        Retrieve the list of DOCSIS 3.0 downstream SC-QAM channel indices.

        Returns:
            List[int]: A list of SC-QAM channel indices present on the device.
        """
        try:
            return await self.getIfTypeIndex(DocsisIfType.docsCableDownstream)

        except Exception as e:
            self.logger.error(f"Failed to retrieve SC-QAM Indexes: {e}")
            return []

    async def getDocsIf31CmDsOfdmChannelIdIndex(self) -> list[InterfaceIndex]:
        """
        Retrieve the list of Docsis 3.1 downstream OFDM channel indices.

        Returns:
            List[int]: A list of channel indices present on the device.
        """
        return await self.getIfTypeIndex(DocsisIfType.docsOfdmDownstream)

    async def getDocsIf31CmDsOfdmChanPlcFreq(
        self,
    ) -> list[tuple[InterfaceIndex, FrequencyHz]]:
        """
        Retrieve the PLC frequencies of DOCSIS 3.1 downstream OFDM channels.

        Returns:
            List[Tuple[int, int]]: A list of tuples where each tuple contains:
                - the index (int) of the OFDM channel
                - the PLC frequency (int, in Hz)
        """
        oid = "docsIf31CmDsOfdmChanPlcFreq"
        self.logger.debug(f"Walking OID for PLC frequencies: {oid}")

        try:
            results = await self._snmp.walk(oid)
            idx_plc_freqs = cast(
                list[tuple[InterfaceIndex, FrequencyHz]],
                Snmp_v2c.snmp_get_result_last_idx_value(results),
            )

            self.logger.debug(f"Retrieved PLC Frequencies: {idx_plc_freqs}")
            return idx_plc_freqs

        except Exception as e:
            self.logger.error(f"Failed to retrieve PLC frequencies from OID {oid}: {e}")
            return []

    async def getDocsPnmCmOfdmChEstCoefMeasStatus(
        self, ofdm_idx: InterfaceIndex
    ) -> int:
        """
        Retrieves the measurement status of OFDM channel estimation coefficients.

        Parameters:
        - ofdm_idx (int): The OFDM index.

        Returns:
        int: The measurement status.
        """
        result = await self._snmp.get(
            f"{'docsPnmCmOfdmChEstCoefMeasStatus'}.{ofdm_idx}"
        )
        return int(Snmp_v2c.snmp_get_result_value(result)[0])

    async def getCmDsOfdmProfileStatsConfigChangeCt(
        self, ofdm_idx: InterfaceIndex
    ) -> dict[int, dict[int, int]]:
        """
        Retrieve the count of configuration change events for a specific OFDM profile.

        Parameters:
        - ofdm_idx (int): The index of the OFDM profile.

        Returns:
            dict[ofdm_idx, dict[profile_id, count_change]]

        TODO: Need to get back, not really working

        """
        result = self._snmp.walk(
            f"{'docsIf31CmDsOfdmProfileStatsConfigChangeCt'}.{ofdm_idx}"
        )
        profile_change_count = Snmp_v2c.snmp_get_result_value(result)[0]
        return profile_change_count

    async def _getDocsIf31CmDsOfdmChanEntry(self) -> list[DocsIf31CmDsOfdmChanEntry]:
        """
        Asynchronously retrieve all DOCSIS 3.1 downstream OFDM channel entries.

        This method queries SNMP for each available OFDM channel index
        and populates a DocsIf31CmDsOfdmChanEntry object with its SNMP attributes.

        NOTE:
            This is an async method. You must use 'await' when calling it.

        Returns:
            List[DocsIf31CmDsOfdmChanEntry]:
                A list of populated DocsIf31CmDsOfdmChanEntry objects,
                each representing one OFDM downstream channel.

        Raises:
            Exception: If SNMP queries fail or unexpected errors occur.
        """
        entries: list[DocsIf31CmDsOfdmChanEntry] = []

        # Get all OFDM Channel Indexes
        channel_indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

        for idx in channel_indices:
            self.logger.debug(f"Processing OFDM Channel Index: {idx}")
            oce = DocsIf31CmDsOfdmChanEntry(ofdm_idx=idx)

            # Iterate over all member attributes
            for member_name in oce.get_member_list():
                oid_base = COMPILED_OIDS.get(member_name)

                if not oid_base:
                    self.logger.warning(f"OID base not found for {member_name}")
                    continue

                oid = f"{oid_base}.{idx}"
                result = await self._snmp.get(oid)

                if result is not None:
                    self.logger.debug(
                        f"Retrieved SNMP value for Member: {member_name} -> OID: {oid}"
                    )
                    try:
                        value = Snmp_v2c.snmp_get_result_value(result)
                        setattr(oce, member_name, value)
                    except (ValueError, TypeError) as e:
                        self.logger.error(
                            f"Failed to set '{member_name}' with value '{result}': {e}"
                        )
                else:
                    self.logger.warning(f"No SNMP response received for OID: {oid}")

            entries.append(oce)

        return entries

    async def getDocsIfSignalQuality(self) -> list[DocsIfSignalQuality]:
        """
        Retrieves signal quality metrics for all downstream QAM channels.

        This method queries the SNMP agent for the list of downstream QAM channel indexes,
        and for each index, creates a `DocsIfSignalQuality` instance, populates it with SNMP data,
        and collects it into a list.

        Returns:
            List[DocsIfSignalQuality]: A list of signal quality objects, one per downstream channel.
        """
        sig_qual_list: list[DocsIfSignalQuality] = []

        indices = await self.getDocsIfCmDsScQamChanChannelIdIndex()
        if not indices:
            self.logger.warning("No downstream channel indices found.")
            return sig_qual_list

        for idx in indices:
            obj = DocsIfSignalQuality(index=idx, snmp=self._snmp)
            await obj.start()
            sig_qual_list.append(obj)

        return sig_qual_list

    async def getDocsIfDownstreamChannel(self) -> list[DocsIfDownstreamChannelEntry]:
        """
        Retrieves signal quality metrics for all downstream SC-QAM channels.

        This method queries the SNMP agent for the list of downstream SC-QAM channel indexes,
        and for each index, fetches and builds a DocsIfDownstreamChannelEntry.

        Returns:
            List[DocsIfDownstreamChannelEntry]: A list of populated downstream channel entries.
        """
        try:
            indices = await self.getDocsIfCmDsScQamChanChannelIdIndex()

            if not indices:
                self.logger.warning("No downstream SC-QAM channel indices found.")
                return []

            entries = await DocsIfDownstreamChannelEntry.get(
                snmp=self._snmp, indices=indices
            )

            return entries

        except Exception as e:
            self.logger.exception(
                "Failed to retrieve downstream SC-QAM channel entries, error: %s", e
            )
            return []

    async def getDocsIfDownstreamChannelCwErrorRate(
        self, sample_time_elapsed: float = 5.0
    ) -> list[DocsIfDownstreamCwErrorRateEntry] | dict[str, Any]:
        """
        Retrieves codeword error rate for all downstream SC-QAM channels.

        1. Fetch initial SNMP snapshot for all channels.
        2. Wait asynchronously for `sample_time_elapsed` seconds.
        3. Fetch second SNMP snapshot.
        4. Compute per-channel & aggregate CW error metrics.
        """
        try:
            # 1) Discover all downstream SC-QAM (index, channel_id) indices
            idx_chanid_indices: list[
                tuple[int, int]
            ] = await self.getDocsIfDownstreamChannelIdIndexStack()

            if not idx_chanid_indices:
                self.logger.warning("No downstream SC-QAM channel indices found.")
                return {"entries": [], "aggregate_error_rate": 0.0}

            self.logger.debug(
                f"Found {len(idx_chanid_indices)} downstream SC-QAM channel indices: {idx_chanid_indices}"
            )
            # Extract only the first element of each tuple
            idx_indices: list[int] = [index[0] for index in idx_chanid_indices]

            # 2) First snapshot
            initial_entry = await DocsIfDownstreamChannelEntry.get(
                snmp=self._snmp, indices=idx_indices
            )
            self.logger.debug(f"Initial snapshot: {len(initial_entry)} channels")

            # 3) Wait the sample interval
            await asyncio.sleep(sample_time_elapsed)

            # 4) Second snapshot
            later_entry = await DocsIfDownstreamChannelEntry.get(
                snmp=self._snmp, indices=idx_indices
            )
            self.logger.debug(
                f"Second snapshot after {sample_time_elapsed}s: {len(later_entry)} channels"
            )

            # 5) Calculate error rates
            calculator = DocsIfDownstreamChannelCwErrorRate(
                entries_1=initial_entry,
                entries_2=later_entry,
                channel_id_index_stack=idx_chanid_indices,
                time_elapsed=sample_time_elapsed,
            )
            return calculator.get()

        except Exception:
            self.logger.exception(
                "Failed to retrieve downstream SC-QAM codeword error rates"
            )
            return {"entries": [], "aggregate_error_rate": 0.0}

    async def getEventEntryIndex(self) -> list[EntryIndex]:
        """
        Retrieves the list of index values for the docsDevEventEntry table.

        Returns:
            List[int]: A list of SNMP index integers.
        """
        oid = "docsDevEvId"

        results = await self._snmp.walk(oid)

        if not results:
            self.logger.warning(f"No results found for OID {oid}")
            return []

        return cast(list[EntryIndex], Snmp_v2c.extract_last_oid_index(results))

    async def getDocsDevEventEntry(
        self, to_dict: bool = False
    ) -> list[DocsDevEventEntry] | list[dict]:
        """
        Retrieves all DocsDevEventEntry SNMP table entries.

        Args:
            to_dict (bool): If True, returns a list of dictionaries instead of DocsDevEventEntry instances.

        Returns:
            Union[List[DocsDevEventEntry], List[dict]]: A list of event log entries.
        """
        event_entries = []

        try:
            indices = await self.getEventEntryIndex()

            if not indices:
                self.logger.warning("No DocsDevEventEntry indices found.")
                return event_entries

            for idx in indices:
                entry = DocsDevEventEntry(index=idx, snmp=self._snmp)
                await entry.start()
                event_entries.append(entry.to_dict() if to_dict else entry)

        except Exception as e:
            self.logger.exception(
                "Failed to retrieve DocsDevEventEntry entries, error: %s", e
            )

        return event_entries

    async def getDocsIf31CmDsOfdmChanEntry(
        self,
    ) -> list[DocsIf31CmDsOfdmChanChannelEntry]:
        """
        Asynchronously retrieves and populates a list of `DocsIf31CmDsOfdmChanEntry` entries.

        This method fetches the indices of the DOCSIS 3.1 CM DS OFDM channels, creates
        `DocsIf31CmDsOfdmChanEntry` objects for each index, and populates their attributes
        by making SNMP queries. The entries are returned as a list.

        Returns:
            List[DocsIf31CmDsOfdmChanEntry]: A list of `DocsIf31CmDsOfdmChanEntry` objects.

        Raises:
            Exception: If any unexpected error occurs during the process of fetching or processing.
        """

        ofdm_chan_entry: list[DocsIf31CmDsOfdmChanChannelEntry] = []

        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning("No DocsIf31CmDsOfdmChanChannelId indices found.")
                return ofdm_chan_entry

            ofdm_chan_entry.extend(
                await DocsIf31CmDsOfdmChanChannelEntry.get(self._snmp, indices)
            )

        except Exception as e:
            self.logger.exception(
                "Failed to retrieve DocsIf31CmDsOfdmChanEntry entries, error: %s", e
            )

        return ofdm_chan_entry

    async def getDocsIf31CmSystemCfgDiplexState(self) -> DocsIf31CmSystemCfgDiplexState:
        """
        Asynchronously retrieves the DOCS-IF31-MIB system configuration state and populates the `DocsIf31CmSystemCfgState` object.

        This method will fetch the necessary MIB data, populate the attributes of the
        `DocsIf31CmSystemCfgState` object, and return the object.

        Returns:
            DocsIf31CmSystemCfgState: An instance of the `DocsIf31CmSystemCfgState` class with populated data.
        """
        obj = DocsIf31CmSystemCfgDiplexState(self._snmp)
        await obj.start()

        return obj

    async def getDocsIf31CmDsOfdmProfileStatsEntry(
        self,
    ) -> list[DocsIf31CmDsOfdmProfileStatsEntry]:
        """
        Asynchronously retrieves the DOCS-IF31-MIB system configuration state and populates the `DocsIf31CmSystemCfgState` object.

        This method will fetch the necessary MIB data, populate the attributes of the
        `DocsIf31CmSystemCfgState` object, and return the object.

        Returns:
            DocsIf31CmSystemCfgState: An instance of the `DocsIf31CmSystemCfgState` class with populated data.
        """

        ofdm_profile_entry: list[DocsIf31CmDsOfdmProfileStatsEntry] = []

        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning(
                    "No DocsIf31CmDsOfdmChanChannelIdIndex indices found."
                )
                return ofdm_profile_entry

            for idx in indices:
                entry = DocsIf31CmDsOfdmProfileStatsEntry(index=idx, snmp=self._snmp)
                await entry.start()
                ofdm_profile_entry.append(entry)

        except Exception as e:
            self.logger.exception(
                "Failed to retrieve DocsIf31CmDsOfdmProfileStatsEntry entries, error: %s",
                e,
            )

        return ofdm_profile_entry

    async def getPnmMeasurementStatus(
        self, test_type: DocsPnmCmCtlTest, ofdm_ifindex: int = 0
    ) -> MeasStatusType:
        """
        Retrieve the measurement status for a given PNM test type.

        Depending on the test type, the appropriate SNMP OID is selected,
        and the required interface index is either used directly or derived
        based on DOCSIS interface type conventions.

        Args:
            test_type (DocsPnmCmCtlTest): Enum specifying the PNM test type.
            ofdm_ifindex (int): Interface index for OFDM-based tests. This may be
                                ignored or overridden for specific test types.

        Returns:
            MeasStatusType: Parsed status value from SNMP response.

        Notes:
            - `DS_SPECTRUM_ANALYZER` uses a fixed ifIndex of 0.
            - `LATENCY_REPORT` dynamically resolves the ifIndex of the DOCSIS MAC layer.
            - If the test type is unsupported or SNMP fails, `MeasStatusType.OTHER | ERROR` is returned.
        """

        oid_key_map = {
            DocsPnmCmCtlTest.SPECTRUM_ANALYZER: "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus",
            DocsPnmCmCtlTest.DS_OFDM_SYMBOL_CAPTURE: "docsPnmCmDsOfdmSymMeasStatus",
            DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF: "docsPnmCmOfdmChEstCoefMeasStatus",
            DocsPnmCmCtlTest.DS_CONSTELLATION_DISP: "docsPnmCmDsConstDispMeasStatus",
            DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR: "docsPnmCmDsOfdmRxMerMeasStatus",
            DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE: "docsPnmCmDsOfdmFecMeasStatus",
            DocsPnmCmCtlTest.DS_HISTOGRAM: "docsPnmCmDsHistMeasStatus",
            DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF: "docsPnmCmUsPreEqMeasStatus",
            DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE: "docsPnmCmDsOfdmModProfMeasStatus",
            DocsPnmCmCtlTest.LATENCY_REPORT: "docsCmLatencyRptCfgMeasStatus",
        }

        if test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            ofdm_ifindex = 0
        elif test_type == DocsPnmCmCtlTest.LATENCY_REPORT:
            ofdm_ifindex = await self.getIfTypeIndex(DocsisIfType.docsCableMaclayer)[0]

        oid = oid_key_map.get(test_type)
        if not oid:
            self.logger.warning(f"Unsupported test type provided: {test_type}")
            return MeasStatusType.OTHER

        oid = f"{oid}.{ofdm_ifindex}"

        try:
            result = await self._snmp.get(oid)
            status_value = int(Snmp_v2c.snmp_get_result_value(result)[0])
            return MeasStatusType(status_value)

        except Exception as e:
            self.logger.error(f"[{test_type.name}] SNMP fetch failed on OID {oid}: {e}")
            self.logger.error(f"[{test_type.name}] {result}")
            return MeasStatusType.ERROR

    async def getDocsIfDownstreamChannelIdIndexStack(
        self,
    ) -> list[tuple[InterfaceIndex, ChannelId]]:
        """
        Retrieve SC-QAM channel index ↔ channelId tuples for DOCSIS 3.0 downstream channels,
        ensuring we only return true SC-QAM channels ( skips OFDM / zero entries ).

        Returns:
            List[Tuple[int, int]]: (entryIndex, channelId) pairs, or [] if none found.
        """
        # 1) fetch indices of all SC-QAM interfaces
        try:
            scqam_if_indices = await self.getIfTypeIndex(
                DocsisIfType.docsCableDownstream
            )
        except Exception:
            self.logger.error(
                "Failed to retrieve SC-QAM interface indices", exc_info=True
            )
            return []
        if not scqam_if_indices:
            self.logger.debug("No SC-QAM interface indices found")
            return []

        # 2) do a single walk of the SC-QAM ChannelId table
        try:
            responses = await self._snmp.walk("docsIfDownChannelId")
        except Exception:
            self.logger.error("SNMP walk failed for docsIfDownChannelId", exc_info=True)
            return []
        if not responses:
            self.logger.debug("No entries returned from docsIfDownChannelId walk")
            return []

        # 3) parse into (idx, chanId), forcing chanId → int
        try:
            raw_pairs: list[tuple[int, int]] = (
                Snmp_v2c.snmp_get_result_last_idx_force_value_type(
                    responses, value_type=int
                )
            )

        except Exception:
            self.logger.error("Failed to parse index/channel-ID pairs", exc_info=True)
            return []

        # 4) filter out non-SC-QAM and zero entries (likely OFDM)
        scqam_set = set(scqam_if_indices)
        filtered: list[tuple[InterfaceIndex, ChannelId]] = []

        for idx, chan_id in raw_pairs:
            if idx not in scqam_set:
                self.logger.debug("Skipping idx %s not in SC-QAM interface list", idx)
                continue
            if chan_id == 0:
                self.logger.debug(
                    "Skipping idx %s with channel_id=0 (likely OFDM)", idx
                )
                continue
            filtered.append((InterfaceIndex(idx), ChannelId(chan_id)))

        return filtered

    async def getDocsIf31CmDsOfdmChannelIdIndexStack(
        self,
    ) -> list[tuple[InterfaceIndex, ChannelId]]:
        """
        Retrieve a list of tuples representing OFDM channel index and their associated channel IDs
        for DOCSIS 3.1 downstream OFDM channels.

        Returns:
            List[Tuple[int, int]]: Each tuple contains (index, channelId). Returns an empty list if no data is found.
        """
        result = await self._snmp.walk(f"{'docsIf31CmDsOfdmChanChannelId'}")

        if not result:
            return []

        raw_pairs: list[tuple[int, int]] = (
            Snmp_v2c.snmp_get_result_last_idx_force_value_type(
                result,
                value_type=int,
            )
        )
        idx_channel_id: list[tuple[InterfaceIndex, ChannelId]] = [
            (InterfaceIndex(idx), ChannelId(chan_id)) for idx, chan_id in raw_pairs
        ]

        return idx_channel_id or []

    async def getSysUpTime(self) -> str | None:
        """
        Retrieves the system uptime of the SNMP target device.

        This method performs an SNMP GET operation on the `sysUpTime` OID (1.3.6.1.2.1.1.3.0),
        which returns the time (in hundredths of a second) since the network management portion
        of the system was last re-initialized.

        Returns:
            Optional[int]: The system uptime in hundredths of a second if successful,
            otherwise `None` if the SNMP request fails or the result cannot be parsed.

        Logs:
            - A warning if the SNMP GET fails or returns no result.
            - An error if the value cannot be converted to an integer.
        """
        result = await self._snmp.get(f"{'sysUpTime'}.0")

        if not result:
            self.logger.warning("SNMP get failed or returned empty for sysUpTime.")
            return None

        try:
            value = Snmp_v2c.get_result_value(result)
            return Snmp_v2c.ticks_to_duration(int(value))

        except (ValueError, TypeError) as e:
            self.logger.error(f"Failed to parse sysUpTime value: {value} - {e}")
            return None

    async def isAmplitudeDataPresent(self) -> bool:
        """
        Check if DOCSIS spectrum amplitude data is available via SNMP.

        Returns:
            bool: True if amplitude data exists; False otherwise.
        """
        oid = COMPILED_OIDS.get("docsIf3CmSpectrumAnalysisMeasAmplitudeData")
        if not oid:
            return False

        try:
            results = await self._snmp.walk(oid)
        except Exception:
            return False

        return bool(results)

    async def getSpectrumAmplitudeData(self) -> bytes:
        """
        Retrieve and return the raw spectrum analyzer amplitude data from the cable modem via SNMP.

        This method queries the 'docsIf3CmSpectrumAnalysisMeasAmplitudeData' table, collects all
        returned byte-chunks, and concatenates them into a single byte stream. It logs a warning
        if no data is found, and logs the first 128 bytes of the raw result (in hex) for inspection.

        Returns:
            A bytes object containing the full amplitude data stream. If no data is returned, an
            empty bytes object is returned.

        Raises:
            RuntimeError: If SNMP walk returns an unexpected data type or if any underlying SNMP
                          operation fails.
        """
        # OID for the amplitude data (should be a ByteString/Textual convention)
        oid = COMPILED_OIDS.get("docsIf3CmSpectrumAnalysisMeasAmplitudeData")
        if oid is None:
            msg = "OID 'docsIf3CmSpectrumAnalysisMeasAmplitudeData' is not defined in COMPILED_OIDS."
            self.logger.error(msg)
            raise RuntimeError(msg)

        # Perform SNMP WALK asynchronously
        try:
            results = await self._snmp.walk(oid)
        except Exception as e:
            self.logger.error(f"SNMP walk for OID {oid} failed: {e}")
            raise RuntimeError(f"SNMP walk failed: {e}") from e

        # If the SNMP WALK returned no varbinds, warn and return empty bytes
        if not results:
            self.logger.warning(f"No results found for OID {oid}")
            return b""

        # Extract raw byte-chunks from the SNMP results
        raw_chunks = []
        for idx, chunk in enumerate(Snmp_v2c.snmp_get_result_bytes(results)):
            # Ensure we got a bytes-like object
            if not isinstance(chunk, (bytes, bytearray)):
                self.logger.error(
                    f"Unexpected data type for chunk #{idx}: {type(chunk).__name__}. "
                    "Expected bytes or bytearray."
                )
                raise RuntimeError(f"Invalid SNMP result type: {type(chunk)}")

            # Log the first 128 bytes of each chunk (hex) for debugging
            preview = chunk[:128].hex()
            self.logger.debug(f"Raw SNMP chunk #{idx} (first 128 bytes): {preview}")

            raw_chunks.append(bytes(chunk))  # ensure immutability

        # Concatenate all chunks into a single bytes object
        varbind_bytes = b"".join(raw_chunks)

        # Log total length for reference
        total_length = len(varbind_bytes)
        if total_length == 0:
            self.logger.warning(
                f"OID {oid} returned an empty byte stream after concatenation."
            )
        else:
            self.logger.debug(
                f"Retrieved {total_length} bytes of amplitude data for OID {oid}."
            )

        return varbind_bytes

    async def getBulkFileUploadStatus(
        self, filename: str
    ) -> DocsPnmBulkFileUploadStatus:
        """
        Retrieve the upload‐status enum of a bulk data file by its filename.

        Args:
            filename: The exact file name to search for in the BulkDataFile table.

        Returns:
            DocsPnmBulkFileUploadStatus:
            - The actual upload status if found
            - DocsPnmBulkFileUploadStatus.ERROR if the filename is not present or any SNMP error occurs
        """
        self.logger.debug(f"Starting getBulkFileUploadStatus for filename: {filename}")

        name_oid = "docsPnmBulkFileName"
        status_oid = "docsPnmBulkFileUploadStatus"

        # 1) Walk file‐name column
        try:
            name_rows = await self._snmp.walk(name_oid)
        except Exception as e:
            self.logger.error(f"SNMP walk failed for BulkFileName: {e}")
            return DocsPnmBulkFileUploadStatus.ERROR

        if not name_rows:
            self.logger.warning("BulkFileName table is empty.")
            return None

        # 2) Loop through (index, name) pairs
        for idx, current_name in Snmp_v2c.snmp_get_result_last_idx_value(name_rows):
            if current_name != filename:
                continue

            # 3) Fetch the status OID for this index
            full_oid = f"{status_oid}.{idx}"
            try:
                resp = await self._snmp.get(full_oid)
            except Exception as e:
                self.logger.error(f"SNMP get failed for {full_oid}: {e}")
                return DocsPnmBulkFileUploadStatus.ERROR

            if not resp:
                self.logger.warning(f"No response for status OID {full_oid}")
                return DocsPnmBulkFileUploadStatus.ERROR

            # 4) Parse and convert to enum
            try:
                _, val = resp[0]
                status_int = int(val)
                status_enum = DocsPnmBulkFileUploadStatus(status_int)
            except ValueError as ve:
                self.logger.error(f"Invalid status value {val}: {ve}")
                return DocsPnmBulkFileUploadStatus.ERROR
            except Exception as e:
                self.logger.error(f"Unexpected error parsing status: {e}")
                return DocsPnmBulkFileUploadStatus.ERROR

            self.logger.debug(
                f"Bulk file '{filename}' upload status: {status_enum.name}"
            )
            return status_enum

        # not found
        self.logger.warning(f"Filename '{filename}' not found in BulkDataFile table.")
        return DocsPnmBulkFileUploadStatus.ERROR

    async def getDocsisBaseCapability(self) -> ClabsDocsisVersion:
        """
        Retrieve the DOCSIS version capability reported by the device.

        This method queries the SNMP OID `docsIf31CmDocsisBaseCapability`, which reflects
        the supported DOCSIS Radio Frequency specification version.

        Returns:
            ClabsDocsisVersion: Enum indicating the DOCSIS version supported by the device, or None if unavailable.

        SNMP MIB Reference:
            - OID: docsIf31DocsisBaseCapability
            - SYNTAX: ClabsDocsisVersion (INTEGER enum from 0 to 6)
            - Affected Devices:
                - CMTS: reports highest supported DOCSIS version.
                - CM: reports supported DOCSIS version.

            This attribute replaces `docsIfDocsisBaseCapability` from RFC 4546.
        """
        self.logger.debug("Fetching docsIf31DocsisBaseCapability")

        try:
            rsp = await self._snmp.get("docsIf31DocsisBaseCapability.0")
            docsis_version_raw = Snmp_v2c.get_result_value(rsp)

            if docsis_version_raw is None:
                self.logger.error(
                    "Failed to retrieve DOCSIS version: SNMP result is None"
                )
                return None

            try:
                docsis_version = int(docsis_version_raw)
            except (ValueError, TypeError):
                self.logger.error(
                    f"Failed to cast DOCSIS version to int: {docsis_version_raw}"
                )
                return None

            cdv = ClabsDocsisVersion.from_value(docsis_version)

            if cdv == ClabsDocsisVersion.OTHER:
                self.logger.warning(
                    f"Unknown DOCSIS version: {docsis_version} -> Enum: {cdv.name}"
                )
            else:
                self.logger.debug(f"DOCSIS version: {cdv.name}")

            return cdv

        except Exception as e:
            self.logger.exception(f"Exception during DOCSIS version retrieval: {e}")
            return None

    async def getInterfaceStatistics(
        self, interface_types: type[Enum] = DocsisIfType
    ) -> dict[str, list[dict]]:
        """
        Retrieves interface statistics grouped by provided Enum of interface types.

        Args:
            interface_types (Type[Enum]): Enum class representing interface types.

        Returns:
            Dict[str, List[Dict]]: Mapping of interface type name to list of interface stats.
        """
        stats: dict[str, list[dict]] = {}

        for if_type in interface_types:
            interfaces = await InterfaceStats.from_snmp(self._snmp, if_type)
            if interfaces:
                stats[if_type.name] = [iface.model_dump() for iface in interfaces]

        return stats

    async def getDocsIf31CmUsOfdmaChanChannelIdIndex(self) -> list[InterfaceIndex]:
        """
        Get the Docsis 3.1 upstream OFDMA channels.

        Returns:
            List[int]: A list of OFDMA channel indices present on the device.
        """
        return await self.getIfTypeIndex(DocsisIfType.docsOfdmaUpstream)

    async def getDocsIf31CmUsOfdmaChanEntry(self) -> list[DocsIf31CmUsOfdmaChanEntry]:
        """
        Retrieves and initializes all OFDMA channel entries from Snmp_v2c.

        Returns:
            List[DocsIf31CmUsOfdmaChanEntry]: List of populated OFDMA channel objects.
        """
        results: list[DocsIf31CmUsOfdmaChanEntry] = []

        indices = await self.getDocsIf31CmUsOfdmaChanChannelIdIndex()
        if not indices:
            self.logger.warning("No upstream OFDMA indices found.")
            return results

        return await DocsIf31CmUsOfdmaChanEntry.get(snmp=self._snmp, indices=indices)

    async def getDocsIfUpstreamChannelEntry(self) -> list[DocsIfUpstreamChannelEntry]:
        """
        Retrieves and initializes all ATDMA US channel entries from Snmp_v2c.

        Returns:
            List[DocsIfUpstreamChannelEntry]: List of populated ATDMA channel objects.
        """
        try:
            indices = await self.getDocsIfCmUsTdmaChanChannelIdIndex()

            if not indices:
                self.logger.warning("No upstream ATDMA indices found.")
                return []

            entries = await DocsIfUpstreamChannelEntry.get(
                snmp=self._snmp, indices=indices
            )

            return entries

        except Exception as e:
            self.logger.exception(
                "Failed to retrieve ATDMA upstream channel entries, error: %s", e
            )
            return []

    async def getDocsIf31CmUsOfdmaChannelIdIndexStack(
        self,
    ) -> list[tuple[InterfaceIndex, ChannelId]]:
        """
        Retrieve a list of tuples representing OFDMA channel index and their associated channel IDs
        for DOCSIS 3.1 upstream OFDMA channels.

        Returns:
            List[Tuple[InterfaceIndex, ChannelId]]: Each tuple contains (index, channelId). Returns an empty list if no data is found.
        """
        result = await self._snmp.walk(f"{'docsIf31CmUsOfdmaChanChannelId'}")

        if not result:
            return []

        raw_pairs: list[tuple[int, int]] = (
            Snmp_v2c.snmp_get_result_last_idx_force_value_type(
                result,
                value_type=int,
            )
        )
        idx_channel_id_list: list[tuple[InterfaceIndex, ChannelId]] = [
            (InterfaceIndex(idx), ChannelId(chan_id)) for idx, chan_id in raw_pairs
        ]

        return idx_channel_id_list or []

    async def getDocsIfCmUsTdmaChanChannelIdIndex(self) -> list[InterfaceIndex]:
        """
        Retrieve the list of DOCSIS 3.0 upstream TDMA/ATDMA channel indices (i.e., TDMA or ATDMA).

        Returns:
            List[int]: A list of TDMA/ATDMA channel indices present on the device.
        """
        idx_list: list[int] = []
        oid_channel_id = "docsIfUpChannelId"

        try:
            results = await self._snmp.walk(oid_channel_id)
            if not results:
                self.logger.warning(f"No results found for OID {oid_channel_id}")
                return []

            index_list = Snmp_v2c.extract_last_oid_index(results)

            oid_modulation = "docsIfUpChannelType"

            for idx in index_list:
                result = await self._snmp.get(f"{oid_modulation}.{idx}")

                if not result:
                    self.logger.warning(
                        f"SNMP get failed or returned empty docsIfUpChannelType for index {idx}."
                    )
                    continue

                val = Snmp_v2c.snmp_get_result_value(result)[0]

                try:
                    channel_type = int(val)

                except ValueError:
                    self.logger.warning(
                        f"Failed to convert channel-type value '{val}' to int for index {idx}. Skipping."
                    )
                    continue

                """
                    DocsisUpstreamType ::= TEXTUAL-CONVENTION
                    STATUS          current
                    DESCRIPTION
                            "Indicates the DOCSIS Upstream Channel Type.
                            'unknown' means information not available.
                            'tdma' is related to TDMA, Time Division
                            Multiple Access; 'atdma' is related to A-TDMA,
                            Advanced Time Division Multiple Access,
                            'scdma' is related to S-CDMA, Synchronous
                            Code Division Multiple Access.
                            'tdmaAndAtdma is related to simultaneous support of
                            TDMA and A-TDMA modes."
                    SYNTAX INTEGER {
                        unknown(0),
                        tdma(1),
                        atdma(2),
                        scdma(3),
                        tdmaAndAtdma(4)
                    }

                """

                if channel_type != 0:  # 0 means OFDMA in this case
                    idx_list.append(idx)

            return idx_list

        except Exception as e:
            self.logger.error(
                f"Failed to retrieve SC-QAM channel indices from {oid_channel_id}: {e}"
            )
            return []

    """
    Measurement Entries
    """

    async def getDocsPnmCmDsOfdmRxMerEntry(self) -> list[DocsPnmCmDsOfdmRxMerEntry]:
        """
        Retrieve RxMER (per-subcarrier) entries for all downstream OFDM channels.

        Returns
        -------
        List[DocsPnmCmDsOfdmRxMerEntry]
            A list of Pydantic models with values already coerced to floats
            where appropriate (e.g., dB fields scaled by 1/100).
        """
        self.logger.debug("Entering into -> getDocsPnmCmDsOfdmRxMerEntry()")
        entries: list[DocsPnmCmDsOfdmRxMerEntry] = []
        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning(
                    "No DocsIf31CmDsOfdmChanChannelIdIndex indices found."
                )
                return entries

            # De-dupe and sort for predictable iteration (optional but nice for logs)
            unique_indices = sorted(set(int(i) for i in indices))
            self.logger.debug(f"RxMER fetch: indices={unique_indices}")

            entries = await DocsPnmCmDsOfdmRxMerEntry.get(
                snmp=self._snmp, indices=unique_indices
            )

            # Helpful summary log—count only; detailed per-field logs happen in the entry fetcher
            self.logger.debug("RxMER fetch complete: %d entries", len(entries))
            return entries

        except Exception as e:
            # Keep the exception in logs for debugging (stacktrace included)
            self.logger.exception(
                "Failed to retrieve DocsPnmCmDsOfdmRxMerEntry entries: %s", e
            )
            return entries

    async def getDocsPnmCmOfdmChanEstCoefEntry(
        self,
    ) -> list[DocsPnmCmOfdmChanEstCoefEntry]:
        """
        Retrieves downstream OFDM Channel Estimation Coefficient entries from the cable modem via SNMP.

        This method:
        - Queries for all available downstream OFDM channel indices using `getDocsIf31CmDsOfdmChannelIdIndex()`.
        - For each index, requests a structured set of coefficient data points including amplitude ripple,
          group delay characteristics, mean values, and measurement status.
        - Constructs a list of `DocsPnmCmOfdmChanEstCoefEntry` objects, each encapsulating the raw
          coefficients for one OFDM channel.

        Returns:
            List[DocsPnmCmOfdmChanEstCoefEntry]: A list of populated OFDM channel estimation entries. Each entry
            includes both metadata and coefficient fields defined in `DocsPnmCmOfdmChanEstCoefFields`.
        """
        entries: list[DocsPnmCmOfdmChanEstCoefEntry] = []

        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning(
                    "No DocsIf31CmDsOfdmChanChannelIdIndex indices found."
                )
                return entries

            entries = await DocsPnmCmOfdmChanEstCoefEntry.get(
                snmp=self._snmp, indices=indices
            )

        except Exception as e:
            self.logger.exception(
                "Failed to retrieve DocsPnmCmOfdmChanEstCoefEntry entries, error: %s", e
            )

        return entries

    async def getDocsPnmCmDsConstDispMeasEntry(
        self,
    ) -> list[DocsPnmCmDsConstDispMeasEntry]:
        """
        Retrieves Constellation Display measurement entries for all downstream OFDM channels.

        This method:
        - Discovers available downstream OFDM channel indices using SNMP via `getDocsIf31CmDsOfdmChannelIdIndex()`
        - For each channel index, fetches constellation capture configuration, modulation info,
          measurement status, and associated binary filename
        - Returns the results as a structured list of `DocsPnmCmDsConstDispMeasEntry` models

        Returns:
            List[DocsPnmCmDsConstDispMeasEntry]: A list of Constellation Display SNMP measurement entries.
        """
        entries: list[DocsPnmCmDsConstDispMeasEntry] = []

        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning(
                    "No DocsIf31CmDsOfdmChanChannelIdIndex indices found."
                )
                return entries

            entries = await DocsPnmCmDsConstDispMeasEntry.get(
                snmp=self._snmp, indices=indices
            )

        except Exception as e:
            self.logger.exception(
                "Failed to retrieve DocsPnmCmDsConstDispMeasEntry entries, error: %s", e
            )

        return entries

    async def getDocsPnmCmUsPreEqEntry(self) -> list[DocsPnmCmUsPreEqEntry]:
        """
        Retrieves upstream OFDMA Pre-Equalization measurement entries for all upstream OFDMA channels.

        This method performs:
        - SNMP index discovery via `getDocsIf31CmDsOfdmChannelIdIndex()` (may need to be updated to upstream index discovery)
        - Per-index SNMP fetch of pre-equalization configuration and measurement metadata
        - Returns structured list of `DocsPnmCmUsPreEqEntry` models
        """
        entries: list[DocsPnmCmUsPreEqEntry] = []

        try:
            indices = await self.getDocsIf31CmUsOfdmaChanChannelIdIndex()

            if not indices:
                self.logger.warning("No DocsIf31CmUsOfdmaChannelIdIndex indices found.")
                return entries

            entries = await DocsPnmCmUsPreEqEntry.get(snmp=self._snmp, indices=indices)

        except Exception as e:
            self.logger.exception(
                "Failed to retrieve DocsPnmCmUsPreEqEntry entries, error: %s", e
            )

        return entries

    async def getDocsPnmCmDsOfdmMerMarEntry(self) -> list[DocsPnmCmDsOfdmMerMarEntry]:
        """
        Retrieves DOCSIS 3.1 Downstream OFDM MER Margin entries.

        This method queries the SNMP agent to collect MER Margin data for each downstream OFDM channel
        using the ifIndex values retrieved from the modem. Each returned entry corresponds to a channel's
        MER margin metrics, including required MER, measured MER, threshold offsets, and measurement status.

        Returns:
            List[DocsPnmCmDsOfdmMerMarEntry]: A list of populated MER margin entries for each OFDM channel.
        """
        entries: list[DocsPnmCmDsOfdmMerMarEntry] = []

        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning(
                    "No DocsIf31CmDsOfdmChanChannelIdIndex indices found."
                )
                return entries

            entries = await DocsPnmCmDsOfdmMerMarEntry.get(
                snmp=self._snmp, indices=indices
            )
            self.logger.debug(
                f"Number of DocsPnmCmDsOfdmMerMarEntry Found: {len(entries)}"
            )

        except Exception as e:
            self.logger.exception(
                "Failed to retrieve DocsPnmCmDsOfdmMerMarEntry entries, error: %s", e
            )

        return entries

    async def getDocsPnmCmDsHistEntry(self) -> list[DocsPnmCmDsHistEntry]:
        """
        Retrieves DOCSIS 3.1 Downstream Histogram entries.

        This method queries the SNMP agent to collect histogram data for each downstream OFDM channel
        using the ifIndex values retrieved from the modem. Each returned entry corresponds to a channel's
        histogram configuration and status.

        """
        entries: list[DocsPnmCmDsHistEntry] = []

        try:
            indices = await self.getIfTypeIndex(DocsisIfType.docsCableMaclayer)

            if not indices:
                self.logger.error("No docsCableMaclayer indices found.")
                return entries

            self.logger.debug(f"Found docsCableDownstream Indices: {indices}")

            entries = await DocsPnmCmDsHistEntry.get(snmp=self._snmp, indices=indices)
            self.logger.debug(f"Number of DocsPnmCmDsHistEntry Found: {len(entries)}")

        except Exception as e:
            self.logger.exception(
                "Failed to retrieve DocsPnmCmDsHistEntry entries, error: %s", e
            )

        return entries

    async def getDocsPnmCmDsOfdmFecEntry(self) -> list[DocsPnmCmDsOfdmFecEntry]:
        """
        Retrieve FEC Summary entries for all downstream OFDM channels.

        Returns
        -------
        List[DocsPnmCmDsOfdmFecEntry].
        """
        self.logger.debug("Entering into -> getDocsPnmCmDsOfdmFecEntry()")
        entries: list[DocsPnmCmDsOfdmFecEntry] = []
        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning(
                    "No DocsIf31CmDsOfdmChanChannelIdIndex indices found."
                )
                return entries

            unique_indices = sorted(set(int(i) for i in indices))
            self.logger.debug(f"`FEC Summary fetch: indices={unique_indices}")

            entries = await DocsPnmCmDsOfdmFecEntry.get(
                snmp=self._snmp, indices=unique_indices
            )

            self.logger.debug("FEC Summary fetch complete: %d entries", len(entries))
            return entries

        except Exception as e:
            self.logger.exception(
                "Failed to retrieve DocsPnmCmDsOfdmFecEntry entries: %s", e
            )
            return entries

    async def getDocsPnmCmDsOfdmModProfEntry(self) -> list[DocsPnmCmDsOfdmModProfEntry]:
        """
        Retrieve Modulation Profile entries for all downstream OFDM channels.

        Returns
        -------
        List[DocsPnmCmDsOfdmModProfEntry].
        """
        self.logger.debug("Entering into -> getDocsPnmCmDsOfdmModProfEntry()")
        entries: list[DocsPnmCmDsOfdmModProfEntry] = []
        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning(
                    "No DocsIf31CmDsOfdmChanChannelIdIndex indices found."
                )
                return entries

            # De-dupe and sort for predictable iteration (optional but nice for logs)
            unique_indices = sorted(set(int(i) for i in indices))
            self.logger.debug(f"ModProf fetch: indices={unique_indices}")

            entries = await DocsPnmCmDsOfdmModProfEntry.get(
                snmp=self._snmp, indices=unique_indices
            )

            # Helpful summary log—count only; detailed per-field logs happen in the entry fetcher
            self.logger.debug("ModProf fetch complete: %d entries", len(entries))
            return entries

        except Exception as e:
            # Keep the exception in logs for debugging (stacktrace included)
            self.logger.exception(
                "Failed to retrieve DocsPnmCmDsOfdmModProfEntry entries: %s", e
            )
            return entries

    async def getDocsIf3CmSpectrumAnalysisEntry(
        self, indices: list[int] = DEFAULT_SPECTRUM_ANALYZER_INDICES
    ) -> list[DocsIf3CmSpectrumAnalysisEntry]:
        """
        Retrieves DOCSIS 3.0 Spectrum Analysis entries
        Args:
            indices: List[int] = DEFAULT_SPECTRUM_ANALYZER_INDICES
                This method queries the SNMP agent to collect spectrum analysis data for each specified index.
                Each returned entry corresponds to a spectrum analyzer's configuration and status.
                Current DOCSIS 3.0 MIB only defines index 0 for downstream spectrum analysis.
                Leaving for possible future expansion.

        """
        entries: list[DocsIf3CmSpectrumAnalysisEntry] = []

        try:
            if not indices:
                self.logger.error("No docsCableMaclayer indices found.")
                return entries

            self.logger.debug(f"Found docsCableDownstream Indices: {indices}")

            entries = await DocsIf3CmSpectrumAnalysisEntry.get(
                snmp=self._snmp, indices=indices
            )
            self.logger.debug(
                f"Number of DocsIf3CmSpectrumAnalysisEntry Found: {len(entries)}"
            )

        except Exception as e:
            self.logger.exception(
                f"Failed to retrieve DocsIf3CmSpectrumAnalysisEntry entries: {e}"
            )

        return entries

    async def getOfdmProfiles(self) -> list[tuple[int, OfdmProfiles]]:
        """
        Retrieve provisioned OFDM profile bits for each downstream OFDM channel.

        Returns:
            List[Tuple[int, OfdmProfiles]]: A list of tuples where each tuple contains:
                - SNMP index (int)
                - Corresponding OfdmProfiles bitmask (OfdmProfiles enum)
        """
        BITS_16: int = 16

        entries: list[tuple[int, OfdmProfiles]] = []

        try:
            indices = await self.getDocsIf31CmDsOfdmChannelIdIndex()

            if not indices:
                self.logger.warning(
                    "No DocsIf31CmDsOfdmChanChannelIdIndex indices found."
                )
                return entries

            for index in indices:
                results = await self._snmp.get(
                    f"docsIf31RxChStatusOfdmProfiles.{index}"
                )
                raw = Snmp_v2c.get_result_value(results)

                if isinstance(raw, bytes):
                    value = int.from_bytes(raw, byteorder="little")
                else:
                    value = int(raw, BITS_16)

                profiles = OfdmProfiles(value)
                entries.append((index, profiles))

        except Exception as e:
            self.logger.exception("Failed to retrieve OFDM profiles, error: %s", e)

        return entries

    ####################
    # DOCSIS 4.0 - FDD #
    ####################

    async def getDocsFddCmFddSystemCfgState(
        self, index: int = 0
    ) -> DocsFddCmFddSystemCfgState | None | None:
        """
        Retrieves the FDD band edge configuration state for a specific cable modem index.

        This queries the DOCSIS 4.0 MIB values for:
        - Downstream Lower Band Edge
        - Downstream Upper Band Edge
        - Upstream Upper Band Edge

        Args:
            index (int): SNMP index of the CM to query (default: 0).

        Returns:
            DocsFddCmFddSystemCfgState | None: Populated object if successful, or None on failure.
        """
        results = await self._snmp.walk("docsFddCmFddSystemCfgState")
        if not results:
            self.logger.warning(
                f"No results found during SNMP walk for OID {'docsFddCmFddSystemCfgState'}"
            )
            return None

        obj = DocsFddCmFddSystemCfgState(index, self._snmp)
        success = await obj.start()

        if not success:
            self.logger.warning(
                f"SNMP population failed for DocsFddCmFddSystemCfgState (index={index})"
            )
            return None

        return obj

    async def getDocsFddCmFddBandEdgeCapabilities(
        self, create_and_start: bool = True
    ) -> list[DocsFddCmFddBandEdgeCapabilities] | None:
        """
        Retrieve a list of FDD band edge capability entries for a DOCSIS 4.0 modem.

        Walks the SNMP table to discover indices, and returns capability objects
        optionally populated with SNMP data.

        Args:
            create_and_start (bool): Whether to call `.start()` on each entry.

        Returns:
            A list of DocsFddCmFddBandEdgeCapabilities objects, or None if none found.
        """
        results = await self._snmp.walk("docsFddDiplexerUsUpperBandEdgeCapability")
        if not results:
            self.logger.warning(
                "No results found during SNMP walk for OID 'docsFddDiplexerUsUpperBandEdgeCapability'"
            )
            return None

        entries = []
        for idx in Snmp_v2c.extract_last_oid_index(results):
            obj = DocsFddCmFddBandEdgeCapabilities(idx, self._snmp)

            if create_and_start and not await obj.start():
                self.logger.warning(
                    f"SNMP population failed for DocsFddCmFddBandEdgeCapabilities (index={idx})"
                )
                continue

            entries.append(obj)

        return entries or None

    ######################
    # SNMP Set Operation #
    ######################

    async def setDocsDevResetNow(self) -> bool:
        """
        Triggers an immediate device reset using the SNMP `docsDevResetNow` object.

        Returns:
        - bool: True if the SNMP set operation is successful, False otherwise.
        """
        try:
            oid = f"{'docsDevResetNow'}.0"
            self.logger.debug(f"Sending device reset via SNMP SET: {oid} = 1")

            response = await self._snmp.set(oid, Snmp_v2c.TRUE, Integer32)

            if response is None:
                self.logger.error("Device reset command returned None")
                return False

            result = Snmp_v2c.snmp_set_result_value(response)

            self.logger.debug(f"Device reset command issued. SNMP response: {result}")
            return True

        except Exception as e:
            self.logger.exception(f"Failed to send device reset command: {e}")
            return False

    async def setDocsPnmBulk(self, tftp_server: str, tftp_path: str = "") -> bool:
        """
        Set Docs PNM Bulk SNMP parameters.

        Args:
            tftp_server (str): TFTP server IP address.
            tftp_path (str, optional): TFTP server path. Defaults to empty string.

        Returns:
            bool: True if all SNMP set operations succeed, False if any fail.
        """
        try:
            ip_type = Snmp_v2c.get_inet_address_type(tftp_server).value
            set_response = await self._snmp.set(
                f"{'docsPnmBulkDestIpAddrType'}.0", ip_type, Integer32
            )
            self.logger.debug(f"docsPnmBulkDestIpAddrType set: {set_response}")

            set_response = await self._snmp.set(
                f"{'docsPnmBulkUploadControl'}.0",
                DocsPnmBulkUploadControl.AUTO_UPLOAD.value,
                Integer32,
            )
            self.logger.debug(f"docsPnmBulkUploadControl set: {set_response}")

            ip_binary = InetGenerate.inet_to_binary(tftp_server)
            if ip_binary is None:
                self.logger.error(
                    f"Failed to convert IP address to binary: {tftp_server}"
                )
                return False
            set_response = await self._snmp.set(
                "docsPnmBulkDestIpAddr.0", ip_binary, OctetString
            )
            self.logger.debug(f"docsPnmBulkDestIpAddr set: {set_response}")

            tftp_path = tftp_path or ""
            set_response = await self._snmp.set(
                f"{'docsPnmBulkDestPath'}.0", tftp_path, OctetString
            )
            self.logger.debug(f"docsPnmBulkDestPath set: {set_response}")

            return True

        except Exception as e:
            self.logger.error(f"Failed to set DocsPnmBulk parameters: {e}")
            return False

    async def setDocsIf3CmSpectrumAnalysisCtrlCmd(
        self,
        spec_ana_cmd: DocsIf3CmSpectrumAnalysisCtrlCmd,
        spectrum_retrieval_type: SpectrumRetrievalType = SpectrumRetrievalType.FILE,
        set_and_go: bool = True,
    ) -> bool:
        """
        Sets all DocsIf3CmSpectrumAnalysisCtrlCmd parameters via SNMP using index 0.

        Parameters:
        - spec_ana_cmd (DocsIf3CmSpectrumAnalysisCtrlCmd): The control command object to apply.
        - spectrum_retrieval_type (SpectrumRetrieval): Determines the method of spectrum retrieval.
            - SpectrumRetrieval.FILE: File-based retrieval, in which case `docsIf3CmSpectrumAnalysisCtrlCmdFileEnable` is set to ENABLE.
            - SpectrumRetrieval.SNMP: SNMP-based retrieval, in which case `docsIf3CmSpectrumAnalysisCtrlCmdEnable` is set to ENABLE.
        - set_and_go (bool): Whether to include the 'Enable' field in the set request.
            - If `data_retrival_opt = SpectrumRetrieval.FILE`, then `docsIf3CmSpectrumAnalysisCtrlCmdFileEnable` is set to ENABLE and `docsIf3CmSpectrumAnalysisCtrlCmdEnable` is skipped.
            - If `data_retrival_opt = SpectrumRetrieval.SNMP`, then `docsIf3CmSpectrumAnalysisCtrlCmdEnable` is set to ENABLE.

        Returns:
        - bool: True if all parameters were set successfully and confirmed, False otherwise.

        Raises:
        - Exception: If any error occurs during the SNMP set operations.
        """

        self.logger.debug(f"SpectrumAnalyzerPara: {spec_ana_cmd.to_dict()}")

        if spec_ana_cmd.precheck_spectrum_analyzer_settings():
            self.logger.debug(
                f"SpectrumAnalyzerPara-PreCheck-Changed: {spec_ana_cmd.to_dict()}"
            )

        """
            Custom SNMP SET for Spectrum Analyzer
        """

        async def __snmp_set(
            field_name: str, obj_value: str | int, snmp_type: type
        ) -> bool:
            """Helper function to perform SNMP set and verify the result."""
            base_oid = COMPILED_OIDS.get(field_name)
            if not base_oid:
                self.logger.warning(
                    f'OID not found for field "{field_name}", skipping.'
                )
                return False

            oid = f"{base_oid}.0"
            logging.debug(
                f"Field-OID: {field_name} -> OID: {oid} -> {obj_value} -> Type: {snmp_type}"
            )

            set_response = await self._snmp.set(oid, obj_value, snmp_type)
            logging.debug(f"Set {field_name} [{oid}] = {obj_value}: {set_response}")

            if not set_response:
                logging.error(f"Failed to set {field_name} to ({obj_value})")
                return False

            result = Snmp_v2c.snmp_set_result_value(set_response)[0]

            if not result:
                logging.error(f"Failed to set {field_name} to ({obj_value})")
                return False

            logging.debug(
                f"Result({result}): {type(result)} -> Value({obj_value}): {type(obj_value)}"
            )

            if str(result) != str(obj_value):
                logging.error(
                    f"Failed to set {field_name}. Expected ({obj_value}), got ({result})"
                )
                return False
            return True

        # Need to get Diplex Setting to make sure that the Spec Analyzer setting are within the band
        cscs: DocsIf31CmSystemCfgDiplexState = (
            await self.getDocsIf31CmSystemCfgDiplexState()
        )
        cscs.to_dict()[0]

        """ TODO: Will need to validate the Spec Analyzer Settings against the Diplex Settings
        lower_edge = int(diplex_dict["docsIf31CmSystemCfgStateDiplexerCfgDsLowerBandEdge"]) * 1_000_000
        upper_edge = diplex_dict["docsIf31CmSystemCfgStateDiplexerCfgDsUpperBandEdge"] * 1_000_000
        """
        try:
            field_type_map = {
                "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout": Integer32,
                "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency": Gauge32,
                "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency": Gauge32,
                "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan": Gauge32,
                "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment": Gauge32,
                "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth": Gauge32,
                "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction": Integer32,
                "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages": Gauge32,
                "docsIf3CmSpectrumAnalysisCtrlCmdEnable": Integer32,
                "docsIf3CmSpectrumAnalysisCtrlCmdFileName": OctetString,
                "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable": Integer32,
            }

            """
                Note: MUST BE THE LAST 2 AND IN THIS ORDER:
                    docsIf3CmSpectrumAnalysisCtrlCmdEnable      <- Triggers SNMP AMPLITUDE DATA RETURN
                    docsIf3CmSpectrumAnalysisCtrlCmdFileEnable  <- Trigger PNM FILE RETURN, OVERRIDES SNMP AMPLITUDE DATA RETURN
            """

            # Iterating through the fields and setting their values via SNMP
            for field_name, snmp_type in field_type_map.items():
                obj_value = getattr(spec_ana_cmd, field_name)

                self.logger.debug(f"Field-Name: {field_name} -> SNMP-Type: {snmp_type}")

                ##############################################################
                # OVERRIDE SECTION TO MAKE SURE WE FOLLOW THE SPEC-ANA RULES #
                ##############################################################

                if field_name == "docsIf3CmSpectrumAnalysisCtrlCmdFileName":
                    file_name = getattr(spec_ana_cmd, field_name)

                    if not file_name:
                        setattr(
                            spec_ana_cmd,
                            field_name,
                            f"snmp-amplitude-get-flag-{Generate.time_stamp()}",
                        )

                    await __snmp_set(
                        field_name, getattr(spec_ana_cmd, field_name), snmp_type
                    )

                    continue

                #######################################################################################
                #                                                                                     #
                #                   START SPECTRUM ANALYZER MEASURING PROCESS                         #
                #                                                                                     #
                # This OID Triggers the start of the Spectrum Analysis for SNMP-AMPLITUDE-DATA RETURN #
                #######################################################################################
                elif field_name == "docsIf3CmSpectrumAnalysisCtrlCmdEnable":
                    obj_value = Snmp_v2c.TRUE
                    self.logger.debug(
                        f"Field-Name: {field_name} -> SNMP-Type: {snmp_type}"
                    )

                    # Need to toggle ? -> FALSE -> TRUE
                    if not await __snmp_set(field_name, Snmp_v2c.FALSE, snmp_type):
                        self.logger.error(
                            f"Fail to set {field_name} to {Snmp_v2c.FALSE}"
                        )
                        return False

                    time.sleep(1)

                    if not await __snmp_set(field_name, Snmp_v2c.TRUE, snmp_type):
                        self.logger.error(
                            f"Fail to set {field_name} to {Snmp_v2c.TRUE}"
                        )
                        return False

                    continue

                ######################################################################################
                #
                #                   CHECK SPECTRUM ANALYZER MEASURING PROCESS
                #                           FOR PNM FILE RETRIVAL
                #
                # This OID Triggers the start of the Spectrum Analysis for PNM-FILE RETURN
                # Override SNMP-AMPLITUDE-DATA RETURN
                ######################################################################################
                elif field_name == "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable":
                    obj_value = (
                        Snmp_v2c.TRUE
                        if spectrum_retrieval_type == SpectrumRetrievalType.FILE
                        else Snmp_v2c.FALSE
                    )
                    self.logger.debug(
                        f"Setting File Retrival, Set-And-Go({set_and_go}) -> Value: {obj_value}"
                    )

                ###############################################
                # Set Field setting not change by above rules #
                ###############################################
                if isinstance(obj_value, Enum):
                    obj_value = str(obj_value.value)
                    self.logger.debug(
                        f"ENUM Found: Set Value Type: {obj_value} -> {type(obj_value)}"
                    )
                else:
                    obj_value = str(obj_value)

                self.logger.debug(
                    f"{field_name} -> Set Value Type: {obj_value} -> {type(obj_value)}"
                )

                if not await __snmp_set(field_name, obj_value, snmp_type):
                    self.logger.error(f"Fail to set {field_name} to {obj_value}")
                    return False

            return True

        except Exception:
            logging.exception(
                "Exception while setting DocsIf3CmSpectrumAnalysisCtrlCmd"
            )
            return False

    async def setDocsPnmCmUsPreEq(
        self,
        ofdma_idx: int,
        filename: str,
        last_pre_eq_filename: str,
        set_and_go: bool = True,
    ) -> bool:
        """
        Set the upstream Pre-EQ file name and enable Pre-EQ capture for a specified OFDMA channel index.

        Args:
            ofdma_idx (int): Index in the DocsPnmCmUsPreEq SNMP table.
            file_name (str): Desired file name to use for Pre-EQ capture.

        Returns:
            bool: True if both SNMP set operations succeed and verify expected values; False otherwise.
        """
        try:
            oid = f"{'docsPnmCmUsPreEqFileName'}.{ofdma_idx}"
            self.logger.debug(f'Setting Pre-EQ filename: [{oid}] = "{filename}"')
            response = await self._snmp.set(oid, filename, OctetString)
            result = Snmp_v2c.snmp_set_result_value(response)

            if not result or str(result[0]) != filename:
                self.logger.error(
                    f'Filename mismatch. Expected "{filename}", got "{result[0] if result else "None"}"'
                )
                return False

            oid = f"{'docsPnmCmUsPreEqLastUpdateFileName'}.{ofdma_idx}"
            self.logger.debug(
                f'Setting Last-Pre-EQ filename: [{oid}] = "{last_pre_eq_filename}"'
            )
            response = await self._snmp.set(oid, last_pre_eq_filename, OctetString)
            result = Snmp_v2c.snmp_set_result_value(response)

            if not result or str(result[0]) != last_pre_eq_filename:
                self.logger.error(
                    f'Filename mismatch. Expected "{last_pre_eq_filename}", got "{result[0] if result else "None"}"'
                )
                return False

            if set_and_go:
                time.sleep(1)
                enable_oid = f"{'docsPnmCmUsPreEqFileEnable'}.{ofdma_idx}"
                self.logger.debug(
                    f"Enabling Pre-EQ capture [{enable_oid}] = {Snmp_v2c.TRUE}"
                )
                response = await self._snmp.set(enable_oid, Snmp_v2c.TRUE, Integer32)
                result = Snmp_v2c.snmp_set_result_value(response)

                if not result or int(result[0]) != Snmp_v2c.TRUE:
                    self.logger.error(
                        f'Failed to enable Pre-EQ capture. Expected 1, got "{result[0] if result else "None"}"'
                    )
                    return False

            return True

        except Exception as e:
            self.logger.exception(
                f"Exception during setDocsPnmCmUsPreEq for index {ofdma_idx}: {e}"
            )
            return False

    async def setDocsPnmCmDsOfdmModProf(
        self, ofdm_idx: int, mod_prof_file_name: str, set_and_go: bool = True
    ) -> bool:
        """
        Set the DocsPnmCmDsOfdmModProf parameters for a given OFDM index.

        Parameters:
        - ofdm_idx (int): The index of the OFDM channel.
        - mod_prof_file_name (str): The filename to set for the modulation profile.

        Returns:
        - bool: True if both SNMP sets were successful, False otherwise.
        """
        try:
            file_oid = f"{'docsPnmCmDsOfdmModProfFileName'}.{ofdm_idx}"
            enable_oid = f"{'docsPnmCmDsOfdmModProfFileEnable'}.{ofdm_idx}"

            file_response = await self._snmp.set(
                file_oid, mod_prof_file_name, OctetString
            )
            self.logger.debug(
                f"Set {file_oid} to {mod_prof_file_name}: {file_response}"
            )

            if set_and_go:
                enable_response = await self._snmp.set(
                    enable_oid, Snmp_v2c.TRUE, Integer32
                )
                self.logger.debug(f"Set {enable_oid} to 1 (enable): {enable_response}")

            return True

        except Exception as e:
            self.logger.error(
                f"Failed to set DocsPnmCmDsOfdmModProf for index {ofdm_idx}: {e}"
            )
            return False

    async def setDocsPnmCmDsOfdmRxMer(
        self, ofdm_idx: int, rxmer_file_name: str, set_and_go: bool = True
    ) -> bool:
        """
        Sets the RxMER file name and enables file capture for a specified OFDM channel index.

        Parameters:
        - ofdm_idx (str): The index in the DocsPnmCmDsOfdmRxMer SNMP table.
        - rxmer_file_name (str): Desired file name to assign for RxMER capture.

        Returns:
        - bool: True if both SNMP set operations succeed and return expected values, False otherwise.
        """
        try:
            oid_file_name = f"{'docsPnmCmDsOfdmRxMerFileName'}.{ofdm_idx}"
            set_response = await self._snmp.set(
                oid_file_name, rxmer_file_name, OctetString
            )
            self.logger.debug(
                f'Setting RxMER file name [{oid_file_name}] = "{rxmer_file_name}"'
            )

            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or str(result[0]) != rxmer_file_name:
                self.logger.error(
                    f'File name mismatch. Expected "{rxmer_file_name}", got "{result[0] if result else "None"}"'
                )
                return False

            if set_and_go:
                oid_file_enable = f"{'docsPnmCmDsOfdmRxMerFileEnable'}.{ofdm_idx}"
                set_response = await self._snmp.set(oid_file_enable, 1, Integer32)
                self.logger.debug(f"Enabling RxMER capture [{oid_file_enable}] = 1")

                result = Snmp_v2c.snmp_set_result_value(set_response)
                if not result or int(result[0]) != 1:
                    self.logger.error(
                        f'Failed to enable RxMER capture. Expected 1, got "{result[0] if result else "None"}"'
                    )
                    return False

            return True

        except Exception as e:
            self.logger.exception(
                f"Exception during setDocsPnmCmDsOfdmRxMer for index {ofdm_idx}: {e}"
            )
            return False

    async def setDocsPnmCmDsOfdmFecSum(
        self,
        ofdm_idx: int,
        fec_sum_file_name: str,
        fec_sum_type: FecSummaryType = FecSummaryType.TEN_MIN,
        set_and_go: bool = True,
    ) -> bool:
        """
        Sets SNMP parameters for FEC summary of an OFDM channel.

        Parameters:
        - ofdm_idx (str): The OFDM index.
        - fec_sum_file_name (str): The file name associated with FEC sum.
        - fec_sum_type (FecSummaryType): The type of FEC summary (default is 10 minutes).

        Returns:
        - bool: True if successful, False if any error occurs during SNMP operations.
        """
        try:
            oid_file_name = f"{'docsPnmCmDsOfdmFecFileName'}.{ofdm_idx}"
            self.logger.debug(
                f'Setting FEC file name [{oid_file_name}] = "{fec_sum_file_name}"'
            )
            set_response = await self._snmp.set(
                oid_file_name, fec_sum_file_name, OctetString
            )
            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or str(result[0]) != fec_sum_file_name:
                self.logger.error(
                    f'File name mismatch. Expected "{fec_sum_file_name}", got "{result[0] if result else "None"}"'
                )
                return False

            oid_sum_type = f"{'docsPnmCmDsOfdmFecSumType'}.{ofdm_idx}"
            self.logger.debug(
                f"Setting FEC sum type [{oid_sum_type}] = {fec_sum_type.name} -> {type(fec_sum_type.value)}"
            )
            set_response = await self._snmp.set(
                oid_sum_type, fec_sum_type.value, Integer32
            )
            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or int(result[0]) != fec_sum_type.value:
                self.logger.error(
                    f'FEC sum type mismatch. Expected {fec_sum_type.value}, got "{result[0] if result else "None"}"'
                )
                return False

            if set_and_go:
                oid_file_enable = f"{'docsPnmCmDsOfdmFecFileEnable'}.{ofdm_idx}"
                self.logger.debug(f"Enabling FEC file capture [{oid_file_enable}] = 1")
                set_response = await self._snmp.set(oid_file_enable, 1, Integer32)
                result = Snmp_v2c.snmp_set_result_value(set_response)
                if not result or int(result[0]) != 1:
                    self.logger.error(
                        f'Failed to enable FEC capture. Expected 1, got "{result[0] if result else "None"}"'
                    )
                    return False

            self.logger.debug(
                f"Successfully configured FEC summary capture for OFDM index {ofdm_idx}"
            )
            return True

        except Exception as e:
            self.logger.exception(
                f"Exception during setDocsPnmCmDsOfdmFecSum for index {ofdm_idx}: {e}"
            )
            return False

    async def setDocsPnmCmOfdmChEstCoef(
        self, ofdm_idx: int, chan_est_file_name: str, set_and_go: bool = True
    ) -> bool:
        """
        Sets SNMP parameters for OFDM channel estimation coefficients.

        Parameters:
        - ofdm_idx (str): The OFDM index.
        - chan_est_file_name (str): The file name associated with the OFDM Channel Estimation.

        Returns:
        - bool: True if the SNMP set operations were successful, False otherwise.
        """
        try:
            oid_file_name = f"{'docsPnmCmOfdmChEstCoefFileName'}.{ofdm_idx}"
            self.logger.debug(
                f'Setting OFDM Channel Estimation File Name [{oid_file_name}] = "{chan_est_file_name}"'
            )
            set_response = await self._snmp.set(
                oid_file_name, chan_est_file_name, OctetString
            )

            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or str(result[0]) != chan_est_file_name:
                self.logger.error(
                    f'Failed to set channel estimation file name. Expected "{chan_est_file_name}", got "{result[0] if result else "None"}"'
                )
                return False

            if set_and_go:
                oid_trigger_enable = f"{'docsPnmCmOfdmChEstCoefTrigEnable'}.{ofdm_idx}"
                self.logger.debug(
                    f"Setting Channel Estimation Trigger Enable [{oid_trigger_enable}] = 1"
                )
                set_response = await self._snmp.set(
                    oid_trigger_enable, Snmp_v2c.TRUE, Integer32
                )

                result = Snmp_v2c.snmp_set_result_value(set_response)
                if not result or int(result[0]) != 1:
                    self.logger.error(
                        f'Failed to enable channel estimation trigger. Expected 1, got "{result[0] if result else "None"}"'
                    )
                    return False

            self.logger.debug(
                f'Successfully configured OFDM channel estimation for index {ofdm_idx} with file name "{chan_est_file_name}"'
            )

        except Exception as e:
            self.logger.exception(
                f"Exception occurred while setting OFDM Channel Estimation coefficients for index {ofdm_idx}: {e}"
            )
            return False

        return True

    async def setDocsPnmCmDsConstDisp(
        self,
        ofdm_idx: int,
        const_disp_name: str,
        modulation_order_offset: int = CmDsConstellationDisplayConst.MODULATION_OFFSET.value,
        number_sample_symbol: int = CmDsConstellationDisplayConst.NUM_SAMPLE_SYMBOL.value,
        set_and_go: bool = True,
    ) -> bool:
        """
        Configures SNMP parameters for the OFDM Downstream Constellation Display.

        Args:
            ofdm_idx (int): Index of the downstream OFDM channel.
            const_disp_name (str): Desired filename to store the constellation display data.
            modulation_offset (int, optional): Modulation order offset. Defaults to standard constant value.
            num_sample_symb (int, optional): Number of sample symbols. Defaults to standard constant value.
            set_and_go (bool, optional): If True, triggers immediate measurement start. Defaults to True.

        Returns:
            bool: True if all SNMP SET operations succeed; False otherwise.
        """
        try:
            # Set file name
            oid = f"{'docsPnmCmDsConstDispFileName'}.{ofdm_idx}"
            self.logger.debug(f'Setting FileName [{oid}] = "{const_disp_name}"')
            set_response = await self._snmp.set(oid, const_disp_name, OctetString)
            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or str(result[0]) != const_disp_name:
                self.logger.error(
                    f'Failed to set FileName. Expected "{const_disp_name}", got "{result[0] if result else "None"}"'
                )
                return False

            # Set modulation order offset
            oid = f"{'docsPnmCmDsConstDispModOrderOffset'}.{ofdm_idx}"
            self.logger.debug(
                f"Setting ModOrderOffset [{oid}] = {modulation_order_offset}"
            )
            set_response = await self._snmp.set(oid, modulation_order_offset, Gauge32)
            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or int(result[0]) != modulation_order_offset:
                self.logger.error(
                    f'Failed to set ModOrderOffset. Expected {modulation_order_offset}, got "{result[0] if result else "None"}"'
                )
                return False

            # Set number of sample symbols
            oid = f"{'docsPnmCmDsConstDispNumSampleSymb'}.{ofdm_idx}"
            self.logger.debug(f"Setting NumSampleSymb [{oid}] = {number_sample_symbol}")
            set_response = await self._snmp.set(oid, number_sample_symbol, Gauge32)
            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or int(result[0]) != number_sample_symbol:
                self.logger.error(
                    f'Failed to set NumSampleSymb. Expected {number_sample_symbol}, got "{result[0] if result else "None"}"'
                )
                return False

            if set_and_go:
                # Trigger measurement
                oid = f"{'docsPnmCmDsConstDispTrigEnable'}.{ofdm_idx}"
                self.logger.debug(f"Setting TrigEnable [{oid}] = 1")
                set_response = await self._snmp.set(oid, Snmp_v2c.TRUE, Integer32)
                result = Snmp_v2c.snmp_set_result_value(set_response)
                if not result or int(result[0]) != 1:
                    self.logger.error(
                        f'Failed to trigger measurement. Expected 1, got "{result[0] if result else "None"}"'
                    )
                    return False

            self.logger.debug(
                f'Successfully configured Constellation Display for OFDM index {ofdm_idx} with file name "{const_disp_name}"'
            )
            return True

        except Exception as e:
            self.logger.exception(
                f"Exception occurred while setting Constellation Display for OFDM index {ofdm_idx}: {e}"
            )
            return False

    async def setDocsCmLatencyRptCfg(
        self,
        latency_rpt_file_name: str,
        num_of_reports: int = 1,
        set_and_go: bool = True,
    ) -> bool:
        """
        Configures the CM upstream latency reporting feature. This enables
        the creation of latency report files containing per-Service Flow
        latency measurements over a defined period of time.

        Parameters:
        - latency_rpt_file_name (str): The filename to store the latency report.
        - num_of_reports (int): Number of report files to generate.

        Returns:
        - bool: True if configuration is successful, False otherwise.
        """

        mac_idx = self.getIfTypeIndex(DocsisIfType.docsCableMaclayer)[0]

        try:
            oid_file_name = f"{'docsCmLatencyRptCfgFileName'}.{mac_idx}"
            self.logger.debug(
                f'Setting US Latency Report file name [{oid_file_name}] = "{latency_rpt_file_name}"'
            )
            set_response = await self._snmp.set(
                oid_file_name, latency_rpt_file_name, OctetString
            )
            result = Snmp_v2c.snmp_set_result_value(set_response)

            if not result or str(result[0]) != latency_rpt_file_name:
                self.logger.error(
                    f'File name mismatch. Expected "{latency_rpt_file_name}", got "{result[0] if result else "None"}"'
                )
                return False

            if set_and_go:
                oid_num_reports = f"{'docsCmLatencyRptCfgNumFiles'}.{mac_idx}"
                self.logger.debug(
                    f"Setting number of latency reports [{oid_num_reports}] = {num_of_reports}"
                )
                set_response = await self._snmp.set(
                    oid_num_reports, num_of_reports, Gauge32
                )
                result = Snmp_v2c.snmp_set_result_value(set_response)

                if not result or int(result[0]) != num_of_reports:
                    self.logger.error(
                        f'Failed to enable latency report capture. Expected {num_of_reports}, got "{result[0] if result else "None"}"'
                    )
                    return False

            return True

        except Exception as e:
            self.logger.exception(f"Exception during setDocsCmLatencyRptCfg: {e}")
            return False

    async def setDocsPnmCmDsHist(
        self, ds_histogram_file_name: str, set_and_go: bool = True, timeout: int = 10
    ) -> bool:
        """
        Configure and enable downstream histogram capture for the CM MAC layer interface.

        This method performs the following steps:
        1. Retrieves the index for the `docsCableMaclayer` interface.
        2. Sets the histogram file name via Snmp_v2c.
        3. Enables histogram data capture via Snmp_v2c.

        Args:
            ds_histogram_file_name (str): The name of the file where the downstream histogram will be saved.

        Returns:
            bool: True if the file name was set and capture was successfully enabled, False otherwise.

        Logs:
            - debug: Index being used.
            - Debug: SNMP set operations for file name and capture enable.
            - Error: Mismatched response or SNMP failure.
            - Exception: Any exception that occurs during the SNMP operations.
        """
        idx_list = await self.getIfTypeIndex(DocsisIfType.docsCableMaclayer)

        if not idx_list:
            self.logger.error("No index found for docsCableMaclayer interface type.")
            return False

        if len(idx_list) > 1:
            self.logger.error(
                f"Expected a single index for docsCableMaclayer, but found multiple: {idx_list}"
            )
            return False

        idx = idx_list[0]

        self.logger.debug(f"setDocsPnmCmDsHist -> idx: {idx}")

        try:
            # TODO: Need to make this dynamic
            set_response = await self._snmp.set(
                f"{'docsPnmCmDsHistTimeOut'}.{idx}", timeout, Gauge32
            )
            self.logger.debug(f"Setting Histogram Timeout: {timeout}")

            oid_file_name = f"{'docsPnmCmDsHistFileName'}.{idx}"
            set_response = await self._snmp.set(
                oid_file_name, ds_histogram_file_name, OctetString
            )
            self.logger.debug(
                f'Setting Histogram file name [{oid_file_name}] = "{ds_histogram_file_name}"'
            )

            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or str(result[0]) != ds_histogram_file_name:
                self.logger.error(
                    f'File name mismatch. Expected "{ds_histogram_file_name}", got "{result[0] if result else "None"}"'
                )
                return False

            if set_and_go:
                oid_file_enable = f"{'docsPnmCmDsHistEnable'}.{idx}"
                set_response = await self._snmp.set(
                    oid_file_enable, Snmp_v2c.TRUE, Integer32
                )
                self.logger.debug(f"Enabling Histogram capture [{oid_file_enable}] = 1")

                result = Snmp_v2c.snmp_set_result_value(set_response)
                if not result or int(result[0]) != 1:
                    self.logger.error(
                        f'Failed to enable Histogram capture. Expected 1, got "{result[0] if result else "None"}"'
                    )
                    return False

        except Exception as e:
            self.logger.exception(
                f"Exception during setDocsPnmCmDsHist for index {idx}: {e}"
            )
            return False

        return True

    async def setDocsPnmCmDsOfdmSymTrig(
        self, ofdm_idx: int, symbol_trig_file_name: str
    ) -> bool:
        """
        Sets SNMP parameters for OFDM Downstream Symbol Capture.

        Parameters:
        - ofdm_idx (str): The OFDM index.
        - symbol_trig_file_name (str): The file name associated with the OFDM Downstream Symbol Capture

        Returns:
        - bool: True if the SNMP set operations were successful, False otherwise.
        TODO: NOT ABLE TO TEST DUE TO CMTS DOES NOT SUPPORT
        """
        try:
            oid_file_name = f"{'docsPnmCmDsOfdmSymCaptFileName'}.{ofdm_idx}"
            self.logger.debug(
                f'Setting OFDM Downstream Symbol Capture File Name [{oid_file_name}] = "{symbol_trig_file_name}"'
            )
            set_response = await self._snmp.set(
                oid_file_name, symbol_trig_file_name, OctetString
            )

            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or str(result[0]) != symbol_trig_file_name:
                self.logger.error(
                    f'Failed to set Downstream Symbol Capture file name. Expected "{symbol_trig_file_name}", got "{result[0] if result else "None"}"'
                )
                return False

            oid_trigger_enable = f"{'docsPnmCmDsConstDispTrigEnable'}.{ofdm_idx}"
            self.logger.debug(
                f"Setting OFDM Downstream Symbol Capture Trigger Enable [{oid_trigger_enable}] = 1"
            )
            set_response = await self._snmp.set(oid_trigger_enable, 1, Integer32)

            result = Snmp_v2c.snmp_set_result_value(set_response)
            if not result or int(result[0]) != 1:
                self.logger.error(
                    f'Failed to enable OFDM Downstream Symbol Capture trigger. Expected 1, got "{result[0] if result else "None"}"'
                )
                return False

            self.logger.debug(
                f'Successfully configured OFDM Downstream Symbol Capturey for index {ofdm_idx} with file name "{symbol_trig_file_name}"'
            )
            return True

        except Exception as e:
            self.logger.exception(
                f"Exception occurred while setting OFDM Downstream Symbol Capture for index {ofdm_idx}: {e}"
            )
            return False

    async def getDocsIf3CmStatusUsEqData(self) -> DocsEqualizerData:
        """
        Retrieve and parse DOCSIS 3.0/3.1 upstream equalizer data via Snmp_v2c.

        This method performs an SNMP walk on the OID corresponding to
        `docsIf3CmStatusUsEqData`, which contains the pre-equalization
        coefficient data for upstream channels.

        It parses the SNMP response into a structured `DocsEqualizerData` object.

        Returns:
            DocsEqualizerData: Parsed equalizer data including real/imaginary tap coefficients
            for each upstream channel index.
            Returns None if SNMP walk fails, no data is returned, or parsing fails.
        """
        oid = "docsIf3CmStatusUsEqData"
        try:
            result = await self._snmp.walk(oid)

        except Exception as e:
            self.logger.error(f"SNMP walk failed for {oid}: {e}")
            return DocsEqualizerData()

        if not result:
            self.logger.warning(f"No data returned from SNMP walk for {oid}.")
            return DocsEqualizerData()

        ded = DocsEqualizerData()

        try:
            for varbind in result:
                us_idx = Snmp_v2c.extract_last_oid_index([varbind])[0]
                eq_data = Snmp_v2c.snmp_get_result_value([varbind])[0]
                eq_data = Format.non_ascii_to_hex(eq_data)
                self.logger.debug(f"idx: {us_idx} -> eq-data: ({eq_data})")
                ded.add(us_idx, eq_data)

        except ValueError as e:
            self.logger.error(f"Failed to parse equalizer data. Error: {e}")
            return None

        if not ded.coefficients_found():
            self.logger.warning(
                "No upstream pre-equalization coefficients found. "
                "Ensure Pre-Equalization is enabled on the upstream interface(s)."
            )

        return ded
# FILE: src/pypnm/examples/common/common_cli.py
#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import sys
from typing import Any, Dict, TypedDict

try:
    import requests
except ImportError:
    print("The 'requests' library is not installed. Please install it before running these examples.")
    sys.exit(2)


EXIT_SUCCESS: int                      = 0
EXIT_IMPORT_ERROR: int                 = 2
EXIT_REQUEST_ERROR: int                = 3

DEFAULT_SNMP_COMMUNITY: str            = "private"
DEFAULT_BASE_URL: str                  = "http://127.0.0.1:8000"
DEFAULT_SAMPLE_TIME_ELAPSED_SEC: int   = 5
DEFAULT_HTTP_TIMEOUT_SEC: float        = 120.0

DEFAULT_TFTP_IPV4: str                 = "192.168.0.10"
DEFAULT_TFTP_IPV6: str                 = "::1"


class SnmpV2CPayload(TypedDict):
    community: str


class SnmpPayload(TypedDict):
    snmpV2C: SnmpV2CPayload


class PnmTftpPayload(TypedDict):
    ipv4: str
    ipv6: str


class PnmParametersPayload(TypedDict, total=False):
    tftp: PnmTftpPayload


class CableModemPayload(TypedDict, total=False):
    mac_address: str
    ip_address: str
    snmp: SnmpPayload
    pnm_parameters: PnmParametersPayload


class CableModemRequestPayload(TypedDict):
    cable_modem: CableModemPayload


class CaptureParametersPayload(TypedDict, total=False):
    sample_time_elapsed: int
    inactivity_timeout: int
    first_segment_center_freq: int
    last_segment_center_freq: int
    segment_freq_span: int
    num_bins_per_segment: int
    noise_bw: int
    window_function: int
    num_averages: int
    spectrum_retrieval_type: int
    number_of_averages: int


class CableModemCaptureRequestPayload(TypedDict):
    cable_modem: CableModemPayload
    capture_parameters: CaptureParametersPayload


def build_cable_modem_payload(mac: str, ip: str, community: str) -> CableModemRequestPayload:
    """
    Build The Common cable_modem Request Payload.

    This helper constructs the JSON structure shared by multiple example
    scripts. The returned payload contains the cable_modem object with the
    MAC address, IP address, and SNMP v2c community configuration.
    """
    return {
        "cable_modem": {
            "mac_address": mac,
            "ip_address": ip,
            "snmp": {
                "snmpV2C": {
                    "community": community,
                },
            },
        },
    }


def build_cable_modem_capture_payload(
    mac: str,
    ip: str,
    community: str,
    sample_time_elapsed: int,
) -> CableModemCaptureRequestPayload:
    """
    Build A cable_modem Request Payload With Capture Parameters.

    This helper extends the common cable_modem payload with a capture_parameters
    section used by measurement endpoints such as downstream SC-QAM codeword
    error rate. The sample_time_elapsed value defines the capture duration in
    seconds.
    """
    base_payload: CableModemRequestPayload = build_cable_modem_payload(mac, ip, community)
    return {
        "cable_modem": base_payload["cable_modem"],
        "capture_parameters": {
            "sample_time_elapsed": sample_time_elapsed,
        },
    }


def send_cable_modem_request(endpoint_path: str, base_url: str, mac: str, ip: str, community: str) -> int:
    """
    Send A POST Request To A PyPNM Endpoint Using The cable_modem Payload.

    The endpoint_path argument supplies the REST path, such as
    "/docs/dev/eventLog". The base_url argument defines the server root, for
    example "http://127.0.0.1:8000". A POST request is issued with the
    cable_modem payload, and the JSON response is printed when available. The
    return value is an exit status where zero indicates success and a non-zero
    value indicates a transport or HTTP error.
    """
    url: str = _join_url(base_url, endpoint_path)
    payload: CableModemRequestPayload = build_cable_modem_payload(mac, ip, community)

    print()
    print(f"Sending POST to {url} with payload:")
    print(json.dumps(payload, indent=2))

    try:
        response = requests.post(url, json=payload, timeout=DEFAULT_HTTP_TIMEOUT_SEC)
        response.raise_for_status()
    except requests.RequestException as exc:
        print()
        print("Request failed:")
        print(str(exc))
        return EXIT_REQUEST_ERROR

    print()
    print("Response:")
    try:
        print(json.dumps(response.json(), indent=2))
    except ValueError:
        print(response.text)

    return EXIT_SUCCESS


def send_cable_modem_capture_request(
    endpoint_path: str,
    base_url: str,
    mac: str,
    ip: str,
    community: str,
    sample_time_elapsed: int,
) -> int:
    """
    Send A POST Request With cable_modem And capture_parameters Payload.

    This helper is intended for measurement endpoints that require both the
    cable_modem configuration and capture_parameters, such as downstream
    SC-QAM codeword error rate. The sample_time_elapsed argument specifies the
    capture duration in seconds. A POST request is issued and the JSON
    response is printed when available. The return value is an exit status
    where zero indicates success and a non-zero value indicates a transport
    or HTTP error.
    """
    url: str = _join_url(base_url, endpoint_path)
    payload: CableModemCaptureRequestPayload = build_cable_modem_capture_payload(
        mac=mac,
        ip=ip,
        community=community,
        sample_time_elapsed=sample_time_elapsed,
    )

    print()
    print(f"Sending POST to {url} with payload:")
    print(json.dumps(payload, indent=2))

    try:
        response = requests.post(url, json=payload, timeout=DEFAULT_HTTP_TIMEOUT_SEC)
        response.raise_for_status()
    except requests.RequestException as exc:
        print()
        print("Request failed:")
        print(str(exc))
        return EXIT_REQUEST_ERROR

    print()
    print("Response:")
    try:
        print(json.dumps(response.json(), indent=2))
    except ValueError:
        print(response.text)

    return EXIT_SUCCESS


def send_cable_modem_pnm_and_analysis_request(
    endpoint_path: str,
    base_url: str,
    mac: str,
    ip: str,
    community: str,
    tftp_ipv4: str | None,
    tftp_ipv6: str | None,
    analysis: Dict[str, Any],
    capture_parameters: Dict[str, Any] | None = None,
) -> int:
    """
    Send A POST Request With cable_modem, pnm_parameters, analysis, And Optional capture_parameters.

    This helper is intended for PNM endpoints that require:
      * cable_modem configuration
      * pnm_parameters.tftp (IPv4 / IPv6)
      * analysis configuration (type, output, plot, etc.)
      * optional capture_parameters

    The endpoint_path argument supplies the REST path, such as
    "/docs/pnm/ds/histogram/getCapture". The base_url argument defines the
    server root, for example "http://127.0.0.1:8000".
    """
    url: str = _join_url(base_url, endpoint_path)

    base_payload: CableModemRequestPayload = build_cable_modem_payload(mac, ip, community)

    tftp_ipv4_value = tftp_ipv4 if tftp_ipv4 and tftp_ipv4.strip() else None
    tftp_ipv6_value = tftp_ipv6 if tftp_ipv6 and tftp_ipv6.strip() else None

    body: Dict[str, Any] = {
        "cable_modem": {
            **base_payload["cable_modem"],
            "pnm_parameters": {
                "tftp": {
                    "ipv4": tftp_ipv4_value,
                    "ipv6": tftp_ipv6_value,
                },
            },
        },
        "analysis": analysis,
    }

    if capture_parameters is not None:
        body["capture_parameters"] = capture_parameters

    print()
    print(f"Sending POST to {url} with payload:")
    print(json.dumps(body, indent=2))

    try:
        response = requests.post(url, json=body, timeout=DEFAULT_HTTP_TIMEOUT_SEC)
        response.raise_for_status()
    except requests.RequestException as exc:
        print()
        print("Request failed:")
        print(str(exc))
        return EXIT_REQUEST_ERROR

    print()
    print("Response:")
    try:
        print(json.dumps(response.json(), indent=2))
    except ValueError:
        print(response.text)

    return EXIT_SUCCESS


def _join_url(base_url: str, endpoint_path: str) -> str:
    """
    Join Base URL And Endpoint Path Into A Single URL String.
    """
    base: str = base_url.rstrip("/")
    path: str = endpoint_path.lstrip("/")
    return f"{base}/{path}"
# FILE: src/pypnm/lib/secret/crypto_manager.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import base64
import contextlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class SecretCryptoError(Exception):
    """
    Secret Encryption/Decryption Failure.

    Raised when a secret cannot be encrypted or decrypted due to missing keys,
    invalid token formats, permission problems, or cryptographic validation
    failures.
    """


@dataclass(frozen=True, slots=True)
class SecretToken:
    """
    Versioned Encrypted Secret Token.

    Attributes
    ----------
    version:
        Token version string (example: "v1").
    payload:
        The encrypted payload (Fernet token string).
    """

    version: str
    payload: str


class SecretCryptoManager:
    """
    Secret Encryption Manager For Config-Stored Passwords.

    This class supports storing encrypted passwords inside JSON configuration
    (example: system.json) while keeping the decryption key outside the repo,
    typically in the user's ~/.ssh directory.

    Security Model
    --------------
    - The encrypted password may safely live in the config file.
    - The decrypt key MUST NOT live in the config file or repo.
    - The decrypt key is loaded from one of:
      1) A key file (default: ~/.ssh/pypnm_secrets.key)
      2) An environment variable (default: PYPNM_SECRET_KEY)

    Token Format
    ------------
    Tokens are stored as:

        ENC[v1]:<fernet-token>

    Where <fernet-token> is a URL-safe base64 encoded token produced by Fernet.

    Notes
    -----
    Fernet provides authenticated encryption (confidentiality + integrity). If a
    token is altered, decryption will fail with an integrity error.
    """

    DEFAULT_ENV_VAR_NAME = "PYPNM_SECRET_KEY"
    DEFAULT_KEY_FILE_NAME = "pypnm_secrets.key"
    DEFAULT_TOKEN_VERSION = "v1"
    DEFAULT_TOKEN_PREFIX = "ENC"
    SSH_DIR_NAME = ".ssh"

    FERNET_KEY_SIZE_BYTES = 32

    KEY_FILE_PERMISSIONS = 0o600
    SSH_DIR_PERMISSIONS = 0o700

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @staticmethod
    def default_key_path() -> Path:
        """
        Return The Default Key File Path Under ~/.ssh.

        Returns
        -------
        Path
            The default key file path: ~/.ssh/pypnm_secrets.key
        """
        home_dir = Path.home()
        return (
            home_dir
            / SecretCryptoManager.SSH_DIR_NAME
            / SecretCryptoManager.DEFAULT_KEY_FILE_NAME
        )

    @staticmethod
    def build_token(payload: str, version: str = DEFAULT_TOKEN_VERSION) -> str:
        """
        Build A Versioned Token String.

        Parameters
        ----------
        payload:
            Fernet token string (URL-safe base64).
        version:
            Token version (default: "v1").

        Returns
        -------
        str
            Versioned token string in format: ENC[vX]:<payload>
        """
        return f"{SecretCryptoManager.DEFAULT_TOKEN_PREFIX}[{version}]:{payload}"

    @staticmethod
    def parse_token(token: str) -> SecretToken:
        """
        Parse A Versioned Token String.

        Parameters
        ----------
        token:
            Token string in format: ENC[vX]:<payload>

        Returns
        -------
        SecretToken
            Parsed token components.

        Raises
        ------
        SecretCryptoError
            If the token is malformed or missing required parts.
        """
        prefix = f"{SecretCryptoManager.DEFAULT_TOKEN_PREFIX}["
        if not token.startswith(prefix):
            raise SecretCryptoError(
                "Encrypted token missing expected 'ENC[...]:...' prefix."
            )

        end_bracket_index = token.find("]:")
        if end_bracket_index < 0:
            raise SecretCryptoError("Encrypted token missing closing ']:' delimiter.")

        version = token[len(prefix) : end_bracket_index].strip()
        if version == "":
            raise SecretCryptoError("Encrypted token version is empty.")

        payload = token[end_bracket_index + 2 :].strip()
        if payload == "":
            raise SecretCryptoError("Encrypted token payload is empty.")

        return SecretToken(version=version, payload=payload)

    @staticmethod
    def generate_key_b64() -> str:
        """
        Generate A New Fernet Key As A Base64 String.

        Returns
        -------
        str
            URL-safe base64 encoded key string.
        """
        key_bytes = Fernet.generate_key()
        return key_bytes.decode("utf-8")

    @staticmethod
    def write_key_file(key_path: Path, key_b64: str) -> Path:
        """
        Write A Fernet Key To Disk With Tight Permissions.

        Parameters
        ----------
        key_path:
            Path to write the key file (example: ~/.ssh/pypnm_secrets.key).
        key_b64:
            Fernet key (URL-safe base64 string).

        Returns
        -------
        Path
            The key_path written.

        Raises
        ------
        SecretCryptoError
            If the key is invalid or cannot be written securely.
        """
        SecretCryptoManager.validate_key_b64(key_b64)
        ssh_dir = key_path.parent
        ssh_dir.mkdir(parents=True, exist_ok=True)

        with contextlib.suppress(OSError):
            os.chmod(ssh_dir, SecretCryptoManager.SSH_DIR_PERMISSIONS)

        key_path.write_text(key_b64.strip() + "\n", encoding="utf-8")

        with contextlib.suppress(OSError):
            os.chmod(key_path, SecretCryptoManager.KEY_FILE_PERMISSIONS)

        return key_path

    @staticmethod
    def validate_key_b64(key_b64: str) -> None:
        """
        Validate A Fernet Key String.

        Parameters
        ----------
        key_b64:
            Fernet key as a URL-safe base64 string.

        Raises
        ------
        SecretCryptoError
            If the key is invalid.
        """
        key_str = key_b64.strip()
        if key_str == "":
            raise SecretCryptoError("Secret key is empty.")

        try:
            raw = base64.urlsafe_b64decode(key_str.encode("utf-8"))
        except Exception as exc:
            raise SecretCryptoError(f"Secret key is not valid base64: {exc}") from exc

        if len(raw) != SecretCryptoManager.FERNET_KEY_SIZE_BYTES:
            raise SecretCryptoError(
                f"Secret key decoded size is invalid: {len(raw)} bytes (expected {SecretCryptoManager.FERNET_KEY_SIZE_BYTES})."
            )

        try:
            Fernet(key_str.encode("utf-8"))
        except Exception as exc:
            raise SecretCryptoError(
                f"Secret key is not a valid Fernet key: {exc}"
            ) from exc

    @staticmethod
    def load_key_bytes(
        key_path: Path, env_var_name: str = DEFAULT_ENV_VAR_NAME
    ) -> bytes:
        """
        Load Secret Key Bytes From Key File Or Environment Variable.

        Resolution Order
        ----------------
        1) key_path file
        2) env var env_var_name

        Parameters
        ----------
        key_path:
            Path to the key file (example: ~/.ssh/pypnm_secrets.key).
        env_var_name:
            Environment variable name to use as fallback (default: PYPNM_SECRET_KEY).

        Returns
        -------
        bytes
            Fernet key bytes.

        Raises
        ------
        SecretCryptoError
            If no key source is available or if the key is invalid.
        """
        if key_path.exists() and key_path.is_file():
            key_b64 = key_path.read_text(encoding="utf-8").strip()
            SecretCryptoManager.validate_key_b64(key_b64)
            return key_b64.encode("utf-8")

        env_value = os.environ.get(env_var_name, "").strip()
        if env_value != "":
            SecretCryptoManager.validate_key_b64(env_value)
            return env_value.encode("utf-8")

        raise SecretCryptoError(
            f"Missing secret key. Provide key file '{key_path}' or set environment variable '{env_var_name}'."
        )

    @staticmethod
    def encrypt_password(
        password: str,
        key_path: Path | None = None,
        env_var_name: str = DEFAULT_ENV_VAR_NAME,
        version: str = DEFAULT_TOKEN_VERSION,
    ) -> str:
        """
        Encrypt A Password For Storage In system.json.

        Parameters
        ----------
        password:
            Plaintext password to encrypt.
        key_path:
            Key file path. If empty, defaults to ~/.ssh/pypnm_secrets.key
        env_var_name:
            Environment variable for key fallback (default: PYPNM_SECRET_KEY).
        version:
            Token version label (default: "v1").

        Returns
        -------
        str
            Versioned token string in format: ENC[vX]:<payload>

        Raises
        ------
        SecretCryptoError
            If encryption fails due to missing/invalid key or invalid input.
        """
        password_str = password.strip()
        if password_str == "":
            raise SecretCryptoError(
                "Password is empty; refusing to encrypt empty value."
            )

        actual_key_path = (
            key_path if key_path is not None else SecretCryptoManager.default_key_path()
        )
        key_bytes = SecretCryptoManager.load_key_bytes(
            actual_key_path, env_var_name=env_var_name
        )
        fernet = Fernet(key_bytes)

        token_bytes = fernet.encrypt(password_str.encode("utf-8"))
        token_str = token_bytes.decode("utf-8")

        return SecretCryptoManager.build_token(payload=token_str, version=version)

    @staticmethod
    def decrypt_password(
        token: str,
        key_path: Path | None = None,
        env_var_name: str = DEFAULT_ENV_VAR_NAME,
        accepted_versions: tuple[str, ...] = (DEFAULT_TOKEN_VERSION,),
    ) -> str:
        """
        Decrypt A Password Token From system.json.

        Parameters
        ----------
        token:
            Versioned token string in format: ENC[vX]:<payload>
        key_path:
            Key file path. If empty, defaults to ~/.ssh/pypnm_secrets.key
        env_var_name:
            Environment variable for key fallback (default: PYPNM_SECRET_KEY).
        accepted_versions:
            Allowed token versions (default: ("v1",)).

        Returns
        -------
        str
            Decrypted plaintext password.

        Raises
        ------
        SecretCryptoError
            If decryption fails due to invalid token, missing key, wrong key,
            unsupported token version, or integrity/authentication failure.
        """
        token_str = token.strip()
        parsed = SecretCryptoManager.parse_token(token_str)
        version_supported = parsed.version in accepted_versions

        if not version_supported:
            raise SecretCryptoError(
                f"Unsupported encrypted token version '{parsed.version}'. Allowed: {', '.join(accepted_versions)}"
            )

        actual_key_path = (
            key_path if key_path is not None else SecretCryptoManager.default_key_path()
        )
        key_bytes = SecretCryptoManager.load_key_bytes(
            actual_key_path, env_var_name=env_var_name
        )
        fernet = Fernet(key_bytes)

        try:
            clear_bytes = fernet.decrypt(parsed.payload.encode("utf-8"))
        except InvalidToken as exc:
            raise SecretCryptoError(
                "Failed to decrypt password: invalid token or wrong secret key."
            ) from exc

        clear_str = clear_bytes.decode("utf-8").strip()
        if clear_str == "":
            raise SecretCryptoError(
                "Decrypted password is empty; token or key may be invalid."
            )

        return clear_str

    @staticmethod
    def encrypt_system_config_secrets(config: dict[str, Any]) -> dict[str, Any]:
        """
        Encrypt System Config Secrets In-Place Semantics (Returns Updated Copy).

        Contract
        --------
        - Never persist a 'password' key.
        - If a password exists (from 'password' or 'password_enc'), store it as
          encrypted token in 'password_enc' (ENC[...]).
        - If password is empty, keep 'password_enc' as "" and still remove 'password'.
        - SCP is not handled here (removed as an option); this function only enforces
          secret storage semantics for configured methods.
        """
        pnm = config.get("PnmFileRetrieval", {})
        retrieval = pnm.get("retrieval_method")
        if not isinstance(retrieval, dict):
            legacy = pnm.get("retrival_method")
            retrieval = legacy if isinstance(legacy, dict) else {}
        methods = retrieval.get("methods", {})

        if not isinstance(methods, dict):
            return config

        for method_cfg in methods.values():
            if not isinstance(method_cfg, dict):
                continue

            password_enc = str(method_cfg.get("password_enc", "") or "").strip()
            password = str(method_cfg.get("password", "") or "").strip()

            token_source = password_enc if password_enc != "" else password

            if token_source == "":
                method_cfg.pop("password", None)
                method_cfg["password_enc"] = ""
                continue

            if token_source.startswith("ENC["):
                method_cfg["password_enc"] = token_source
            else:
                method_cfg["password_enc"] = SecretCryptoManager.encrypt_password(
                    token_source
                )

            method_cfg.pop("password", None)

        return config
# FILE: src/pypnm/tools/qa_checker.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import subprocess
import sys


Command = tuple[str, list[str]]


def _run_command(label: str, cmd: list[str]) -> int:
    """
    Run A Single QA Tool Command And Stream Its Output.

    Parameters
    ----------
    label : str
        Human-readable label for the tool (e.g., "ruff", "pyright").
    cmd : Sequence[str]
        The command and arguments to execute.

    Returns
    -------
    int
        The process return code (0 on success, non-zero on failure).
    """
    print(f"\n=== [{label}] running: {' '.join(cmd)} ===", flush=True)
    try:
        proc = subprocess.run(cmd, check=False)
        if proc.returncode == 0:
            print(f"=== [{label}] OK ===", flush=True)
        else:
            print(f"=== [{label}] FAILED (exit code {proc.returncode}) ===", flush=True)
        return proc.returncode
    except FileNotFoundError:
        print(f"=== [{label}] NOT FOUND on PATH ===", flush=True)
        return 127


def _build_commands(include_pyright: bool, pytest_args: list[str]) -> list[Command]:
    """
    Build The Ordered List Of QA Commands To Run.

    Parameters
    ----------
    include_pyright : bool
        If True, include a `pyright` static type-check step after Ruff.
    pytest_args : Sequence[str]
        Additional arguments to pass through to pytest (for example, via
        the CLI separator ``--``).

    Returns
    -------
    list[Command]
        Ordered list of (label, cmd) tuples to execute.
    """
    python_cmd = sys.executable or "python"
    commands: list[Command] = [
        ("secrets", ["./tools/security/scan-secrets.sh"]),
        ("enc-secrets", [python_cmd, "./tools/security/scan-enc-secrets.py"]),
        ("macs", ["./tools/security/scan-mac-addresses.py", "--fail-on-found"]),
        ("headers", [python_cmd, "./tools/maintenance/add-required-python-headers.py"]),
        ("ruff", ["ruff", "check", "src"]),
    ]

    if include_pyright:
        # Insert Pyright after Ruff but before loop nesting and pytest for faster feedback.
        commands.append(("pyright", ["pyright"]))

    commands.append(("loop-nesting", [python_cmd, "-m", "pypnm.tools.loop_nesting_checker", "src"]))
    commands.append(("pytest", ["pytest", *pytest_args]))

    return commands


def main() -> None:
    """
    Run The Standard PyPNM Software QA Suite.

    Default Behavior
    ----------------
    By default, this helper aggregates the core quality checks configured for
    the project:

    1) secrets             - secret scanning via ./tools/security/scan-secrets.sh
                             (gitleaks + .gitleaks.toml if available).
    2) enc-secrets         - encrypted password pattern scan (ENC[v1] + password_enc).
    3) macs                - repository scan for non-approved MAC addresses.
    4) headers             - ensure SPDX/license headers (./tools/maintenance/add-required-python-headers.py).
    5) ruff check src      - syntax, style, and common bug patterns.
    6) loop nesting        - ensure no function exceeds 3+ nested loops.
    7) pytest              - unit tests (pytest options from pyproject.toml).

    Optional Pyright
    ----------------
    To enable static type checking with Pyright, pass the flag:

        pypnm-software-qa-checker --with-pyright

    This will run an additional step:

    - pyright              - static type analysis using [tool.pyright] settings,
                             executed after Ruff but before loop nesting and pytest.

    Passing Extra Pytest Arguments
    ------------------------------
    To pass additional arguments directly to pytest, use ``--`` as a separator.
    Any arguments after ``--`` are forwarded only to pytest. For example:

        pypnm-software-qa-checker --with-pyright -- -k \"fast\" --maxfail=1

    In this example, pytest will be invoked as:

        pytest -k \"fast\" --maxfail=1

    The process exit code is non-zero if any check fails.
    """
    raw_args = sys.argv[1:]

    pytest_args: list[str] = []
    qa_args: list[str] = raw_args

    if "--" in raw_args:
        sep_index = raw_args.index("--")
        qa_args = raw_args[:sep_index]
        pytest_args = raw_args[sep_index + 1 :]

    include_pyright = "--with-pyright" in qa_args
    filtered_qa_args = [a for a in qa_args if a != "--with-pyright"]

    # Preserve a minimal sys.argv for any downstream libraries that inspect it.
    sys.argv = [sys.argv[0], *filtered_qa_args]

    commands = _build_commands(include_pyright=include_pyright, pytest_args=pytest_args)

    overall_rc = 0
    for label, cmd in commands:
        rc = _run_command(label, cmd)
        if rc != 0 and overall_rc == 0:
            overall_rc = rc

    print("\n=== PyPNM Software QA Suite Finished ===", flush=True)
    if overall_rc == 0:
        print("All checks passed.", flush=True)
    else:
        print(f"One or more checks failed (exit code {overall_rc}).", flush=True)

    sys.exit(overall_rc)


if __name__ == "__main__":
    main()
# FILE: src/pypnm/tools/system_config/__init__.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

"""PyPNM system configuration tools (packaged)."""
from __future__ import annotations

# FILE: tests/test_complex_array_ops.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_complex_array_ops.py
from __future__ import annotations

import math

import numpy as np
import pytest

from pypnm.lib.signal_processing.complex_array_ops import ComplexArrayOps


def pairs(*vals: float) -> list[tuple[float, float]]:
    """Build (re, im) pairs from flat numbers: r1,i1,r2,i2,..."""
    assert len(vals) % 2 == 0
    it = iter(vals)
    return [(float(r), float(i)) for r, i in zip(it, it, strict=False)]


def test_init_and_len_and_repr() -> None:
    x = pairs(1, 0, 0, 1, -1, 0)
    ops = ComplexArrayOps(x)
    assert len(ops) == 3
    r = repr(ops)
    assert "ComplexArrayOps" in r
    assert "RMS=" in r and "MeanPwr=" in r


def test_invalid_shape_raises() -> None:
    with pytest.raises(ValueError):
        ComplexArrayOps([(1.0,)] * 2)
    with pytest.raises(ValueError):
        ComplexArrayOps([])


def test_as_array_and_to_pairs_roundtrip() -> None:
    x = pairs(1, 2, 3, 4, -5, 0)
    ops = ComplexArrayOps(x)
    arr = ops.as_array()
    assert arr.dtype == np.complex128
    assert np.allclose(arr.real, [1, 3, -5])
    assert np.allclose(arr.imag, [2, 4, 0])

    back = ops.to_pairs()
    assert back == x


def test_magnitude_power_and_db() -> None:
    x = pairs(3, 4, 0, 0)
    ops = ComplexArrayOps(x)

    mag = ops.magnitude()
    pwr = ops.power()
    pwr_db = ops.power_db()

    assert np.allclose(mag, [5.0, 0.0])
    assert np.allclose(pwr, [25.0, 0.0])

    assert np.isfinite(pwr_db[1])
    assert pwr_db[0] > pwr_db[1]


def test_phase_and_unwrap() -> None:
    # With default discont=π, unwrap does NOT add 2π for jump exactly π
    x = pairs(1, 0, -1, 0, 1, 0)
    ops = ComplexArrayOps(x)
    ph = ops.phase()
    ph_u = ops.phase(unwrap=True)

    assert np.allclose(ph, [0.0, np.pi, 0.0])
    assert np.allclose(ph_u, [0.0, np.pi, 0.0])


def test_rms_and_mean_power_with_mask() -> None:
    x = pairs(1, 0, 0, 2, 0, 0)  # powers: 1, 4, 0 → mean=5/3
    ops = ComplexArrayOps(x)

    assert ops.mean_power() == pytest.approx(5.0 / 3.0, abs=1e-12)
    assert ops.rms() == pytest.approx(math.sqrt(5.0 / 3.0), abs=1e-12)

    mask = np.array([True, False, True])
    assert ops.mean_power(mask=mask) == pytest.approx(0.5, abs=1e-12)
    assert ops.rms(mask=mask) == pytest.approx(math.sqrt(0.5), abs=1e-12)

    with pytest.raises(ValueError):
        ops.mean_power(mask=[True])


def test_conjugate_and_scale() -> None:
    x = pairs(1, -2, -3, 4)
    ops = ComplexArrayOps(x)

    conj = ops.conj()
    assert np.allclose(conj.as_array(), np.conjugate(ops.as_array()))
    assert not np.shares_memory(conj.as_array(), ops.as_array())

    scaled = ops.scale(2.0 - 1.0j)
    assert np.allclose(scaled.as_array(), (2.0 - 1.0j) * ops.as_array())

    def test_reciprocal_exact_and_eps() -> None:
        x = pairs(1, 0, 0, 1, 0, 0)
        ops = ComplexArrayOps(x)

        inv = ops.reciprocal()

        # Silence intentional divide-by-zero for the zero sample
        with np.errstate(divide="ignore", invalid="ignore"):
            target = 1.0 / ops.as_array()  # inf+nanj for the last zero sample

        assert np.allclose(inv.as_array(), target, equal_nan=True)

        inv_eps = ops.reciprocal(eps=1e-9)
        assert np.isfinite(inv_eps.as_array()[-1])
        assert np.allclose(inv_eps.as_array()[:-1], target[:-1], rtol=1e-12, atol=1e-12)


def test_normalize_rms_global_and_masked() -> None:
    x = pairs(3, 4, 0, 0)  # RMS = 5/sqrt(2)
    ops = ComplexArrayOps(x)

    target = 1.0
    norm = ops.normalize_rms(target=target)
    assert norm.rms() == pytest.approx(target, abs=1e-12)

    mask = np.array([True, False])
    norm_m = ops.normalize_rms(target=2.0, mask=mask)
    assert norm_m.rms(mask=mask) == pytest.approx(2.0, abs=1e-12)


def test_fft_ifft_roundtrip() -> None:
    x = np.zeros((8, 2), dtype=float)
    x[0] = (1.0, 0.0)
    ops = ComplexArrayOps([tuple(row) for row in x])

    X = ops.fft()
    x_rt = X.ifft()
    assert np.allclose(x_rt.as_array(), ops.as_array(), atol=1e-12)


def test_real_imag_accessors() -> None:
    x = pairs(1.2, -3.4, 5.6, 7.8)
    ops = ComplexArrayOps(x)
    assert np.allclose(ops.real(), [1.2, 5.6])
    assert np.allclose(ops.imag(), [-3.4, 7.8])


def test_copy_is_independent() -> None:
    x = pairs(1, 2, 3, 4)
    ops = ComplexArrayOps(x)
    cpy = ops.copy()
    assert np.allclose(cpy.as_array(), ops.as_array())
    cpy_scaled = cpy.scale(2.0)
    assert np.allclose(ops.as_array(), np.array([1 + 2j, 3 + 4j], dtype=np.complex128))
    assert np.allclose(cpy_scaled.as_array(), 2.0 * cpy.as_array())
# FILE: tests/test_docs_pnm_chan_est_entry_casts.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.cm_snmp_operation import MeasStatusType
from pypnm.docsis.data_type.pnm.DocsPnmCmOfdmChanEstCoefEntry import (
    DocsPnmCmOfdmChanEstCoefEntry,
    DocsPnmCmOfdmChanEstCoefFields,
)
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, idx: int, table: dict[str, object]) -> None:
        self._idx, self._t = idx, table

    async def get(self, oq: str) -> object | None:
        sym, _, sfx = oq.rpartition(".")
        assert int(sfx) == self._idx
        # return None if the OID isn't present (simulate missing field)
        return self._t.get(sym)


@pytest.mark.asyncio
async def test_chan_est_from_snmp_scaling_and_types(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 11
    fake = _FakeSnmp(
        idx,
        {
            "docsPnmCmOfdmChEstCoefTrigEnable": 1,  # -> True
            "docsPnmCmOfdmChEstCoefAmpRipplePkToPk": 3323,  # -> 33.23
            "docsPnmCmOfdmChEstCoefAmpRippleRms": 631,  # -> 6.31
            "docsPnmCmOfdmChEstCoefAmpSlope": 92,  # -> 0.92
            "docsPnmCmOfdmChEstCoefGrpDelayRipplePkToPk": 7,  # int
            "docsPnmCmOfdmChEstCoefGrpDelayRippleRms": 5,  # int
            "docsPnmCmOfdmChEstCoefMeasStatus": 4,  # -> "sample_ready"
            "docsPnmCmOfdmChEstCoefFileName": "chan_est.bin",
            "docsPnmCmOfdmChEstCoefAmpMean": 4288,  # -> 42.88
            "docsPnmCmOfdmChEstCoefGrpDelaySlope": 3,  # int
            "docsPnmCmOfdmChEstCoefGrpDelayMean": 12,  # int
        },
    )

    e = await DocsPnmCmOfdmChanEstCoefEntry.from_snmp(idx, fake)  # type: ignore[arg-type]
    assert e.index == idx and e.channel_id == idx
    f: DocsPnmCmOfdmChanEstCoefFields = e.entry

    assert f.docsPnmCmOfdmChEstCoefTrigEnable is True
    assert f.docsPnmCmOfdmChEstCoefMeasStatus == str(
        MeasStatusType(4)
    )  # "sample_ready"
    assert f.docsPnmCmOfdmChEstCoefFileName == "chan_est.bin"

    assert f.docsPnmCmOfdmChEstCoefAmpRipplePkToPk == pytest.approx(33.23, abs=0.0)
    assert f.docsPnmCmOfdmChEstCoefAmpRippleRms == pytest.approx(6.31, abs=0.0)
    assert f.docsPnmCmOfdmChEstCoefAmpSlope == pytest.approx(0.92, abs=0.0)
    assert f.docsPnmCmOfdmChEstCoefAmpMean == pytest.approx(42.88, abs=0.0)

    assert f.docsPnmCmOfdmChEstCoefGrpDelayRipplePkToPk == 7
    assert f.docsPnmCmOfdmChEstCoefGrpDelayRippleRms == 5
    assert f.docsPnmCmOfdmChEstCoefGrpDelaySlope == 3
    assert f.docsPnmCmOfdmChEstCoefGrpDelayMean == 12


@pytest.mark.asyncio
async def test_chan_est_missing_field_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))
    idx = 2
    fake = _FakeSnmp(
        idx,
        {
            "docsPnmCmOfdmChEstCoefTrigEnable": 1,
            "docsPnmCmOfdmChEstCoefAmpRipplePkToPk": 100,  # 1.00
            "docsPnmCmOfdmChEstCoefAmpRippleRms": 200,  # 2.00
            "docsPnmCmOfdmChEstCoefAmpSlope": 50,  # 0.50
            "docsPnmCmOfdmChEstCoefGrpDelayRipplePkToPk": 1,
            "docsPnmCmOfdmChEstCoefGrpDelayRippleRms": 1,
            "docsPnmCmOfdmChEstCoefMeasStatus": 3,
            "docsPnmCmOfdmChEstCoefFileName": "x.bin",
            # "docsPnmCmOfdmChEstCoefAmpMean": MISSING -> should raise
            "docsPnmCmOfdmChEstCoefGrpDelaySlope": 1,
            "docsPnmCmOfdmChEstCoefGrpDelayMean": 1,
        },
    )
    with pytest.raises(ValueError):
        await DocsPnmCmOfdmChanEstCoefEntry.from_snmp(idx, fake)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_chan_est_get_empty_indices_returns_empty_list() -> None:
    out = await DocsPnmCmOfdmChanEstCoefEntry.get(snmp=None, indices=[])  # type: ignore[arg-type]
    assert out == []
# FILE: tests/test_docs_pnm_rxmer_entry_casts.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_docs_pnm_rxmer_entry_casts.py
from __future__ import annotations

import pytest

from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmRxMerEntry import (
    DocsPnmCmDsOfdmRxMerEntry,
    DocsPnmCmDsOfdmRxMerFields,
    MeasStatusType,  # enum whose str() returns the lowercase name
)
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, idx: int, table: dict[str, object]) -> None:
        self._idx = idx
        self._t = table

    async def get(self, oq: str) -> object:
        sym, _, sfx = oq.rpartition(".")
        assert int(sfx) == self._idx
        return self._t[sym]


@pytest.mark.asyncio
async def test_from_snmp_scaling_and_types(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Happy-path test:
      • get_result_value is pass-through
      • integer fixed-point fields scale by /100.0
      • status is mapped to its lowercase string name
      • frequency is left as plain integer-ish Hz
    """
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 7
    fake = _FakeSnmp(
        idx,
        {
            "docsPnmCmDsOfdmRxMerFileEnable": 1,
            "docsPnmCmDsOfdmRxMerMeasStatus": 4,  # -> "sample_ready"
            "docsPnmCmDsOfdmRxMerFileName": "ds_ofdm_rxmer.bin",
            "docsPnmCmDsOfdmRxMerPercentile": 2,  # -> 0.02
            "docsPnmCmDsOfdmRxMerMean": 3323,  # -> 33.23
            "docsPnmCmDsOfdmRxMerStdDev": 631,  # -> 6.31
            "docsPnmCmDsOfdmRxMerThrVal": 92,  # -> 0.92
            "docsPnmCmDsOfdmRxMerThrHighestFreq": 314_800_000,  # -> 314800000
        },
    )

    e = await DocsPnmCmDsOfdmRxMerEntry.from_snmp(idx, fake)  # type: ignore[arg-type]
    assert e.index == idx and e.channel_id == idx
    f: DocsPnmCmDsOfdmRxMerFields = e.entry

    assert f.docsPnmCmDsOfdmRxMerFileEnable is True
    assert f.docsPnmCmDsOfdmRxMerMeasStatus == "sample_ready"  # string name now
    assert f.docsPnmCmDsOfdmRxMerFileName == "ds_ofdm_rxmer.bin"

    assert f.docsPnmCmDsOfdmRxMerPercentile == pytest.approx(0.02, abs=0.0)
    assert f.docsPnmCmDsOfdmRxMerMean == pytest.approx(33.23, abs=0.0)
    assert f.docsPnmCmDsOfdmRxMerStdDev == pytest.approx(6.31, abs=0.0)
    assert f.docsPnmCmDsOfdmRxMerThrVal == pytest.approx(0.92, abs=0.0)

    # Frequency Hz remains an integer-ish value (typed alias), compare numerically
    assert f.docsPnmCmDsOfdmRxMerThrHighestFreq == pytest.approx(314_800_000, abs=0.0)


@pytest.mark.asyncio
async def test_from_snmp_missing_required_fields_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Since the entry class enforces non-optional fields, missing any of them should raise ValueError.
    Here we omit several fields and verify the error message lists them.
    """
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 1
    # Missing file_name + all float fields → should raise
    fake = _FakeSnmp(
        idx,
        {
            "docsPnmCmDsOfdmRxMerFileEnable": 0,
            "docsPnmCmDsOfdmRxMerMeasStatus": 3,  # "busy"
            # "docsPnmCmDsOfdmRxMerFileName": ... MISSING ...
            # float-ish fields MISSING:
            # "docsPnmCmDsOfdmRxMerPercentile"
            # "docsPnmCmDsOfdmRxMerMean"
            # "docsPnmCmDsOfdmRxMerStdDev"
            # "docsPnmCmDsOfdmRxMerThrVal"
            "docsPnmCmDsOfdmRxMerThrHighestFreq": 100_000_000,
        },
    )

    with pytest.raises(ValueError) as exc:
        await DocsPnmCmDsOfdmRxMerEntry.from_snmp(idx, fake)  # type: ignore[arg-type]

    msg = str(exc.value)
    # Ensure the expected keys are called out
    for missing_key in ("file_name", "perc", "mean", "stddev", "thr_val"):
        assert missing_key in msg


@pytest.mark.asyncio
async def test_get_empty_indices_returns_empty_list() -> None:
    out = await DocsPnmCmDsOfdmRxMerEntry.get(snmp=None, indices=[])  # type: ignore[arg-type]
    assert out == []


@pytest.mark.parametrize(
    "code, expected",
    [
        (1, "other"),
        (2, "inactive"),
        (3, "busy"),
        (4, "sample_ready"),
        (5, "error"),
        (6, "resource_unavailable"),
        (7, "sample_truncated"),
        (8, "interface_modification"),
    ],
)
def test_status_enum_string_names(code: int, expected: str) -> None:
    # Sanity-check the enum-to-string behavior used by the entry class
    assert str(MeasStatusType(code)) == expected


@pytest.mark.asyncio
async def test_debug_toggle_does_not_break(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Flip the ClassVar DEBUG flag to True and run a fetch to ensure no exceptions are thrown
    (we're not asserting logs here, just that it still works).
    """
    monkeypatch.setattr(Snmp_v2c, "get_result_value", staticmethod(lambda x: x))

    idx = 2
    fake = _FakeSnmp(
        idx,
        {
            "docsPnmCmDsOfdmRxMerFileEnable": 1,
            "docsPnmCmDsOfdmRxMerMeasStatus": 2,  # "inactive"
            "docsPnmCmDsOfdmRxMerFileName": "foo.bin",
            "docsPnmCmDsOfdmRxMerPercentile": 10,  # -> 0.10
            "docsPnmCmDsOfdmRxMerMean": 1234,  # -> 12.34
            "docsPnmCmDsOfdmRxMerStdDev": 5,  # -> 0.05
            "docsPnmCmDsOfdmRxMerThrVal": 200,  # -> 2.00
            "docsPnmCmDsOfdmRxMerThrHighestFreq": 765_000_000,
        },
    )

    # flip DEBUG on for the class during this test
    prev = DocsPnmCmDsOfdmRxMerEntry.DEBUG
    DocsPnmCmDsOfdmRxMerEntry.DEBUG = True
    try:
        e = await DocsPnmCmDsOfdmRxMerEntry.from_snmp(idx, fake)  # type: ignore[arg-type]
        f = e.entry
        assert f.docsPnmCmDsOfdmRxMerMeasStatus == "inactive"
        assert f.docsPnmCmDsOfdmRxMerPercentile == pytest.approx(0.10, abs=0.0)
        assert f.docsPnmCmDsOfdmRxMerMean == pytest.approx(12.34, abs=0.0)
        assert f.docsPnmCmDsOfdmRxMerStdDev == pytest.approx(0.05, abs=0.0)
        assert f.docsPnmCmDsOfdmRxMerThrVal == pytest.approx(2.00, abs=0.0)
        assert f.docsPnmCmDsOfdmRxMerThrHighestFreq == 765_000_000
    finally:
        DocsPnmCmDsOfdmRxMerEntry.DEBUG = prev
# FILE: tests/test_echo_detector.py
# test_echo_detector.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

# Import your detector from its project path
from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.echo_detector import (
    EchoDetector,
)
from pypnm.lib.types import ChannelId

# Fixed PHY/Test parameters
DF_HZ = 50_000.0  # subcarrier spacing (Hz)
NFFT = 4096  # IFFT length
FS = NFFT * DF_HZ  # sample rate (Hz) = 204.8 MHz
VF = 0.87  # RG6 default
C0 = 299_792_458.0  # m/s
V = C0 * VF  # propagation speed in the cable
FEET_PER_METER = 3.280839895013123


def _bins_for_distance_ft(distance_ft: float, fs: float = FS, v: float = V) -> int:
    """
    Convert a one-way distance (ft) to the echo bin index after the direct path
    using round-trip time t = 2d / v and bin = t * fs.
    """
    d_m = distance_ft / FEET_PER_METER
    t = (2.0 * d_m) / v
    return int(round(t * fs))


def _make_freq_response_from_impulses(
    pulses: list[tuple[int, float]], nfft: int = NFFT
) -> np.ndarray:
    """
    Build H(f) by FFT of h[n] with time-domain impulses:
    pulses = [(bin_index, amplitude), ...]
    """
    h = np.zeros(nfft, dtype=np.complex128)
    for idx, amp in pulses:
        h[idx % nfft] += complex(float(amp), 0.0)
    H = np.fft.fft(h, n=nfft)
    return H.astype(np.complex128)


def test_direct_plus_known_echo_bin_and_distance() -> None:
    """
    Create a direct path at bin 0 and a single echo at ~20 ft.
    Validate that the detector finds the echo near the expected bin and that
    echo distances increase (monotonic) relative to the direct path.
    """
    distance_ft = 20.0
    echo_bin = _bins_for_distance_ft(distance_ft)
    # A modest echo amplitude (linear)
    echo_amp = 0.25

    H = _make_freq_response_from_impulses([(0, 1.0), (echo_bin, echo_amp)], nfft=NFFT)
    det = EchoDetector(
        freq_data=H,
        subcarrier_spacing_hz=DF_HZ,
        n_fft=NFFT,
        cable_type="RG6",
        channel_id=ChannelId(197),
    )

    rep = det.multi_echo(
        threshold_mode="fractional",
        threshold_frac=0.05,  # 5% of direct amplitude
        guard_bins=0,  # allow immediate search; detector also has 10-ft guard by default
        min_separation_s=8.0 / det.fs,  # ~8 bins
        max_delay_s=3.5e-6,
        max_peaks=3,
        include_time_response=False,
        direct_at_zero=True,
        window="hann",
        normalize_power=True,
        edge_guard_bins=8,
        # keep default min_detect_distance_ft=10.0
    )

    # Must have at least one echo
    assert len(rep.echoes) >= 1, "Expected at least one echo to be detected."

    first = rep.echoes[0]
    # Bin check: within ±1 bin of expected
    assert first.bin_index == pytest.approx(echo_bin, abs=1), (
        f"First echo bin {first.bin_index} not close to expected {echo_bin}"
    )

    # Time/Distance sanity: > 0
    assert first.time_s > 0.0
    assert first.distance_m > 0.0
    # Distance close to 20 ft (±1 ft tolerance)
    assert first.distance_ft == pytest.approx(distance_ft, abs=1.0)

    # If more echoes somehow cross threshold, ensure distances are non-decreasing
    dists = [e.distance_m for e in rep.echoes]
    assert dists == sorted(dists), "Echo distances should be non-decreasing."


def test_snapshot_average_with_guard_and_min_separation() -> None:
    """
    Two-snapshot average case:
      - A strong artifact at 2 bins (inside the 10-ft guard → should be ignored)
      - A valid echo beyond the guard (e.g., ~15 ft) that should be detected
    Also enforces min-separation (~8 bins).
    """
    # Near artifact within ~10 ft guard
    near_ft = 5.0
    near_bin = _bins_for_distance_ft(near_ft)

    # Valid echo beyond guard
    valid_ft = 15.0
    valid_bin = _bins_for_distance_ft(valid_ft)

    # Build two snapshots with slight amplitude variation
    H1 = _make_freq_response_from_impulses(
        [(0, 1.0), (near_bin, 0.5), (valid_bin, 0.25)], nfft=NFFT
    )
    H2 = _make_freq_response_from_impulses(
        [(0, 1.0), (near_bin, 0.45), (valid_bin, 0.3)], nfft=NFFT
    )
    H_snapshots = np.vstack([H1, H2])  # shape (2, NFFT), complex

    det = EchoDetector(
        freq_data=H_snapshots,  # (M, N) complex → averaged internally
        subcarrier_spacing_hz=DF_HZ,
        n_fft=NFFT,
        cable_type="RG6",
        channel_id=194,
    )

    rep = det.multi_echo(
        threshold_mode="fractional",
        threshold_frac=0.05,
        guard_bins=0,  # leave explicit guard at 0; detector uses 10-ft min distance guard
        min_separation_s=8.0 / det.fs,  # ~8 bins
        max_delay_s=3.5e-6,
        max_peaks=3,
        include_time_response=False,
        direct_at_zero=True,
        window="hann",
        normalize_power=True,
        edge_guard_bins=8,
        # keep default min_detect_distance_ft=10.0
    )

    # We expect the near artifact to be rejected by min_detect_distance_ft (~5 bins)
    # and the valid echo beyond ~10 ft to be included.
    bins = [e.bin_index for e in rep.echoes]

    # Valid echo must be present (±1 bin)
    assert any(abs(b - valid_bin) <= 1 for b in bins), (
        f"Valid echo near bin {valid_bin} not detected; got bins {bins}"
    )

    # Near artifact must be absent
    assert all(abs(b - near_bin) > 1 for b in bins), (
        f"Near artifact within guard (bin {near_bin}) should have been rejected; got bins {bins}"
    )

    # Min separation: all selected bins spaced by ≥ ~8 bins
    bins_sorted = sorted(bins)
    for i in range(1, len(bins_sorted)):
        assert (bins_sorted[i] - bins_sorted[i - 1]) >= 8 - 1, (
            "Echo picks violate min separation constraint"
        )
# FILE: tests/test_fixed_point_decoder.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import math

import pytest

from pypnm.pnm.lib.fixed_point_decoder import (
    FixedPointDecoder,
    FractionalBits,
    IntegerBits,
)

# ───────────────────────── helpers ─────────────────────────


def _q(a: int, b: int) -> tuple[IntegerBits, FractionalBits]:
    return (IntegerBits(a), FractionalBits(b))


def _bits_per_component(q: tuple[IntegerBits, FractionalBits]) -> int:
    a, b = int(q[0]), int(q[1])
    return a + b + 1  # +1 sign bit


def _bytes_per_component(q: tuple[IntegerBits, FractionalBits]) -> int:
    tbits = _bits_per_component(q)
    assert tbits % 8 == 0, "Test helper expects byte-aligned Q formats"
    return tbits // 8


def _scale(q: tuple[IntegerBits, FractionalBits]) -> int:
    return 1 << int(q[1])


def _twos_wrap(n: int, total_bits: int) -> int:
    mask = (1 << total_bits) - 1
    return n & mask


def _pack_component(
    value: float, q: tuple[IntegerBits, FractionalBits], *, signed: bool, byteorder: str
) -> bytes:
    """Pack one fixed-point component into bytes, respecting endianness."""
    frac = int(q[1])
    total_bits = _bits_per_component(q)
    byte_len = _bytes_per_component(q)
    scale = 1 << frac

    # Convert float to fixed
    raw = int(round(value * scale))

    if signed:
        raw = _twos_wrap(raw, total_bits)
        return raw.to_bytes(byte_len, byteorder=byteorder, signed=False)

    # unsigned path (clamp)
    max_u = (1 << total_bits) - 1
    raw_u = max(0, min(max_u, raw))
    return raw_u.to_bytes(byte_len, byteorder=byteorder, signed=False)


def _pack_q_pair(
    re: float,
    im: float,
    q: tuple[IntegerBits, FractionalBits],
    *,
    signed: bool = True,
    endian: str = "little",
) -> bytes:
    """Encode one complex sample for generic Q(a,b), honoring endianness."""
    return _pack_component(re, q, signed=signed, byteorder=endian) + _pack_component(
        im, q, signed=signed, byteorder=endian
    )


# ───────────────────────── unit tests ─────────────────────────


@pytest.mark.parametrize("q", [_q(1, 14), _q(2, 13)])
def test_decode_fixed_point_signed_basic(q: tuple[IntegerBits, FractionalBits]) -> None:
    frac = int(q[1])
    # +1.0
    assert FixedPointDecoder.decode_fixed_point(
        1 << frac, q, signed=True
    ) == pytest.approx(1.0)
    # +0.25
    assert FixedPointDecoder.decode_fixed_point(
        1 << (frac - 2), q, signed=True
    ) == pytest.approx(0.25)
    # -1.0 (two's complement of +1.0)
    total_bits = _bits_per_component(q)
    neg_one_tc = _twos_wrap(-(1 << frac), total_bits)
    assert FixedPointDecoder.decode_fixed_point(
        neg_one_tc, q, signed=True
    ) == pytest.approx(-1.0)


def test_decode_fixed_point_unsigned_q1_14() -> None:
    q = _q(1, 14)
    val = FixedPointDecoder.decode_fixed_point(0x7FFF, q, signed=False)
    assert val == pytest.approx(0x7FFF / (2**14))


def test_decode_fixed_point_non_byte_aligned_allowed_single_value() -> None:
    # Single-value decoder does not enforce byte alignment (only complex decoder does).
    q_bad = _q(1, 15)  # 17 total bits
    val = FixedPointDecoder.decode_fixed_point(0x1, q_bad, signed=True)
    assert val == pytest.approx(1 / (2**15))


def test_decode_complex_rejects_non_byte_aligned() -> None:
    q_bad = _q(1, 15)  # 17 total bits → not byte aligned
    with pytest.raises(ValueError, match="must be a multiple of 8"):
        FixedPointDecoder.decode_complex_data(b"\x00" * 8, q_bad, signed=True)


@pytest.mark.parametrize("q", [_q(1, 14), _q(2, 13)])
@pytest.mark.parametrize("endian", ["little", "big"])
def test_decode_complex_two_samples_signed_roundtrip(
    q: tuple[IntegerBits, FractionalBits],
    endian: str,
) -> None:
    # Two samples: (1.0, -0.5) and (0.25, 0.0)
    blob = b"".join(
        [
            _pack_q_pair(1.0, -0.5, q, signed=True, endian=endian),
            _pack_q_pair(0.25, 0.0, q, signed=True, endian=endian),
        ]
    )
    out = FixedPointDecoder.decode_complex_data(blob, q, signed=True, endian=endian)
    assert isinstance(out, list)
    assert len(out) == 2
    assert out[0].real == pytest.approx(1.0)
    assert out[0].imag == pytest.approx(-0.5)
    assert out[1].real == pytest.approx(0.25)
    assert out[1].imag == pytest.approx(0.0)


def test_decode_complex_invalid_length() -> None:
    q = _q(1, 14)
    with pytest.raises(
        ValueError, match="data length must be a multiple of the complex number size"
    ):
        FixedPointDecoder.decode_complex_data(b"\x00\x01\x02", q, signed=True)


def test_decode_complex_unsigned_mode() -> None:
    q = _q(1, 14)
    # Pack using unsigned semantics:
    blob = _pack_q_pair(0x7FFF / (2**14), 0.5, q, signed=False, endian="little")
    vals = FixedPointDecoder.decode_complex_data(blob, q, signed=False, endian="little")
    assert len(vals) == 1
    assert vals[0].real == pytest.approx(0x7FFF / (2**14))
    assert vals[0].imag == pytest.approx(0.5)


def test_decode_complex_empty_ok() -> None:
    q = _q(2, 13)
    out = FixedPointDecoder.decode_complex_data(b"", q, signed=True, endian="big")
    assert isinstance(out, list)
    assert len(out) == 0


@pytest.mark.parametrize("q", [_q(1, 14), _q(2, 13)])
def test_decode_complex_wrong_endian_changes_values(
    q: tuple[IntegerBits, FractionalBits],
) -> None:
    # Build little-endian blob but decode as big-endian: values should not match expected
    expected = [(0.5, -0.25), (-0.75, 0.125)]
    blob_le = b"".join(
        _pack_q_pair(r, i, q, signed=True, endian="little") for (r, i) in expected
    )

    out_be = FixedPointDecoder.decode_complex_data(
        blob_le, q, signed=True, endian="big"
    )
    assert len(out_be) == len(expected)

    # At least one component must differ significantly if endian is wrong.
    mismatches = 0
    for got, (er, ei) in zip(out_be, expected, strict=False):
        if not math.isclose(
            got.real, er, rel_tol=1e-6, abs_tol=1e-6
        ) or not math.isclose(got.imag, ei, rel_tol=1e-6, abs_tol=1e-6):
            mismatches += 1
    assert mismatches >= 1


@pytest.mark.parametrize("q", [_q(1, 14), _q(2, 13)])
def test_decode_complex_data_multiple_samples_roundtrip_like(
    q: tuple[IntegerBits, FractionalBits],
) -> None:
    samples = [(0.0, 0.0), (0.5, 0.5), (-0.75, 0.25), (1.0, -1.0)]
    blob = b"".join(
        _pack_q_pair(r, i, q, signed=True, endian="little") for (r, i) in samples
    )
    out = FixedPointDecoder.decode_complex_data(blob, q, signed=True, endian="little")
    assert len(out) == len(samples)
    for got, (er, ei) in zip(out, samples, strict=False):
        assert got.real == pytest.approx(er, abs=1e-4)
        assert got.imag == pytest.approx(ei, abs=1e-4)
# FILE: tests/test_ftp_connector.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import ftplib
from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pypnm.lib.ftp.ftp_connector import FTPConnector


@pytest.fixture
def mock_ftp() -> MagicMock:
    m = MagicMock(spec=ftplib.FTP)
    m.nlst.return_value = ["file1.txt", "dir"]
    m.size.return_value = 1234
    m.pwd.return_value = "/"
    return m


def test_connect_plain_success(mock_ftp: MagicMock) -> None:
    # Plain FTP should connect/login; don't assert prot_p on a non-TLS client.
    with patch("ftplib.FTP", return_value=mock_ftp) as cls:
        c = FTPConnector("example.com", username="u", password="p", use_tls=False)
        assert c.connect() is True
        cls.assert_called_once()
        mock_ftp.connect.assert_called_once_with("example.com", 21, timeout=30)
        mock_ftp.login.assert_called_once_with("u", "p")


def test_connect_tls_calls_prot_p() -> None:
    m = MagicMock(spec=ftplib.FTP_TLS)
    with patch("ftplib.FTP_TLS", return_value=m):
        c = FTPConnector("host", use_tls=True)
        assert c.connect() is True
        m.prot_p.assert_called_once()


def test_connect_failure_returns_false() -> None:
    with patch("ftplib.FTP", side_effect=RuntimeError("boom")):
        c = FTPConnector("host")
        assert c.connect() is False


def test_disconnect_quit_no_raise(mock_ftp: MagicMock) -> None:
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        assert c.connect()
        c.disconnect()
        mock_ftp.quit.assert_called_once()
        assert c.ftp is None


def test_list_dir_returns_names(mock_ftp: MagicMock) -> None:
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        c.connect()
        out = c.list_dir("/some")
        mock_ftp.nlst.assert_called_once_with("/some")
        assert out == ["file1.txt", "dir"]


def test_make_dirs_creates_nested_when_missing(mock_ftp: MagicMock) -> None:
    # Let cwd fail for any subdir to force mkd; root is fine
    def cwd_side_effect(path: str) -> None:
        if path != "/":
            raise ftplib.error_perm("nope")

    mock_ftp.cwd.side_effect = cwd_side_effect
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        c.connect()
        c.make_dirs("/a/b/c")
        # mkd should be called for each missing component
        assert mock_ftp.mkd.call_count == 3
        mock_ftp.cwd.assert_any_call("/")  # returned to root at end


def test_upload_file_success(tmp_path: Path) -> None:
    ftp = MagicMock(spec=ftplib.FTP)

    # Track created directories so subsequent cwd to them succeeds
    created: set[str] = set()

    def cwd_side_effect(path: str) -> None:
        # Root always ok
        if path == "/":
            return
        # Accept cwd if previously "created"
        if path.lstrip("/") in created:
            return
        # Otherwise pretend it doesn't exist (trigger mkd)
        raise ftplib.error_perm("missing")

    def mkd_side_effect(path: str) -> None:
        created.add(path.lstrip("/"))

    ftp.cwd.side_effect = cwd_side_effect
    ftp.mkd.side_effect = mkd_side_effect

    local = tmp_path / "in.bin"
    local.write_bytes(b"payload")

    with patch("ftplib.FTP", return_value=ftp):
        c = FTPConnector("h")
        assert c.connect()
        ok = c.upload_file(str(local), "/x/y/out.bin")
        assert ok is True
        # ensure it tried to create both levels
        assert "x" in created and "x/y" in created
        ftp.storbinary.assert_called_once()
        args, _ = ftp.storbinary.call_args
        assert args[0].startswith("STOR ")


def test_upload_file_missing_local_returns_false() -> None:
    ftp = MagicMock(spec=ftplib.FTP)
    with patch("ftplib.FTP", return_value=ftp):
        c = FTPConnector("h")
        c.connect()
        assert c.upload_file("no_such_file.bin", "/remote.bin") is False
        ftp.storbinary.assert_not_called()


def test_download_file_to_dir_and_to_file(tmp_path: Path) -> None:
    ftp = MagicMock(spec=ftplib.FTP)

    def retr_side_effect(cmd: str, writer_cb: Callable[[bytes], object]) -> None:
        writer_cb(b"abc123")

    ftp.retrbinary.side_effect = retr_side_effect

    with patch("ftplib.FTP", return_value=ftp):
        c = FTPConnector("h")
        c.connect()

        # Download to directory path (auto-append filename)
        out_dir = tmp_path / "dl"
        out_dir.mkdir()
        ok = c.download_file("/r/file.txt", str(out_dir))
        assert ok is True
        data = (out_dir / "file.txt").read_bytes()
        assert data == b"abc123"

        # Download to explicit file path
        out_file = tmp_path / "explicit.bin"
        ok = c.download_file("/remote.bin", str(out_file))
        assert ok is True
        assert out_file.read_bytes() == b"abc123"


def test_delete_get_size_cwd_pwd(mock_ftp: MagicMock) -> None:
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        c.connect()

        assert c.delete_file("/a.txt") is True
        mock_ftp.delete.assert_called_once_with("/a.txt")

        assert c.get_size("/a.txt") == 1234
        mock_ftp.size.assert_called_once_with("/a.txt")

        assert c.cwd("/some") is True
        mock_ftp.cwd.assert_called_with("/some")

        assert c.pwd() == "/"
        mock_ftp.pwd.assert_called_once()


def test_get_size_failure_returns_none(mock_ftp: MagicMock) -> None:
    mock_ftp.size.side_effect = RuntimeError("oops")
    with patch("ftplib.FTP", return_value=mock_ftp):
        c = FTPConnector("h")
        c.connect()
        assert c.get_size("/bad") is None


def test_methods_raise_without_connection() -> None:
    c = FTPConnector("h")
    with pytest.raises(ConnectionError):
        c.list_dir("/")
    with pytest.raises(ConnectionError):
        c.make_dirs("/a")
    with pytest.raises(ConnectionError):
        c.upload_file(__file__, "/r")
    with pytest.raises(ConnectionError):
        c.download_file("/r", ".")
    with pytest.raises(ConnectionError):
        c.delete_file("/r")
    with pytest.raises(ConnectionError):
        c.get_size("/r")
    with pytest.raises(ConnectionError):
        c.cwd("/")
    with pytest.raises(ConnectionError):
        c.pwd()
# FILE: tests/test_group_delay_calculator.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

from pypnm.api.routes.advance.analysis.signal_analysis.group_delay_calculator import (
    GroupDelayCalculator,
    GroupDelayCalculatorModel,
)

RTOL = 1e-6
ATOL = 1e-9


def _mk_linear_phase(freqs_hz: np.ndarray, tau_s: float) -> np.ndarray:
    """
    Build H(f) = exp(-j*2π f τ). Group delay should be constant τ.
    """
    return np.exp(-1j * 2.0 * np.pi * freqs_hz * tau_s)


@pytest.mark.pnm
def test_group_delay_constant_for_linear_phase_single_snapshot() -> None:
    K = 256
    tau_true = 5e-6
    f0 = 100e6
    df = 25e3
    freqs = f0 + df * np.arange(K)

    H = _mk_linear_phase(freqs, tau_true)
    calc = GroupDelayCalculator(H, freqs)
    f_out, tau_g = calc.compute_group_delay_full()

    assert f_out.shape == (K,)
    assert tau_g.shape == (K,)
    assert np.allclose(tau_g, tau_true, rtol=RTOL, atol=ATOL)


@pytest.mark.pnm
def test_group_delay_median_across_snapshots_with_noise() -> None:
    K = 128
    M = 5
    tau_true = 2.5e-6
    f0 = 90e6
    df = 50e3
    freqs = f0 + df * np.arange(K)

    rng = np.random.default_rng(123)
    Hs = []
    for _ in range(M):
        H_clean = _mk_linear_phase(freqs, tau_true)
        phase_jitter = rng.normal(scale=1e-2, size=K)
        H_noisy = H_clean * np.exp(1j * phase_jitter)
        Hs.append(H_noisy)
    H = np.stack(Hs, axis=0)

    calc = GroupDelayCalculator(H, freqs)
    f_med, tau_med = calc.median_group_delay()

    assert f_med.shape == (K,)
    assert tau_med.shape == (K,)
    assert np.allclose(tau_med, tau_true, rtol=5e-3, atol=1e-7)


@pytest.mark.pnm
def test_input_encodings_pairs_and_mk2() -> None:
    K = 64
    tau_true = 1e-6
    f0 = 200e6
    df = 25e3
    freqs = f0 + df * np.arange(K)

    H_complex = _mk_linear_phase(freqs, tau_true)

    pairs_K2 = np.stack([np.real(H_complex), np.imag(H_complex)], axis=1)
    calc_pairs = GroupDelayCalculator(pairs_K2, freqs)
    _, tau_pairs = calc_pairs.compute_group_delay_full()

    pairs_MK2 = pairs_K2[np.newaxis, ...]
    calc_pairs_batched = GroupDelayCalculator(pairs_MK2, freqs)
    _, tau_pairs_batched = calc_pairs_batched.compute_group_delay_full()

    calc_c = GroupDelayCalculator(H_complex, freqs)
    _, tau_c = calc_c.compute_group_delay_full()

    assert np.allclose(tau_pairs, tau_c, rtol=RTOL, atol=ATOL)
    assert np.allclose(tau_pairs_batched, tau_c, rtol=RTOL, atol=ATOL)


@pytest.mark.pnm
def test_snapshot_group_delay_shape() -> None:
    K = 33
    M = 3
    tau_true = 4e-6
    f0, df = 50e6, 25e3
    freqs = f0 + df * np.arange(K)
    H = np.stack([_mk_linear_phase(freqs, tau_true) for _ in range(M)], axis=0)

    calc = GroupDelayCalculator(H, freqs)
    taus = calc.snapshot_group_delay()
    assert taus.shape == (M, K)
    assert np.allclose(taus, tau_true, rtol=RTOL, atol=ATOL)


@pytest.mark.pnm
def test_model_build_and_alias_fields() -> None:
    K = 40
    tau_true = 3e-6
    f0, df = 70e6, 25e3
    freqs = f0 + df * np.arange(K)
    H = _mk_linear_phase(freqs, tau_true)

    mdl: GroupDelayCalculatorModel = GroupDelayCalculator(H, freqs).to_model()

    assert mdl.dataset_info.subcarriers == K
    assert mdl.dataset_info.snapshots == 1
    assert mdl.complex_unit == "[Real, Imaginary]"
    assert len(mdl.freqs) == K
    assert len(mdl.H_avg) == K
    assert len(mdl.group_delay_full.freqs) == K
    assert len(mdl.group_delay_full.tau_g) == K
    assert len(mdl.snapshot_group_delay.taus) == 1
    assert len(mdl.snapshot_group_delay.taus[0]) == K
    assert len(mdl.median_group_delay.freqs) == K
    assert len(mdl.median_group_delay.tau_med) == K
    assert np.allclose(mdl.group_delay_full.tau_g, tau_true, rtol=RTOL, atol=ATOL)
    assert np.allclose(mdl.median_group_delay.tau_med, tau_true, rtol=RTOL, atol=ATOL)


@pytest.mark.pnm
def test_to_dict_uses_alias_and_is_serializable() -> None:
    K = 16
    tau_true = 1e-6
    f0, df = 10e6, 25e3
    freqs = f0 + df * np.arange(K)
    H = _mk_linear_phase(freqs, tau_true)

    dct = GroupDelayCalculator(H, freqs).to_dict()

    assert "H_avg" in dct
    assert isinstance(dct["H_avg"], list)
    assert all(isinstance(x, tuple) and len(x) == 2 for x in dct["H_avg"])
    assert "complex_unit" in dct
    assert dct["complex_unit"] == "[Real, Imaginary]"
    assert "H_raw" in dct
    assert "group_delay_full" in dct


@pytest.mark.pnm
def test_validation_duplicate_freqs_and_mismatched_lengths() -> None:
    freqs = np.array([100.0, 100.0, 200.0])
    H = np.array([1 + 0j, 1 + 0j, 1 + 0j])
    calc = GroupDelayCalculator(H, freqs)
    with pytest.raises(ValueError):
        _ = calc.compute_group_delay_full()

    freqs2 = np.array([1.0, 2.0, 3.0, 4.0])
    H2 = np.array([1 + 0j, 1 + 0j, 1 + 0j])
    with pytest.raises(ValueError):
        _ = GroupDelayCalculator(H2, freqs2)

    with pytest.raises(ValueError):
        _ = GroupDelayCalculator(np.zeros((2, 3, 3)), np.array([1.0, 2.0, 3.0]))
# FILE: tests/test_heatmap_anomaly_detector.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

from pypnm.api.routes.advance.analysis.signal_analysis.detection.anolamaly.heatmap_anomaly_detection import (
    HeatmapAnomalyDetector,
)


@pytest.mark.pnm
def test_compute_zmap_basic_stats() -> None:
    # simple 2D ramp
    a = np.arange(20, dtype=float).reshape(4, 5)
    det = HeatmapAnomalyDetector(a, threshold=2.0)
    z = det.compute_zmap()

    assert z.shape == a.shape
    # zmap should be zero-mean, unit-variance (up to numerical tolerance)
    assert abs(z.mean()) < 1e-12
    assert abs(z.std() - 1.0) < 1e-12


@pytest.mark.pnm
def test_compute_zmap_zero_sigma() -> None:
    # constant matrix -> std == 0 -> zmap should be all zeros
    a = np.full((3, 4), 7.0)
    det = HeatmapAnomalyDetector(a, threshold=3.0)
    z = det.compute_zmap()
    assert np.all(z == 0.0)

    mask = det.detect()
    assert mask.shape == a.shape
    # no anomalies because z == 0 everywhere
    assert not mask.any()


@pytest.mark.pnm
def test_detect_thresholding_and_boxes_single_blob() -> None:
    # Create a small grid with one obvious high anomaly block
    a = np.zeros((6, 6), dtype=float)
    a[2:4, 3:5] = 100.0  # 2x2 bright blob

    det = HeatmapAnomalyDetector(a, threshold=2.0)
    mask = det.detect()

    # Blob region should be True; outside False
    assert mask[2:4, 3:5].all()
    assert not mask[:2, :].any()
    assert not mask[4:, :].any()

    boxes = det.find_boxes()
    # exactly one box, spanning the 2x2 region
    assert len(boxes) == 1
    r0, c0, r1, c1 = boxes[0]
    assert (r0, c0, r1, c1) == (2, 3, 3, 4)


@pytest.mark.pnm
def test_find_boxes_multiple_disjoint_blobs() -> None:
    a = np.zeros((8, 8), dtype=float)
    a[1:3, 1:3] = 10.0  # blob A
    a[5:7, 5:7] = -10.0  # blob B (negative should also be flagged via |z|)

    det = HeatmapAnomalyDetector(a, threshold=1.0)
    det.detect()
    boxes = det.find_boxes()

    # We expect two disjoint boxes
    assert len(boxes) == 2
    assert (1, 1, 2, 2) in boxes
    assert (5, 5, 6, 6) in boxes


@pytest.mark.pnm
def test_four_connectivity_not_diagonal_connected() -> None:
    # Two pixels touching diagonally should be separate components.
    a = np.zeros((3, 3), dtype=float)
    a[0, 0] = 100.0
    a[1, 1] = 100.0

    det = HeatmapAnomalyDetector(a, threshold=1.0)
    det.detect()
    boxes = det.find_boxes()

    assert len(boxes) == 2
    assert (0, 0, 0, 0) in boxes
    assert (1, 1, 1, 1) in boxes


@pytest.mark.pnm
def test_to_json_structure_after_detection() -> None:
    a = np.zeros((5, 5), dtype=float)
    a[2, 2] = 50.0

    det = HeatmapAnomalyDetector(a, threshold=1.5)
    det.detect()
    det.find_boxes()
    payload = det.to_json()

    assert "threshold" in payload and payload["threshold"] == 1.5
    assert "boxes" in payload and isinstance(payload["boxes"], list)
    # one 1x1 box expected
    assert payload["boxes"] == [
        {"row_min": 2, "col_min": 2, "row_max": 2, "col_max": 2}
    ]
# FILE: tests/test_host_endpoint.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import socket

import pytest

from pypnm.lib.host_endpoint import HostEndpoint
from pypnm.lib.ping import Ping
from pypnm.lib.types import HostNameStr


def test_ping_delegates_to_ping_is_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, object] = {}

    def fake_is_reachable(host: str, timeout: int, count: int) -> bool:
        called["host"] = host
        called["timeout"] = timeout
        called["count"] = count
        return True

    monkeypatch.setattr(Ping, "is_reachable", fake_is_reachable)

    endpoint = HostEndpoint(HostNameStr("example.com"))
    result = endpoint.ping(timeout=2, count=3)

    assert result is True
    assert called["host"] == "example.com"
    assert called["timeout"] == 2
    assert called["count"] == 3


def test_resolve_returns_unique_addresses_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_getaddrinfo(host: str, _service: object) -> list[tuple[object, ...]]:
        assert host == "example.com"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    endpoint = HostEndpoint(HostNameStr("example.com"))
    addresses = endpoint.resolve()

    assert "192.0.2.1" in addresses
    assert "2001:db8::1" in addresses
    assert len(addresses) == 2


def test_resolve_logs_error_and_returns_empty_on_dns_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def fake_getaddrinfo(
        host: str, _service: int | str | None
    ) -> list[tuple[object, ...]]:
        raise OSError("temporary failure in name resolution")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    endpoint = HostEndpoint(HostNameStr("bad-hostname.invalid"))

    logger_name = "HostEndpoint"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        addresses = endpoint.resolve()

    assert addresses == []
    assert "DNS lookup failed for bad-hostname.invalid" in caplog.text


def test_resolve_google_dns_smoke() -> None:
    """
    Smoke-Test Real DNS Resolution For www.google.com.

    This test exercises the HostEndpoint.resolve() method against a well-known
    public hostname. If DNS resolution fails (for example, due to an offline
    or sandboxed environment), the test is skipped instead of treated as a
    hard failure.
    """
    endpoint = HostEndpoint(HostNameStr("www.google.com"))
    addresses = endpoint.resolve()

    if not addresses:
        pytest.skip("DNS resolution failed for www.google.com; skipping smoke test")

    for addr in addresses:
        assert isinstance(addr, str)
        assert len(addr) > 0


def test_ping_localhost_reachable() -> None:
    """
    Verify That Localhost Is Reachable Via HostEndpoint.ping.

    This is an integration-style smoke test using the real Ping.is_reachable()
    implementation. It will fail if ICMP ping to 'localhost' is not functioning
    correctly in the current environment.
    """
    endpoint = HostEndpoint(HostNameStr("localhost"))
    assert endpoint.ping(timeout=1, count=1) is True
# FILE: tests/test_ifft_echo_detector.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest

from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.ifft import (
    IfftEchoDetector,
)
from pypnm.lib.constants import SPEED_OF_LIGHT as C0


@pytest.mark.pnm
def test_to_model_detects_single_echo_basic() -> None:
    # Build a simple time response: impulse at 0 and smaller echo at bin d
    N = 256
    d = 10  # echo at 10 samples
    fs = 1_000_000.0  # 1 MHz sample rate -> 1 us per sample
    vf = 0.87  # velocity factor for to_model() (used in detector ctor)

    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0 + 0j
    h[d] = 0.4 + 0j

    H = np.fft.fft(h)  # detector expects frequency-domain data
    det = IfftEchoDetector(H, sample_rate=fs, prop_speed_frac=vf)

    m = det.to_model(threshold_frac=0.2, guard_bins=1, max_delay_s=None, n_fft=None)

    # Indices
    assert m.reflection.direct_index == 0
    assert m.reflection.echo_index == d

    # Delay and distance
    expected_delay = d / fs
    expected_dist_m = expected_delay * (C0 * vf) / 2.0
    assert m.reflection.reflection_delay_s == pytest.approx(expected_delay, rel=1e-6)
    assert m.reflection.reflection_distance_m == pytest.approx(
        expected_dist_m, rel=1e-6
    )

    # Amplitude ratio ~ 0.4
    assert m.reflection.amp_ratio == pytest.approx(0.4, rel=1e-3)

    # Model shape fields
    assert m.dataset_info.subcarriers == N
    assert m.dataset_info.snapshots == 1
    assert m.sample_rate_hz == fs
    assert m.prop_speed_mps == pytest.approx(C0 * vf, rel=1e-12)

    # Optional time block present by default
    assert m.time_response is not None
    assert m.time_response.n_fft == N
    assert len(m.time_response.time_axis_s) == N
    assert len(m.time_response.time_response) == N


@pytest.mark.pnm
def test_detect_multiple_reflections_with_spacing_and_padding() -> None:
    N = 512
    fs = 2_000_000.0
    vf = 0.82

    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0
    h[15] = 0.6
    h[40] = 0.5
    H = np.fft.fft(h)

    det = IfftEchoDetector(H, sample_rate=fs, prop_speed_frac=vf)

    nfft = 1024
    rpt = det.detect_multiple_reflections(
        cable_type="RG59",
        velocity_factor=None,
        threshold_frac=0.2,
        guard_bins=1,
        min_separation_s=0.0,
        max_delay_s=None,
        max_peaks=5,
        n_fft=nfft,
        include_time_response=True,
    )

    scale = nfft // N  # 2
    expected_bins = [15 * scale, 40 * scale]
    assert [e.bin_index for e in rpt.echoes[:2]] == expected_bins

    # distance sanity remains the same
    dists = [e.distance_m for e in rpt.echoes]
    assert all(d > 0 for d in dists)
    assert dists[0] < dists[1]

    assert rpt.time_response is not None
    assert rpt.time_response.n_fft == nfft
    assert len(rpt.time_response.time_axis_s) == nfft
    assert len(rpt.time_response.time_response) == nfft


@pytest.mark.pnm
def test_accepts_real_imag_pair_inputs_shapes() -> None:
    N = 128
    fs = 500_000.0

    # Build simple time response and FFT to get H
    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0
    h[8] = 0.25
    H = np.fft.fft(h)

    # (N,2) real/imag input (single snapshot)
    H_pairs = np.column_stack((H.real, H.imag))
    det_single = IfftEchoDetector(H_pairs, sample_rate=fs)
    m_single = det_single.to_model()
    assert m_single.dataset_info.snapshots == 1
    assert m_single.dataset_info.subcarriers == N

    # (M,N,2) real/imag input (two snapshots, identical)
    H_pairs2 = np.stack([H_pairs, H_pairs], axis=0)
    det_multi = IfftEchoDetector(H_pairs2, sample_rate=fs)
    m_multi = det_multi.to_model()
    assert m_multi.dataset_info.snapshots == 2
    assert m_multi.dataset_info.subcarriers == N


@pytest.mark.pnm
def test_compute_time_response_raises_when_nfft_too_small() -> None:
    N = 64
    fs = 1e6
    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0
    H = np.fft.fft(h)

    det = IfftEchoDetector(H, sample_rate=fs)
    with pytest.raises(ValueError):
        det.compute_time_response(n_fft=N - 1)  # must be >= N


@pytest.mark.pnm
def test_no_echo_found_when_threshold_too_high() -> None:
    N = 128
    fs = 1e6
    h = np.zeros(N, dtype=np.complex128)
    h[0] = 1.0
    h[20] = 0.05  # small echo

    H = np.fft.fft(h)
    det = IfftEchoDetector(H, sample_rate=fs)

    # Threshold above 5% echo → expect failure
    with pytest.raises(RuntimeError):
        det.to_model(threshold_frac=0.2)  # 20% > 5%, so no echo should be found
# FILE: tests/test_ping.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable
from typing import NoReturn

import pytest

from pypnm.lib.ping import Ping


class DummyCompleted:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode


def _mock_run_factory(
    expected_cmd_out: list[str], rc: int = 0
) -> Callable[..., DummyCompleted]:
    captured: dict[str, object] = {}

    def _mock_run(cmd: list[str], *args: object, **kwargs: object) -> DummyCompleted:
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs

        if "stdout" in kwargs:
            assert kwargs["stdout"] is subprocess.DEVNULL
        if "stderr" in kwargs:
            assert kwargs["stderr"] is subprocess.DEVNULL

        return DummyCompleted(rc)

    _mock_run.captured = captured  # type: ignore[attr-defined]
    _mock_run.expected = expected_cmd_out  # type: ignore[attr-defined]
    return _mock_run


def test_linux_mac_builds_correct_command_and_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("platform.system", lambda: "Linux")

    expected_cmd = ["ping", "-c", "3", "-W", "2", "host.example"]
    mock_run = _mock_run_factory(expected_cmd, rc=0)
    monkeypatch.setattr("subprocess.run", mock_run)

    ok = Ping.is_reachable("host.example", timeout=2, count=3)
    assert ok is True
    assert mock_run.captured["cmd"] == expected_cmd


def test_linux_mac_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")

    expected_cmd = ["ping", "-c", "1", "-W", "1", "8.8.8.8"]
    mock_run = _mock_run_factory(expected_cmd, rc=1)
    monkeypatch.setattr("subprocess.run", mock_run)

    ok = Ping.is_reachable("8.8.8.8")
    assert ok is False
    assert mock_run.captured["cmd"] == expected_cmd


def test_windows_builds_correct_command_and_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("platform.system", lambda: "Windows")

    expected_cmd = ["ping", "-n", "4", "-w", "3000", "10.0.0.1"]
    mock_run = _mock_run_factory(expected_cmd, rc=0)
    monkeypatch.setattr("subprocess.run", mock_run)

    ok = Ping.is_reachable("10.0.0.1", timeout=3, count=4)
    assert ok is True
    assert mock_run.captured["cmd"] == expected_cmd


def test_subprocess_exception_returns_false(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr("platform.system", lambda: "Linux")

    def boom(*args: object, **kwargs: object) -> NoReturn:
        raise OSError("no ping here")

    monkeypatch.setattr("subprocess.run", boom)

    with caplog.at_level(logging.ERROR):
        ok = Ping.is_reachable("nowhere.invalid", timeout=1, count=1)

    assert ok is False
    # Optional: assert we actually logged the error
    assert "[Ping Error] no ping here" in caplog.text
# FILE: tests/test_pnm_channel_estimation_parse.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typing_extensions import assert_type

from pypnm.lib.types import ComplexArray, ComplexSeries
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef

DATA_DIR = Path(__file__).parent / "files"
CE_PATH = DATA_DIR / "channel_estimation.bin"
NON_CE_PATH = DATA_DIR / "rxmer.bin"  # negative test: valid PNM but wrong type

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _is_pair_seq(x: object) -> bool:
    """Return True for [re, im] where both are number-like."""
    return (
        isinstance(x, (list, tuple))
        and len(x) == 2
        and all(isinstance(v, (int, float)) for v in x)
    )


@pytest.fixture(scope="session")
def ce_bytes() -> bytes:
    return CE_PATH.read_bytes()


@pytest.mark.pnm
def test_ce_parses_and_model_shape(ce_bytes: bytes) -> None:
    ce_model = CmDsOfdmChanEstimateCoef(ce_bytes).to_model()

    # Basic header fields
    assert isinstance(ce_model.channel_id, int)
    assert MAC_RE.match(ce_model.mac_address)

    # Subcarrier metadata sane
    assert (
        isinstance(ce_model.subcarrier_spacing, int) and ce_model.subcarrier_spacing > 0
    )
    assert isinstance(ce_model.first_active_subcarrier_index, int)
    assert ce_model.first_active_subcarrier_index >= 0

    # Data length is raw bytes; must be multiple of 4 (2B real + 2B imag per complex)
    assert ce_model.data_length % 4 == 0

    # Number of complex points = data_length / 4
    num_points = ce_model.data_length // 4
    assert isinstance(ce_model.values, list) and len(ce_model.values) == num_points
    assert all(_is_pair_seq(p) for p in ce_model.values)

    # Units
    assert ce_model.value_units == "complex"

    # OBW equals (#points) * spacing
    assert (
        ce_model.occupied_channel_bandwidth == num_points * ce_model.subcarrier_spacing
    )


@pytest.mark.pnm
def test_ce_coeff_rounding_and_raw_access(ce_bytes: bytes) -> None:
    parser = CmDsOfdmChanEstimateCoef(ce_bytes)

    # Rounded → ComplexArray: list[[re, im], ...]
    rounded = parser.get_coefficients("rounded")
    assert isinstance(rounded, list)
    assert all(_is_pair_seq(v) for v in rounded)

    # Raw → ComplexSeries: list[complex]
    raw = parser.get_coefficients("raw")
    assert isinstance(raw, list)
    assert all(isinstance(v, complex) for v in raw)

    # Same length views
    assert len(raw) == len(rounded)

    # ---- Static typing assertions (validate overloads) ----
    assert_type(
        parser.get_coefficients("rounded"), ComplexArray
    )  # Literal["rounded"] → ComplexArray
    assert_type(
        parser.get_coefficients("raw"), ComplexSeries
    )  # Literal["raw"] → ComplexSeries
    assert_type(parser.get_coefficients(), ComplexArray)  # default → ComplexArray


@pytest.mark.pnm
def test_ce_serialization_roundtrip(ce_bytes: bytes) -> None:
    parser = CmDsOfdmChanEstimateCoef(ce_bytes)

    d = parser.to_dict()
    j = parser.to_json()

    parsed = json.loads(j)
    # Top-level keys must match dict export
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_non_ce_file_rejected() -> None:
    with pytest.raises(ValueError):
        _ = CmDsOfdmChanEstimateCoef(NON_CE_PATH.read_bytes())
# FILE: tests/test_pnm_constellation_parse.py
# tests/test_pnm_constellation_parse.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia


from __future__ import annotations

import math
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsConstDispMeas import CmDsConstDispMeas

DATA_DIR = Path(__file__).parent / "files"
CONST_PATH = DATA_DIR / "const_display.bin"
NON_CONST_PATH = DATA_DIR / "fec_summary.bin"  # negative test sample


@pytest.fixture(scope="session")
def const_bytes() -> bytes:
    return CONST_PATH.read_bytes()


@pytest.mark.pnm
def test_constellation_file_parses_and_model_shape(const_bytes: bytes) -> None:
    cm = CmDsConstDispMeas(const_bytes)
    m = cm.to_model()

    # basic header presence
    assert m.pnm_header is not None
    # required top-level fields
    assert isinstance(m.channel_id, int)
    assert (
        isinstance(m.mac_address, str) and len(m.mac_address) >= 11
    )  # "aa:bb:cc:dd:ee:ff"
    assert isinstance(m.subcarrier_zero_frequency, int)
    assert isinstance(m.subcarrier_spacing, int) and m.subcarrier_spacing > 0

    # model semantics
    assert m.sample_units == "[Real(I), Imaginary(Q)]"
    assert isinstance(m.actual_modulation_order, int) and m.actual_modulation_order >= 0
    assert isinstance(m.num_sample_symbols, int) and m.num_sample_symbols >= 0
    assert isinstance(m.sample_length, int) and m.sample_length >= 0

    # samples shape: list of [I, Q] float pairs
    assert isinstance(m.samples, list)
    assert all(isinstance(pair, (list, tuple)) and len(pair) == 2 for pair in m.samples)
    assert all(
        all(isinstance(v, (int, float)) and math.isfinite(v) for v in pair)
        for pair in m.samples
    )

    # length consistency: payload bytes / 4 => number of complex pairs
    assert len(m.samples) == m.sample_length // 4


@pytest.mark.pnm
def test_constellation_samples_decoded_nonempty_and_reasonable_range() -> None:
    cm = CmDsConstDispMeas(CONST_PATH.read_bytes())
    m = cm.to_model()

    # Must have some content
    assert len(m.samples) > 0

    # Values should be small (fixed-point 2.13 typical ranges); don't over-constrain:
    # just ensure not absurd. (Avoid strict bounds—device-dependent.)
    flat = [v for pair in m.samples for v in pair]
    assert all(math.isfinite(v) for v in flat)
    # Very loose sanity: within a few standard units
    assert all(-10.0 <= v <= 10.0 for v in flat)


@pytest.mark.pnm
def test_constellation_serialization_roundtrip() -> None:
    cm = CmDsConstDispMeas(CONST_PATH.read_bytes())

    d = cm.to_dict()
    j = cm.to_json()

    # Ensure core keys exist and JSON serializes without error
    for key in ("pnm_header", "channel_id", "mac_address", "samples", "sample_length"):
        assert key in d

    import json

    parsed = json.loads(j)
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_non_constellation_file_is_rejected() -> None:
    with pytest.raises(ValueError):
        _ = CmDsConstDispMeas(NON_CONST_PATH.read_bytes())
# FILE: tests/test_pnm_factory_fetcher.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path
from struct import pack

import pytest

from pypnm.pnm.parser.CmDsConstDispMeas import CmDsConstDispMeas
from pypnm.pnm.parser.CmDsHist import CmDsHist
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef
from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer
from pypnm.pnm.parser.CmSpectrumAnalysis import CmSpectrumAnalysis
from pypnm.pnm.parser.fetch_pnm_process import PnmFileTypeObjectFetcher

DATA_DIR = Path(__file__).parent / "files"


@pytest.mark.pnm
@pytest.mark.parametrize(
    "filename, expected_cls",
    [
        ("rxmer.bin", CmDsOfdmRxMer),
        ("channel_estimation.bin", CmDsOfdmChanEstimateCoef),
        ("const_display.bin", CmDsConstDispMeas),
        ("histogram.bin", CmDsHist),
        ("fec_summary.bin", CmDsOfdmFecSummary),
        ("modulation_profile.bin", CmDsOfdmModulationProfile),
        ("spectrum_analyzer.bin", CmSpectrumAnalysis),
    ],
)
def test_factory_returns_correct_parser(
    filename: str, expected_cls: type[object]
) -> None:
    blob = (DATA_DIR / filename).read_bytes()
    parser = PnmFileTypeObjectFetcher(blob).get_parser()
    assert isinstance(parser, expected_cls)
    # Smoketest that the parser can materialize a model/dict without exceptions
    assert hasattr(parser, "to_model") or hasattr(parser, "to_dict")
    _ = parser.to_model() if hasattr(parser, "to_model") else parser.to_dict()


@pytest.mark.pnm
def test_factory_unknown_type_raises_value_error() -> None:
    """
    Build a minimal, valid-looking PNM header with an unknown 3-char type ("PNX")
    so the factory cannot map it to a known parser.
    Header format (standard): '!3sBBBI'
    """
    # file_type="PNX", file_type_num=5, major=1, minor=0, capture_time=0
    header = pack("!3sBBBI", b"PNX", 5, 1, 0, 0)
    with pytest.raises(ValueError):
        PnmFileTypeObjectFetcher(header)
# FILE: tests/test_pnm_fec_summary_parse.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.model.parser_rtn_models import CmDsOfdmFecSummaryModel

DATA_DIR = Path(__file__).parent / "files"
FEC_PATH = DATA_DIR / "fec_summary.bin"


@pytest.fixture(scope="session")
def fec_bytes() -> bytes:
    return FEC_PATH.read_bytes()


@pytest.mark.pnm
def test_fec_summary_parses_and_model_shape(fec_bytes: bytes) -> None:
    """Basic parse + model shape."""
    fec = CmDsOfdmFecSummary(fec_bytes).to_model()
    assert isinstance(fec, CmDsOfdmFecSummaryModel)

    # top-level fields exist
    assert fec.channel_id >= 0
    assert (
        isinstance(fec.mac_address, str) and len(fec.mac_address) >= 11
    )  # "aa:bb:cc:dd:ee:ff"
    assert fec.num_profiles >= 0
    assert len(fec.fec_summary_data) == fec.num_profiles


@pytest.mark.pnm
def test_profiles_and_sets_are_consistent(fec_bytes: bytes) -> None:
    """Each profile has number_of_sets matching entry arrays, and values are sane."""
    model = CmDsOfdmFecSummary(fec_bytes).to_model()

    for p in model.fec_summary_data:
        assert p.number_of_sets == len(p.codeword_entries.timestamp)
        assert (
            len(p.codeword_entries.timestamp)
            == len(p.codeword_entries.total_codewords)
            == len(p.codeword_entries.corrected)
            == len(p.codeword_entries.uncorrectable)
        )

        # timestamps monotonic non-decreasing
        ts = p.codeword_entries.timestamp
        assert all(ts[i] <= ts[i + 1] for i in range(len(ts) - 1))

        # counts are non-negative and totals >= corrected + uncorrectable (best-effort sanity)
        tot = p.codeword_entries.total_codewords
        cor = p.codeword_entries.corrected
        unc = p.codeword_entries.uncorrectable
        assert all(x >= 0 for x in tot)
        assert all(x >= 0 for x in cor)
        assert all(x >= 0 for x in unc)
        assert all(t >= c + u for t, c, u in zip(tot, cor, unc, strict=False))


@pytest.mark.pnm
def test_capture_time_overridden_from_first_timestamp(fec_bytes: bytes) -> None:
    """
    FEC Summary PNN8 omits header capture_time; the parser should override it
    from the first timestamp in the first profile.
    """
    obj = CmDsOfdmFecSummary(fec_bytes)
    model = obj.to_model()

    # pull first timestamp actually parsed
    first_ts = model.fec_summary_data[0].codeword_entries.timestamp[0]
    assert model.pnm_header.capture_time == first_ts


@pytest.mark.pnm
def test_summary_type_label_is_readable(fec_bytes: bytes) -> None:
    model = CmDsOfdmFecSummary(fec_bytes).to_model()
    # label should be a non-empty string; known mapping currently has "24-hour interval" for type 2
    assert isinstance(model.summary_type_label, str) and model.summary_type_label


@pytest.mark.pnm
def test_serialization_roundtrip(fec_bytes: bytes) -> None:
    obj = CmDsOfdmFecSummary(fec_bytes)

    d = obj.to_dict()
    j = obj.to_model().model_dump_json()
    parsed = json.loads(j)

    # top-level keys should match
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_wrong_type_rejected() -> None:
    """Smoke check: feeding a non-FEC file should raise ValueError."""
    # Use another PNM sample as a negative test if present; fallback to rxmer.bin
    alt_path = DATA_DIR / "rxmer.bin"
    raw = alt_path.read_bytes()
    with pytest.raises(ValueError):
        _ = CmDsOfdmFecSummary(raw)
# FILE: tests/test_pnm_file_type_mapper.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_pnm_file_type_mapper.py
from __future__ import annotations

import pytest

from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_type_header_mapper import PnmFileTypeMapper


def test_test_to_file_type_mapping_round_trip() -> None:
    """
    Verify that every DocsPnmCmCtlTest → PnmFileType mapping works in both directions.
    """
    for test_type, file_type in PnmFileTypeMapper._test_to_file_type.items():
        assert PnmFileTypeMapper.get_file_type(test_type) is file_type
        assert PnmFileTypeMapper.get_test_type(file_type) is test_type


def test_all_mapped_tests_are_known_enums() -> None:
    """
    Ensure that all keys in the mapping are valid DocsPnmCmCtlTest members.
    """
    for test_type in PnmFileTypeMapper._test_to_file_type:
        assert isinstance(test_type, DocsPnmCmCtlTest)


def test_all_mapped_file_types_are_known_enums() -> None:
    """
    Ensure that all values in the mapping are valid PnmFileType members.
    """
    for file_type in PnmFileTypeMapper._test_to_file_type.values():
        assert isinstance(file_type, PnmFileType)


def test_unmapped_test_type_returns_none_if_any_exist() -> None:
    """
    If there are DocsPnmCmCtlTest members not present in the mapping,
    verify that get_file_type returns None for at least one of them.
    """
    unmapped_tests = [
        t for t in DocsPnmCmCtlTest if t not in PnmFileTypeMapper._test_to_file_type
    ]
    if not unmapped_tests:
        pytest.skip(
            "All DocsPnmCmCtlTest values are mapped; no unmapped test type to validate."
        )
    assert PnmFileTypeMapper.get_file_type(unmapped_tests[0]) is None


def test_unmapped_file_type_returns_none_if_any_exist() -> None:
    """
    If there are PnmFileType members not present in the mapping values,
    verify that get_test_type returns None for at least one of them.
    """
    mapped_file_types = set(PnmFileTypeMapper._test_to_file_type.values())
    unmapped_file_types = [ft for ft in PnmFileType if ft not in mapped_file_types]
    if not unmapped_file_types:
        pytest.skip(
            "All PnmFileType values are mapped; no unmapped file type to validate."
        )
    assert PnmFileTypeMapper.get_test_type(unmapped_file_types[0]) is None
# FILE: tests/test_pnm_header_each_file.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import time
from pathlib import Path

import pytest

from pypnm.lib.constants import DEFAULT_CAPTURE_TIME
from pypnm.lib.types import CaptureTime
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader

DATA_DIR = Path(__file__).parent / "files"

ALL_FILES = [
    "channel_estimation.bin",
    "const_display.bin",
    "fec_summary.bin",
    "histogram.bin",
    "modulation_profile.bin",
    "rxmer.bin",
    "spectrum_analyzer.bin",
]

MISSING_CAPTURE = {"fec_summary.bin"}  # PNN8 → no capture_time in header


def _p(name: str) -> Path:
    return DATA_DIR / name


@pytest.mark.pnm
def test_data_files_present() -> None:
    assert DATA_DIR.is_dir()
    for f in ALL_FILES:
        assert _p(f).is_file(), f"Missing test file: {f}"


@pytest.mark.pnm
@pytest.mark.parametrize("fname", ALL_FILES)
def test_pnm_header_per_file(fname: str) -> None:
    """Exercise PnmHeader parsing for each file and validate invariants."""
    data = _p(fname).read_bytes()
    hdr = PnmHeader.from_bytes(data)
    params = hdr.getPnmHeaderParameterModel()

    # Basic invariants for every file
    assert params.file_type is not None and len(params.file_type) == 3
    assert params.file_type_version >= 0
    assert params.major_version >= 0
    assert params.minor_version >= 0
    # payload is captured
    assert isinstance(hdr.pnm_data, (bytes, bytearray))

    # Header dict behavior
    d_full = hdr.getPnmHeader(header_only=False)
    d_hdr = hdr.getPnmHeader(header_only=True)
    assert "pnm_header" in d_full and "pnm_header" in d_hdr
    assert "data" in d_full and "data" not in d_hdr

    # File-type resolution should produce something (may be None if unknown)
    # This doesn’t force a specific enum—just tries to resolve it.
    _ = hdr.get_pnm_file_type()

    # capture_time semantics:
    if fname in MISSING_CAPTURE:
        # FEC summary omits capture_time → override must succeed
        ts = int(time.time())
        changed = hdr.override_capture_time(CaptureTime(ts))
        assert changed is True
        assert hdr.getPnmHeaderParameterModel().capture_time == ts
        assert hdr.getPnmHeaderParameterModel().capture_time != DEFAULT_CAPTURE_TIME
        # Sanity: if enum resolves, it must be the FEC summary type
        et = hdr.get_pnm_file_type()
        if et is not None:
            assert et == PnmFileType.OFDM_FEC_SUMMARY
    else:
        # Others should keep their original capture_time; override should be rejected
        before = hdr.getPnmHeaderParameterModel().capture_time
        changed = hdr.override_capture_time(CaptureTime(int(time.time())))
        after = hdr.getPnmHeaderParameterModel().capture_time
        assert changed is False
        assert after == before
# FILE: tests/test_pnm_histogram_parse.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia


from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsHist import CmDsHist

DATA_DIR = Path(__file__).parent / "files"
HIST_PATH = DATA_DIR / "histogram.bin"
NON_HIST_PATH = DATA_DIR / "rxmer.bin"  # valid PNM but wrong type -> negative test

MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


@pytest.fixture(scope="session")
def hist_bytes() -> bytes:
    return HIST_PATH.read_bytes()


@pytest.mark.pnm
def test_hist_parses_and_model_shape(hist_bytes: bytes) -> None:
    m = CmDsHist(hist_bytes).to_model()

    # Header present
    assert m.pnm_header is not None

    # MAC format from parser is hex with colons
    assert isinstance(m.mac_address, str) and MAC_RE.match(m.mac_address)

    # Symmetry is a single byte -> int
    assert isinstance(m.symmetry, int)
    assert m.symmetry >= 0  # don’t assume meaning, just non-negative

    # Length fields are consistent with arrays
    assert m.dwell_count_values_length == len(m.dwell_count_values) * 4
    assert m.hit_count_values_length == len(m.hit_count_values) * 4

    # Non-empty arrays expected for a real capture
    assert len(m.dwell_count_values) > 0
    assert len(m.hit_count_values) > 0

    # Values are non-negative integers (stored as 32-bit big-endian)
    assert all(isinstance(v, (int, float)) and v >= 0 for v in m.dwell_count_values)
    assert all(isinstance(v, (int, float)) and v >= 0 for v in m.hit_count_values)


@pytest.mark.pnm
def test_hist_serialization_roundtrip(hist_bytes: bytes) -> None:
    h = CmDsHist(hist_bytes)
    d = h.to_dict()
    j = h.to_json()

    parsed = json.loads(j)
    # Top-level keys should match
    assert set(parsed.keys()) == set(d.keys())

    # Spot-check nested keys exist
    for k in (
        "pnm_header",
        "mac_address",
        "symmetry",
        "dwell_count_values_length",
        "dwell_count_values",
        "hit_count_values_length",
        "hit_count_values",
    ):
        assert k in d and k in parsed


@pytest.mark.pnm
def test_non_hist_file_rejected() -> None:
    with pytest.raises(ValueError):
        _ = CmDsHist(NON_HIST_PATH.read_bytes())
# FILE: tests/test_pnm_modulation_profile_parse.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
from pypnm.pnm.parser.model.parser_rtn_models import CmDsOfdmModulationProfileModel

DATA_DIR = Path(__file__).parent / "files"
MODPROF_PATH = DATA_DIR / "modulation_profile.bin"
NON_MODPROF_PATH = DATA_DIR / "rxmer.bin"  # negative test sample


@pytest.fixture(scope="session")
def modprof_bytes() -> bytes:
    return MODPROF_PATH.read_bytes()


@pytest.mark.pnm
def test_modprof_parses_and_model_shape(modprof_bytes: bytes) -> None:
    mp = CmDsOfdmModulationProfile(modprof_bytes).to_model()
    assert isinstance(mp, CmDsOfdmModulationProfileModel)

    # Header & core fields
    assert mp.num_profiles >= 0
    assert mp.profile_data_length_bytes >= 0
    assert (
        isinstance(mp.mac_address, str) and len(mp.mac_address) >= 11
    )  # "aa:bb:cc:dd:ee:ff"
    assert mp.subcarrier_spacing > 0
    assert mp.first_active_subcarrier_index >= 0
    assert mp.subcarrier_zero_frequency >= 0

    # Profiles container aligns with count
    assert len(mp.profiles) == mp.num_profiles


@pytest.mark.pnm
def test_profile_schemes_valid_and_decoded(modprof_bytes: bytes) -> None:
    mp = CmDsOfdmModulationProfile(modprof_bytes).to_model()

    for profile in mp.profiles:
        # profile ids are non-negative
        assert profile.profile_id >= 0

        # schemes should be a list; if present, each has required fields
        assert isinstance(profile.schemes, list)
        for sch in profile.schemes:
            # Discriminated union: schema_type is 0 (range) or 1 (skip)
            assert sch.schema_type in (0, 1)
            if sch.schema_type == 0:
                # Range schema
                assert hasattr(sch, "modulation_order")
                assert isinstance(sch.modulation_order, str) and sch.modulation_order
                assert sch.num_subcarriers >= 0
            else:
                # Skip schema
                assert hasattr(sch, "main_modulation_order")
                assert hasattr(sch, "skip_modulation_order")
                assert (
                    isinstance(sch.main_modulation_order, str)
                    and sch.main_modulation_order
                )
                assert (
                    isinstance(sch.skip_modulation_order, str)
                    and sch.skip_modulation_order
                )
                assert sch.num_subcarriers >= 0


@pytest.mark.pnm
def test_serialization_roundtrip(modprof_bytes: bytes) -> None:
    obj = CmDsOfdmModulationProfile(modprof_bytes)

    d = obj.to_dict()
    j = obj.to_model().model_dump_json()
    parsed = json.loads(j)

    # Top-level keys parity
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_get_frequencies_current_behavior_is_empty(modprof_bytes: bytes) -> None:
    """
    get_frequencies currently returns [] (TODO noted in implementation).
    Keep this as a behavioral check until the TODO is implemented.
    """
    obj = CmDsOfdmModulationProfile(modprof_bytes)
    freqs = obj.get_frequencies()
    assert isinstance(freqs, list)
    assert len(freqs) == 0


@pytest.mark.pnm
def test_wrong_type_rejected() -> None:
    """Feeding a non-modulation-profile file should raise ValueError."""
    raw = NON_MODPROF_PATH.read_bytes()
    with pytest.raises(ValueError):
        _ = CmDsOfdmModulationProfile(raw)
# FILE: tests/test_pnm_parser_and_parameters.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.lib.mac_address import MacAddress
from pypnm.pnm.parser.CmDsConstDispMeas import CmDsConstDispMeas
from pypnm.pnm.parser.CmDsHist import CmDsHist
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef
from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_parameter import GetPnmParserAndParameters

DATA_DIR = Path(__file__).parent / "files"

# fname, supported, expected parser class (or None when unsupported)
CASES = [
    ("channel_estimation.bin", True, CmDsOfdmChanEstimateCoef),
    ("const_display.bin", True, CmDsConstDispMeas),
    ("fec_summary.bin", True, CmDsOfdmFecSummary),
    ("modulation_profile.bin", True, CmDsOfdmModulationProfile),
    ("rxmer.bin", True, CmDsOfdmRxMer),
    ("histogram.bin", True, CmDsHist),
    ("spectrum_analyzer.bin", False, None),
]


@pytest.mark.pnm
@pytest.mark.parametrize("fname,supported,parser_cls", CASES)
def test_get_pnm_parser_and_parameters_and_models(
    fname: str,
    supported: bool,
    parser_cls: type[object] | None,
) -> None:
    blob = (DATA_DIR / fname).read_bytes()
    wrapper = GetPnmParserAndParameters(blob)

    if not supported:
        with pytest.raises(NotImplementedError):
            _ = wrapper.to_model()
        with pytest.raises(NotImplementedError):
            _ = wrapper.get_parser()
        return

    # 1) High-level parameter model
    params = wrapper.to_model()
    assert isinstance(params.file_type, PnmFileType)
    assert isinstance(params.mac_address, str)

    params_dict = wrapper.to_dict()

    # file_type should be a PnmFileType enum in the dict as well
    assert "file_type" in params_dict
    ft = params_dict["file_type"]
    assert isinstance(ft, PnmFileType)
    assert ft is params.file_type

    # Canonical string like "PNN2", "PNN4", etc.
    ft_str = ft.value
    assert isinstance(ft_str, str)
    assert len(ft_str) >= 3

    # mac_address must be present and a string
    assert "mac_address" in params_dict
    assert isinstance(params_dict["mac_address"], str)

    # MAC sanity when formatted as aa:bb:...
    mac = params_dict["mac_address"]
    if mac:
        parts = mac.split(":")
        if all(len(p) == 2 for p in parts):
            assert all(0 <= int(p, 16) <= 0xFF for p in parts)

    # 2) Concrete parser + its own model
    parser, params_again = wrapper.get_parser()

    # Wrapper must return the same params instance/data
    assert params_again.file_type == params.file_type
    assert params_again.mac_address == params.mac_address

    # Concrete parser type must match the expected parser for this file
    assert isinstance(parser, parser_cls)

    # All concrete parsers must expose .to_model()
    model = parser.to_model()

    # Every measurement model should have mac_address and pnm_header
    assert hasattr(model, "mac_address")
    assert hasattr(model, "pnm_header")

    assert isinstance(model.mac_address, str)

    # If the top-level params has a non-null MAC, it must match the model MAC.
    # For file types where we intentionally don't propagate MAC (e.g. some headers),
    # params.mac_address will be the null MAC and we don't enforce equality.
    if params.mac_address != MacAddress.null():
        assert model.mac_address == params.mac_address

    # pnm_header should have file_type and file_type_version so we can reconstruct the PNM code
    header = model.pnm_header
    assert hasattr(header, "file_type")
    assert hasattr(header, "file_type_version")

    header_code = f"{header.file_type}{header.file_type_version}"
    assert header_code == ft_str
# FILE: tests/test_pnm_rxmer_parse.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer

DATA_DIR = Path(__file__).parent / "files"
RXMER_PATH = DATA_DIR / "rxmer.bin"
NON_RXMER_PATH = DATA_DIR / "fec_summary.bin"  # negative test sample


@pytest.fixture(scope="session")
def rxmer_bytes() -> bytes:
    return RXMER_PATH.read_bytes()


@pytest.mark.pnm
def test_rxmer_file_loads_and_models_ok(rxmer_bytes: bytes) -> None:
    rx = CmDsOfdmRxMer(rxmer_bytes).to_model()

    # basic shape
    assert rx.data_length == len(rx.values)
    assert rx.value_units == "dB"
    assert rx.occupied_channel_bandwidth == rx.data_length * rx.subcarrier_spacing

    # stats: Pydantic -> dict for key checks
    stats = rx.signal_statistics.model_dump()
    assert "mean" in stats
    mean = stats["mean"]

    # Some implementations expose min/max directly; others via quantiles; fall back to computed.
    if "min" in stats and "max" in stats:
        smin, smax = stats["min"], stats["max"]
    elif "quantiles" in stats and isinstance(stats["quantiles"], dict):
        q = stats["quantiles"]
        # try common keys, else fallback to computed
        smin = q.get("min", min(rx.values))
        smax = q.get("max", max(rx.values))
    else:
        smin, smax = min(rx.values), max(rx.values)

    assert smin <= mean <= smax

    # modulation stats is already a dict
    mod = rx.modulation_statistics
    assert isinstance(mod, dict) and mod


@pytest.mark.pnm
def test_rxmer_values_in_range_and_cached() -> None:
    raw = RXMER_PATH.read_bytes()
    rxmer = CmDsOfdmRxMer(raw)

    vals1 = rxmer.get_rxmer_values()
    # Quarter-dB decoded and clamped [0.0, 63.5]
    assert all((0.0 <= v <= 63.5) for v in vals1)

    # Cached behavior: second call returns identical content
    vals2 = rxmer.get_rxmer_values()
    assert vals1 is vals2 or vals1 == vals2  # either same object or same content


@pytest.mark.pnm
def test_rxmer_frequencies_monotonic_and_sized() -> None:
    raw = RXMER_PATH.read_bytes()
    rxmer = CmDsOfdmRxMer(raw)
    model = rxmer.to_model()

    freqs = rxmer.get_frequencies()
    assert len(freqs) == model.data_length

    # Monotonic ascending with step == subcarrier spacing
    if len(freqs) >= 2:
        step = freqs[1] - freqs[0]
        assert step == model.subcarrier_spacing
        assert all(freqs[i] < freqs[i + 1] for i in range(len(freqs) - 1))


@pytest.mark.pnm
def test_rxmer_serialization_roundtrip() -> None:
    raw = RXMER_PATH.read_bytes()
    rxmer = CmDsOfdmRxMer(raw)

    d = rxmer.to_dict()
    j = rxmer.to_json()

    # JSON should be valid and represent same keys as dict (at least top-level)
    parsed = json.loads(j)
    assert set(parsed.keys()) == set(d.keys())


@pytest.mark.pnm
def test_non_rxmer_file_rejected() -> None:
    raw = NON_RXMER_PATH.read_bytes()
    with pytest.raises(ValueError):
        _ = CmDsOfdmRxMer(raw)
# FILE: tests/test_pnm_spectrum_analysis_parse.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmSpectrumAnalysis import CmSpectrumAnalysis

DATA_DIR = Path(__file__).parent / "files"
SPEC_PATH = DATA_DIR / "spectrum_analyzer.bin"


@pytest.fixture(scope="session")
def spectrum_bytes() -> bytes:
    return SPEC_PATH.read_bytes()


@pytest.mark.pnm
def test_spectrum_analyzer_parses_and_model_shape(spectrum_bytes: bytes) -> None:
    sa = CmSpectrumAnalysis(spectrum_bytes)
    m = sa.to_model()

    # header basics
    assert m.num_bins_per_segment >= 1
    assert m.segment_frequency_span > 0
    assert m.bin_frequency_spacing > 0

    # numeric types can be int or float depending on decode
    assert isinstance(m.first_segment_center_frequency, (int, float))
    assert isinstance(m.last_segment_center_frequency, (int, float))
    assert isinstance(m.spectrum_analysis_data_length, int)

    # serialized in dict/json via field_serializer
    assert isinstance(m.spectrum_analysis_data, (bytes, str))

    # segments present & each segment is a list[float]
    assert len(m.amplitude_bin_segments_float) >= 1
    for seg in m.amplitude_bin_segments_float:
        assert isinstance(seg, list)
        assert all(isinstance(v, float) for v in seg)
        assert len(seg) <= m.num_bins_per_segment

    if len(m.amplitude_bin_segments_float) > 1:
        for seg in m.amplitude_bin_segments_float[:-1]:
            assert len(seg) == m.num_bins_per_segment


@pytest.mark.pnm
def test_spectrum_analyzer_json_and_dict_roundtrip(spectrum_bytes: bytes) -> None:
    sa = CmSpectrumAnalysis(spectrum_bytes)

    d = sa.to_dict()
    j = sa.to_json()
    parsed = json.loads(j)

    # top-level keys align
    assert set(parsed.keys()) == set(d.keys())

    # In both dict and JSON, spectrum_analysis_data is hex string (due to field_serializer)
    assert isinstance(d["spectrum_analysis_data"], str)
    assert isinstance(parsed["spectrum_analysis_data"], str)
    assert parsed["spectrum_analysis_data"] == d["spectrum_analysis_data"]


@pytest.mark.pnm
def test_bin_frequency_spacing_consistency(spectrum_bytes: bytes) -> None:
    sa = CmSpectrumAnalysis(spectrum_bytes)
    m = sa.to_model()

    expect = int(m.segment_frequency_span / m.num_bins_per_segment)
    assert m.bin_frequency_spacing == expect
# FILE: tests/test_scalar_value_converters.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.lib.types import ScalarValue
from pypnm.snmp.casts import (
    as_bool,
    as_float0,
    as_float2,
    as_int,
    as_str,
    measurement_status,
    per_hundred,
    per_thousand,
    scale,
)


@pytest.mark.parametrize("value", [0, 1, "0", "1", 2, "2"])
def test_measurement_status_valid_enum_values(value: ScalarValue) -> None:
    """
    measurement_status should map numeric codes to MeasStatusType string form.
    We use the first enum member as a reference to avoid hard-coding values.
    """
    first_member = list(MeasStatusType)[0]
    # Only run a strict check when the value matches the first_member.value,
    # otherwise we just verify that valid ints do not raise and produce a string.
    if int(value) == int(first_member.value):
        assert measurement_status(value) == str(first_member)
    else:
        out = measurement_status(value)
        assert isinstance(out, str)
        assert out != ""


@pytest.mark.parametrize("value", ["not-an-int", "abc", "", object()])
def test_measurement_status_invalid_returns_other(value: object) -> None:
    assert measurement_status(value) == "other"


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, False),
        (1, True),
        ("0", False),
        ("1", True),
        ("2", True),  # bool(2) is True
        ("", False),  # fallback to bool("") -> False
        ("false", True),  # int() fails, so bool("false") -> True
    ],
)
def test_as_bool_behaviour(value: ScalarValue, expected: bool) -> None:
    assert as_bool(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, 0),
        (1, 1),
        (-5, -5),
        ("10", 10),
        ("-3", -3),
    ],
)
def test_as_int_converts_numeric_strings_and_ints(
    value: ScalarValue, expected: int
) -> None:
    assert as_int(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, "0"),
        (1, "1"),
        (-3, "-3"),
        (1.5, "1.5"),
        ("abc", "abc"),
    ],
)
def test_as_str_round_trips_to_string(value: ScalarValue, expected: str) -> None:
    assert as_str(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, 0.0),
        (1, 1.0),
        (-3, -3.0),
        ("2.5", 2.5),
        ("0", 0.0),
    ],
)
def test_as_float0_basic_conversion(value: ScalarValue, expected: float) -> None:
    assert as_float0(value) == pytest.approx(expected)


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, 0.0),
        (1, 0.01),
        (123, 1.23),
        ("250", 2.50),
        (-100, -1.00),
    ],
)
def test_as_float2_fixed_point_two_decimals(
    value: ScalarValue, expected: float
) -> None:
    assert as_float2(value) == pytest.approx(expected, rel=1e-9, abs=1e-9)


@pytest.mark.parametrize(
    "value, factor, ndigits, expected",
    [
        (100, 0.01, None, 1.0),
        (100, 0.01, 2, 1.00),
        ("250", 0.1, 1, 25.0),
        (5, 2.0, 0, 10.0),
    ],
)
def test_scale_with_and_without_rounding(
    value: ScalarValue,
    factor: float,
    ndigits: int | None,
    expected: float,
) -> None:
    out = scale(value, factor=factor, ndigits=ndigits)
    assert out == pytest.approx(expected, rel=1e-9, abs=1e-9)


@pytest.mark.parametrize(
    "value, ndigits, expected",
    [
        (0, 2, 0.0),
        (100, 2, 1.0),
        ("250", 2, 2.5),
        (123, 1, 1.2),
    ],
)
def test_per_hundred_normalization(
    value: ScalarValue, ndigits: int, expected: float
) -> None:
    assert per_hundred(value, ndigits=ndigits) == pytest.approx(
        expected, rel=1e-9, abs=1e-9
    )


@pytest.mark.parametrize(
    "value, ndigits, expected",
    [
        (0, 3, 0.0),
        (1000, 3, 1.0),
        ("2500", 3, 2.5),
        (1234, 3, 1.234),
        (1234, 2, 1.23),
    ],
)
def test_per_thousand_normalization(
    value: ScalarValue, ndigits: int, expected: float
) -> None:
    assert per_thousand(value, ndigits=ndigits) == pytest.approx(
        expected, rel=1e-9, abs=1e-9
    )
# FILE: tests/test_shannon.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_shannon.py
from __future__ import annotations

import math

import numpy as np
import pytest

from pypnm.lib.signal_processing.shan.shannon import Shannon
from pypnm.pnm.parser.CmDsOfdmModulationProfile import ModulationOrderType


def test_snr_to_bits_examples() -> None:
    assert Shannon._snr_to_bits(0.0) == 1
    assert Shannon._snr_to_bits(3.0) == 1
    assert Shannon._snr_to_bits(10.0) == 3
    assert Shannon._snr_to_bits(30.0) == 9


def test_bits_to_snr_and_inverse_relations() -> None:
    expected_db = 10.0 * math.log10((2**8) - 1)
    assert Shannon.bits_to_snr(8) == pytest.approx(expected_db, rel=1e-12)
    with pytest.raises(ValueError):
        Shannon.bits_to_snr(0)


def test_bits_from_symbol_count() -> None:
    assert Shannon.bits_from_symbol_count(1) == 0
    assert Shannon.bits_from_symbol_count(2) == 1
    assert Shannon.bits_from_symbol_count(256) == 8
    with pytest.raises(ValueError):
        Shannon.bits_from_symbol_count(0)


def test_from_modulation_and_getters() -> None:
    sh = Shannon.from_modulation("qam_256")
    target_bits = 8
    # Allow one-bit drop due to FP rounding of 10*log10(2**bits - 1)
    assert sh.bits in (target_bits, target_bits - 1)
    # SNR should match theoretical for target_bits
    assert sh.get_snr_db() == pytest.approx(Shannon.bits_to_snr(target_bits), rel=1e-12)


def test_from_modulation_type_enum() -> None:
    sh = Shannon.from_modulation_type(ModulationOrderType.qam_256)
    target_bits = 8
    assert sh.bits in (target_bits, target_bits - 1)
    assert sh.get_snr_db() == pytest.approx(Shannon.bits_to_snr(target_bits), rel=1e-12)


def test_snr_from_modulation_matches_bits_to_snr() -> None:
    by_name = Shannon.snr_from_modulation("qam_256")
    by_bits = Shannon.bits_to_snr(8)
    assert by_name == pytest.approx(by_bits, rel=1e-12)
    with pytest.raises(ValueError):
        Shannon.snr_from_modulation("qam_999")


def test_snr_to_limit_vectorized_and_scalar() -> None:
    snrs = [0.0, 3.0, 10.0, 30.0]
    expected = [Shannon._snr_to_bits(s) for s in snrs]
    assert Shannon.snr_to_limit(snrs) == expected
    arr = np.array(snrs, dtype=float)
    assert Shannon.snr_to_limit(arr) == expected
    assert Shannon.snr_to_limit(10.0) == [Shannon._snr_to_bits(10.0)]


def test_snr_to_snr_limit_roundtrip() -> None:
    snrs = [0.0, 10.0, 24.0, 30.0]
    bits_limits = Shannon.snr_to_limit(snrs)
    expected_db_limits = [Shannon.bits_to_snr(b) for b in bits_limits]
    got = Shannon.snr_to_snr_limit(snrs)
    assert len(got) == len(expected_db_limits)
    for g, e in zip(got, expected_db_limits, strict=False):
        assert g == pytest.approx(e, rel=1e-12)
# FILE: tests/test_shannon_series.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_shannon_series.py
from __future__ import annotations

import json
import math

import pytest

from pypnm.lib.signal_processing.shan.series import ShannonSeries
from pypnm.lib.signal_processing.shan.shannon import Shannon


def test_invalid_inputs_raise() -> None:
    with pytest.raises(ValueError):
        ShannonSeries([-1.0])
    with pytest.raises(ValueError):
        ShannonSeries([float("nan")])
    with pytest.raises(ValueError):
        ShannonSeries([float("inf")])


def test_basic_series_outputs() -> None:
    snrs = [0.0, 3.0, 10.0, 30.0]
    series = ShannonSeries(snrs)

    # lengths
    assert len(series.snr_db_values) == len(snrs)
    assert len(series.bits_list) == len(snrs)
    assert len(series.modulations) == len(snrs)
    assert len(series.limit()) == len(snrs)

    # per-element expectations via Shannon
    exp_bits = [Shannon(s).bits for s in snrs]
    exp_mods = [Shannon(s).get_modulation() for s in snrs]
    assert series.bits_list == exp_bits
    assert series.modulations == exp_mods

    # average bits within bounds
    avg = series.average_bits()
    assert isinstance(avg, float)
    assert min(exp_bits) <= avg <= max(exp_bits)

    # max modulation matches the highest bits entry
    assert series.max_modulation() == exp_mods[exp_bits.index(max(exp_bits))]


def test_supported_modulation_counts_and_model() -> None:
    snrs = [0.0, 6.0, 12.0, 18.0, 24.0, 30.0]
    series = ShannonSeries(snrs)

    # counts should include all known modulations from Shannon.QAM_MODULATIONS
    known_mods = set(Shannon.QAM_MODULATIONS.values())
    counts = series.supported_modulation_counts()
    assert set(counts.keys()) == known_mods

    # monotonic: higher-order modulations cannot have higher counts than lower-order ones
    # build a list sorted by bits (ascending)
    bits_sorted = sorted(Shannon.QAM_MODULATIONS.items(), key=lambda kv: kv[0])
    prev = math.inf
    for _bits, name in bits_sorted:
        c = counts[name]
        assert isinstance(c, int) and 0 <= c <= len(snrs)
        assert c <= prev
        prev = c

    # model / dict / json shapes
    model = series.to_model()
    d = series.to_dict()
    j = series.to_json()
    j_obj = json.loads(j)

    assert model.bits_per_symbol == series.bits_list
    assert model.modulations == series.modulations
    assert model.snr_db_values == series.snr_db_values
    assert set(model.supported_modulation_counts.keys()) == known_mods
    assert d["bits_per_symbol"] == series.bits_list
    assert set(d["supported_modulation_counts"].keys()) == known_mods
    assert j_obj.get("avg", True)  # tolerate additional fields if present


def test_repr_and_str() -> None:
    snrs = [0.0, 10.0]
    series = ShannonSeries(snrs)
    r = repr(series)
    s = str(series)
    assert "ShannonSeries" in r
    assert "SNR values" in s
# FILE: tests/test_signal_statistics.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import math

import numpy as np
import pytest

from pypnm.pnm.lib.signal_statistics import SignalStatistics, SignalStatisticsModel


def _isclose(a: float, b: float, rtol: float = 1e-12, atol: float = 1e-12) -> float:
    return float(np.isclose(a, b, rtol=rtol, atol=atol))


def _allclose(a: float, b: float, rtol: float = 1e-12, atol: float = 1e-12) -> bool:
    return bool(np.allclose(a, b, rtol=rtol, atol=atol))


def test_rejects_empty_input() -> None:
    with pytest.raises(ValueError):
        SignalStatistics([]).compute()  # type: ignore[arg-type]


def test_basic_stats_on_simple_vector() -> None:
    x = np.array([1.0, 2.0, 3.0, 4.0])
    s = SignalStatistics(x).compute()

    # mean / median
    assert _isclose(s.mean, np.mean(x))
    assert _isclose(s.median, np.median(x))

    # std/variance (population)
    assert _isclose(s.std, np.std(x))
    assert _isclose(s.variance, np.var(x))
    assert _isclose(s.std**2, s.variance)

    # power = mean(x^2)
    assert _isclose(s.power, np.mean(x**2))

    # peak-to-peak
    assert _isclose(s.peak_to_peak, np.ptp(x))

    # mean absolute deviation around mean
    mad = np.mean(np.abs(x - x.mean()))
    assert _isclose(s.mean_abs_deviation, mad)

    # crest factor = max(|x|)/sqrt(power)
    peak = np.abs(x).max()
    expect_cf = peak / math.sqrt(np.mean(x**2))
    assert _isclose(s.crest_factor, expect_cf)

    # zero crossing rate / count
    crossings = int(np.sum(x[:-1] * x[1:] < 0))
    expect_zcr = crossings / (len(x) - 1)
    assert s.zero_crossings == crossings
    assert _isclose(s.zero_crossing_rate, expect_zcr)


def test_handles_single_sample() -> None:
    x = np.array([3.5])
    s = SignalStatistics(x).compute()

    # With one sample:
    assert _isclose(s.mean, 3.5)
    assert _isclose(s.median, 3.5)
    assert _isclose(s.std, 0.0)
    assert _isclose(s.variance, 0.0)
    assert _isclose(s.power, 3.5**2)
    assert _isclose(s.peak_to_peak, 0.0)
    assert _isclose(s.mean_abs_deviation, 0.0)
    # zero-crossing metrics defined this way in implementation:
    assert s.zero_crossings == 0
    assert _isclose(s.zero_crossing_rate, 0.0)

    # skewness/kurtosis are NaN when std == 0
    assert math.isnan(s.skewness)
    assert math.isnan(s.kurtosis)

    # crest factor with one nonzero value equals 1.0
    assert _isclose(s.crest_factor, 1.0)


def test_constant_signal_properties() -> None:
    x = np.ones(256) * -7.0
    s = SignalStatistics(x).compute()

    assert _isclose(s.mean, -7.0)
    assert _isclose(s.median, -7.0)
    assert _isclose(s.std, 0.0)
    assert _isclose(s.variance, 0.0)
    assert _isclose(s.power, 49.0)
    assert _isclose(s.peak_to_peak, 0.0)
    assert _isclose(s.mean_abs_deviation, 0.0)
    assert s.zero_crossings == 0
    assert _isclose(s.zero_crossing_rate, 0.0)
    assert math.isnan(s.skewness)
    assert math.isnan(s.kurtosis)
    # crest factor = |peak|/sqrt(power) = 7 / 7 = 1
    assert _isclose(s.crest_factor, 1.0)


def test_random_signal_matches_numpy() -> None:
    rng = np.random.default_rng(12345)
    x = rng.normal(loc=0.0, scale=2.0, size=10_000)
    s = SignalStatistics(x).compute()

    # basic alignment with numpy (population stats)
    assert _isclose(s.mean, np.mean(x), rtol=1e-9, atol=1e-9)
    assert _isclose(s.std, np.std(x), rtol=1e-9, atol=1e-9)
    assert _isclose(s.variance, np.var(x), rtol=1e-9, atol=1e-9)
    assert _isclose(s.power, np.mean(x**2), rtol=1e-9, atol=1e-9)

    # zero-crossings sanity: for zero-mean Gaussian, ZCR ~ 0.5
    assert 0.45 <= s.zero_crossing_rate <= 0.55


def test_nd_shapes_are_flattened() -> None:
    x2d = np.array([[1.0, -2.0, 3.0], [4.0, -5.0, 6.0]])
    s = SignalStatistics(x2d).compute()
    x1d = x2d.flatten()
    s_ref = SignalStatistics(x1d).compute()

    # Every numeric field should match after flatten
    for field in SignalStatisticsModel.model_fields:
        v = getattr(s, field)
        v_ref = getattr(s_ref, field)
        if isinstance(v, float) and math.isnan(v):
            assert isinstance(v_ref, float) and math.isnan(v_ref)
        else:
            assert _isclose(v, v_ref)


def test_model_serialization_roundtrip() -> None:
    x = np.array([0.0, 1.0, -1.0, 2.0, -2.0])
    s = SignalStatistics(x).compute()

    # dict keys present
    d = s.model_dump()
    for key in SignalStatisticsModel.model_fields:
        assert key in d

    # JSON round-trip
    j = s.model_dump_json()
    parsed = json.loads(j)
    assert set(parsed.keys()) == set(d.keys())
# FILE: tests/test_utils_time_stamp.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_utils_time_stamp.py
from __future__ import annotations

import time

import pytest

from pypnm.lib.utils import Generate, TimeUnit


def test_time_unit_values() -> None:
    """
    Verify that TimeUnit enum members have the expected string values.
    """
    assert TimeUnit.SECONDS.value == "s"
    assert TimeUnit.MILLISECONDS.value == "ms"
    assert TimeUnit.NANOSECONDS.value == "ns"


def test_time_stamp_default_is_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Ensure the default time_stamp() call uses seconds and int(time.time()).
    """
    calls = {"time": 0, "time_ns": 0}

    def fake_time() -> float:
        calls["time"] += 1
        return 1_234.567

    def fake_time_ns() -> int:
        calls["time_ns"] += 1
        return 999_999_999

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "time_ns", fake_time_ns)

    ts = Generate.time_stamp()
    assert ts == 1_234
    assert calls["time"] == 1
    assert calls["time_ns"] == 0


def test_time_stamp_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify explicit TimeUnit.SECONDS returns truncated seconds from time.time().
    """
    calls = {"time": 0, "time_ns": 0}

    def fake_time() -> float:
        calls["time"] += 1
        return 2_000.999

    def fake_time_ns() -> int:
        calls["time_ns"] += 1
        return 0

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "time_ns", fake_time_ns)

    ts = Generate.time_stamp(TimeUnit.SECONDS)
    assert ts == 2_000
    assert calls["time"] == 1
    assert calls["time_ns"] == 0


def test_time_stamp_milliseconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify TimeUnit.MILLISECONDS uses time.time_ns() and converts to ms.
    """
    calls = {"time": 0, "time_ns": 0}

    def fake_time() -> float:
        calls["time"] += 1
        return 0.0

    def fake_time_ns() -> int:
        calls["time_ns"] += 1
        return 1_234_567_890  # ns

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "time_ns", fake_time_ns)

    ts = Generate.time_stamp(TimeUnit.MILLISECONDS)
    assert ts == 1_234_567_890 // 1_000_000
    assert calls["time_ns"] == 1
    # time() is never used in this branch
    assert calls["time"] == 0


def test_time_stamp_nanoseconds(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify TimeUnit.NANOSECONDS returns the raw value from time.time_ns().
    """
    calls = {"time": 0, "time_ns": 0}

    def fake_time() -> float:
        calls["time"] += 1
        return 0.0

    def fake_time_ns() -> int:
        calls["time_ns"] += 1
        return 987_654_321

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "time_ns", fake_time_ns)

    ts = Generate.time_stamp(TimeUnit.NANOSECONDS)
    assert ts == 987_654_321
    assert calls["time_ns"] == 1
    # time() is never used in this branch
    assert calls["time"] == 0
# FILE: tools/maintenance/add-required-python-headers.py
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

"""
Ensure each .py file has:
1) SPDX Apache-2.0 header
2) Current-year copyright
3) (Optionally) `from __future__ import annotations`

Usage:
  ./tools/maintenance/add-required-python-headers.py [ROOT_DIR] [--exclude a,b] \
    [--future {auto,yes,no}] [--author "Name"] [--year 2025] [--verbose]
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from datetime import datetime

DEFAULT_AUTHOR = "Maurice Garcia"
DEFAULT_YEAR = datetime.now().year
SPDX_ID = "Apache-2.0"
SPDX_LINE = f"# SPDX-License-Identifier: {SPDX_ID}\n"
COPYRIGHT_TEMPLATE = "# Copyright (c) {year} {author}\n"
FUTURE_LINE = "from __future__ import annotations\n"
DOCSTRING_NOT_FOUND = -1
MAX_HEADER_SCAN_LINES = 12
COPYRIGHT_INSERT_SCAN_LINES = 5

COPYRIGHT_RE = re.compile(r"^#\s*Copyright\s*\(c\)\s*(\d{4})(?:-(\d{4}))?\s+(.*)$")
ENCODING_RE = re.compile(r"^#.*coding[:=]\s*([-\w.]+)")
SPDX_RE = re.compile(r"^#\s*SPDX-License-Identifier:\s*(.+)$")

DEFAULT_EXCLUDED_DIRS: set[str] = {
    ".git",
    ".env",
    "env",
    "venv",
    ".venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "node_modules",
    "build",
    "dist",
    ".idea",
    ".vscode",
}


class HeaderUpdater:
    """Update SPDX and copyright headers across a directory tree."""

    def __init__(
        self,
        author: str,
        year: int,
        add_future: bool,
        extra_excluded: set[str],
        verbose: bool,
    ) -> None:
        self.author = author
        self.year = year
        self.add_future = add_future
        self.extra_excluded = extra_excluded
        self.verbose = verbose

    def run(self, root: str) -> None:
        """Scan the root directory and update all Python files in place."""
        if self._should_skip_dir(root):
            if self.verbose:
                print(f"⏭ Root appears to be a virtualenv or excluded: {root}")
            return

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d
                for d in dirnames
                if not self._should_skip_dir(os.path.join(dirpath, d))
            ]
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                full_path = os.path.join(dirpath, filename)
                try:
                    self._ensure_header_and_future(full_path)
                except Exception as exc:
                    print(f"❌ Error processing {full_path}: {exc}")

    def _ensure_header_and_future(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()

        original = lines[:]
        prefix, remainder = self._split_shebang_encoding(lines)

        body: list[str] = []
        header_added = False
        header_updated = False

        spdx_idx = self._find_spdx_line_index(lines)
        if spdx_idx is None:
            body.append(SPDX_LINE)
            body.append(self._copyright_line())
            body.append("\n")
            header_added = True
        else:
            spdx_match = SPDX_RE.match(lines[spdx_idx])
            if spdx_match is not None:
                existing_spdx = spdx_match.group(1).strip()
                if existing_spdx != SPDX_ID:
                    lines[spdx_idx] = SPDX_LINE
                    header_updated = True

            copyright_idx = self._find_copyright_line_index(lines)
            if copyright_idx is not None:
                match = COPYRIGHT_RE.match(lines[copyright_idx])
                if match is not None:
                    start_year = int(match.group(1))
                    end_year_text = match.group(2)
                    old_author = match.group(3).strip()
                    if end_year_text is None:
                        if start_year != self.year:
                            lines[copyright_idx] = self._copyright_line(
                                author=old_author or self.author,
                                start_year=start_year,
                            )
                            header_updated = True
                    else:
                        end_year = int(end_year_text)
                        if end_year != self.year:
                            lines[copyright_idx] = self._copyright_line(
                                author=old_author or self.author,
                                start_year=start_year,
                            )
                            header_updated = True
            else:
                rem_copy = remainder[:]
                inserted = False
                for index, line in enumerate(rem_copy[:COPYRIGHT_INSERT_SCAN_LINES]):
                    if "SPDX-License-Identifier:" in line:
                        insert_at = index + 1
                        rem_copy.insert(insert_at, self._copyright_line())
                        rem_copy.insert(insert_at + 1, "\n")
                        remainder = rem_copy
                        header_updated = True
                        inserted = True
                        break
                if not inserted:
                    body.append(SPDX_LINE)
                    body.append(self._copyright_line())
                    body.append("\n")
                    header_added = True

        body.extend(remainder)

        future_added = False
        if self.add_future and not self._has_future_import(lines):
            ds_start, ds_end = self._find_module_docstring_span(body)
            insert_at = 0 if ds_start == DOCSTRING_NOT_FOUND else ds_end + 1
            if insert_at < len(body) and body[insert_at].strip():
                body.insert(insert_at, "\n")
                insert_at += 1
            body.insert(insert_at, FUTURE_LINE)
            insert_at += 1
            if insert_at >= len(body) or body[insert_at].strip():
                body.insert(insert_at, "\n")
            future_added = True

        new_lines = prefix + body

        if new_lines != original:
            with open(path, "w", encoding="utf-8") as handle:
                handle.writelines(new_lines)
            tags = []
            if header_added:
                tags.append("header")
            if header_updated and not header_added:
                tags.append("copyright-year")
            if future_added:
                tags.append("future")
            tag = "+".join(tags) if tags else "modified"
            print(f"✅ Updated ({tag}): {path}")
        else:
            if self.verbose:
                print(f"⏭ No changes: {path}")

    def _copyright_line(self, author: str | None = None, start_year: int | None = None) -> str:
        year_text = str(self.year)
        if start_year is not None and start_year != self.year:
            year_text = f"{start_year}-{self.year}"
        return COPYRIGHT_TEMPLATE.format(
            year=year_text,
            author=author or self.author,
        )

    def _find_spdx_line_index(self, lines: list[str]) -> int | None:
        for index, line in enumerate(lines[:MAX_HEADER_SCAN_LINES]):
            if SPDX_RE.match(line):
                return index
        return None

    def _find_copyright_line_index(self, lines: list[str]) -> int | None:
        for index, line in enumerate(lines[:MAX_HEADER_SCAN_LINES]):
            if COPYRIGHT_RE.match(line):
                return index
        return None

    def _has_future_import(self, lines: list[str]) -> bool:
        return "from __future__ import annotations" in "".join(lines)

    def _split_shebang_encoding(self, lines: list[str]) -> tuple[list[str], list[str]]:
        prefix: list[str] = []
        index = 0
        if lines and lines[0].startswith("#!"):
            prefix.append(lines[0])
            index = 1
        if len(lines) > index and ENCODING_RE.match(lines[index] or ""):
            prefix.append(lines[index])
            index += 1
        return prefix, lines[index:]

    def _find_module_docstring_span(self, body_lines: list[str]) -> tuple[int, int]:
        text = "".join(body_lines)
        try:
            module = ast.parse(text)
        except Exception:
            return DOCSTRING_NOT_FOUND, DOCSTRING_NOT_FOUND
        if not getattr(module, "body", None):
            return DOCSTRING_NOT_FOUND, DOCSTRING_NOT_FOUND
        first = module.body[0]
        if isinstance(first, ast.Expr) and isinstance(
            getattr(first, "value", None),
            (ast.Str, ast.Constant),
        ):
            value = (
                first.value.s
                if isinstance(first.value, ast.Str)
                else (
                    first.value.value
                    if isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)
                    else None
                )
            )
            if isinstance(value, str):
                return first.lineno - 1, first.end_lineno - 1
        return DOCSTRING_NOT_FOUND, DOCSTRING_NOT_FOUND

    def _is_virtualenv_dir(self, path: str) -> bool:
        if os.path.isfile(os.path.join(path, "pyvenv.cfg")):
            return True
        if os.path.isfile(os.path.join(path, "bin", "activate")):
            return True
        if os.path.isfile(os.path.join(path, "Scripts", "activate")):
            return True
        return False

    def _is_site_packages_path(self, path: str) -> bool:
        return "site-packages" in set(path.split(os.sep))

    def _should_skip_dir(self, path: str) -> bool:
        base = os.path.basename(path)
        if base in DEFAULT_EXCLUDED_DIRS or base in self.extra_excluded:
            return True
        if os.path.islink(path):
            return True
        if self._is_virtualenv_dir(path):
            return True
        if self._is_site_packages_path(path):
            return True
        return False


class HeaderCli:
    """Parse CLI arguments and run the header updater."""

    @staticmethod
    def parse_args() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description=(
                "Ensure Apache-2.0 SPDX headers, current year, and future import"
                " across a tree."
            ),
        )
        parser.add_argument(
            "root",
            nargs="?",
            default=os.getcwd(),
            help="Root directory (default: CWD)",
        )
        parser.add_argument(
            "--exclude",
            default="",
            help="Comma-separated extra directory names to exclude.",
        )
        parser.add_argument(
            "--future",
            choices=("auto", "yes", "no"),
            default="auto",
            help="Control insertion of `from __future__ import annotations`.",
        )
        parser.add_argument(
            "--author",
            default=DEFAULT_AUTHOR,
            help="Author name (default: %(default)s)",
        )
        parser.add_argument(
            "--year",
            type=int,
            default=DEFAULT_YEAR,
            help="Year (default: current year)",
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Print scan summary and unchanged files.",
        )
        return parser.parse_args()

    @staticmethod
    def decide_add_future(policy: str) -> bool:
        match policy:
            case "yes":
                return True
            case "no":
                return False
            case _:
                version_info = sys.version_info
                if version_info < (3, 14):
                    return True
                if sys.stdin.isatty():
                    prompt = (
                        "Python 3.14+ detected: annotations are lazy by default.\n"
                        "Insert `from __future__ import annotations` anyway? [y/N]: "
                    )
                    print(prompt, end="", flush=True)
                    try:
                        answer = input().strip().lower()
                    except EOFError:
                        answer = ""
                    return answer in ("y", "yes")
                return False


def main() -> None:
    """Entry point for CLI usage."""
    args = HeaderCli.parse_args()
    extra = {entry.strip() for entry in args.exclude.split(",") if entry.strip()}
    add_future = HeaderCli.decide_add_future(args.future)

    if args.verbose:
        print(f"Scanning for .py files under: {args.root}")
        if extra:
            print(f"Additional excludes: {sorted(extra)}")
        print(f"Adding future import: {'YES' if add_future else 'NO'}")
        print(f"Using author: {args.author} • year: {args.year}")

    updater = HeaderUpdater(
        author=args.author,
        year=args.year,
        add_future=add_future,
        extra_excluded=extra,
        verbose=args.verbose,
    )
    updater.run(args.root)

    if args.verbose:
        print("Done.")


if __name__ == "__main__":
    main()
# FILE: tools/release/check_version.py
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia


from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


class VersionCheckTool:
    """Verify version consistency between src/pypnm/version.py and pyproject.toml."""

    MAX_ROOT_SEARCH_DEPTH: int = 6
    VERSION_FILE_RELATIVE: str = "src/pypnm/version.py"
    PYPROJECT_RELATIVE: str = "pyproject.toml"
    VERSION_PATTERN: str = r'__version__\s*(?::\s*[^=]+)?=\s*"([^"]+)"'
    PYPROJECT_PATTERN: str = r'^\s*version\s*=\s*"([^"]+)"\s*$'
    EXIT_OK: int = 0
    EXIT_ERROR: int = 1
    EXIT_MISMATCH: int = 2

    @staticmethod
    def _read_text(path: Path) -> str:
        """Read a file as UTF-8 text; return empty string when unavailable."""
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return ""

    @staticmethod
    def _find_project_root(start_path: Path) -> Path:
        """Walk upwards to locate pyproject.toml, fallback to start path."""
        current = start_path
        for _ in range(VersionCheckTool.MAX_ROOT_SEARCH_DEPTH):
            if (current / VersionCheckTool.PYPROJECT_RELATIVE).is_file():
                return current
            if current.parent == current:
                break
            current = current.parent
        return start_path

    @staticmethod
    def _read_version_from_file(path: Path) -> str:
        """Extract the __version__ value from src/pypnm/version.py."""
        text = VersionCheckTool._read_text(path)
        if not text:
            return ""
        match = re.search(VersionCheckTool.VERSION_PATTERN, text)
        if not match:
            return ""
        return match.group(1)

    @staticmethod
    def _read_version_from_pyproject(path: Path) -> str:
        """Extract the project version value from pyproject.toml."""
        text = VersionCheckTool._read_text(path)
        if not text:
            return ""
        match = re.search(VersionCheckTool.PYPROJECT_PATTERN, text, re.MULTILINE)
        if not match:
            return ""
        return match.group(1)

    @staticmethod
    def _build_parser() -> argparse.ArgumentParser:
        """Build the CLI parser for the version check tool."""
        parser = argparse.ArgumentParser(
            description=(
                "Verify that src/pypnm/version.py and pyproject.toml carry the same version."
            )
        )
        parser.add_argument(
            "--json",
            action="store_true",
            help="Print results as JSON.",
        )
        return parser

    @staticmethod
    def _emit_text(version_file_version: str, pyproject_version: str, status: str) -> None:
        """Emit human-readable output."""
        if status == "error":
            print("Version check failed: unable to read one or more version values.")
        print(f"version.py: {version_file_version or 'missing'}")
        print(f"pyproject.toml: {pyproject_version or 'missing'}")
        if status == "mismatch":
            print("Version mismatch detected.")
        if status == "ok":
            print("Version match confirmed.")

    @staticmethod
    def _emit_json(version_file_version: str, pyproject_version: str, status: str) -> None:
        """Emit JSON output."""
        payload = {
            "version_py": version_file_version,
            "pyproject": pyproject_version,
            "match": status == "ok",
            "status": status,
        }
        print(json.dumps(payload, ensure_ascii=True))

    @staticmethod
    def run(options: argparse.Namespace) -> int:
        """Print versions from tracked files and return a status code."""
        script_dir = Path(__file__).resolve().parent
        root_path = VersionCheckTool._find_project_root(script_dir)
        version_path = root_path / VersionCheckTool.VERSION_FILE_RELATIVE
        pyproject_path = root_path / VersionCheckTool.PYPROJECT_RELATIVE

        version_file_version = VersionCheckTool._read_version_from_file(version_path)
        pyproject_version = VersionCheckTool._read_version_from_pyproject(pyproject_path)

        if not version_file_version or not pyproject_version:
            if options.json:
                VersionCheckTool._emit_json(version_file_version, pyproject_version, "error")
            else:
                VersionCheckTool._emit_text(version_file_version, pyproject_version, "error")
            return VersionCheckTool.EXIT_ERROR

        if version_file_version != pyproject_version:
            if options.json:
                VersionCheckTool._emit_json(version_file_version, pyproject_version, "mismatch")
            else:
                VersionCheckTool._emit_text(version_file_version, pyproject_version, "mismatch")
            return VersionCheckTool.EXIT_MISMATCH

        if options.json:
            VersionCheckTool._emit_json(version_file_version, pyproject_version, "ok")
        else:
            VersionCheckTool._emit_text(version_file_version, pyproject_version, "ok")
        return VersionCheckTool.EXIT_OK


if __name__ == "__main__":
    parser = VersionCheckTool._build_parser()
    args = parser.parse_args()
    sys.exit(VersionCheckTool.run(args))
# FILE: tools/security/scan-mac-addresses.py
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

# Scan the repository for non-approved MAC addresses.

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Iterable


# -----------------------------------------------------------------------------
# Configuration: Approved MAC Address Allowlist
# -----------------------------------------------------------------------------
# Add any MAC addresses here that are allowed to appear in the repository.
# They will be normalized to lowercase with ':' separators before comparison,
# so "AA-BB-CC-DD-EE-FF" and "aa:bb:cc:dd:ee:ff" are considered equivalent.
#
# Example entries you might add over time:
#   "aa:bb:cc:dd:ee:ff"  - generic example MAC (preferred default).
#   "00:11:22:33:44:55"  - alternate generic example, if ever needed in docs.
#
APPROVED_MACS: set[str] = {
    "aa:bb:cc:dd:ee:ff",
    "00:11:22:33:44:55",
    "00:00:00:00:00:01",
    "00:00:00:00:00:00",
    "00:1a:2b:3c:4d:5e",
    "ff-ff-ff-ff-ff-ff",
    "10-23-45-67-89-ab",
    "01:00:5e:00:00:00",
    "de:ad:be:ef:00:01",
    "de:ad:be:ef:00:bb",
    "00:00:ca:12:03:60",
    "00:00:00-23:00:00",
}


# -----------------------------------------------------------------------------
# Configuration: Directory Ignore List
# -----------------------------------------------------------------------------
IGNORE_DIRS: set[str] = {
    ".git",
    ".env",
    ".venv",
    ".pytest_cache",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
    ".data",
}


MAC_REGEX = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

MACMatch = tuple[str, int, int, str]  # (path, line_no, col, mac)


def _normalize_mac(mac: str) -> str:
    """
    Normalize MAC Address For Comparison.

    Converts to lowercase and replaces '-' with ':' so patterns such as
    'AA-BB-CC-DD-EE-FF' and 'aa:bb:cc:dd:ee:ff' are treated equivalently.
    """
    return mac.lower().replace("-", ":")


# Precompute normalized allowlist once
APPROVED_MACS_NORMALIZED: set[str] = {_normalize_mac(m) for m in APPROVED_MACS}


def _is_approved(mac: str) -> bool:
    """
    Return True If The MAC Address Is In The Approved Allowlist.
    """
    return _normalize_mac(mac) in APPROVED_MACS_NORMALIZED


def _iter_files(root: str) -> Iterable[str]:
    """
    Yield Text File Candidates Under The Given Root Directory.

    Skips common virtualenv and build directories using IGNORE_DIRS.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]

        for name in filenames:
            path = os.path.join(dirpath, name)
            yield path


def _scan_file(path: str) -> list[MACMatch]:
    """
    Scan A Single File For Non-Approved MAC Addresses.

    Returns
    -------
    list[MACMatch]
        A list of (path, line_number, column, mac_string) tuples.
    """
    matches: list[MACMatch] = []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line_no, line in enumerate(fh, start=1):
                for match in MAC_REGEX.finditer(line):
                    mac = match.group(0)
                    if _is_approved(mac):
                        continue
                    col = match.start() + 1
                    matches.append((path, line_no, col, mac))
    except (OSError, UnicodeDecodeError):
        return matches

    return matches


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan the repository tree for non-approved MAC addresses."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Root directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--fail-on-found",
        action="store_true",
        help="Exit with non-zero status if any MAC addresses are found.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """
    Scan Repository For Non-Approved MAC Addresses And Report Any Findings.

    Exit Codes
    ----------
    0 : No non-approved MAC addresses found, or only warnings printed.
    2 : Non-approved MAC addresses were found and --fail-on-found is set.
    """
    if argv is None:
        argv = sys.argv[1:]

    args = _parse_args(argv)

    root = os.path.abspath(args.root)
    print(f"Scanning for MAC addresses under: {root}")
    print(f"Approved MACs: {sorted(APPROVED_MACS_NORMALIZED)}")

    all_matches: list[MACMatch] = []

    for path in _iter_files(root):
        file_matches = _scan_file(path)
        all_matches.extend(file_matches)

    if not all_matches:
        print("No non-approved MAC addresses found.")
        sys.exit(0)

    print("\nNon-approved MAC addresses found:")
    for path, line_no, col, mac in all_matches:
        print(f"{path}:{line_no}:{col}: {mac}")

    if args.fail_on_found:
        print(
            f"\nTotal non-approved MAC occurrences: {len(all_matches)} "
            "(failing due to --fail-on-found)."
        )
        sys.exit(2)

    print(f"\nTotal non-approved MAC occurrences: {len(all_matches)}")
    sys.exit(0)


if __name__ == "__main__":
    main()
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
# FILE: src/pypnm/lib/db/model/db_health_model.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.lib.types import DatabaseBackend


class DatabaseHealthModel(BaseModel):
    """
    Database health status for schema diagnostics.
    """

    backend: DatabaseBackend = Field(..., description="Database backend under test")
    schema_version: int = Field(
        ..., description="Detected schema version (0 when missing)"
    )
    missing_tables: list[str] = Field(
        default_factory=list, description="Required tables that are missing"
    )
    unknown_sysdescr_present: bool = Field(
        ..., description="Whether the canonical UNKNOWN sysDescr row exists"
    )
    default_artifact_store_present: bool = Field(
        ..., description="Whether the default artifact store row exists"
    )
    ok: bool = Field(..., description="True when schema is healthy and complete")
    details: str = Field("", description="Diagnostic summary")
# FILE: src/pypnm/tools/loop_nesting_checker.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import cast


@dataclass(frozen=True)
class LoopNestingFinding:
    file_path: str
    function_name: str
    line_number: int
    max_depth: int


class LoopNestingAnalyzer:
    _LOOP_TYPES = (ast.For, ast.AsyncFor, ast.While)
    _COMP_TYPES = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
    _SKIP_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    _TRY_TYPES  = (ast.Try, getattr(ast, "TryStar", ast.Try))

    @staticmethod
    def analyze_source(source: str, file_path: str) -> list[LoopNestingFinding]:
        tree = ast.parse(source, filename=file_path)
        return LoopNestingAnalyzer._analyze_tree(tree=tree, file_path=file_path)

    @staticmethod
    def analyze_path(path: Path) -> list[LoopNestingFinding]:
        source = path.read_text(encoding="utf-8")
        return LoopNestingAnalyzer.analyze_source(source=source, file_path=str(path))

    @staticmethod
    def _analyze_tree(tree: ast.AST, file_path: str) -> list[LoopNestingFinding]:
        visitor = _QualifiedFunctionVisitor(file_path=file_path)
        visitor.visit(tree)
        return visitor.findings

    @staticmethod
    def _max_depth_in_nodes(nodes: list[ast.stmt], current_depth: int) -> int:
        max_depth = current_depth
        for node in nodes:
            max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_node(node, current_depth))
        return max_depth

    @staticmethod
    def _max_depth_in_node(node: ast.AST, current_depth: int) -> int:
        if isinstance(node, LoopNestingAnalyzer._SKIP_TYPES):
            return current_depth

        if isinstance(node, LoopNestingAnalyzer._LOOP_TYPES):
            loop_depth = current_depth + 1
            max_depth = loop_depth
            max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_nodes(node.body, loop_depth))
            max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_nodes(node.orelse, loop_depth))
            return max_depth

        if isinstance(node, LoopNestingAnalyzer._COMP_TYPES):
            return LoopNestingAnalyzer._max_depth_in_comprehension(node, current_depth)

        max_depth = current_depth
        for block in LoopNestingAnalyzer._child_blocks(node):
            max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_nodes(block, current_depth))
        max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_expr_nodes(node, current_depth))
        return max_depth

    @staticmethod
    def _child_blocks(node: ast.AST) -> list[list[ast.stmt]]:
        blocks: list[list[ast.stmt]] = []
        if isinstance(node, ast.If):
            blocks.append(node.body)
            blocks.append(node.orelse)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            blocks.append(node.body)
        elif isinstance(node, ast.Try):
            blocks.append(node.body)
            blocks.append(node.orelse)
            blocks.append(node.finalbody)
            for handler in node.handlers:
                blocks.append(handler.body)
        elif hasattr(ast, "TryStar") and isinstance(node, getattr(ast, "TryStar")):
            try_node = cast(ast.Try, node)
            blocks.append(try_node.body)
            blocks.append(try_node.orelse)
            blocks.append(try_node.finalbody)
            for handler in try_node.handlers:
                blocks.append(handler.body)
        elif isinstance(node, ast.Match):
            for case in node.cases:
                blocks.append(case.body)
        elif isinstance(node, ast.ExceptHandler):
            blocks.append(node.body)
        return blocks

    @staticmethod
    def _max_depth_in_expr_nodes(node: ast.AST, current_depth: int) -> int:
        max_depth = current_depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_expr(child, current_depth))
        return max_depth

    @staticmethod
    def _max_depth_in_expr(node: ast.expr, current_depth: int) -> int:
        if isinstance(node, ast.Lambda):
            return current_depth
        if isinstance(node, LoopNestingAnalyzer._COMP_TYPES):
            return LoopNestingAnalyzer._max_depth_in_comprehension(node, current_depth)

        max_depth = current_depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_expr(child, current_depth))
        return max_depth

    @staticmethod
    def _max_depth_in_comprehension(node: ast.AST, current_depth: int) -> int:
        max_depth = current_depth
        generator_depth = current_depth
        generators: list[ast.comprehension] = []

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            generators = node.generators
        elif isinstance(node, ast.DictComp):
            generators = node.generators

        for generator in generators:
            generator_depth += 1
            max_depth = max(max_depth, generator_depth)
            max_depth = max(
                max_depth,
                LoopNestingAnalyzer._max_depth_in_expr(generator.iter, generator_depth),
            )
            for if_expr in generator.ifs:
                max_depth = max(
                    max_depth,
                    LoopNestingAnalyzer._max_depth_in_expr(if_expr, generator_depth),
                )

        if isinstance(node, ast.DictComp):
            max_depth = max(
                max_depth,
                LoopNestingAnalyzer._max_depth_in_expr(node.key, generator_depth),
            )
            max_depth = max(
                max_depth,
                LoopNestingAnalyzer._max_depth_in_expr(node.value, generator_depth),
            )
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            max_depth = max(
                max_depth,
                LoopNestingAnalyzer._max_depth_in_expr(node.elt, generator_depth),
            )

        return max_depth


class _QualifiedFunctionVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str) -> None:
        self._file_path = file_path
        self._stack: list[str] = []
        self.findings: list[LoopNestingFinding] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._stack.append(node.name)
        try:
            self.generic_visit(node)
        finally:
            self._stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_like(node=node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_like(node=node)

    def _visit_function_like(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._stack.append(node.name)
        try:
            function_name = ".".join(self._stack) if self._stack else node.name
            depth = LoopNestingAnalyzer._max_depth_in_nodes(node.body, 0)
            self.findings.append(
                LoopNestingFinding(
                    file_path=self._file_path,
                    function_name=function_name,
                    line_number=node.lineno,
                    max_depth=depth,
                )
            )
            self.generic_visit(node)
        finally:
            self._stack.pop()


class LoopNestingChecker:
    _FAIL_DEPTH = 3
    _WARN_DEPTH = 2

    _EXCLUDE_DIR_NAMES = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "site-packages",
        "venv",
    }

    @staticmethod
    def run(paths: list[str]) -> int:
        files = LoopNestingChecker._collect_files(paths)
        if not files:
            print("No Python files found for loop nesting check.", flush=True)
            return 2

        findings: list[LoopNestingFinding] = []
        parse_failures = 0

        for path in files:
            try:
                findings.extend(LoopNestingAnalyzer.analyze_path(path))
            except (SyntaxError, UnicodeDecodeError, OSError) as exc:
                parse_failures += 1
                print(f"ERROR: {path}: {exc.__class__.__name__}: {exc}", flush=True)

        findings.sort(key=lambda f: (f.file_path, f.line_number, f.function_name))

        warnings = [f for f in findings if f.max_depth == LoopNestingChecker._WARN_DEPTH]
        errors = [f for f in findings if f.max_depth >= LoopNestingChecker._FAIL_DEPTH]

        for finding in warnings:
            LoopNestingChecker._print_finding(prefix="WARNING", finding=finding)

        for finding in errors:
            LoopNestingChecker._print_finding(prefix="ERROR", finding=finding)

        if parse_failures:
            print(f"Loop nesting check encountered {parse_failures} file error(s).", flush=True)
            return 2

        if errors:
            print(
                f"Loop nesting check failed: {len(errors)} function(s) reach depth "
                f"{LoopNestingChecker._FAIL_DEPTH} or higher.",
                flush=True,
            )
            return 1

        print("Loop nesting check passed.", flush=True)
        return 0

    @staticmethod
    def _collect_files(paths: list[str]) -> list[Path]:
        files: list[Path] = []
        for raw in paths:
            files.extend(LoopNestingChecker._collect_from_path(Path(raw)))
        return LoopNestingChecker._dedupe_paths(files)

    @staticmethod
    def _collect_from_path(path: Path) -> list[Path]:
        if path.is_dir():
            return [
                p
                for p in path.rglob("*.py")
                if p.is_file() and not LoopNestingChecker._is_excluded_path(p)
            ]
        if path.is_file() and path.suffix == ".py":
            return [path]
        print(f"Skipping missing path: {path}", flush=True)
        return []

    @staticmethod
    def _is_excluded_path(path: Path) -> bool:
        parts = set(path.parts)
        return bool(parts & LoopNestingChecker._EXCLUDE_DIR_NAMES)

    @staticmethod
    def _dedupe_paths(paths: list[Path]) -> list[Path]:
        seen: set[Path] = set()
        unique: list[Path] = []
        for path in paths:
            if path in seen:
                continue
            seen.add(path)
            unique.append(path)
        return unique

    @staticmethod
    def _print_finding(prefix: str, finding: LoopNestingFinding) -> None:
        print(
            f"{prefix}: {finding.file_path}:{finding.line_number} "
            f"{finding.function_name} max_depth={finding.max_depth}",
            flush=True,
        )


def main() -> None:
    raw_args = sys.argv[1:]
    paths = raw_args if raw_args else ["src"]
    exit_code = LoopNestingChecker.run(paths=paths)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
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
    UNKNOWN_SYSDESCR_HASH,
    DatabaseSchemaManager,
)
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath

SCHEMA_META_ID: int = 1
EXPECTED_UNKNOWN_COUNT: int = 1
EXPECTED_SCHEMA_STATEMENTS_MIN: int = 1


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
# FILE: tests/test_loop_nesting_checker.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.tools.loop_nesting_checker import LoopNestingAnalyzer


def _depths_by_function(source: str) -> dict[str, int]:
    findings = LoopNestingAnalyzer.analyze_source(source=source, file_path="snippet.py")
    return {finding.function_name: finding.max_depth for finding in findings}


def test_loop_depth_zero() -> None:
    source = "def demo():\n    value = 1\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 0


def test_loop_depth_one() -> None:
    source = "def demo():\n    for idx in range(3):\n        value = idx\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 1


def test_loop_depth_two() -> None:
    source = (
        "def demo():\n"
        "    for idx in range(3):\n"
        "        while idx > 0:\n"
        "            idx -= 1\n"
    )
    depths = _depths_by_function(source)
    assert depths["demo"] == 2


def test_loop_depth_three() -> None:
    source = (
        "def demo():\n"
        "    for idx in range(3):\n"
        "        if idx > 0:\n"
        "            while idx > 0:\n"
        "                for jdx in range(2):\n"
        "                    idx -= jdx\n"
    )
    depths = _depths_by_function(source)
    assert depths["demo"] == 3


def test_nested_function_loops_not_counted_in_parent() -> None:
    source = (
        "def demo():\n"
        "    for idx in range(2):\n"
        "        def inner():\n"
        "            for jdx in range(2):\n"
        "                for kdx in range(2):\n"
        "                    pass\n"
        "        value = idx\n"
    )
    depths = _depths_by_function(source)
    assert depths["demo"] == 1
    assert depths["demo.inner"] == 2


def test_comprehension_depth_one() -> None:
    source = "def demo():\n    values = [x for x in range(3)]\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 1


def test_comprehension_nested_generators_depth_two() -> None:
    source = "def demo():\n    values = [(x, y) for x in range(2) for y in range(2)]\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 2


def test_comprehension_nested_expression_depth_two() -> None:
    source = "def demo():\n    values = [[y for y in range(2)] for x in range(2)]\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 2


def test_comprehension_nested_depth_three() -> None:
    source = (
        "def demo():\n"
        "    values = [[z for z in range(2)] for x in range(2) for y in range(2)]\n"
    )
    depths = _depths_by_function(source)
    assert depths["demo"] == 3


def test_generator_expression_depth_one() -> None:
    source = "def demo():\n    values = (x for x in range(3))\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 1
