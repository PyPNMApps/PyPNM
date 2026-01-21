# Phase 3 · Transactions Migration (Replace `transactions.json`) (M3)

## Table Of Contents

- [Overview](#overview)
- [Objectives](#objectives)
- [Scope](#scope)
- [Out Of Scope](#out-of-scope)
- [Deliverables](#deliverables)
- [Burndown Tracker](#burndown-tracker)
- [Acceptance Criteria](#acceptance-criteria)
- [Test And Quality Gates](#test-and-quality-gates)
- [Codex Training Prompt](#codex-training-prompt)
- [Notes](#notes)

## Overview

Phase 3 migrates PyPNM transaction persistence from the legacy `transactions.json` ledger into the DB backend (SQLite default, Postgres
optional). The phase goal is to eliminate runtime JSON dependency while preserving the transaction payload contract used by downstream
callers (API responses, analysis routing, artifact resolution, and UI consumers).

This phase assumes Phase 2 schema initialization and DSN invariants are complete and stable.

## Objectives

1) Replace operational reads/writes of `transactions.json` with DB-backed repositories.
2) Provide an explicit, idempotent, one-time migration tool to import legacy `transactions.json` into the DB.
3) Preserve the legacy transaction record shape and semantics for downstream compatibility.
4) Ensure migration and DB usage are covered by deterministic unit tests, with Postgres tests gated by environment variables.

## Scope

- Canonicalize the transaction record contract (transaction_id, timestamp_epoch, mac_address, pnm_test_type, filename, device_details).
- Confirm repository capabilities and DB constraints needed for transaction operations.
- Add/confirm indexes required for expected query patterns (by transaction_id, mac_address, time ordering, operation_id joins where
  applicable).
- Implement a CLI migration command that imports legacy transactions into DB and is safe to re-run.
- Remove (or gate) runtime code paths that depend on `transactions.json`, leaving JSON usage only for migration tooling (and optionally
  documentation).

## Out Of Scope

- Rewriting analysis algorithms, parsers, or report generation.
- Introducing new database engines beyond the existing SQLite/Postgres contract.
- Automatic migration on import/startup. Migration must be explicit (CLI invoked).
- Major API contract changes to endpoints beyond replacing data source (JSON -> DB).

## Deliverables

- DB-backed transaction persistence as the sole runtime source of truth.
- CLI command to migrate legacy transactions:
  - Missing file -> no-op with clear logging.
  - Invalid JSON -> clear failure mode (raise or controlled error response), covered by tests.
  - Idempotent behavior (safe to run multiple times).
- Updated documentation:
  - How to run migration.
  - What happens to `transactions.json` after migration (retained for audit; user may delete after verifying import).
  - Postgres optional gating behavior.
- Test suite coverage proving:
  - Migration imports expected count.
  - Re-running migration produces no duplicates.
  - Repository uniqueness invariants hold.
- Hygiene gates remain green:
  - `python3 -m compileall src`
  - `ruff check .`
  - `ruff format --check .`
  - `pytest -q`

## Burndown Tracker

### Phase 3 Checklist

- [ ] 3.1 · Inventory current `transactions.json` usage paths (read/write) and call sites.
- [ ] 3.2 · Confirm canonical transaction contract (model fields and required invariants).
- [ ] 3.3 · Validate repository surface is complete for:
      - insert_transaction
      - get_transaction_record
      - list_transactions_for_mac
      - list_all_transactions
      - list_macs
- [ ] 3.4 · Enforce uniqueness invariants:
      - DB constraint on transaction_id (and conflict handling behavior).
      - Repository behavior for idempotent inserts (skip/ignore duplicates).
- [ ] 3.5 · Index verification:
      - transactions(mac_address)
      - transactions(timestamp_epoch) (recommended)
      - capture_group / operation-related indexes (if already modeled in schema)
- [ ] 3.6 · Implement CLI migration command:
      - explicit invocation only (no import/startup side effects)
      - supports configurable path to `transactions.json` if needed (default to known location)
      - logs import counts and skipped duplicates
- [ ] 3.7 · Migration normalization rules:
      - sysDescr normalization via SystemDescriptor -> repository dims
      - device_details/system_description behavior consistent with existing DB rows
      - artifact registration alignment (do not invent new roles or paths)
- [ ] 3.8 · Remove runtime JSON dependency:
      - eliminate reads for listing, searching, resolving
      - eliminate writes for new captures/uploads
      - keep JSON only for migration tooling and docs
- [ ] 3.9 · Tests:
      - imports expected records from sample JSON
      - idempotent on second run
      - missing file no-op
      - invalid/empty JSON behavior
      - uniqueness constraint behavior
      - Postgres optional tests gated by env
- [ ] 3.10 · Documentation updates (MkDocs + GitHub compatible; no horizontal rules).
- [ ] 3.11 · Run gates and confirm expected skips only.

### Owner Notes (Optional)

- Expected skips: cm_it hardware integration; Postgres tests when `PYPNM_TEST_POSTGRES!=1` or DSN not set.

## Acceptance Criteria

Phase 3 is complete when all of the following are true:

- Runtime code does not require `transactions.json` for normal operation.
- DB is the source of truth for transaction record operations.
- Migration CLI exists and is demonstrably idempotent.
- Transaction payload compatibility is preserved for API/service consumers.
- All quality gates pass with only the expected skips.

## Test And Quality Gates

Run locally before merge:

```bash
python3 -m compileall src
ruff check .
ruff format --check .
pytest -q
```

Optional Postgres gating (only when enabled):

```bash
export PYPNM_TEST_POSTGRES=1
export PYPNM_DB_POSTGRES_DSN="postgresql://pypnm@localhost:5432/pypnm"
pytest -q
```

## Codex Training Prompt

```text
Goal: Implement Phase 3 (M3) by migrating PyPNM transactions from legacy `transactions.json` to the DB backend (SQLite default, Postgres
optional). Provide an explicit, idempotent CLI migration tool, remove runtime JSON dependency, preserve transaction payload contract,
and extend tests. Follow AGENTS.md rules (strict typing, BaseModel preference, no magic numbers, preserve whitespace/alignment, no
printing code in chat, SPDX year 2026 for touched Python files). Run compileall, ruff check/format, pytest -q; keep Postgres tests gated
by PYPNM_TEST_POSTGRES and PYPNM_DB_POSTGRES_DSN. Update docs for migration usage; no horizontal rules.
```

## Notes

- Migration must not run implicitly at import-time or service startup. It must be a deliberate CLI action.
- Preserve the existing transaction record shape to avoid cascading downstream changes.
- Prefer repository-level conflict handling to keep migration logic simple and repeatable.
