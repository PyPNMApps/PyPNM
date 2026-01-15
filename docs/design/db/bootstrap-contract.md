# DB Bootstrap Contract (Implemented)

## Purpose

This document describes the implemented DB bootstrap contract for Phase 2. It covers adapter lifecycle, backend
selection precedence, and the current schema scope (bootstrap-only).

Implemented vs planned:

- Implemented: adapter lifecycle and schema bootstrap readiness checks.
- Planned: full schema and migrations for transactions, capture groups, operations, and artifacts.

## Adapter Contract

Adapters implement a minimal lifecycle interface:

- connect
- apply_schema
- healthcheck
- close

Adapters must remain policy-neutral and focused on bootstrap readiness only.

## Backend Selection Precedence

Backend selection is deterministic and follows this order:

1) Environment overrides (`PYPNM_DB_BACKEND`, `PYPNM_DB_POSTGRES_DSN`)
2) Configuration file values (`Database.backend`, `Database.postgres.dsn`)
3) Defaults (SQLite)

If Postgres is selected but the DSN is invalid or blank, DatabaseManager selection falls back to SQLite without
raising from get_adapter. Direct configuration validation may still raise ValidationError. The schema manager is
fail-fast when backend is postgres and the DSN is invalid or blank.

## Schema Bootstrap Scope

The bootstrap schema is the baseline schema for Phase 2:

- `apply_schema` initializes `schema_meta` and the baseline tables required for transactions, grouping, and artifacts.
- Required seed rows are inserted (`schema_meta` version, `UNKNOWN` system description, default artifact store).
- Runtime does not perform destructive migrations.
- Schema DDL assets are loaded from package data via importlib.resources; docs copies are reference-only.

Postgres driver support is optional and provided by the `postgres` extra (install with `pypnm-docsis[postgres]`).

## Lifecycle Usage

`initialize()` performs connect, applies the bootstrap schema, and checks health. `close()` shuts down the adapter and
clears the cached instance so selection can be re-evaluated.

## Mermaid Support

Documentation builds expect Mermaid diagrams to render through the MkDocs Material pipeline with Mermaid JS enabled.
