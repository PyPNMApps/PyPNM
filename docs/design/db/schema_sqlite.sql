<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Maurice Garcia -->

# Database Backend Design (PyPNM)

## Purpose

PyPNM currently persists transaction metadata using JSON “ledger” files under `.data/db/` (for example `transactions.json`,
`capture_group.json`, and `operation_capture.json`). This design document defines the target state for replacing the ledger
with a relational database while preserving PyPNM’s operational model (filesystem-based binary artifacts plus lightweight
metadata persistence).

This document is written to support both:

- PyPNM (authoritative engine and persistence owner)
- PyPNM-CMTS (consumer of PyPNM; cannot select a different DB backend)

## Scope

In scope:

- A normalized relational schema for transaction metadata and grouping constructs (capture groups and operations)
- A durable way to link transactions to one-or-more files on disk (binary artifacts and future derived artifacts)
- Support for two database backends with the same schema intent:
  - Postgres
  - SQLite

Out of scope for this document:

- Refactoring implementation details (phasing and prompts are tracked separately)
- Security/sanitization pipeline refactor (captured as requirements and constraints here)
- Any change to the on-disk binary format

## Non-Goals

- No database-specific business logic in PyPNM-CMTS
- No separate DB selection logic in PyPNM-CMTS
- No requirement for Kubernetes APIs or a K8 operator

## Key Requirements

1) **PyPNM owns persistence**  
   PyPNM-CMTS consumes PyPNM as a dependency. PyPNM decides which DB backend is used. PyPNM-CMTS must use the same
   backend that PyPNM selected during install.

2) **Timestamps remain epoch seconds**  
   All stored timestamps are epoch seconds. ISO-8601 conversion is a display concern only.

3) **Artifact linkage is explicit and normalized**  
   A transaction must be able to reference one-or-more on-disk artifacts (binary capture, derived JSON/PNG/CSV, archives).

4) **SysDescr de-duplication**  
   `system_description` values must be normalized to avoid redundant rows since most modems share the same software level.
   A special UNKNOWN entry must exist for user-uploaded PNM files that lack sysDescr.

5) **Demo mode uses the same schema**  
   Demo mode uses the same schema and code paths. The only difference is which dataset (directory root + DB file/DSN)
   is used.

6) **Paths stored in DB must be portable**  
   Store paths as repo-relative (or app-root-relative) strings. Do not store user-specific absolute paths such as
   `/home/dev01/...`.

## Data Model Overview

### Primary Entities

- **System Description (dimension)**  
  De-duplicated sysDescr fields. One row per unique sysDescr hash.

- **Device Details**  
  A normalized container for device metadata. References `system_description_dim`. Can grow over time without forcing
  an exploding `transaction_records` table.

- **Transaction Record**  
  One row per capture/measurement transaction.

- **Capture Group**  
  Represents a logical grouping of multiple transactions captured together.

- **Operation Capture**  
  Represents a higher-level operation that points to a capture group.

### Artifact Linkage (Filesystem Integration)

Transactions need an explicit association to files on disk. The schema introduces:

- **Artifact Store**: a named root directory (repo/app-root relative)
- **File Artifact**: one row per file; unique by `(store_id, relative_path)` and by `sha256`
- **Transaction Artifact**: joins transactions to artifacts with a `role` (for example `raw_bin`)

This decouples transaction metadata from the filesystem layout, and it supports future derived artifacts per transaction.

## Path Contract (Portable Storage)

### Repo / App Root Resolution

At runtime, PyPNM resolves an `app_root` (often the repo root during development, and a container directory such as `/app`
during Docker runs). All stored paths are interpreted relative to this `app_root`.

### What is stored in the DB

- `artifact_stores.root_path` is a repo/app-root relative root directory.
  - Example (prod): `.data/pnm`
  - Example (demo): `demo/.data/pnm`

- `file_artifacts.relative_path` is relative to `artifact_stores.root_path`.
  - Example: `ds_ofdm_rxmer_per_subcar_aabbccddeeff_193_1768036758.bin`

### How the absolute path is constructed

`absolute_path = Path(app_root) / artifact_stores.root_path / file_artifacts.relative_path`

This avoids leaking local absolute paths into the database and keeps the DB portable across machines and containers.

## Demo Mode

The demo dataset lives under the repo at:

- `demo/.data/...`

Demo can be implemented by pointing PyPNM at a different DB and seeding `artifact_stores` accordingly:

- Demo DB: `artifact_stores.root_path = 'demo/.data/pnm'`
- Prod DB: `artifact_stores.root_path = '.data/pnm'`

Both databases use the same schema. The difference is only data and file roots.

## Database Location and Release Hygiene

### Where The Database Resides

PyPNM database files and runtime state must **not** live inside the installed Python package (`src/pypnm/...`) and must
**not** be committed to the repository. They are runtime artifacts and belong under the existing `.data/` hierarchy.

Recommended default locations (repo/app-root relative):

- SQLite database file: `.data/db/pypnm.sqlite3`
- Postgres: no local database file (PyPNM stores only a DSN/connection settings); schemas are applied to the external DB.

Rationale:

- Keeps the package immutable and reproducible.
- Supports containerized deployments (bind mount or volume mount `.data/`).
- Prevents accidental shipping of customer data with releases.

### Demo Database Location

Demo uses the same schema but a different runtime root:

- Demo SQLite file: `demo/.data/db/pypnm.sqlite3`
- Demo artifacts: `demo/.data/pnm`

### Release Safety: Never Ship DB Data

When a release is pushed (PyPI package build, GitHub release, container image build):

- Do **not** include any SQLite DB files (prod or demo) in the release artifacts.
- Do **not** include any `.data/` contents in the sdist/wheel or container image layers.
- Do **not** include any customer-generated binary captures or derived artifacts.

Implementation safeguards (expected repo hygiene):

- Add `.data/` and `demo/.data/` to `.gitignore`.
- Ensure packaging excludes `.data/**` and `demo/.data/**` (sdist/wheel).
- Docker builds should not `COPY` `.data/` into the image; data must come from volumes at runtime.
- K8 deployments must mount `.data/` via PVC (SQLite) or configure DSN secrets (Postgres).

Operational note:

- The installer (or first-run initialization) should create the DB schema and seed the `UNKNOWN` sysDescr row, but it must
  never ship pre-populated data.


## Validation and Safeguards

### MAC Address Format

All transactions must store a MAC address in colon-separated hex format:

`xx:xx:xx:xx:xx:xx`

The schema enforces this via CHECK constraints in both Postgres and SQLite.

### JSON Fields

The schema uses JSON columns for forward compatibility:

- Postgres: `JSONB`
- SQLite: `TEXT` with `CHECK (json_valid(...))` (requires JSON1 extension)

These JSON blobs provide an escape hatch for future growth without table rewrites, while still keeping normalized foreign
keys for the most important dimensions.

### UNKNOWN sysDescr Row

The schema seeds an `UNKNOWN` sysDescr row. This supports user-uploaded PNM files where sysDescr is absent. Normal modem
captures should always reference a non-UNKNOWN sysDescr, but the UNKNOWN row must exist as a safe fallback.

## Schema Diagram (Mermaid)

```mermaid
erDiagram
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
        TEXT       operation_capture_id PK
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

## Installation Contract

### Backend Selection

PyPNM selects the DB backend at install time (for example via `install.sh` flags such as):

- `--db-install-postgres`
- `--db-install-sqlite`


### Database Configuration Keys (High-Level)

PyPNM should expose configuration for:

- Backend selection: `postgres` or `sqlite`
- SQLite path (repo/app-root relative): default `.data/db/pypnm.sqlite3`
- Postgres DSN (host/port/db/user/password/ssl): stored in configuration and/or environment variables

These values are resolved by PyPNM at startup and inherited by PyPNM-CMTS implicitly through PyPNM usage.

PyPNM-CMTS does not implement a separate DB selection mechanism and must not use a different backend than PyPNM.

### Docker and Kubernetes Implications

SQLite:

- Uses a single DB file under a persisted application data volume (recommended: `.data/db/pypnm.sqlite3`).
- Simplifies deployment because no external DB service is required.
- For container deployments, the SQLite file must be placed on a persisted volume.

Postgres:

- Runs as a separate service (container or external managed service).
- Requires DSN configuration and network connectivity.
- Better concurrency and observability for multi-process / multi-worker scenarios.

In either backend, the artifact root directories must also be persisted (volume mounts) because binaries remain on disk.

## Example Rows (Illustrative)

### Transaction record fields

- `transaction_id`: text id (example: `7d6058eb9c92bd98`)
- `timestamp_epoch`: epoch seconds
- `mac_address`: `aa:bb:cc:dd:ee:ff`
- `pnm_test_type`: measurement token (example: `DS_OFDM_RXMER_PER_SUBCAR`)
- `filename`: file name for convenience (legacy carry-over; artifact linkage is authoritative)
- `device_detail_id`: FK to device_details

### System description fields (canonical example block)

```json
{"HW_REV":"1.0","VENDOR":"LANCity","BOOTR":"NONE","SW_REV":"1.0.0","MODEL":"LCPET-3"}
```

## Appendix A: Postgres DDL

```sql
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Maurice Garcia

BEGIN;

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
    operation_capture_id  TEXT   PRIMARY KEY,
    capture_group_id      TEXT   NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,
    created_epoch         BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
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

## Appendix B: SQLite DDL

```sql
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Maurice Garcia

PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

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
    operation_capture_id  TEXT    PRIMARY KEY,
    capture_group_id      TEXT    NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,
    created_epoch         INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
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

## Appendix C: Store Seeding Examples

### Prod DB seed

- `artifact_stores.store_name = 'default'`
- `artifact_stores.root_path = '.data/pnm'`

### Demo DB seed

- `artifact_stores.store_name = 'default'`
- `artifact_stores.root_path = 'demo/.data/pnm'`

This keeps the database portable and aligned with your repo layout.
