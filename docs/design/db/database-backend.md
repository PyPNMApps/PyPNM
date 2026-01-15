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
  - [7.5 Adapter Contract And Bootstrap](#75-adapter-contract-and-bootstrap)
- [8. Release Hygiene Requirements](#8-release-hygiene-requirements)
  - [8.1 Git Ignore And Packaging Exclusions](#81-git-ignore-and-packaging-exclusions)
  - [8.2 Docker And Container Image Hygiene](#82-docker-and-container-image-hygiene)
- [9. Target Schema (Planned)](#9-target-schema-planned)
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

This section is a working marker so you can see progress against the design while the DB cutover is in-flight.

Work completed toward the DB bootstrap contract:

- Unified operation workflow payload shape across newer registry-style endpoints:
  - Dual-status support (legacy `status` string plus canonical `service_status`)
  - Shared `time_remaining` contract on registry status endpoints, including safe coercion and default fallback behavior
- Multi-capture registry status endpoints aligned to the shared `time_remaining` contract:
  - Multi-RxMER `/advance/multiRxMer/status` (POST)
  - Multi-ChannelEstimation `/advance/multiChannelEstimation/status` (POST)
- Test coverage added to lock in the above contract behavior and keep the validation gate green.

Bootstrap status:

- The adapter contract and schema bootstrap readiness check are implemented.
- The full schema and data migrations remain planned work.

## 1. Purpose

PyPNM historically persisted transaction metadata using JSON “ledger” files under `.data/db/`. The DB backend is
being introduced incrementally; the JSON ledgers are deprecated, but the DB is not yet authoritative for
transactions, capture groups, or operations. This design defines the target state for replacing the ledger with a
relational database while preserving PyPNM’s operational model
(filesystem-based binary artifacts plus lightweight metadata persistence).

This document is authoritative for:

- PyPNM (authoritative engine and persistence owner)
- PyPNM-CMTS (consumer of PyPNM; inherits PyPNM’s backend choice)

The current implementation only provides a minimal bootstrap contract; see [Bootstrap Contract](bootstrap-contract.md)
for implemented behavior. The schema and workflow sections below are forward-looking until later phases land.

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

Planned changes for later phases:

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

- The template and SystemConfigSettings accessors align to this contract; installer output preserves the same keys.

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
- Postgres driver support is optional and provided by the `postgres` extra (install with `pypnm-docsis[postgres]`).

### 7.5 Adapter Contract And Bootstrap

The DB adapter contract provides a minimal lifecycle interface: `connect`, `apply_schema`, `healthcheck`, and `close`.
Adapters must remain policy-neutral and focused on the bootstrap path only.

Backend selection precedence (contract):

1) Environment overrides (`PYPNM_DB_BACKEND`, `PYPNM_DB_POSTGRES_DSN`)
2) Configuration file values (`Database.backend`, `Database.postgres.dsn`)
3) Defaults (SQLite)

DatabaseManager selection may fall back to SQLite without raising if the Postgres DSN is invalid or blank. The
schema manager is fail-fast: when backend is postgres and the DSN is invalid or blank, it raises a clear error.

Schema bootstrap scope (current phase):

- `schema_meta` and the baseline tables are applied to support transactions, grouping, and artifact metadata.
- `initialize()` connects, applies schema/seed rows idempotently, and checks health.
- `close()` tears down the adapter and clears the cached instance for re-selection.
- Schema DDL assets are loaded from package data (via importlib.resources); docs copies are reference-only.

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

## 9. Target Schema (Planned)

This section describes the planned target schema and workflow contracts. It is not implemented yet beyond the
bootstrap table used for readiness checks.

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
- Position assignment uses `MAX(position) + 1` with bounded retries on collisions

operation_captures:

- One row per operation id
- References capture group id
- DB-backed mapping is authoritative; JSON ledgers are deprecated

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

Documentation changes required (planned, not yet complete):

- Remove or clearly mark deprecated any documentation that describes JSON ledger persistence as the design
- When the DB becomes authoritative (Phase 3+), update file manager docs to state: transactions capture groups operations are DB-backed; binaries remain on disk
- Update any docs that still imply JSON ledger authority for transaction/group/operation metadata
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

- The initial DB-backed release is `schema_meta.schema_version = 1`.
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

Authoritative DDL is maintained in the schema_*.sql files.

```sql
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

CREATE INDEX IF NOT EXISTS idx_cg_tx_capture_group_position
ON capture_group_transactions (capture_group_id, position);

CREATE INDEX IF NOT EXISTS idx_cg_tx_transaction_id
ON capture_group_transactions (transaction_id);

CREATE TABLE IF NOT EXISTS operation_captures (
    operation_id     TEXT   PRIMARY KEY,
    capture_group_id TEXT   NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,
    created_epoch    BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_operation_captures_capture_group_id
ON operation_captures (capture_group_id);

CREATE INDEX IF NOT EXISTS idx_operation_captures_operation_id
ON operation_captures (operation_id);

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

Authoritative DDL is maintained in the schema_*.sql files.

```sql
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

CREATE INDEX IF NOT EXISTS idx_cg_tx_capture_group_position
ON capture_group_transactions (capture_group_id, position);

CREATE INDEX IF NOT EXISTS idx_cg_tx_transaction_id
ON capture_group_transactions (transaction_id);

CREATE TABLE IF NOT EXISTS operation_captures (
    operation_id     TEXT    PRIMARY KEY,
    capture_group_id TEXT    NOT NULL REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,
    created_epoch    INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_operation_captures_capture_group_id
ON operation_captures (capture_group_id);

CREATE INDEX IF NOT EXISTS idx_operation_captures_operation_id
ON operation_captures (operation_id);

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
