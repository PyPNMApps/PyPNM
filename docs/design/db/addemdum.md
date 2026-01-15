# PyPNM DB Backend · Locked Decisions (Selection Summary)

This file captures the decision set you selected:

`1A, 2B+2.1B, 3B, 4A(SQLite)+4C(Postgres when PyPNM-CMTS/multi-worker), 5C+5.1A, 6B+6.1A, 7B, 8A`

## Insert Into Design Doc

Add this as a new section (recommended placement: after **4. Design Requirements** or after **7. Backend Selection And Installation Contract**).

### Design Decision Register

1) **Persistence Ownership (1A)**  
   PyPNM owns persistence, schema initialization, and DB access APIs. PyPNM-CMTS must use PyPNM DB APIs only and must not implement a separate backend selector or schema manager.

2) **Installer Behavior (2B)**  
   `install.sh` supports explicit flags and a safe default:
   - `--db-install-sqlite` (default when no flag provided)
   - `--db-install-postgres`
   - If no flag is provided: interactive prompt with default `sqlite`.

3) **Secrets / Credential Handling (2.1B)**  
   Postgres credentials are not required to be stored in tracked JSON.  
   Required behavior:
   - Support env var overrides (and/or `.env`) for DSN/password
   - CI/dev may use `pypnm/pypnm` defaults, but docs must label them “development only”.

4) **Schema Application Model (3B)**  
   Schema init is performed via an idempotent SQL apply step using the shipped DDL assets:
   - `docs/design/db/schema_sqlite.sql`
   - `docs/design/db/schema_postgres.sql`  
   The apply step must:
   - Create tables/indexes idempotently
   - Seed canonical `UNKNOWN` sysDescr row idempotently
   - Seed default `artifact_stores` row idempotently (prod and demo, as applicable)
   - Enable SQLite FK enforcement (`PRAGMA foreign_keys = ON`).

5) **Concurrency And Backend Guidance (4A + 4C)**  
   - **SQLite (4A)** is supported for single-process, single-writer deployments (typical PyPNM standalone use).  
   - **Postgres (4C)** is the recommended backend when running **PyPNM-CMTS** and/or any **multi-worker / multi-process** deployment mode.  
   Installer and docs must communicate this clearly (no ambiguity).

6) **Artifact Store + Path Portability (5C + 5.1A)**  
   The DB stores only portable, app-root relative paths:
   - `artifact_stores.root_path` is app-root relative (prod: `.data/pnm`; demo: `demo/.data/pnm`)
   - `file_artifacts.relative_path` is relative to the store root  
   Runtime resolution:
   `absolute_path = Path(app_root) / artifact_stores.root_path / file_artifacts.relative_path`

7) **CI Policy And Postgres Validation (6B + 6.1A)**  
   - SQLite tests are mandatory in CI.  
   - Postgres tests are validated in CI using a service container (recommended: required, not “allowed failure”), with DSN provided via env vars.  
   CI credential defaults are acceptable for the service container only.

8) **Cutover / Legacy Ledger Strategy (8A)**  
   Treat JSON ledger persistence as deprecated and removed from the design and code paths.  
   Optional: a one-time offline migrator may be added later, but it must not be required for normal installs and must not ship populated DBs.

## Burndown Deltas

If these items are not already explicit in the burndown, add them so Codex cannot miss them.

### Phase 1 (M1) · Installer

- [ ] Add install-time warning text:
  - [ ] SQLite is recommended for standalone PyPNM/single-writer.
  - [ ] Postgres is recommended for PyPNM-CMTS and/or multi-worker.
- [ ] Postgres prompt path:
  - [ ] Allow DSN entry OR discrete fields that render into a DSN.
  - [ ] Ensure password can be provided via env var override (no plaintext requirement in JSON).

### Phase 2 (M2) · Schema Apply

- [ ] Seed `artifact_stores` idempotently:
  - [ ] prod store: `.data/pnm`
  - [ ] demo store: `demo/.data/pnm` (only if demo enabled/used)

### Phase 6 (M6) · Docs + Mermaid

- [ ] Remove/replace any remaining doc references to legacy JSON ledgers now that the DB is authoritative.
- [ ] Add Mermaid support for docs builds:
  - [ ] Add Mermaid plugin dependency to docs extras in `pyproject.toml` (example: `mkdocs-mermaid2-plugin`)
  - [ ] Update MkDocs config to render Mermaid fences (`pymdownx.superfences` mermaid custom fence)

### Phase 7 (M7) · Pytest + GitHub Actions

- [ ] Replace legacy ledger fixtures/tests with DB fixtures:
  - [ ] temporary SQLite DB under `tmp_path` + schema init helper
  - [ ] default artifact store seed helper
  - [ ] UNKNOWN sysDescr seed helper
- [ ] Add CI job for Postgres:
  - [ ] `postgres` service container
  - [ ] env var DSN provided to tests
  - [ ] schema init executed during test setup (idempotent)

## Optional Text For Docs

Use this wording (or equivalent) in the design doc and install docs:

- SQLite is intended for single-writer deployments and local/lab usage.
- For PyPNM-CMTS and/or multi-worker deployments, Postgres is recommended to avoid SQLite write contention and locked-database failure modes.
