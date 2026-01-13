## Agent Review Bundle Summary
- Goal: Replace session_group.json runtime persistence with DB-backed storage and provide a migrator.
- Changes: Added session group tables and repository, migrated SessionGroup to DB, added migrator tool, updated docs, and added tests.
- Files: docs/design/db/schema_sqlite.sql, docs/design/db/schema_postgres.sql, src/pypnm/api/routes/common/classes/file_capture/session_group.py, src/pypnm/lib/db/session_group_repository.py, src/pypnm/tools/migrate_session_groups.py, tests/test_session_group_repository.py, tests/test_session_group_migrator.py, tests/test_transaction_id_persistence_guards.py, docs/system/system-config.md, docs/issues/index.md, src/pypnm/lib/db/db_schema_manager.py.
- Tests: python3 -m compileall src; ruff check src; ruff format --check .; pytest -q.
- Notes: Pytest skips: SNMP integration tests (PNM_CM_IT) and Postgres schema init (PYPNM_DB_POSTGRES_DSN).

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

CREATE TABLE IF NOT EXISTS session_groups (
    session_id     TEXT   PRIMARY KEY,
    created_epoch  BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_session_groups_created_epoch
ON session_groups (created_epoch);

CREATE TABLE IF NOT EXISTS session_group_transactions (
    session_group_transaction_id  BIGSERIAL PRIMARY KEY,
    session_id                    TEXT     NOT NULL REFERENCES session_groups(session_id) ON DELETE CASCADE,
    transaction_id                TEXT     NOT NULL,
    position                      INTEGER  NOT NULL,
    added_epoch                   BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT uq_session_group_position UNIQUE (session_id, position),
    CONSTRAINT uq_session_group_transaction UNIQUE (session_id, transaction_id)
);

CREATE INDEX IF NOT EXISTS idx_sg_tx_session_id
ON session_group_transactions (session_id);

CREATE INDEX IF NOT EXISTS idx_sg_tx_transaction_id
ON session_group_transactions (transaction_id);

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

CREATE TABLE IF NOT EXISTS session_groups (
    session_id     TEXT    PRIMARY KEY,
    created_epoch  INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX IF NOT EXISTS idx_session_groups_created_epoch
ON session_groups (created_epoch);

CREATE TABLE IF NOT EXISTS session_group_transactions (
    session_group_transaction_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id                    TEXT    NOT NULL REFERENCES session_groups(session_id) ON DELETE CASCADE,
    transaction_id                TEXT    NOT NULL,
    position                      INTEGER NOT NULL,
    added_epoch                   INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    UNIQUE (session_id, position),
    UNIQUE (session_id, transaction_id)
);

CREATE INDEX IF NOT EXISTS idx_sg_tx_session_id
ON session_group_transactions (session_id);

CREATE INDEX IF NOT EXISTS idx_sg_tx_transaction_id
ON session_group_transactions (transaction_id);

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
    "session_groups",
    "session_group_transactions",
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

# FILE: src/pypnm/api/routes/common/classes/file_capture/session_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import time
import uuid

from pypnm.lib.db.session_group_repository import SessionGroupRepository
from pypnm.lib.types import GroupId, TimestampSec, TransactionId


class SessionGroup:
    """
    Manage sessions of measure operations (e.g., RxMER runs that contains multiple
    OFDM Channels within a single session) by grouping multiple file-transfer
    transactions under a single UUID-based group ID.

    Features:
      - Persist groups and their transaction lists in the configured DB backend.
      - Generate or load a 16-character hexadecimal group ID per session.
      - Add, list, delete transactions; prune stale groups.

    Example:
        # New session
        cg = CaptureGroup()
        group_id = cg.create_group()

        # Existing session
        cg2 = SessionGroup(group_id=group_id)
        txns = cg2.get_transactions()
    """

    def __init__(
        self, session_id: GroupId | None = None, db_path: str | None = None
    ) -> None:
        """
        Initialize the SessionGroup manager.

        Args:
            session_id: Optional existing session ID to load; generates a new one if None.
            db_path: Legacy JSON DB path (deprecated; ignored in DB-backed storage).
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        if db_path:
            self.logger.debug(
                "Ignoring legacy session_group_db path override: %s",
                db_path,
            )
        self._repo = SessionGroupRepository.from_system_config()
        self._grp_id: GroupId | None = session_id
        self._create_group_id()

    def _create_group_id(self) -> GroupId:
        """
        Ensure a session ID is set (use existing or generate new).
        Returns the active session ID.
        """
        if not self._grp_id:
            self._grp_id = GroupId(uuid.uuid4().hex[:16])
        return self._grp_id

    def get_session_id(self) -> GroupId:
        """
        Get the current active session ID.
        Raises AssertionError if uninitialized.
        """
        assert self._grp_id, "session ID not initialized"
        return self._grp_id

    def create_session(self) -> GroupId:
        """
        Add the current session to the DB (no-op if exists).
        Returns the session ID.
        """
        gid = self.get_session_id()
        if not self._repo.session_exists(gid):
            created_epoch = TimestampSec(int(time.time()))
            self._repo.create_session_group(gid, created_epoch)
            self.logger.info(f"Created new session: {gid}")
        else:
            self.logger.debug(f"session {gid} already exists")
        return gid

    def add_transaction(self, txn_id: TransactionId | str) -> None:
        """
        Append a transaction ID to this session, saving the DB.
        Raises ValueError if session missing.
        """
        txn_value = str(txn_id)
        if not txn_value or not txn_value.strip():
            self.logger.warning(
                "Skipping empty transaction_id persistence in session_group for session_id=%s",
                self.get_session_id(),
            )
            return
        gid = self.get_session_id()
        if not self._repo.session_exists(gid):
            raise ValueError("session not found; create_session() first")
        self._repo.add_transaction(
            gid, TransactionId(txn_value), TimestampSec(int(time.time()))
        )
        self.logger.debug(f"Added txn {txn_value} to session {gid}")

    def get_transactions(self) -> list[TransactionId]:
        """
        Return all transaction IDs for this session (empty list if none).
        """
        return self._repo.list_transactions(self.get_session_id())

    def delete_session(self) -> None:
        """
        Remove this session and its transactions from the DB; resets session ID.
        """
        gid = self.get_session_id()
        self._repo.delete_session(gid)
        self.logger.info(f"Deleted session: {gid}")
        self._grp_id = None

    def list_sessions(self) -> list[GroupId]:
        """
        List all session IDs currently in the DB.
        """
        return self._repo.list_sessions()

    def prune_older_than(self, seconds: int) -> None:
        """
        Remove sessions older than the given age (seconds).
        """
        cutoff = TimestampSec(int(time.time()) - seconds)
        pruned = self._repo.delete_older_than(cutoff)
        if pruned:
            self.logger.info(f"Pruned sessions: {pruned}")

# FILE: src/pypnm/lib/db/session_group_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.lib.db.transaction_repository import _RepositoryBase
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    TimestampSec,
    TransactionId,
)

_NO_POSITION: int = -1
_POSITION_INCREMENT: int = 1


class SessionGroupRepository(_RepositoryBase):
    """
    Repository for session_groups and session_group_transactions.
    """

    @classmethod
    def from_system_config(cls) -> SessionGroupRepository:
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
    ) -> SessionGroupRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def session_exists(self, session_id: GroupId) -> bool:
        """
        Return True if the session group exists.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        "SELECT 1 FROM session_groups WHERE session_id = ? LIMIT 1;",
                        (str(session_id),),
                    )
                    row = cursor.fetchone()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT 1 FROM session_groups WHERE session_id = %s LIMIT 1;",
                            (str(session_id),),
                        )
                        row = cursor.fetchone()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
            return row is not None
        finally:
            connection.close()

    def create_session_group(
        self, session_id: GroupId, created_epoch: TimestampSec
    ) -> None:
        """
        Insert a session group row (idempotent on session_id).
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        ""
                        "INSERT OR IGNORE INTO session_groups ("
                        "    session_id, created_epoch"
                        ") VALUES (?, ?);",
                        (str(session_id), int(created_epoch)),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            ""
                            "INSERT INTO session_groups ("
                            "    session_id, created_epoch"
                            ") VALUES (%s, %s) ON CONFLICT (session_id) DO NOTHING;",
                            (str(session_id), int(created_epoch)),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def add_transaction(
        self,
        session_id: GroupId,
        transaction_id: TransactionId,
        added_epoch: TimestampSec,
    ) -> None:
        """
        Insert a transaction mapping for a session group (idempotent on transaction_id).
        """
        position = self._next_position(session_id)
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        ""
                        "INSERT OR IGNORE INTO session_group_transactions ("
                        "    session_id, transaction_id, position, added_epoch"
                        ") VALUES (?, ?, ?, ?);",
                        (
                            str(session_id),
                            str(transaction_id),
                            int(position),
                            int(added_epoch),
                        ),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            ""
                            "INSERT INTO session_group_transactions ("
                            "    session_id, transaction_id, position, added_epoch"
                            ") VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING;",
                            (
                                str(session_id),
                                str(transaction_id),
                                int(position),
                                int(added_epoch),
                            ),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def list_transactions(self, session_id: GroupId) -> list[TransactionId]:
        """
        Return ordered transaction IDs for a session group.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        ""
                        "SELECT transaction_id FROM session_group_transactions "
                        "WHERE session_id = ? "
                        "ORDER BY position ASC, transaction_id ASC;",
                        (str(session_id),),
                    )
                    rows = cursor.fetchall()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            ""
                            "SELECT transaction_id FROM session_group_transactions "
                            "WHERE session_id = %s "
                            "ORDER BY position ASC, transaction_id ASC;",
                            (str(session_id),),
                        )
                        rows = cursor.fetchall()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
            return [TransactionId(str(row[0])) for row in rows]
        finally:
            connection.close()

    def list_sessions(self) -> list[GroupId]:
        """
        Return all session IDs in creation order.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        ""
                        "SELECT session_id FROM session_groups "
                        "ORDER BY created_epoch ASC, session_id ASC;"
                    )
                    rows = cursor.fetchall()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            ""
                            "SELECT session_id FROM session_groups "
                            "ORDER BY created_epoch ASC, session_id ASC;"
                        )
                        rows = cursor.fetchall()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
            return [GroupId(str(row[0])) for row in rows]
        finally:
            connection.close()

    def delete_session(self, session_id: GroupId) -> None:
        """
        Delete a session group and cascade its transaction mappings.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        "DELETE FROM session_groups WHERE session_id = ?;",
                        (str(session_id),),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM session_groups WHERE session_id = %s;",
                            (str(session_id),),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def delete_older_than(self, cutoff_epoch: TimestampSec) -> list[GroupId]:
        """
        Delete sessions older than the cutoff epoch and return deleted IDs.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        "SELECT session_id FROM session_groups WHERE created_epoch < ?;",
                        (int(cutoff_epoch),),
                    )
                    rows = cursor.fetchall()
                    connection.execute(
                        "DELETE FROM session_groups WHERE created_epoch < ?;",
                        (int(cutoff_epoch),),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT session_id FROM session_groups WHERE created_epoch < %s;",
                            (int(cutoff_epoch),),
                        )
                        rows = cursor.fetchall()
                        cursor.execute(
                            "DELETE FROM session_groups WHERE created_epoch < %s;",
                            (int(cutoff_epoch),),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
            return [GroupId(str(row[0])) for row in rows]
        finally:
            connection.close()

    def _next_position(self, session_id: GroupId) -> int:
        max_position = self._fetch_max_position(session_id)
        return max_position + _POSITION_INCREMENT

    def _fetch_max_position(self, session_id: GroupId) -> int:
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        ""
                        "SELECT MAX(position) FROM session_group_transactions "
                        "WHERE session_id = ?;",
                        (str(session_id),),
                    )
                    row = cursor.fetchone()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            ""
                            "SELECT MAX(position) FROM session_group_transactions "
                            "WHERE session_id = %s;",
                            (str(session_id),),
                        )
                        row = cursor.fetchone()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
            if not row or row[0] is None:
                return _NO_POSITION
            return int(row[0])
        finally:
            connection.close()

# FILE: src/pypnm/tools/migrate_session_groups.py
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.session_group_repository import SessionGroupRepository
from pypnm.lib.types import ExitCode, GroupId, JsonObject, StringArray, TimestampSec, TransactionId

_DEFAULT_LOG_FORMAT: str = "%(levelname)s %(name)s: %(message)s"
_CREATED_EPOCH_KEYS: tuple[str, ...] = ("created_epoch", "created", "timestamp", "created_at")


@dataclass(frozen=True)
class SessionGroupRecord:
    session_id: GroupId
    created_epoch: TimestampSec
    transactions: list[TransactionId]


class SessionGroupMigrator:
    """
    Import legacy session_group.json into the DB-backed session group tables.
    """

    EXIT_OK: ExitCode = ExitCode(0)
    EXIT_USAGE: ExitCode = ExitCode(2)
    EXIT_FAILURE: ExitCode = ExitCode(1)

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @staticmethod
    def _load_json(path: Path) -> JsonObject:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("session_group.json must contain a JSON object")
        return payload

    @staticmethod
    def _extract_transactions(entry: object) -> list[TransactionId]:
        if isinstance(entry, dict):
            candidates = (
                entry.get("transactions"),
                entry.get("transaction_ids"),
                entry.get("transaction_id_list"),
            )
            for candidate in candidates:
                if isinstance(candidate, list):
                    return SessionGroupMigrator._normalize_transactions(candidate)
            return []
        if isinstance(entry, list):
            return SessionGroupMigrator._normalize_transactions(entry)
        return []

    @staticmethod
    def _normalize_transactions(items: list[object]) -> list[TransactionId]:
        transactions: list[TransactionId] = []
        for item in items:
            if not isinstance(item, str):
                continue
            cleaned = item.strip()
            if cleaned:
                transactions.append(TransactionId(cleaned))
        return transactions

    @staticmethod
    def _extract_created_epoch(entry: object, fallback: TimestampSec) -> TimestampSec:
        if isinstance(entry, dict):
            for key in _CREATED_EPOCH_KEYS:
                raw = entry.get(key)
                if isinstance(raw, int):
                    return TimestampSec(int(raw))
                if isinstance(raw, float):
                    return TimestampSec(int(raw))
                if isinstance(raw, str) and raw.isdigit():
                    return TimestampSec(int(raw))
        return fallback

    def _parse_records(self, payload: JsonObject) -> list[SessionGroupRecord]:
        records: list[SessionGroupRecord] = []
        now = TimestampSec(int(time.time()))
        for session_id, entry in payload.items():
            if not isinstance(session_id, str):
                continue
            normalized_session = session_id.strip()
            if not normalized_session:
                continue
            created_epoch = self._extract_created_epoch(entry, now)
            transactions = self._extract_transactions(entry)
            records.append(
                SessionGroupRecord(
                    session_id=GroupId(normalized_session),
                    created_epoch=created_epoch,
                    transactions=transactions,
                )
            )
        return records

    def _migrate_records(self, records: list[SessionGroupRecord]) -> tuple[int, int]:
        repo = SessionGroupRepository.from_system_config()
        session_count = 0
        transaction_count = 0
        for record in records:
            repo.create_session_group(record.session_id, record.created_epoch)
            session_count += 1
            for txn_id in record.transactions:
                repo.add_transaction(record.session_id, txn_id, record.created_epoch)
                transaction_count += 1
        return session_count, transaction_count

    def run(self, argv: StringArray) -> ExitCode:
        parser = argparse.ArgumentParser(
            description="Migrate legacy session_group.json into the DB backend."
        )
        parser.add_argument(
            "--input",
            type=Path,
            help="Path to legacy session_group.json (defaults to system.json config).",
        )

        args = parser.parse_args(argv)
        SystemConfigSettings.reload()

        input_path = args.input
        if input_path is None:
            configured = SystemConfigSettings.session_group_db()
            if not configured:
                self.logger.error("No session_group_db configured and --input not provided.")
                return self.EXIT_USAGE
            input_path = Path(configured)

        if not input_path.exists():
            self.logger.error("Legacy session_group.json not found: %s", input_path)
            return self.EXIT_USAGE

        try:
            payload = self._load_json(input_path)
        except Exception as exc:
            self.logger.error("Failed to read legacy session_group.json: %s", exc)
            return self.EXIT_FAILURE

        DatabaseSchemaManager.from_system_config().initialize_schema()

        records = self._parse_records(payload)
        session_count, transaction_count = self._migrate_records(records)

        self.logger.info(
            "Migrated %d session groups and %d transactions from %s",
            session_count,
            transaction_count,
            input_path,
        )
        return self.EXIT_OK


def main() -> None:
    logging.basicConfig(level=logging.INFO, format=_DEFAULT_LOG_FORMAT)
    migrator = SessionGroupMigrator()
    raise SystemExit(migrator.run(sys.argv[1:]))


if __name__ == "__main__":
    main()

# FILE: tests/test_transaction_id_persistence_guards.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.session_group import SessionGroup
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.session_group_repository import SessionGroupRepository
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    TransactionId,
)
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest

_TRANSACTION_ID_LENGTH: int = 16
_TIME_NS_FIRST: int = 100
_TIME_NS_SECOND: int = 101


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


def _guard_json_ledgers(monkeypatch: pytest.MonkeyPatch) -> None:
    original_open = Path.open

    def _guarded_open(
        self: Path, *args: tuple[object, ...], **kwargs: dict[str, object]
    ) -> object:
        if self.name == "session_group.json":
            raise AssertionError(f"Unexpected JSON ledger access: {self}")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _guarded_open)


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
    _configure_transaction_db(tmp_path, monkeypatch)
    _guard_json_ledgers(monkeypatch)
    caplog.set_level("WARNING")
    group = SessionGroup()
    session_id = group.create_session()

    group.add_transaction("")
    group.add_transaction("   ")
    group.add_transaction("txn-1")

    repo = SessionGroupRepository.from_system_config()
    assert repo.list_transactions(session_id) == [TransactionId("txn-1")]
    assert "Skipping empty transaction_id persistence in session_group" in caplog.text


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


@pytest.mark.asyncio
async def test_pnm_file_transaction_insert_persists_mac_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_transaction_db(tmp_path, monkeypatch)
    txn_store = PnmFileTransaction()
    cm = CableModem(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        inet=Inet("192.168.0.100"),
        write_community="public",
    )

    async def _fake_sysdescr() -> SystemDescriptor:
        return SystemDescriptor.empty()

    monkeypatch.setattr(cm, "getSysDescr", _fake_sysdescr)

    txn_id = await txn_store.insert(
        cable_modem=cm,
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        filename="rxmer.bin",
    )

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.execute(
            "SELECT mac_address FROM transaction_records WHERE transaction_id = ?;",
            (str(txn_id),),
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == "aa:bb:cc:dd:ee:ff"
    finally:
        connection.close()


def test_pnm_file_transaction_id_is_unique_and_16_chars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_transaction_db(tmp_path, monkeypatch)

    time_ns_values = iter([_TIME_NS_FIRST, _TIME_NS_SECOND])

    def _fake_time_ns() -> int:
        return next(time_ns_values)

    monkeypatch.setattr(
        "pypnm.api.routes.common.classes.file_capture.pnm_file_transaction.time.time_ns",
        _fake_time_ns,
    )

    txn_store = PnmFileTransaction()
    mac_address = MacAddress("aa:bb:cc:dd:ee:ff")
    first_id = txn_store._insert_generic(
        mac_address=mac_address,
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        filename="rxmer.bin",
    )
    second_id = txn_store._insert_generic(
        mac_address=mac_address,
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        filename="rxmer.bin",
    )

    assert str(first_id) != str(second_id)
    assert len(str(first_id)) == _TRANSACTION_ID_LENGTH
    assert len(str(second_id)) == _TRANSACTION_ID_LENGTH

# FILE: tests/test_session_group_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.session_group_repository import SessionGroupRepository
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    TimestampSec,
    TransactionId,
)

DEFAULT_CREATED_EPOCH: int = 10
DEFAULT_ADDED_EPOCH: int = 11


def _configure_session_group_db(
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


def test_session_group_repository_ordering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_session_group_db(tmp_path, monkeypatch)
    repo = SessionGroupRepository.from_system_config()
    session_id = GroupId("session-1")
    repo.create_session_group(session_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        session_id,
        TransactionId("txn-b"),
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )
    repo.add_transaction(
        session_id,
        TransactionId("txn-a"),
        TimestampSec(DEFAULT_ADDED_EPOCH + 1),
    )

    assert repo.list_transactions(session_id) == [
        TransactionId("txn-b"),
        TransactionId("txn-a"),
    ]


def test_session_group_repository_ignores_duplicate_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_session_group_db(tmp_path, monkeypatch)
    repo = SessionGroupRepository.from_system_config()
    session_id = GroupId("session-dup")
    repo.create_session_group(session_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        session_id,
        TransactionId("txn-1"),
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )
    repo.add_transaction(
        session_id,
        TransactionId("txn-1"),
        TimestampSec(DEFAULT_ADDED_EPOCH + 1),
    )

    assert repo.list_transactions(session_id) == [TransactionId("txn-1")]

# FILE: tests/test_session_group_migrator.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.session_group_repository import SessionGroupRepository
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    TransactionId,
)
from pypnm.tools.migrate_session_groups import SessionGroupMigrator

DEFAULT_CREATED_EPOCH: int = 10


def _configure_session_group_db(
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
    return db_path


def test_session_group_migrator_imports_legacy_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_session_group_db(tmp_path, monkeypatch)
    legacy_path = tmp_path / "session_group.json"
    legacy_payload = {
        "session-1": {
            "transactions": ["txn-1", "txn-2"],
            "created_epoch": DEFAULT_CREATED_EPOCH,
        },
        "session-2": ["txn-3"],
    }
    legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

    exit_code = SessionGroupMigrator().run(["--input", str(legacy_path)])

    assert exit_code == SessionGroupMigrator.EXIT_OK

    repo = SessionGroupRepository.from_system_config()
    assert repo.list_transactions(GroupId("session-1")) == [
        TransactionId("txn-1"),
        TransactionId("txn-2"),
    ]
    assert repo.list_transactions(GroupId("session-2")) == [TransactionId("txn-3")]

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
Legacy JSON ledger paths remain for offline migration or diagnostics only. Runtime persistence for transactions, capture groups, operation mappings, and session groups is DB-backed.

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
| transaction_db      | string | Legacy JSON ledger for file transactions (migration only). |
| capture_group_db    | string | Legacy JSON map of grouped transactions (migration only).  |
| session_group_db    | string | Legacy JSON map of session groups (migration only).        |
| operation_db        | string | Legacy JSON map of operation to capture group (migration only). |
| json_transaction_db | string | Legacy JSON map of JSON transaction metadata (migration only). |

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

Runtime no longer reads `operation_capture.json` after the DB cutover, so legacy
keys are not accepted by live endpoints. Use the offline migrator or re-run the
capture workflow on a DB-backed build to populate the operation-to-group
mapping in the database.

### Session group mappings missing after upgrade

Runtime no longer reads `session_group.json`; session groups are DB-backed. Use
the offline migrator (`python -m pypnm.tools.migrate_session_groups --input
PATH`) or re-run the session workflow to repopulate the DB.

### Transaction records store an unexpected MAC address value

The canonical MAC address stored in `transaction_records` is a lowercase string.
Earlier builds could persist a non-string value when `PnmFileTransaction.insert`
was passed a callable. Upgrade to a build with the fix and re-run captures to
refresh affected entries.
