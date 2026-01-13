## Agent Review Bundle Summary
- Goal: Enforce FK integrity for session group transactions and remove position race drop behavior.
- Changes: Added FK constraints in schema, reordered session transaction listing, adjusted add_transaction to avoid silent position drops, updated SessionGroup logging/docstring, and seeded transaction records in tests.
- Files: docs/design/db/schema_sqlite.sql, docs/design/db/schema_postgres.sql, src/pypnm/lib/db/session_group_repository.py, src/pypnm/api/routes/common/classes/file_capture/session_group.py, tests/test_session_group_repository.py, tests/test_session_group_migrator.py, tests/test_transaction_id_persistence_guards.py.
- Tests: python3 -m compileall src; ruff check src; ruff format --check .; pytest -q.
- Notes: Pytest skips: SNMP integration tests (PNM_CM_IT) and Postgres schema init (PYPNM_DB_POSTGRES_DSN).

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
    transaction_id                TEXT    NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    position                      INTEGER NOT NULL,
    added_epoch                   INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

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
    transaction_id                TEXT     NOT NULL REFERENCES transaction_records(transaction_id) ON DELETE CASCADE,
    position                      INTEGER  NOT NULL,
    added_epoch                   BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

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

# FILE: src/pypnm/lib/db/session_group_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import sqlite3

from pypnm.lib.db.transaction_repository import _RepositoryBase
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    TimestampSec,
    TransactionId,
)

_POSITION_RETRY_LIMIT: int = 5


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
        position_base = int(added_epoch)
        connection = self._connect()
        try:
            for attempt in range(_POSITION_RETRY_LIMIT):
                position = position_base + attempt
                try:
                    match self._backend:
                        case DatabaseBackend.SQLITE:
                            connection.execute(
                                ""
                                "INSERT INTO session_group_transactions ("
                                "    session_id, transaction_id, position, added_epoch"
                                ") VALUES (?, ?, ?, ?) "
                                "ON CONFLICT(session_id, transaction_id) DO NOTHING;",
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
                                    ") VALUES (%s, %s, %s, %s) "
                                    "ON CONFLICT (session_id, transaction_id) DO NOTHING;",
                                    (
                                        str(session_id),
                                        str(transaction_id),
                                        int(position),
                                        int(added_epoch),
                                    ),
                                )
                            connection.commit()
                        case _:
                            raise ValueError(
                                f"Unsupported Database backend: {self._backend}"
                            )
                    return
                except sqlite3.IntegrityError as exc:
                    if not self._is_sqlite_position_conflict(exc):
                        raise
                    if attempt >= (_POSITION_RETRY_LIMIT - 1):
                        raise
                except Exception as exc:
                    if not self._is_postgres_position_conflict(exc):
                        raise
                    if attempt >= (_POSITION_RETRY_LIMIT - 1):
                        raise
            raise RuntimeError(
                "Failed to insert session group transaction after retries"
            )
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
                        "ORDER BY added_epoch ASC, transaction_id ASC;",
                        (str(session_id),),
                    )
                    rows = cursor.fetchall()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            ""
                            "SELECT transaction_id FROM session_group_transactions "
                            "WHERE session_id = %s "
                            "ORDER BY added_epoch ASC, transaction_id ASC;",
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

    @staticmethod
    def _is_sqlite_position_conflict(exc: sqlite3.IntegrityError) -> bool:
        marker = (
            "session_group_transactions.session_id, session_group_transactions.position"
        )
        return marker in str(exc)

    @staticmethod
    def _is_postgres_position_conflict(exc: Exception) -> bool:
        try:
            from psycopg import errors as psycopg_errors
        except ImportError:
            return False
        if isinstance(exc, psycopg_errors.UniqueViolation):
            constraint_name = getattr(exc.diag, "constraint_name", "")
            return constraint_name == "uq_session_group_position"
        return False

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
        sg = SessionGroup()
        session_id = sg.create_session()

        # Existing session
        sg2 = SessionGroup(session_id=session_id)
        txns = sg2.get_transactions()
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
            self.logger.info("Created new session: %s", gid)
        else:
            self.logger.debug("Session %s already exists", gid)
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
        self.logger.debug("Added txn %s to session %s", txn_value, gid)

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
        self.logger.info("Deleted session: %s", gid)
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
            self.logger.info("Pruned sessions: %s", pruned)

# FILE: tests/test_session_group_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.session_group_repository import SessionGroupRepository
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    GroupId,
    TimestampSec,
    TransactionId,
)

DEFAULT_CREATED_EPOCH: int = 10
DEFAULT_ADDED_EPOCH: int = 11
DEFAULT_TIMESTAMP: int = 12
PNM_TEST_TYPE: str = "DS_RXMER"
SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
}
DEVICE_DETAILS: dict[str, object] = {"system_description": SYS_DESCR}
DEFAULT_FILENAME = FileName("rxmer.bin")
DEFAULT_MAC = MacAddress("aa:bb:cc:dd:ee:ff")


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


def _insert_transaction(db_path: Path, transaction_id: str) -> None:
    sqlite_path = DatabasePath(str(db_path))
    postgres_dsn = DatabaseDsn("")
    sys_repo = SystemDescriptionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    device_repo = DeviceDetailsRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    txn_repo = TransactionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    sysdescr_id = sys_repo.get_or_create_sysdescr_id(SYS_DESCR)
    device_detail_id = device_repo.get_or_create_device_detail_id(
        DEVICE_DETAILS, sysdescr_id
    )
    txn_repo.insert_transaction(
        transaction_id=TransactionId(transaction_id),
        timestamp_epoch=TimestampSec(DEFAULT_TIMESTAMP),
        mac_address=DEFAULT_MAC,
        pnm_test_type=PNM_TEST_TYPE,
        filename=DEFAULT_FILENAME,
        device_detail_id=device_detail_id,
    )


def test_session_group_repository_ordering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_session_group_db(tmp_path, monkeypatch)
    _insert_transaction(db_path, "txn-b")
    _insert_transaction(db_path, "txn-a")
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
    db_path = _configure_session_group_db(tmp_path, monkeypatch)
    _insert_transaction(db_path, "txn-1")
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
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.session_group_repository import SessionGroupRepository
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    GroupId,
    TimestampSec,
    TransactionId,
)
from pypnm.tools.migrate_session_groups import SessionGroupMigrator

DEFAULT_CREATED_EPOCH: int = 10
DEFAULT_TIMESTAMP: int = 11
PNM_TEST_TYPE: str = "DS_RXMER"
SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
}
DEVICE_DETAILS: dict[str, object] = {"system_description": SYS_DESCR}
DEFAULT_FILENAME = FileName("rxmer.bin")
DEFAULT_MAC = MacAddress("aa:bb:cc:dd:ee:ff")


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


def _insert_transaction(db_path: Path, transaction_id: str) -> None:
    sqlite_path = DatabasePath(str(db_path))
    postgres_dsn = DatabaseDsn("")
    sys_repo = SystemDescriptionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    device_repo = DeviceDetailsRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    txn_repo = TransactionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    sysdescr_id = sys_repo.get_or_create_sysdescr_id(SYS_DESCR)
    device_detail_id = device_repo.get_or_create_device_detail_id(
        DEVICE_DETAILS, sysdescr_id
    )
    txn_repo.insert_transaction(
        transaction_id=TransactionId(transaction_id),
        timestamp_epoch=TimestampSec(DEFAULT_TIMESTAMP),
        mac_address=DEFAULT_MAC,
        pnm_test_type=PNM_TEST_TYPE,
        filename=DEFAULT_FILENAME,
        device_detail_id=device_detail_id,
    )


def test_session_group_migrator_imports_legacy_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_session_group_db(tmp_path, monkeypatch)
    _insert_transaction(db_path, "txn-1")
    _insert_transaction(db_path, "txn-2")
    _insert_transaction(db_path, "txn-3")
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
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    TimestampSec,
    TransactionId,
)
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest

_TRANSACTION_ID_LENGTH: int = 16
_TIME_NS_FIRST: int = 100
_TIME_NS_SECOND: int = 101
DEFAULT_TIMESTAMP: int = 12
PNM_TEST_TYPE: str = "DS_RXMER"
SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
}
DEVICE_DETAILS: dict[str, object] = {"system_description": SYS_DESCR}
DEFAULT_FILENAME = FileName("rxmer.bin")


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


def _insert_transaction(db_path: Path, transaction_id: str) -> None:
    sqlite_path = DatabasePath(str(db_path))
    postgres_dsn = DatabaseDsn("")
    sys_repo = SystemDescriptionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    device_repo = DeviceDetailsRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    txn_repo = TransactionRepository.from_overrides(
        DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
    )
    sysdescr_id = sys_repo.get_or_create_sysdescr_id(SYS_DESCR)
    device_detail_id = device_repo.get_or_create_device_detail_id(
        DEVICE_DETAILS, sysdescr_id
    )
    txn_repo.insert_transaction(
        transaction_id=TransactionId(transaction_id),
        timestamp_epoch=TimestampSec(DEFAULT_TIMESTAMP),
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        pnm_test_type=PNM_TEST_TYPE,
        filename=DEFAULT_FILENAME,
        device_detail_id=device_detail_id,
    )


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
    db_path = _configure_transaction_db(tmp_path, monkeypatch)
    _guard_json_ledgers(monkeypatch)
    _insert_transaction(db_path, "txn-1")
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
