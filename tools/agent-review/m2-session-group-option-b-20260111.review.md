## Agent Review Bundle Summary
- Goal: Implement Option B session group membership with FK integrity and timestamp-based ordering.
- Changes: Dropped position from session_group_transactions, added composite order index, simplified repository insert, and updated session group docs.
- Files: docs/design/db/schema_sqlite.sql, docs/design/db/schema_postgres.sql, src/pypnm/lib/db/session_group_repository.py, src/pypnm/api/routes/common/classes/file_capture/session_group.py.
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
    added_epoch                   INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),

    UNIQUE (session_id, transaction_id)
);

CREATE INDEX IF NOT EXISTS idx_sg_tx_session_order
ON session_group_transactions (session_id, added_epoch, transaction_id);

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
    added_epoch                   BIGINT   NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),

    CONSTRAINT uq_session_group_transaction UNIQUE (session_id, transaction_id)
);

CREATE INDEX IF NOT EXISTS idx_sg_tx_session_order
ON session_group_transactions (session_id, added_epoch, transaction_id);

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

from pypnm.lib.db.transaction_repository import _RepositoryBase
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    TimestampSec,
    TransactionId,
)

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
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        ""
                        "INSERT INTO session_group_transactions ("
                        "    session_id, transaction_id, added_epoch"
                        ") VALUES (?, ?, ?) "
                        "ON CONFLICT(session_id, transaction_id) DO NOTHING;",
                        (
                            str(session_id),
                            str(transaction_id),
                            int(added_epoch),
                        ),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            ""
                            "INSERT INTO session_group_transactions ("
                            "    session_id, transaction_id, added_epoch"
                            ") VALUES (%s, %s, %s) "
                            "ON CONFLICT (session_id, transaction_id) DO NOTHING;",
                            (
                                str(session_id),
                                str(transaction_id),
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
      - Persist groups and their transaction membership in the configured DB backend.
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
        Return all transaction IDs for this session (empty list if none), ordered
        by added timestamp then transaction ID.
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
