## Agent Review Bundle Summary
- Goal: Harden capture group and operation capture DB persistence with deterministic position selection, legacy operation column coverage, and tightened Postgres column detection.
- Changes: Added get_next_position with MAX(position) strategy, updated CaptureGroup to use it, scoped Postgres information_schema lookup to current_schema, and added a legacy-column sqlite test.
- Files: src/pypnm/lib/db/capture_group_repository.py, src/pypnm/api/routes/common/classes/file_capture/capture_group.py, src/pypnm/lib/db/operation_capture_repository.py, tests/test_operation_capture_repository.py
- Tests: python3 -m compileall src; ruff check src; ruff format --check .; pytest -q
- Notes: Postgres-gated tests skipped when PYPNM_DB_POSTGRES_DSN not set; PNM_CM_IT hardware tests skipped.

# FILE: src/pypnm/lib/db/capture_group_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from dataclasses import dataclass

from pypnm.lib.db.db_schema_manager import DbConnection
from pypnm.lib.db.transaction_repository import _RepositoryBase
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    TimestampSec,
    TransactionId,
)

_POSITION_START: int = 0
_POSITION_INCREMENT: int = 1


@dataclass(frozen=True)
class CaptureGroupRow:
    capture_group_id: GroupId
    created_epoch: TimestampSec


class CaptureGroupRepository(_RepositoryBase):
    """
    Repository for capture_groups and capture_group_transactions tables.
    """

    @classmethod
    def from_system_config(cls) -> CaptureGroupRepository:
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
    ) -> CaptureGroupRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def capture_group_exists(self, capture_group_id: GroupId) -> bool:
        """
        Return True if the capture group exists.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        "SELECT 1 FROM capture_groups WHERE capture_group_id = ? LIMIT 1;",
                        (str(capture_group_id),),
                    )
                    row = cursor.fetchone()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT 1 FROM capture_groups WHERE capture_group_id = %s LIMIT 1;",
                            (str(capture_group_id),),
                        )
                        row = cursor.fetchone()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
            return row is not None
        finally:
            connection.close()

    def create_capture_group(
        self, capture_group_id: GroupId, created_epoch: TimestampSec
    ) -> None:
        """
        Insert a capture group row (idempotent on capture_group_id).
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        ""
                        "INSERT OR IGNORE INTO capture_groups (capture_group_id, created_epoch)"
                        " VALUES (?, ?);",
                        (str(capture_group_id), int(created_epoch)),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            ""
                            "INSERT INTO capture_groups (capture_group_id, created_epoch)"
                            " VALUES (%s, %s) ON CONFLICT (capture_group_id) DO NOTHING;",
                            (str(capture_group_id), int(created_epoch)),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def get_or_create_capture_group(
        self, capture_group_id: GroupId, created_epoch: TimestampSec
    ) -> CaptureGroupRow:
        """
        Resolve or insert a capture group row.
        """
        connection = self._connect()
        try:
            existing = self._fetch_capture_group(connection, capture_group_id)
            if existing is not None:
                return existing
            self._insert_capture_group(connection, capture_group_id, created_epoch)
            fetched = self._fetch_capture_group(connection, capture_group_id)
            if fetched is None:
                raise RuntimeError("Failed to resolve capture_group after insert")
            return fetched
        finally:
            connection.close()

    def add_transaction(
        self,
        capture_group_id: GroupId,
        transaction_id: TransactionId,
        position: int,
        added_epoch: TimestampSec,
    ) -> None:
        """
        Insert a transaction membership row for a capture group.
        """
        connection = self._connect()
        try:
            if self._fetch_capture_group_transaction(
                connection, capture_group_id, transaction_id
            ):
                return
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        ""
                        "INSERT INTO capture_group_transactions ("
                        "    capture_group_id, transaction_id, position, added_epoch"
                        ") VALUES (?, ?, ?, ?);",
                        (
                            str(capture_group_id),
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
                            "INSERT INTO capture_group_transactions ("
                            "    capture_group_id, transaction_id, position, added_epoch"
                            ") VALUES (%s, %s, %s, %s);",
                            (
                                str(capture_group_id),
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

    def list_transactions(self, capture_group_id: GroupId) -> list[TransactionId]:
        """
        Return ordered transaction IDs for a capture group.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        ""
                        "SELECT transaction_id FROM capture_group_transactions "
                        "WHERE capture_group_id = ? "
                        "ORDER BY position ASC, transaction_id ASC;",
                        (str(capture_group_id),),
                    )
                    rows = cursor.fetchall()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            ""
                            "SELECT transaction_id FROM capture_group_transactions "
                            "WHERE capture_group_id = %s "
                            "ORDER BY position ASC, transaction_id ASC;",
                            (str(capture_group_id),),
                        )
                        rows = cursor.fetchall()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
            return [TransactionId(str(row[0])) for row in rows]
        finally:
            connection.close()

    def get_next_position(self, capture_group_id: GroupId) -> int:
        """
        Return the next position value for a capture group.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        ""
                        "SELECT MAX(position) FROM capture_group_transactions "
                        "WHERE capture_group_id = ?;",
                        (str(capture_group_id),),
                    )
                    row = cursor.fetchone()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            ""
                            "SELECT MAX(position) FROM capture_group_transactions "
                            "WHERE capture_group_id = %s;",
                            (str(capture_group_id),),
                        )
                        row = cursor.fetchone()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
            if row is None or row[0] is None:
                return _POSITION_START
            return int(row[0]) + _POSITION_INCREMENT
        finally:
            connection.close()

    def list_capture_groups(self) -> list[GroupId]:
        """
        Return all capture group identifiers.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        "SELECT capture_group_id FROM capture_groups ORDER BY created_epoch ASC;"
                    )
                    rows = cursor.fetchall()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT capture_group_id FROM capture_groups ORDER BY created_epoch ASC;"
                        )
                        rows = cursor.fetchall()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
            return [GroupId(str(row[0])) for row in rows]
        finally:
            connection.close()

    def delete_capture_group(self, capture_group_id: GroupId) -> None:
        """
        Delete a capture group and cascade its transaction mappings.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        "DELETE FROM capture_groups WHERE capture_group_id = ?;",
                        (str(capture_group_id),),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM capture_groups WHERE capture_group_id = %s;",
                            (str(capture_group_id),),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def delete_older_than(self, cutoff_epoch: TimestampSec) -> list[GroupId]:
        """
        Delete capture groups older than the cutoff epoch and return deleted IDs.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        "SELECT capture_group_id FROM capture_groups WHERE created_epoch < ?;",
                        (int(cutoff_epoch),),
                    )
                    rows = cursor.fetchall()
                    connection.execute(
                        "DELETE FROM capture_groups WHERE created_epoch < ?;",
                        (int(cutoff_epoch),),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT capture_group_id FROM capture_groups WHERE created_epoch < %s;",
                            (int(cutoff_epoch),),
                        )
                        rows = cursor.fetchall()
                        cursor.execute(
                            "DELETE FROM capture_groups WHERE created_epoch < %s;",
                            (int(cutoff_epoch),),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
            return [GroupId(str(row[0])) for row in rows]
        finally:
            connection.close()

    def prune_older_than(self, cutoff_epoch: TimestampSec) -> int:
        """
        Delete capture groups older than the cutoff epoch and return count.
        """
        deleted = self.delete_older_than(cutoff_epoch)
        return len(deleted)

    def _fetch_capture_group(
        self, connection: DbConnection, group_id: GroupId
    ) -> CaptureGroupRow | None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    "SELECT capture_group_id, created_epoch FROM capture_groups WHERE capture_group_id = ?;",
                    (str(group_id),),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT capture_group_id, created_epoch FROM capture_groups WHERE capture_group_id = %s;",
                        (str(group_id),),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if row is None:
            return None
        return CaptureGroupRow(
            capture_group_id=GroupId(str(row[0])),
            created_epoch=TimestampSec(int(row[1])),
        )

    def _insert_capture_group(
        self,
        connection: DbConnection,
        group_id: GroupId,
        created_epoch: TimestampSec,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    ""
                    "INSERT OR IGNORE INTO capture_groups (capture_group_id, created_epoch)"
                    " VALUES (?, ?);",
                    (str(group_id), int(created_epoch)),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        ""
                        "INSERT INTO capture_groups (capture_group_id, created_epoch)"
                        " VALUES (%s, %s) ON CONFLICT (capture_group_id) DO NOTHING;",
                        (str(group_id), int(created_epoch)),
                    )
                connection.commit()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

    def _fetch_capture_group_transaction(
        self, connection: DbConnection, group_id: GroupId, txn_id: TransactionId
    ) -> bool:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    ""
                    "SELECT 1 FROM capture_group_transactions "
                    "WHERE capture_group_id = ? AND transaction_id = ?;",
                    (str(group_id), str(txn_id)),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        ""
                        "SELECT 1 FROM capture_group_transactions "
                        "WHERE capture_group_id = %s AND transaction_id = %s;",
                        (str(group_id), str(txn_id)),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        return row is not None

# FILE: src/pypnm/api/routes/common/classes/file_capture/capture_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path

from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.transaction_repository import TransactionRepository
from pypnm.lib.types import GroupId, TimestampSec, TransactionId


class CaptureGroup:
    """
    Manage sessions of capture operations (e.g., multi-RxMER runs) by grouping
    multiple file-transfer transactions under a single UUID-based group ID.

    Features:
      - Persist groups and their transaction lists in the DB backend.
      - Generate or load a 16-character hexadecimal group ID per session.
      - Add, list, delete transactions; prune stale groups.

    Example:
        # New session
        cg = CaptureGroup()
        group_id = cg.create_group()

        # Existing session
        cg2 = CaptureGroup(group_id=group_id)
        txns = cg2.get_transactions()
    """

    def __init__(
        self, group_id: GroupId | None = None, db_path: Path | None = None
    ) -> None:
        """
        Initialize the CaptureGroup manager.

        Args:
            group_id: Optional existing group ID to load; generates a new one if None.
            db_path: Deprecated legacy JSON path override. Ignored; DB is authoritative.

        Raises:
            OSError: If the parent directory cannot be created.
        """
        self.logger = logging.getLogger(self.__class__.__name__)

        self._repo = CaptureGroupRepository.from_system_config()
        self._transaction_repo = TransactionRepository.from_system_config()

        self._grp_id: GroupId | None = group_id
        self._create_group_id()

    def _create_group_id(self) -> GroupId:
        """
        Ensure a group ID is set (use existing or generate new).
        Returns the active group ID.
        """
        if not self._grp_id:
            self._grp_id = GroupId(uuid.uuid4().hex[:16])
        return self._grp_id

    def get_group_id(self) -> GroupId:
        """
        Get the current active group ID.
        Raises AssertionError if uninitialized.
        """
        assert self._grp_id, "Group ID not initialized"
        return self._grp_id

    def create_group(self) -> GroupId:
        """
        Add the current group to the DB (no-op if exists).
        Returns the group ID.
        """
        gid = self.get_group_id()
        created_epoch = TimestampSec(int(time.time()))
        self._repo.create_capture_group(gid, created_epoch)
        self.logger.info(f"Created new group: {gid}")
        return gid

    def add_transaction(self, txn_id: str) -> None:
        """
        Append a transaction ID to this group, saving the DB.
        Raises ValueError if group missing.
        """
        tx_id = str(txn_id).strip()
        if not tx_id:
            self.logger.warning("Skipping empty transaction_id persistence")
            return
        gid = self.get_group_id()
        if not self._repo.capture_group_exists(gid):
            raise ValueError("Group not found; create_group() first")
        if self._transaction_repo.get_transaction_record(TransactionId(tx_id)) is None:
            self.logger.warning(
                "Skipping capture_group link for missing transaction_id=%s",
                tx_id,
            )
            return
        position = self._repo.get_next_position(gid)
        created_epoch = TimestampSec(int(time.time()))
        self._repo.add_transaction(gid, TransactionId(tx_id), position, created_epoch)
        self.logger.debug(f"Added txn {tx_id} to group {gid}")

    def getTransactionIds(self) -> list[TransactionId]:
        """
        Return all transaction IDs for this group (empty list if none).
        """
        return self._repo.list_transactions(self.get_group_id())

    def delete_group(self) -> None:
        """
        Remove this group and its transactions from the DB; resets group ID.
        """
        gid = self.get_group_id()
        self._repo.delete_capture_group(gid)
        self.logger.info(f"Deleted group: {gid}")
        self._grp_id = None

    def list_groups(self) -> list[str]:
        """
        List all group IDs currently in the DB.
        """
        return [str(group_id) for group_id in self._repo.list_capture_groups()]

    def prune_older_than(self, seconds: int) -> None:
        """
        Remove groups older than the given age (seconds).
        """
        cutoff = TimestampSec(int(time.time()) - seconds)
        deleted = self._repo.delete_older_than(cutoff)
        if deleted:
            self.logger.info(f"Pruned groups: {len(deleted)}")

# FILE: src/pypnm/lib/db/operation_capture_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.lib.db.db_schema_manager import DbConnection
from pypnm.lib.db.transaction_repository import _RepositoryBase
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    OperationId,
    TimestampSec,
)

_OPERATION_ID_COLUMN: str = "operation_id"
_LEGACY_OPERATION_ID_COLUMN: str = "operation_capture_id"


class OperationCaptureRepository(_RepositoryBase):
    """
    Repository for operation_captures table.
    """

    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        super().__init__(backend, sqlite_path, postgres_dsn)
        self._operation_id_column: str | None = None

    @classmethod
    def from_system_config(cls) -> OperationCaptureRepository:
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
    ) -> OperationCaptureRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def operation_exists(self, operation_id: OperationId) -> bool:
        """
        Return True if the operation capture row exists.
        """
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        f"SELECT 1 FROM operation_captures WHERE {column} = ? LIMIT 1;",
                        (str(operation_id),),
                    )
                    row = cursor.fetchone()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"SELECT 1 FROM operation_captures WHERE {column} = %s LIMIT 1;",
                            (str(operation_id),),
                        )
                        row = cursor.fetchone()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
            return row is not None
        finally:
            connection.close()

    def create_operation_capture(
        self,
        operation_id: OperationId,
        capture_group_id: GroupId,
        created_epoch: TimestampSec,
    ) -> None:
        """
        Insert an operation capture mapping (idempotent on operation_id).
        """
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        (
                            "INSERT OR IGNORE INTO operation_captures ("
                            f"    {column}, capture_group_id, created_epoch"
                            ") VALUES (?, ?, ?);"
                        ),
                        (
                            str(operation_id),
                            str(capture_group_id),
                            int(created_epoch),
                        ),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            (
                                "INSERT INTO operation_captures ("
                                f"    {column}, capture_group_id, created_epoch"
                                ") VALUES (%s, %s, %s) ON CONFLICT ({column}) DO NOTHING;"
                            ),
                            (
                                str(operation_id),
                                str(capture_group_id),
                                int(created_epoch),
                            ),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def get_capture_group_id(self, operation_id: OperationId) -> GroupId | None:
        """
        Resolve capture_group_id for the given operation_id.
        """
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        f"SELECT capture_group_id FROM operation_captures WHERE {column} = ?;",
                        (str(operation_id),),
                    )
                    row = cursor.fetchone()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"SELECT capture_group_id FROM operation_captures WHERE {column} = %s;",
                            (str(operation_id),),
                        )
                        row = cursor.fetchone()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

        if row is None:
            return None
        return GroupId(str(row[0]))

    def delete_operation(self, operation_id: OperationId) -> None:
        """
        Delete an operation capture mapping.
        """
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        f"DELETE FROM operation_captures WHERE {column} = ?;",
                        (str(operation_id),),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"DELETE FROM operation_captures WHERE {column} = %s;",
                            (str(operation_id),),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def list_operation_ids(self) -> list[OperationId]:
        """
        Return all operation IDs.
        """
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        f"SELECT {column} FROM operation_captures ORDER BY created_epoch ASC;"
                    )
                    rows = cursor.fetchall()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"SELECT {column} FROM operation_captures ORDER BY created_epoch ASC;"
                        )
                        rows = cursor.fetchall()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
            return [OperationId(str(row[0])) for row in rows]
        finally:
            connection.close()

    def _resolve_operation_id_column(self, connection: DbConnection) -> str:
        if self._operation_id_column:
            return self._operation_id_column

        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute("PRAGMA table_info('operation_captures');")
                rows = cursor.fetchall()
                column_names = {str(row[1]) for row in rows}
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        ""
                        "SELECT column_name "
                        "FROM information_schema.columns "
                        "WHERE table_schema = current_schema() "
                        "AND table_name = 'operation_captures';"
                    )
                    rows = cursor.fetchall()
                column_names = {str(row[0]) for row in rows}
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        if _OPERATION_ID_COLUMN in column_names:
            self._operation_id_column = _OPERATION_ID_COLUMN
        elif _LEGACY_OPERATION_ID_COLUMN in column_names:
            self._operation_id_column = _LEGACY_OPERATION_ID_COLUMN
        else:
            raise RuntimeError("operation_captures table has no operation id column")

        return self._operation_id_column

# FILE: tests/test_operation_capture_repository.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
import sqlite3
import uuid
from pathlib import Path

import pytest

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.operation_capture_repository import OperationCaptureRepository
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    OperationId,
    TimestampSec,
)

DEFAULT_CREATED_EPOCH: int = 20
UNIQUE_SUFFIX_LEN: int = 8


def _unique_suffix() -> str:
    return uuid.uuid4().hex[:UNIQUE_SUFFIX_LEN]


def _configure_operation_capture_db(
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


def _configure_operation_capture_legacy_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    db_path = tmp_path / "pypnm-legacy.sqlite3"
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute(
            ""
            "CREATE TABLE IF NOT EXISTS capture_groups ("
            "    capture_group_id  TEXT    PRIMARY KEY,"
            "    created_epoch     INTEGER NOT NULL"
            ");"
        )
        connection.execute(
            ""
            "CREATE TABLE IF NOT EXISTS operation_captures ("
            "    operation_capture_id TEXT PRIMARY KEY,"
            "    capture_group_id     TEXT    NOT NULL "
            "        REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,"
            "    created_epoch        INTEGER NOT NULL "
            "        DEFAULT (CAST(strftime('%s','now') AS INTEGER))"
            ");"
        )
        connection.commit()
    finally:
        connection.close()

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


def _configure_operation_capture_postgres(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dsn: DatabaseDsn
) -> DatabasePath:
    sqlite_placeholder = DatabasePath(str(tmp_path / "unused.sqlite3"))
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.POSTGRES),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: sqlite_placeholder),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: dsn),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()
    return sqlite_placeholder


def test_operation_capture_repository_links_and_resolves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_capture_db(tmp_path, monkeypatch)
    capture_repo = CaptureGroupRepository.from_system_config()
    operation_repo = OperationCaptureRepository.from_system_config()
    capture_group_id = GroupId("cg-op-1")
    operation_id = OperationId("op-1")

    capture_repo.create_capture_group(
        capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )
    operation_repo.create_operation_capture(
        operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )

    resolved = operation_repo.get_capture_group_id(operation_id)
    assert resolved == capture_group_id


def test_operation_capture_repository_fk_enforced_on_missing_capture_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_capture_db(tmp_path, monkeypatch)
    operation_repo = OperationCaptureRepository.from_system_config()
    capture_group_id = GroupId("cg-missing")
    operation_id = OperationId("op-missing")

    with pytest.raises(sqlite3.IntegrityError):
        operation_repo.create_operation_capture(
            operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
        )


def test_operation_capture_repository_legacy_column_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_operation_capture_legacy_db(tmp_path, monkeypatch)
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute(
            "INSERT INTO capture_groups (capture_group_id, created_epoch) VALUES (?, ?);",
            ("cg-legacy", DEFAULT_CREATED_EPOCH),
        )
        connection.commit()
    finally:
        connection.close()

    operation_repo = OperationCaptureRepository.from_system_config()
    capture_group_id = GroupId("cg-legacy")
    operation_id = OperationId("op-legacy")
    operation_repo.create_operation_capture(
        operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )

    assert operation_repo.get_capture_group_id(operation_id) == capture_group_id
    assert operation_repo._operation_id_column == "operation_capture_id"


def test_operation_capture_repository_fk_enforced_on_missing_capture_group_postgres(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dsn_env = os.environ.get("PYPNM_DB_POSTGRES_DSN", "")
    if not dsn_env:
        pytest.skip("PYPNM_DB_POSTGRES_DSN not set")
    try:
        import psycopg
    except ImportError:
        pytest.skip("psycopg not installed")

    postgres_dsn = DatabaseDsn(dsn_env)
    _configure_operation_capture_postgres(tmp_path, monkeypatch, postgres_dsn)
    suffix = _unique_suffix()
    capture_group_id = GroupId(f"cg-op-missing-{suffix}")
    operation_id = OperationId(f"op-missing-{suffix}")

    operation_repo = OperationCaptureRepository.from_system_config()
    with pytest.raises(psycopg.IntegrityError):
        operation_repo.create_operation_capture(
            operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
        )
