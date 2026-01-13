## Agent Review Bundle Summary
- Goal: Add DB-backed capture group + operation capture repositories and regression tests, plus wire existing call sites/tests to use them.
- Changes: Added CaptureGroupRepository/OperationCaptureRepository, updated capture-group workflow usage with positions, updated tests/imports, added SQLite/Postgres-gated repo tests.
- Files: src/pypnm/lib/db/capture_group_repository.py, src/pypnm/lib/db/operation_capture_repository.py, src/pypnm/api/routes/advance/common/operation_manager.py, src/pypnm/api/routes/common/classes/file_capture/capture_group.py, src/pypnm/api/routes/common/classes/file_capture/pnm_file_opearation.py, tests/test_capture_group_repository.py, tests/test_operation_capture_repository.py, tests/test_capture_group_persistence_normalizes_transaction_id.py, tests/test_multi_rxmer_result_resolves_transactions.py, tests/test_multi_channel_estimation_result.py, tests/test_operation_manager_get_capture_group.py, tests/test_operation_manager_capture_group_id.py
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
                        "WHERE table_name = 'operation_captures';"
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

# FILE: src/pypnm/api/routes/advance/common/operation_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path

from pypnm.lib.constants import cast
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.operation_capture_repository import OperationCaptureRepository
from pypnm.lib.types import GroupId, OperationId, TimestampSec


class OperationManager:
    """
    Manager for mapping background capture operations to their capture group IDs.

    Each operation is assigned a unique operation_id and linked to a
    capture_group_id. Mappings are persisted in the DB backend so that
    captures can be looked up later by operation ID.
    """

    def __init__(self, capture_group_id: GroupId, db_path: Path | None = None) -> None:
        """
        Initialize a new operation manager for a given capture group.

        Args:
            capture_group_id: The ID of the capture group to associate.
            db_path: Deprecated legacy JSON path override. Ignored; DB is authoritative.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.capture_group_id: GroupId = capture_group_id
        self.operation_id: OperationId = cast(OperationId, uuid.uuid4().hex[:16])

        self._capture_repo = CaptureGroupRepository.from_system_config()
        self._operation_repo = OperationCaptureRepository.from_system_config()

    def register(self) -> OperationId:
        """
        Register this operation with its capture group ID in the DB.

        Verifies that the associated capture group exists before registration.

        Returns:
            The operation_id assigned.

        Raises:
            ValueError: If the capture_group_id is not present in the CaptureGroup database.
        """
        if not self._capture_repo.capture_group_exists(self.capture_group_id):
            raise ValueError(f"CaptureGroup '{self.capture_group_id}' does not exist")

        created_epoch = TimestampSec(int(time.time()))
        self._operation_repo.create_operation_capture(
            self.operation_id, self.capture_group_id, created_epoch
        )
        self.logger.info(
            f"Registered operation {self.operation_id} for group {self.capture_group_id}"
        )
        return self.operation_id

    @classmethod
    def get_capture_group(
        cls, operation_id: OperationId, db_path: Path | None = None
    ) -> GroupId | None:
        """
        Retrieve the capture_group_id for a given operation_id.

        Args:
            operation_id: The operation ID to look up.
            db_path: Deprecated legacy JSON path override. Ignored; DB is authoritative.

        Returns:
            capture_group_id if found, otherwise None.
        """
        operation_repo = OperationCaptureRepository.from_system_config()
        capture_group_id = operation_repo.get_capture_group_id(operation_id)
        if capture_group_id is not None:
            return capture_group_id
        return None

    @classmethod
    def list_operations(cls, db_path: Path | None = None) -> list[str]:
        """
        List all registered operation IDs.

        Args:
            db_path: Deprecated legacy JSON path override. Ignored; DB is authoritative.

        Returns:
            List of operation_id strings.
        """
        operation_repo = OperationCaptureRepository.from_system_config()
        operation_ids = operation_repo.list_operation_ids()
        return [str(op_id) for op_id in operation_ids]

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

POSITION_START: int = 0


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
        position = POSITION_START + len(self._repo.list_transactions(gid))
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

# FILE: src/pypnm/api/routes/common/classes/file_capture/pnm_file_opearation.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import logging

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.operation_capture_repository import OperationCaptureRepository
from pypnm.lib.types import GroupId, OperationId, TransactionId


class OperationCaptureGroupResolver:
    """
    Resolve Operation IDs Into Capture Groups And Transaction Records.

    This helper class ties together DB-backed datasets for operation resolution:

    1) Operation Database
       - DB: operation_captures table (operation_id -> capture_group_id)

    2) Capture Group Database
       - DB: capture_groups/capture_group_transactions tables

    3) Transaction Database (transaction_records)
       - Already managed by PnmFileTransaction.

    Public APIs:
      - get_capture_group_id(operation_id)
      - get_transaction_ids_for_operation(operation_id)
      - get_transaction_models_for_operation(operation_id)
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self._capture_repo = CaptureGroupRepository.from_system_config()
        self._operation_repo = OperationCaptureRepository.from_system_config()

    # ------------------------------------------------------------------ #
    # Resolution helpers
    # ------------------------------------------------------------------ #
    def get_capture_group_id(self, operation_id: OperationId) -> GroupId | None:
        """
        Resolve A Capture Group Identifier From An Operation ID.

        Returns the associated capture_group_id string when present in the
        operation database; otherwise returns None.
        """
        capture_group_id = self._operation_repo.get_capture_group_id(operation_id)
        if capture_group_id is not None:
            return capture_group_id
        self.logger.info("No operation record found for operation_id=%s", operation_id)
        return None

    def get_transaction_ids_for_capture_group(
        self, capture_group_id: GroupId
    ) -> list[TransactionId]:
        """
        Resolve All Transaction IDs Belonging To A Capture Group.

        Returns an ordered list of TransactionId values, or an empty list if
        the capture group is unknown or has no associated transactions.
        """
        db_transactions = self._capture_repo.list_transactions(capture_group_id)
        if db_transactions:
            return db_transactions
        self.logger.info(
            "No capture group record found for capture_group_id=%s",
            capture_group_id,
        )
        return []

    def get_transaction_ids_for_operation(
        self, operation_id: OperationId
    ) -> list[TransactionId]:
        """
        Resolve All Transaction IDs Associated With An Operation ID.

        This is a convenience wrapper that:
          1) Finds the capture_group_id for the supplied operation_id.
          2) Returns the list of TransactionId values for that capture group.
        """
        capture_group_id = self.get_capture_group_id(operation_id)
        if not capture_group_id:
            return []
        return self.get_transaction_ids_for_capture_group(capture_group_id)

    def get_transaction_models_for_operation(
        self, operation_id: OperationId
    ) -> list[TransactionRecordModel]:
        """
        Resolve TransactionRecordModel Instances For An Operation ID.

        For each transaction id mapped to the given operation, this method
        constructs a canonical TransactionRecordModel via PnmFileTransaction.

        Missing records are skipped; only models with a non-empty transaction_id
        field are returned.
        """
        txn_ids = self.get_transaction_ids_for_operation(operation_id)
        if not txn_ids:
            self.logger.info(
                "No transaction IDs found for operation_id=%s", operation_id
            )
            return []

        txn_store = PnmFileTransaction()
        models: list[TransactionRecordModel] = []

        for tid in txn_ids:
            model = txn_store.getRecordModel(tid)
            # Assuming TransactionRecordModel.null() sets transaction_id to an empty string.
            tx_id = str(getattr(model, "transaction_id", "")).strip()
            if tx_id:
                models.append(model)
            else:
                self.logger.warning(
                    "TransactionRecordModel for tid=%s is null/empty and will be skipped",
                    tid,
                )

        return models

# FILE: tests/test_capture_group_repository.py
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
DEFAULT_ADDED_EPOCH_NEXT: int = 12
DEFAULT_TIMESTAMP: int = 13
POSITION_FIRST: int = 0
POSITION_SECOND: int = 1
UNIQUE_SUFFIX_LEN: int = 8
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


def _unique_suffix() -> str:
    return uuid.uuid4().hex[:UNIQUE_SUFFIX_LEN]


def _configure_capture_group_db(
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


def _configure_capture_group_postgres(
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


def _insert_transaction_sqlite(db_path: Path, transaction_id: str) -> None:
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


def _insert_transaction_postgres(
    dsn: DatabaseDsn, sqlite_path: DatabasePath, transaction_id: str
) -> None:
    sys_repo = SystemDescriptionRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, dsn
    )
    device_repo = DeviceDetailsRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, dsn
    )
    txn_repo = TransactionRepository.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, dsn
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


def test_capture_group_repository_orders_by_position(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _insert_transaction_sqlite(db_path, "txn-b")
    _insert_transaction_sqlite(db_path, "txn-a")
    repo = CaptureGroupRepository.from_system_config()
    group_id = GroupId("cg-1")
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        group_id,
        TransactionId("txn-b"),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )
    repo.add_transaction(
        group_id,
        TransactionId("txn-a"),
        POSITION_SECOND,
        TimestampSec(DEFAULT_ADDED_EPOCH_NEXT),
    )

    assert repo.list_transactions(group_id) == [
        TransactionId("txn-b"),
        TransactionId("txn-a"),
    ]


def test_capture_group_repository_ignores_duplicate_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _insert_transaction_sqlite(db_path, "txn-dup")
    repo = CaptureGroupRepository.from_system_config()
    group_id = GroupId("cg-dup")
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        group_id,
        TransactionId("txn-dup"),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )
    repo.add_transaction(
        group_id,
        TransactionId("txn-dup"),
        POSITION_SECOND,
        TimestampSec(DEFAULT_ADDED_EPOCH_NEXT),
    )

    assert repo.list_transactions(group_id) == [TransactionId("txn-dup")]


def test_capture_group_repository_rejects_duplicate_position(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _insert_transaction_sqlite(db_path, "txn-1")
    _insert_transaction_sqlite(db_path, "txn-2")
    repo = CaptureGroupRepository.from_system_config()
    group_id = GroupId("cg-pos")
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        group_id,
        TransactionId("txn-1"),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )

    with pytest.raises(sqlite3.IntegrityError):
        repo.add_transaction(
            group_id,
            TransactionId("txn-2"),
            POSITION_FIRST,
            TimestampSec(DEFAULT_ADDED_EPOCH_NEXT),
        )


def test_capture_group_repository_enforces_fk_integrity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    repo = CaptureGroupRepository.from_system_config()
    group_id = GroupId("cg-fk")
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))

    with pytest.raises(sqlite3.IntegrityError):
        repo.add_transaction(
            group_id,
            TransactionId("missing-txn"),
            POSITION_FIRST,
            TimestampSec(DEFAULT_ADDED_EPOCH),
        )

    _insert_transaction_sqlite(db_path, "missing-txn")
    repo.add_transaction(
        group_id,
        TransactionId("missing-txn"),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )

    assert repo.list_transactions(group_id) == [TransactionId("missing-txn")]


def test_capture_group_repository_enforces_fk_integrity_postgres(
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
    sqlite_placeholder = _configure_capture_group_postgres(
        tmp_path, monkeypatch, postgres_dsn
    )
    suffix = _unique_suffix()
    group_id = GroupId(f"cg-pg-fk-{suffix}")
    missing_txn = f"missing-txn-{suffix}"

    repo = CaptureGroupRepository.from_system_config()
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))

    with pytest.raises(psycopg.IntegrityError):
        repo.add_transaction(
            group_id,
            TransactionId(missing_txn),
            POSITION_FIRST,
            TimestampSec(DEFAULT_ADDED_EPOCH),
        )

    _insert_transaction_postgres(postgres_dsn, sqlite_placeholder, missing_txn)
    repo.add_transaction(
        group_id,
        TransactionId(missing_txn),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )

    assert repo.list_transactions(group_id) == [TransactionId(missing_txn)]


def test_capture_group_repository_rejects_duplicate_position_postgres(
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
    sqlite_placeholder = _configure_capture_group_postgres(
        tmp_path, monkeypatch, postgres_dsn
    )
    suffix = _unique_suffix()
    group_id = GroupId(f"cg-pg-pos-{suffix}")
    txn_one = f"txn-pos-{suffix}-a"
    txn_two = f"txn-pos-{suffix}-b"

    repo = CaptureGroupRepository.from_system_config()
    repo.create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    _insert_transaction_postgres(postgres_dsn, sqlite_placeholder, txn_one)
    _insert_transaction_postgres(postgres_dsn, sqlite_placeholder, txn_two)

    repo.add_transaction(
        group_id,
        TransactionId(txn_one),
        POSITION_FIRST,
        TimestampSec(DEFAULT_ADDED_EPOCH),
    )

    with pytest.raises(psycopg.IntegrityError):
        repo.add_transaction(
            group_id,
            TransactionId(txn_two),
            POSITION_FIRST,
            TimestampSec(DEFAULT_ADDED_EPOCH_NEXT),
        )

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

# FILE: tests/test_capture_group_persistence_normalizes_transaction_id.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.api.routes.common.classes.file_capture.pnm_file_opearation import (
    OperationCaptureGroupResolver,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
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

DEFAULT_CREATED_EPOCH: int = 1
DEFAULT_TIMESTAMP: int = 1
POSITION_FIRST: int = 0
POSITION_SECOND: int = 1
POSITION_THIRD: int = 2
ADDED_EPOCH_FIRST: int = 1
ADDED_EPOCH_SECOND: int = 2
ADDED_EPOCH_THIRD: int = 3
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


def _guard_json_ledgers(monkeypatch: pytest.MonkeyPatch) -> None:
    original_open = Path.open

    def _guarded_open(
        self: Path, *args: tuple[object, ...], **kwargs: dict[str, object]
    ) -> object:
        if self.name in ("capture_group.json", "operation_capture.json"):
            raise AssertionError(f"Unexpected JSON ledger access: {self}")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _guarded_open)


def _configure_capture_group_db(
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


def test_capture_group_skips_whitespace_transaction_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_capture_group_db(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    group = CaptureGroup()
    group_id = group.create_group()

    group.add_transaction("   ")

    repo = CaptureGroupRepository.from_system_config()
    assert repo.list_transactions(group_id) == []
    assert "Skipping empty transaction_id persistence" in caplog.text


def test_resolver_filters_whitespace_transaction_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _insert_transaction(db_path, "txn123")
    group_id = GroupId("group-1")
    repo = CaptureGroupRepository.from_system_config()
    repo.get_or_create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        group_id,
        TransactionId("txn123"),
        POSITION_FIRST,
        TimestampSec(ADDED_EPOCH_SECOND),
    )

    resolver = OperationCaptureGroupResolver()
    txns = resolver.get_transaction_ids_for_capture_group(group_id)

    assert txns == [TransactionId("txn123")]


def test_resolver_prefers_db_transaction_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    group_id = GroupId("group-db")
    repo = CaptureGroupRepository.from_system_config()
    repo.get_or_create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    _insert_transaction(db_path, "txn-b")
    _insert_transaction(db_path, "txn-a")
    repo.add_transaction(
        group_id,
        TransactionId("txn-b"),
        POSITION_FIRST,
        TimestampSec(ADDED_EPOCH_SECOND),
    )
    repo.add_transaction(
        group_id,
        TransactionId("txn-a"),
        POSITION_SECOND,
        TimestampSec(ADDED_EPOCH_THIRD),
    )

    resolver = OperationCaptureGroupResolver()
    txns = resolver.get_transaction_ids_for_capture_group(group_id)

    assert txns == [TransactionId("txn-b"), TransactionId("txn-a")]


def test_resolver_does_not_touch_json_ledgers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    _guard_json_ledgers(monkeypatch)
    group_id = GroupId("group-no-json")
    _insert_transaction(db_path, "txn-json-guard")
    repo = CaptureGroupRepository.from_system_config()
    repo.get_or_create_capture_group(group_id, TimestampSec(DEFAULT_CREATED_EPOCH))
    repo.add_transaction(
        group_id,
        TransactionId("txn-json-guard"),
        POSITION_FIRST,
        TimestampSec(ADDED_EPOCH_FIRST),
    )

    resolver = OperationCaptureGroupResolver()
    txns = resolver.get_transaction_ids_for_capture_group(group_id)

    assert txns == [TransactionId("txn-json-guard")]

# FILE: tests/test_multi_rxmer_result_resolves_transactions.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.router import router
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.operation_capture_repository import OperationCaptureRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    GroupId,
    OperationId,
    TimestampSec,
    TransactionId,
)


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


PNM_TEST_TYPE: str = "DS_OFDM_RXMER_PER_SUBCAR"
DEFAULT_CREATED_EPOCH: int = 1
DEFAULT_TIMESTAMP: int = 1
POSITION_START: int = 0
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


class _DbFixture:
    @staticmethod
    def initialize(db_path: Path) -> None:
        sqlite_path = DatabasePath(str(db_path))
        postgres_dsn = DatabaseDsn("")
        manager = DatabaseSchemaManager.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        manager.initialize_schema()

    @staticmethod
    def insert_transaction(db_path: Path, transaction_id: str) -> None:
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

    @staticmethod
    def bind_operation(
        db_path: Path,
        operation_id: OperationId,
        capture_group_id: GroupId,
        transaction_ids: list[str],
    ) -> None:
        sqlite_path = DatabasePath(str(db_path))
        postgres_dsn = DatabaseDsn("")
        capture_repo = CaptureGroupRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        operation_repo = OperationCaptureRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        capture_repo.get_or_create_capture_group(
            capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
        )
        for position, transaction_id in enumerate(
            transaction_ids, start=POSITION_START
        ):
            capture_repo.add_transaction(
                capture_group_id,
                TransactionId(transaction_id),
                position,
                TimestampSec(DEFAULT_CREATED_EPOCH),
            )
        operation_repo.create_operation_capture(
            operation_id,
            capture_group_id,
            TimestampSec(DEFAULT_CREATED_EPOCH),
        )


def _configure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Path]:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    sqlite_db = db_dir / "pypnm.sqlite3"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    _DbFixture.initialize(sqlite_db)

    return {
        "database_sqlite_path": sqlite_db,
    }


def test_result_resolves_transactions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())
    operation_id = OperationId("op-123")
    capture_group_id = GroupId("group-123")
    transaction_id_one = "txn-123-a"
    transaction_id_two = "txn-123-b"

    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id_one)
    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id_two)
    _DbFixture.bind_operation(
        paths["database_sqlite_path"],
        operation_id,
        capture_group_id,
        [transaction_id_two, transaction_id_one],
    )

    store = OperationStore()
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )

    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert payload["transactions"]
    assert payload["transactions"][0]["transaction_id"] == transaction_id_two
    assert payload["transactions"][1]["transaction_id"] == transaction_id_one
    OperationRegistry.unregister(operation_id)


def test_result_rejects_when_no_transactions_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-124")
    capture_group_id = GroupId("group-124")
    _DbFixture.bind_operation(
        paths["database_sqlite_path"],
        operation_id,
        capture_group_id,
        [],
    )

    store = OperationStore()
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )

    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 404
    assert "No transaction records found" in response.json()["detail"]


def test_result_resolves_transactions_without_json_ledgers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-125")
    capture_group_id = GroupId("group-125")
    transaction_id = "txn125"

    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id)
    _DbFixture.bind_operation(
        paths["database_sqlite_path"],
        operation_id,
        capture_group_id,
        [transaction_id],
    )

    store = OperationStore()
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )

    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert payload["transactions"][0]["transaction_id"] == transaction_id

# FILE: tests/test_multi_channel_estimation_result.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.multi_ds_chan_est.router import router
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.operation_capture_repository import OperationCaptureRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.transaction_repository import (
    DeviceDetailsRepository,
    SystemDescriptionRepository,
    TransactionRepository,
)
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileName,
    GroupId,
    OperationId,
    TimestampSec,
    TransactionId,
)


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


PNM_TEST_TYPE: str = "DS_OFDM_CHAN_EST_COEF"
DEFAULT_CREATED_EPOCH: int = 1
DEFAULT_TIMESTAMP: int = 1
POSITION_START: int = 0
SYS_DESCR: dict[str, str] = {
    "HW_REV": "1.0",
    "VENDOR": "LANCity",
    "BOOTR": "NONE",
    "SW_REV": "1.0.0",
    "MODEL": "LCPET-3",
}
DEVICE_DETAILS: dict[str, object] = {"system_description": SYS_DESCR}
DEFAULT_FILENAME = FileName("chan_est.bin")
DEFAULT_MAC = MacAddress("aa:bb:cc:dd:ee:ff")


class _DbFixture:
    @staticmethod
    def initialize(db_path: Path) -> None:
        sqlite_path = DatabasePath(str(db_path))
        postgres_dsn = DatabaseDsn("")
        manager = DatabaseSchemaManager.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        manager.initialize_schema()

    @staticmethod
    def insert_transaction(db_path: Path, transaction_id: str) -> None:
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

    @staticmethod
    def bind_operation(
        db_path: Path,
        operation_id: OperationId,
        capture_group_id: GroupId,
        transaction_ids: list[str],
    ) -> None:
        sqlite_path = DatabasePath(str(db_path))
        postgres_dsn = DatabaseDsn("")
        capture_repo = CaptureGroupRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        operation_repo = OperationCaptureRepository.from_overrides(
            DatabaseBackend.SQLITE, sqlite_path, postgres_dsn
        )
        capture_repo.get_or_create_capture_group(
            capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
        )
        for position, transaction_id in enumerate(
            transaction_ids, start=POSITION_START
        ):
            capture_repo.add_transaction(
                capture_group_id,
                TransactionId(transaction_id),
                position,
                TimestampSec(DEFAULT_CREATED_EPOCH),
            )
        operation_repo.create_operation_capture(
            operation_id,
            capture_group_id,
            TimestampSec(DEFAULT_CREATED_EPOCH),
        )


def _configure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Path]:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    sqlite_db = db_dir / "pypnm.sqlite3"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    _DbFixture.initialize(sqlite_db)

    return {
        "database_sqlite_path": sqlite_db,
    }


def _seed_transaction_db(transaction_id: str, paths: dict[str, Path]) -> None:
    _DbFixture.insert_transaction(paths["database_sqlite_path"], transaction_id)


def _complete_operation(operation_id: OperationId) -> None:
    store = OperationStore()
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )


def test_multi_channel_estimation_result_returns_transactions_from_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-300")
    capture_group_id = GroupId("group-300")
    txn_ok = "txn-ok"

    _seed_transaction_db(txn_ok, paths)
    _DbFixture.bind_operation(
        paths["database_sqlite_path"],
        operation_id,
        capture_group_id,
        [txn_ok],
    )
    _complete_operation(operation_id)

    response = client.post(
        "/advance/multiChannelEstimation/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert len(payload["transactions"]) == 1
    assert payload["transactions"][0]["transaction_id"] == txn_ok


def test_multi_channel_estimation_result_returns_404_when_none_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-301")
    capture_group_id = GroupId("group-301")

    _DbFixture.bind_operation(
        paths["database_sqlite_path"],
        operation_id,
        capture_group_id,
        [],
    )
    _complete_operation(operation_id)

    response = client.post(
        "/advance/multiChannelEstimation/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 404
    assert "No transaction records found" in response.json()["detail"]


def test_multi_channel_estimation_result_uses_db_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-302")
    capture_group_id = GroupId("group-302")
    txn_ok = "txn-ok-302"

    _seed_transaction_db(txn_ok, paths)
    _DbFixture.bind_operation(
        paths["database_sqlite_path"],
        operation_id,
        capture_group_id,
        [txn_ok],
    )
    _complete_operation(operation_id)

    response = client.post(
        "/advance/multiChannelEstimation/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert payload["transactions"][0]["transaction_id"] == txn_ok

# FILE: tests/test_operation_manager_get_capture_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.operation_capture_repository import OperationCaptureRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    OperationId,
    TimestampSec,
)

DEFAULT_CREATED_EPOCH: int = 1


def _configure_operation_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base_dir = tmp_path / ".data"
    db_dir = base_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    sqlite_db = db_dir / "pypnm.sqlite3"
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()
    return sqlite_db


def _guard_json_ledgers(monkeypatch: pytest.MonkeyPatch) -> None:
    original_open = Path.open

    def _guarded_open(
        self: Path, *args: tuple[object, ...], **kwargs: dict[str, object]
    ) -> object:
        if self.name in ("capture_group.json", "operation_capture.json"):
            raise AssertionError(f"Unexpected JSON ledger access: {self}")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _guarded_open)


def test_get_capture_group_prefers_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-199")
    capture_group_id = GroupId("group-199")

    capture_repo = CaptureGroupRepository.from_system_config()
    capture_repo.get_or_create_capture_group(
        capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )
    operation_repo = OperationCaptureRepository.from_system_config()
    operation_repo.create_operation_capture(
        operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id
    operation_repo = OperationCaptureRepository.from_system_config()
    assert operation_repo.get_capture_group_id(operation_id) == capture_group_id


def test_get_capture_group_returns_none_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-202")

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved is None


def test_get_capture_group_does_not_touch_json_ledgers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_db(tmp_path, monkeypatch)
    _guard_json_ledgers(monkeypatch)
    operation_id = OperationId("op-203")

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved is None

# FILE: tests/test_operation_manager_capture_group_id.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.operation_capture_repository import OperationCaptureRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath


def _configure_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base_dir = tmp_path / ".data"
    db_dir = base_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    sqlite_db = db_dir / "pypnm.sqlite3"

    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()

    return sqlite_db


def test_operation_manager_writes_capture_group_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    group = CaptureGroup()
    group_id = group.create_group()

    manager = OperationManager(capture_group_id=group_id)
    operation_id = manager.register()

    operation_repo = OperationCaptureRepository.from_system_config()
    resolved = operation_repo.get_capture_group_id(operation_id)
    assert resolved == group_id
