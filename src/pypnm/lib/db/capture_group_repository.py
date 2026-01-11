# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from dataclasses import dataclass

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import (
    DatabaseSchemaManager,
    DbConnection,
)
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    GroupId,
    OperationId,
    TimestampSec,
    TransactionId,
)

_POSITION_START: int = 0
_OPERATION_ID_COLUMN: str = "operation_id"
_LEGACY_OPERATION_ID_COLUMN: str = "operation_capture_id"


@dataclass(frozen=True)
class CaptureGroupRow:
    capture_group_id: GroupId
    created_epoch: TimestampSec


class CaptureGroupRepository:
    """
    Repository for capture_groups and capture_group_transactions tables.
    """

    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._schema_manager = DatabaseSchemaManager.from_overrides(
            backend, sqlite_path, postgres_dsn
        )
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def from_system_config(cls) -> CaptureGroupRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
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
    ) -> CaptureGroupRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def get_or_create_capture_group(
        self, capture_group_id: GroupId | str, created_epoch: TimestampSec
    ) -> CaptureGroupRow:
        """
        Resolve or insert a capture group row.
        """
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            existing = self._fetch_capture_group(connection, group_id)
            if existing is not None:
                return existing
            self._insert_capture_group(connection, group_id, created_epoch)
            fetched = self._fetch_capture_group(connection, group_id)
            if fetched is None:
                raise RuntimeError("Failed to resolve capture_group after insert")
            return fetched
        finally:
            connection.close()

    def capture_group_exists(self, capture_group_id: GroupId | str) -> bool:
        """
        Check whether a capture group exists.
        """
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            return self._fetch_capture_group(connection, group_id) is not None
        finally:
            connection.close()

    def add_transaction(
        self,
        capture_group_id: GroupId | str,
        transaction_id: TransactionId | str,
        created_epoch: TimestampSec,
    ) -> None:
        """
        Add a transaction membership row (idempotent). Assigns sequential position.
        """
        group_id = GroupId(str(capture_group_id))
        txn_id = TransactionId(str(transaction_id))
        connection = self._connect()
        try:
            existing = self._fetch_capture_group_transaction(
                connection, group_id, txn_id
            )
            if existing:
                return
            position = self._next_position(connection, group_id)
            self._insert_capture_group_transaction(
                connection, group_id, txn_id, position, created_epoch
            )
        finally:
            connection.close()

    def list_transactions(self, capture_group_id: GroupId | str) -> list[TransactionId]:
        """
        List transaction IDs for a capture group in deterministic order.
        """
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            rows = self._fetch_capture_group_transactions(connection, group_id)
        finally:
            connection.close()
        return [TransactionId(str(row[0])) for row in rows]

    def list_capture_groups(self) -> list[GroupId]:
        """
        List all capture group identifiers.
        """
        connection = self._connect()
        try:
            rows = self._fetch_capture_groups(connection)
        finally:
            connection.close()
        return [GroupId(str(row[0])) for row in rows]

    def delete_capture_group(self, capture_group_id: GroupId | str) -> None:
        """
        Delete a capture group and its membership rows.
        """
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        "DELETE FROM capture_groups WHERE capture_group_id = ?;",
                        (str(group_id),),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM capture_groups WHERE capture_group_id = %s;",
                            (str(group_id),),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def prune_older_than(self, cutoff_epoch: TimestampSec) -> int:
        """
        Delete capture groups older than the cutoff epoch and return count.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        "DELETE FROM capture_groups WHERE created_epoch < ?;",
                        (int(cutoff_epoch),),
                    )
                    connection.commit()
                    return int(cursor.rowcount or 0)
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM capture_groups WHERE created_epoch < %s;",
                            (int(cutoff_epoch),),
                        )
                        deleted = cursor.rowcount
                    connection.commit()
                    return int(deleted or 0)
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def _connect(self) -> DbConnection:
        return self._schema_manager.connect()

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
                    """
                    INSERT OR IGNORE INTO capture_groups (capture_group_id, created_epoch)
                    VALUES (?, ?);
                    """,
                    (str(group_id), int(created_epoch)),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO capture_groups (capture_group_id, created_epoch)
                        VALUES (%s, %s)
                        ON CONFLICT (capture_group_id) DO NOTHING;
                        """,
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
                    """
                    SELECT 1 FROM capture_group_transactions
                    WHERE capture_group_id = ? AND transaction_id = ?;
                    """,
                    (str(group_id), str(txn_id)),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT 1 FROM capture_group_transactions
                        WHERE capture_group_id = %s AND transaction_id = %s;
                        """,
                        (str(group_id), str(txn_id)),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        return row is not None

    def _next_position(self, connection: DbConnection, group_id: GroupId) -> int:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT MAX(position) FROM capture_group_transactions
                    WHERE capture_group_id = ?;
                    """,
                    (str(group_id),),
                )
                row = cursor.fetchone()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT MAX(position) FROM capture_group_transactions
                        WHERE capture_group_id = %s;
                        """,
                        (str(group_id),),
                    )
                    row = cursor.fetchone()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")
        if row is None or row[0] is None:
            return _POSITION_START
        return int(row[0]) + 1

    def _insert_capture_group_transaction(
        self,
        connection: DbConnection,
        group_id: GroupId,
        txn_id: TransactionId,
        position: int,
        created_epoch: TimestampSec,
    ) -> None:
        match self._backend:
            case DatabaseBackend.SQLITE:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO capture_group_transactions (
                        capture_group_id, transaction_id, position, added_epoch
                    )
                    VALUES (?, ?, ?, ?);
                    """,
                    (str(group_id), str(txn_id), int(position), int(created_epoch)),
                )
                connection.commit()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO capture_group_transactions (
                            capture_group_id, transaction_id, position, added_epoch
                        )
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (capture_group_id, transaction_id) DO NOTHING;
                        """,
                        (str(group_id), str(txn_id), int(position), int(created_epoch)),
                    )
                connection.commit()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

    def _fetch_capture_group_transactions(
        self, connection: DbConnection, group_id: GroupId
    ) -> list[tuple[str]]:
        match self._backend:
            case DatabaseBackend.SQLITE:
                cursor = connection.execute(
                    """
                    SELECT transaction_id FROM capture_group_transactions
                    WHERE capture_group_id = ?
                    ORDER BY position ASC, transaction_id ASC;
                    """,
                    (str(group_id),),
                )
                rows = cursor.fetchall()
            case DatabaseBackend.POSTGRES:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT transaction_id FROM capture_group_transactions
                        WHERE capture_group_id = %s
                        ORDER BY position ASC, transaction_id ASC;
                        """,
                        (str(group_id),),
                    )
                    rows = cursor.fetchall()
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

        return [(str(row[0]),) for row in rows]

    def _fetch_capture_groups(self, connection: DbConnection) -> list[tuple[str]]:
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

        return [(str(row[0]),) for row in rows]


class OperationCaptureRepository:
    """
    Repository for operation_captures table.
    """

    def __init__(
        self,
        backend: DatabaseBackend,
        sqlite_path: DatabasePath,
        postgres_dsn: DatabaseDsn,
    ) -> None:
        self._backend = backend
        self._schema_manager = DatabaseSchemaManager.from_overrides(
            backend, sqlite_path, postgres_dsn
        )
        self._operation_id_column: str | None = None
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def from_system_config(cls) -> OperationCaptureRepository:
        """
        Build a repository using SystemConfigSettings DB overrides.
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
    ) -> OperationCaptureRepository:
        """
        Build a repository using explicit backend overrides.
        """
        return cls(backend, sqlite_path, postgres_dsn)

    def upsert_operation_capture(
        self,
        operation_id: OperationId | str,
        capture_group_id: GroupId | str,
        created_epoch: TimestampSec,
    ) -> None:
        """
        Insert or update an operation capture mapping.
        """
        op_id = OperationId(str(operation_id))
        group_id = GroupId(str(capture_group_id))
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    connection.execute(
                        f"""
                        INSERT OR REPLACE INTO operation_captures (
                            {column}, capture_group_id, created_epoch
                        )
                        VALUES (?, ?, ?);
                        """,
                        (str(op_id), str(group_id), int(created_epoch)),
                    )
                    connection.commit()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"""
                            INSERT INTO operation_captures (
                                {column}, capture_group_id, created_epoch
                            )
                            VALUES (%s, %s, %s)
                            ON CONFLICT ({column}) DO UPDATE SET
                                capture_group_id = EXCLUDED.capture_group_id,
                                created_epoch = EXCLUDED.created_epoch;
                            """,
                            (str(op_id), str(group_id), int(created_epoch)),
                        )
                    connection.commit()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

    def get_capture_group_id(self, operation_id: OperationId | str) -> GroupId | None:
        """
        Resolve capture_group_id for the given operation_id.
        """
        op_id = OperationId(str(operation_id))
        connection = self._connect()
        try:
            column = self._resolve_operation_id_column(connection)
            match self._backend:
                case DatabaseBackend.SQLITE:
                    cursor = connection.execute(
                        f"""
                        SELECT capture_group_id FROM operation_captures
                        WHERE {column} = ?;
                        """,
                        (str(op_id),),
                    )
                    row = cursor.fetchone()
                case DatabaseBackend.POSTGRES:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"""
                            SELECT capture_group_id FROM operation_captures
                            WHERE {column} = %s;
                            """,
                            (str(op_id),),
                        )
                        row = cursor.fetchone()
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

        if row is None:
            return None
        return GroupId(str(row[0]))

    def list_operation_ids(self) -> list[OperationId]:
        """
        List all operation IDs.
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
        finally:
            connection.close()

        return [OperationId(str(row[0])) for row in rows]

    def _connect(self) -> DbConnection:
        return self._schema_manager.connect()

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
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_name = 'operation_captures';
                        """
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
