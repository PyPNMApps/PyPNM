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
