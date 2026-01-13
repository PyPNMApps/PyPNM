# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import sqlite3
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
_POSITION_RETRY_START: int = 0
_POSITION_MAX_RETRIES: int = 5
_SQLITE_FK_ERROR: str = "FOREIGN KEY constraint failed"
_SQLITE_UNIQUE_POSITION_ERROR: str = (
    "capture_group_transactions.capture_group_id, capture_group_transactions.position"
)
_SQLITE_UNIQUE_TRANSACTION_ERROR: str = "capture_group_transactions.capture_group_id, capture_group_transactions.transaction_id"
_PSYCOPG_SQLSTATE_UNIQUE: str = "23505"
_PSYCOPG_SQLSTATE_FOREIGN_KEY: str = "23503"


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
            if self._transaction_exists_conn(
                connection, capture_group_id, transaction_id
            ):
                return
            self._add_transaction_conn(
                connection, capture_group_id, transaction_id, position, added_epoch
            )
            connection.commit()
        finally:
            connection.close()

    def add_transaction_next_position(
        self,
        capture_group_id: GroupId,
        transaction_id: TransactionId,
        added_epoch: TimestampSec,
    ) -> None:
        """
        Insert a transaction membership row using MAX(position) + 1 with retries.

        Retries are bounded and only intended to resolve position collisions that
        may occur under concurrent writers. Duplicate transaction IDs are treated
        as no-ops.
        """
        connection = self._connect()
        try:
            match self._backend:
                case DatabaseBackend.SQLITE:
                    for attempt in range(_POSITION_RETRY_START, _POSITION_MAX_RETRIES):
                        if self._transaction_exists_conn(
                            connection, capture_group_id, transaction_id
                        ):
                            return
                        position = self._get_next_position_conn(
                            connection, capture_group_id
                        )
                        try:
                            self._add_transaction_conn(
                                connection,
                                capture_group_id,
                                transaction_id,
                                position,
                                added_epoch,
                            )
                            connection.commit()
                            return
                        except sqlite3.IntegrityError as exc:
                            connection.rollback()
                            if self._is_sqlite_fk_violation(exc):
                                raise
                            if self._is_sqlite_unique_transaction_violation(exc):
                                return
                            if self._is_sqlite_unique_position_violation(exc):
                                if attempt == _POSITION_MAX_RETRIES - 1:
                                    raise
                                continue
                            if self._transaction_exists_conn(
                                connection, capture_group_id, transaction_id
                            ):
                                return
                            raise
                case DatabaseBackend.POSTGRES:
                    try:
                        import psycopg
                    except ImportError as exc:
                        raise RuntimeError(
                            "psycopg is required for Postgres capture group writes"
                        ) from exc
                    for attempt in range(_POSITION_RETRY_START, _POSITION_MAX_RETRIES):
                        if self._transaction_exists_conn(
                            connection, capture_group_id, transaction_id
                        ):
                            return
                        position = self._get_next_position_conn(
                            connection, capture_group_id
                        )
                        try:
                            self._add_transaction_conn(
                                connection,
                                capture_group_id,
                                transaction_id,
                                position,
                                added_epoch,
                            )
                            connection.commit()
                            return
                        except psycopg.IntegrityError as exc:
                            connection.rollback()
                            sqlstate = self._get_psycopg_sqlstate(exc)
                            if sqlstate == _PSYCOPG_SQLSTATE_FOREIGN_KEY:
                                raise
                            if sqlstate == _PSYCOPG_SQLSTATE_UNIQUE:
                                if self._transaction_exists_conn(
                                    connection, capture_group_id, transaction_id
                                ):
                                    return
                                if attempt == _POSITION_MAX_RETRIES - 1:
                                    raise
                                continue
                            if self._transaction_exists_conn(
                                connection, capture_group_id, transaction_id
                            ):
                                return
                            raise
                case _:
                    raise ValueError(f"Unsupported Database backend: {self._backend}")
        finally:
            connection.close()

        raise RuntimeError(
            f"Position retry limit reached for capture_group_id={capture_group_id}"
        )

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
            return self._get_next_position_conn(connection, capture_group_id)
        finally:
            connection.close()

    def _transaction_exists_conn(
        self,
        connection: DbConnection,
        capture_group_id: GroupId,
        transaction_id: TransactionId,
    ) -> bool:
        return self._fetch_capture_group_transaction(
            connection, capture_group_id, transaction_id
        )

    def _get_next_position_conn(
        self, connection: DbConnection, capture_group_id: GroupId
    ) -> int:
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

    def _add_transaction_conn(
        self,
        connection: DbConnection,
        capture_group_id: GroupId,
        transaction_id: TransactionId,
        position: int,
        added_epoch: TimestampSec,
    ) -> None:
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
            case _:
                raise ValueError(f"Unsupported Database backend: {self._backend}")

    @staticmethod
    def _is_sqlite_fk_violation(error: sqlite3.IntegrityError) -> bool:
        return _SQLITE_FK_ERROR in str(error)

    @staticmethod
    def _is_sqlite_unique_transaction_violation(error: sqlite3.IntegrityError) -> bool:
        return _SQLITE_UNIQUE_TRANSACTION_ERROR in str(error)

    @staticmethod
    def _is_sqlite_unique_position_violation(error: sqlite3.IntegrityError) -> bool:
        return _SQLITE_UNIQUE_POSITION_ERROR in str(error)

    @staticmethod
    def _get_psycopg_sqlstate(error: Exception) -> str | None:
        return getattr(error, "sqlstate", None) or getattr(error, "pgcode", None)

    def _transaction_exists(
        self, capture_group_id: GroupId, transaction_id: TransactionId
    ) -> bool:
        connection = self._connect()
        try:
            return self._transaction_exists_conn(
                connection, capture_group_id, transaction_id
            )
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
