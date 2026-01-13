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
        Insert a transaction mapping for a session group (idempotent on
        session_id + transaction_id).
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
