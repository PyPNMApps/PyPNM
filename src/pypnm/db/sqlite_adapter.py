# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.db.database_adapter import DatabaseAdapter
from pypnm.db.schema_version import (
    SCHEMA_META_ID_SEED,
    SCHEMA_VERSION_COUNT,
    SCHEMA_VERSION_DDL,
    SCHEMA_VERSION_SEED,
    SQLITE_SCHEMA_VERSION_INSERT,
)
from pypnm.lib.types import DatabasePath

_HEALTHCHECK_QUERY: str = "SELECT 1"


class SQLiteDatabaseAdapter(DatabaseAdapter):
    """
    SQLite backend adapter (schema skeleton only).
    """

    def __init__(self, sqlite_path: DatabasePath) -> None:
        self._sqlite_path = sqlite_path
        self._connection: sqlite3.Connection | None = None
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def from_system_config(cls) -> SQLiteDatabaseAdapter:
        """
        Build an adapter using the configured SQLite path.
        """
        return cls(SystemConfigSettings.database_sqlite_path())

    def connect(self) -> None:
        if self._connection is not None:
            return
        sqlite_path = Path(str(self._sqlite_path))
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(sqlite_path)

    def close(self) -> None:
        if self._connection is None:
            return
        self._connection.close()
        self._connection = None

    def apply_schema(self) -> None:
        self._ensure_connection()
        if self._connection is None:
            return
        self._connection.execute(SCHEMA_VERSION_DDL)
        cursor = self._connection.execute(SCHEMA_VERSION_COUNT)
        count_row = cursor.fetchone()
        count = 0 if count_row is None else int(count_row[0])
        if count == 0:
            self._connection.execute(
                SQLITE_SCHEMA_VERSION_INSERT,
                (SCHEMA_META_ID_SEED, SCHEMA_VERSION_SEED),
            )
        self._connection.commit()

    def schema_meta_stats(self) -> tuple[int, int]:
        self._ensure_connection()
        if self._connection is None:
            return 0, 0
        cursor = self._connection.execute(
            "SELECT COUNT(*), MIN(schema_version) FROM schema_meta"
        )
        row = cursor.fetchone()
        if row is None:
            return 0, 0
        count = int(row[0]) if row[0] is not None else 0
        minimum = int(row[1]) if row[1] is not None else 0
        return count, minimum

    def healthcheck(self) -> bool:
        self._ensure_connection()
        if self._connection is None:
            return False
        try:
            cursor = self._connection.execute(_HEALTHCHECK_QUERY)
            return cursor.fetchone() is not None
        except sqlite3.Error as exc:
            self.logger.error("SQLite healthcheck failed: %s", exc)
            return False

    def _ensure_connection(self) -> None:
        if self._connection is None:
            self.connect()
