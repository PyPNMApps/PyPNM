# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.db.database_adapter import DatabaseAdapter
from pypnm.db.schema_version import (
    POSTGRES_SCHEMA_VERSION_INSERT,
    SCHEMA_META_ID_SEED,
    SCHEMA_VERSION_COUNT,
    SCHEMA_VERSION_DDL,
    SCHEMA_VERSION_SEED,
)
from pypnm.lib.types import DatabaseDsn

if TYPE_CHECKING:
    from psycopg import Connection as PsycopgConnection
else:
    PsycopgConnection = object

PostgresConnectFn = Callable[[DatabaseDsn], PsycopgConnection]

_HEALTHCHECK_QUERY: str = "SELECT 1"


class PostgresDatabaseAdapter(DatabaseAdapter):
    """
    Postgres backend adapter (schema skeleton only).
    """

    def __init__(
        self,
        dsn: DatabaseDsn,
        connect_fn: PostgresConnectFn | None = None,
    ) -> None:
        self._dsn = dsn
        self._connect_fn = connect_fn or self._default_connect
        self._connection: PsycopgConnection | None = None
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

    @classmethod
    def from_system_config(cls) -> PostgresDatabaseAdapter:
        """
        Build an adapter using the configured Postgres DSN.
        """
        return cls(SystemConfigSettings.database_postgres_dsn())

    def connect(self) -> None:
        if self._connection is not None:
            return
        if str(self._dsn).strip() == "":
            raise ValueError("Postgres DSN must be configured")
        self._connection = self._connect_fn(self._dsn)

    def close(self) -> None:
        if self._connection is None:
            return
        self._connection.close()
        self._connection = None

    def apply_schema(self) -> None:
        self._ensure_connection()
        if self._connection is None:
            return
        cursor = self._connection.cursor()
        cursor.execute(SCHEMA_VERSION_DDL)
        cursor.execute(SCHEMA_VERSION_COUNT)
        count_row = cursor.fetchone()
        count = 0 if count_row is None else int(count_row[0])
        if count == 0:
            cursor.execute(
                POSTGRES_SCHEMA_VERSION_INSERT,
                (SCHEMA_META_ID_SEED, SCHEMA_VERSION_SEED),
            )
        self._connection.commit()
        cursor.close()

    def healthcheck(self) -> bool:
        self._ensure_connection()
        if self._connection is None:
            return False
        try:
            cursor = self._connection.cursor()
            cursor.execute(_HEALTHCHECK_QUERY)
            ok = cursor.fetchone() is not None
            cursor.close()
            return ok
        except Exception as exc:
            self.logger.error("Postgres healthcheck failed: %s", exc)
            return False

    def _ensure_connection(self) -> None:
        if self._connection is None:
            self.connect()

    @staticmethod
    def _default_connect(dsn: DatabaseDsn) -> PsycopgConnection:
        try:
            import psycopg
        except ImportError as exc:
            raise ImportError(
                "psycopg is required for Postgres backend support"
            ) from exc
        return psycopg.connect(str(dsn))
