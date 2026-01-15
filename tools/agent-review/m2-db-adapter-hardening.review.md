## Agent Review Bundle Summary
- Goal: Seed schema_version deterministically and add DatabaseManager lifecycle helpers with tests.
- Changes: Added schema_version seed logic/constants to SQLite/Postgres adapters, added DatabaseManager.initialize/close, and expanded tests for seed behavior, manager lifecycle, and fake Postgres execution.
- Files: src/pypnm/db/sqlite_adapter.py; src/pypnm/db/postgres_adapter.py; src/pypnm/db/database_manager.py; tests/test_database_manager.py.
- Tests: python3 -m compileall src; ruff check .; ruff format --check .; pytest -q.
- Notes: Skipped hardware integration and Postgres DSN-dependent tests due to missing environment flags/DSN.

# FILE: src/pypnm/db/sqlite_adapter.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.db.database_adapter import DatabaseAdapter
from pypnm.lib.types import DatabasePath

_SCHEMA_VERSION_DDL: str = (
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
)
_HEALTHCHECK_QUERY: str = "SELECT 1"
SCHEMA_VERSION_SEED: int = 1
_SCHEMA_VERSION_COUNT: str = "SELECT COUNT(*) FROM schema_version"
_SCHEMA_VERSION_INSERT: str = "INSERT INTO schema_version (version) VALUES (?)"


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
        self._connection.execute(_SCHEMA_VERSION_DDL)
        cursor = self._connection.execute(_SCHEMA_VERSION_COUNT)
        count_row = cursor.fetchone()
        count = 0 if count_row is None else int(count_row[0])
        if count == 0:
            self._connection.execute(_SCHEMA_VERSION_INSERT, (SCHEMA_VERSION_SEED,))
        self._connection.commit()

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

# FILE: src/pypnm/db/postgres_adapter.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.db.database_adapter import DatabaseAdapter
from pypnm.lib.types import DatabaseDsn

if TYPE_CHECKING:
    from psycopg import Connection as PsycopgConnection
else:
    PsycopgConnection = object

PostgresConnectFn = Callable[[DatabaseDsn], PsycopgConnection]

_SCHEMA_VERSION_DDL: str = (
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
)
_HEALTHCHECK_QUERY: str = "SELECT 1"
SCHEMA_VERSION_SEED: int = 1
_SCHEMA_VERSION_COUNT: str = "SELECT COUNT(*) FROM schema_version"
_SCHEMA_VERSION_INSERT: str = "INSERT INTO schema_version (version) VALUES (%s)"


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
        cursor.execute(_SCHEMA_VERSION_DDL)
        cursor.execute(_SCHEMA_VERSION_COUNT)
        count_row = cursor.fetchone()
        count = 0 if count_row is None else int(count_row[0])
        if count == 0:
            cursor.execute(_SCHEMA_VERSION_INSERT, (SCHEMA_VERSION_SEED,))
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

# FILE: src/pypnm/db/database_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging

from pydantic import ValidationError

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.db.database_adapter import DatabaseAdapter
from pypnm.db.postgres_adapter import PostgresDatabaseAdapter
from pypnm.db.sqlite_adapter import SQLiteDatabaseAdapter
from pypnm.lib.types import DatabaseBackend


class DatabaseManager:
    """
    Select and cache the configured database adapter.
    """

    _adapter: DatabaseAdapter | None = None
    _logger = logging.getLogger("DatabaseManager")

    @classmethod
    def get_adapter(cls) -> DatabaseAdapter:
        if cls._adapter is not None:
            return cls._adapter

        try:
            settings = SystemConfigSettings.database_settings()
            backend = settings.backend
        except ValidationError as exc:
            cls._logger.error("Invalid Database configuration: %s", exc)
            backend = DatabaseBackend.SQLITE
            settings = None

        match backend:
            case DatabaseBackend.POSTGRES:
                if settings is None:
                    adapter = SQLiteDatabaseAdapter(
                        SystemConfigSettings.database_sqlite_path()
                    )
                else:
                    adapter = PostgresDatabaseAdapter(settings.postgres.dsn)
            case DatabaseBackend.SQLITE:
                if settings is None:
                    adapter = SQLiteDatabaseAdapter(
                        SystemConfigSettings.database_sqlite_path()
                    )
                else:
                    adapter = SQLiteDatabaseAdapter(settings.sqlite.path)
            case _:
                adapter = SQLiteDatabaseAdapter(
                    SystemConfigSettings.database_sqlite_path()
                )

        cls._adapter = adapter
        return adapter

    @classmethod
    def initialize(cls) -> bool:
        try:
            adapter = cls.get_adapter()
            backend = SystemConfigSettings.database_backend()
        except Exception as exc:
            cls._logger.error("Database initialize failed before connect: %s", exc)
            return False

        try:
            adapter.connect()
        except Exception as exc:
            cls._logger.error(
                "Database initialize connect failed (%s): %s", backend, exc
            )
            return False

        try:
            adapter.apply_schema()
        except Exception as exc:
            cls._logger.error(
                "Database initialize apply_schema failed (%s): %s", backend, exc
            )
            return False

        try:
            return adapter.healthcheck()
        except Exception as exc:
            cls._logger.error(
                "Database initialize healthcheck failed (%s): %s", backend, exc
            )
            return False

    @classmethod
    def close(cls) -> None:
        if cls._adapter is None:
            return
        try:
            cls._adapter.close()
        except Exception as exc:
            cls._logger.error("Database adapter close failed: %s", exc)
        finally:
            cls._adapter = None

# FILE: tests/test_database_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.db.database_manager import DatabaseManager
from pypnm.db.postgres_adapter import SCHEMA_VERSION_SEED, PostgresDatabaseAdapter
from pypnm.db.sqlite_adapter import SQLiteDatabaseAdapter
from pypnm.lib.types import DatabaseDsn, DatabasePath


class FakeConfigManager:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = data or {}

    def get(self, *path: str) -> object | None:
        key = ".".join(path)
        return self._data.get(key)

    def reload(self) -> None:
        return None


@pytest.fixture(autouse=True)
def _reset_config(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    monkeypatch.setattr(SystemConfigSettings, "_deprecated_ledger_warned", set())
    monkeypatch.setattr(DatabaseManager, "_adapter", None)
    monkeypatch.delenv("PYPNM_DB_BACKEND", raising=False)
    monkeypatch.delenv("PYPNM_DB_POSTGRES_DSN", raising=False)


def test_database_manager_defaults_to_sqlite() -> None:
    adapter = DatabaseManager.get_adapter()
    assert isinstance(adapter, SQLiteDatabaseAdapter)


def test_database_manager_env_override_postgres(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYPNM_DB_BACKEND", "postgres")
    monkeypatch.setenv(
        "PYPNM_DB_POSTGRES_DSN", "postgresql://pypnm@localhost:5432/pypnm"
    )

    adapter = DatabaseManager.get_adapter()
    assert isinstance(adapter, PostgresDatabaseAdapter)


def test_database_manager_handles_blank_postgres_dsn(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeConfigManager(
        {
            "Database.backend": "postgres",
            "Database.postgres.dsn": "",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    with pytest.raises(ValidationError):
        SystemConfigSettings.database_settings()

    logger_name = "DatabaseManager"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        adapter = DatabaseManager.get_adapter()

    assert isinstance(adapter, SQLiteDatabaseAdapter)
    assert "Invalid Database configuration" in caplog.text


def test_sqlite_adapter_creates_parent_dir(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "pypnm.sqlite3"
    adapter = SQLiteDatabaseAdapter(DatabasePath(str(db_path)))

    adapter.connect()
    try:
        assert db_path.parent.is_dir()
    finally:
        adapter.close()


def test_sqlite_adapter_apply_schema_seeds_version(tmp_path: Path) -> None:
    db_path = tmp_path / "pypnm.sqlite3"
    adapter = SQLiteDatabaseAdapter(DatabasePath(str(db_path)))

    adapter.connect()
    try:
        adapter.apply_schema()
        adapter.apply_schema()
        cursor = adapter._connection.execute(
            "SELECT COUNT(*), MIN(version) FROM schema_version"
        )
        row = cursor.fetchone()
        assert row is not None
        assert int(row[0]) == 1
        assert int(row[1]) == SCHEMA_VERSION_SEED
    finally:
        adapter.close()


class FakeCursor:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[object, ...] | None]] = []
        self._fetch_queue: list[tuple[int]] = [(0,)]

    def execute(self, query: str, params: tuple[object, ...] | None = None) -> None:
        self.executed.append((query, params))

    def fetchone(self) -> tuple[int] | None:
        if not self._fetch_queue:
            return None
        return self._fetch_queue.pop(0)

    def close(self) -> None:
        return None


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self._cursor = cursor
        self.committed: bool = False

    def cursor(self) -> FakeCursor:
        return self._cursor

    def commit(self) -> None:
        self.committed = True

    def close(self) -> None:
        return None


def test_postgres_adapter_apply_schema_executes_seed() -> None:
    cursor = FakeCursor()
    connection = FakeConnection(cursor)

    def _connect(_: DatabaseDsn) -> FakeConnection:
        return connection

    adapter = PostgresDatabaseAdapter(
        DatabaseDsn("postgresql://stub"), connect_fn=_connect
    )
    adapter.connect()
    adapter.apply_schema()

    queries = [entry[0] for entry in cursor.executed]
    assert (
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
        in queries
    )
    assert "SELECT COUNT(*) FROM schema_version" in queries
    assert "INSERT INTO schema_version (version) VALUES (%s)" in queries
    assert cursor.executed[-1][1] == (SCHEMA_VERSION_SEED,)
    assert connection.committed is True


def test_database_manager_initialize_and_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "pypnm.sqlite3"
    adapter = SQLiteDatabaseAdapter(DatabasePath(str(db_path)))
    monkeypatch.setattr(DatabaseManager, "_adapter", adapter)
    assert DatabaseManager.initialize() is True
    DatabaseManager.close()
    assert DatabaseManager._adapter is None
