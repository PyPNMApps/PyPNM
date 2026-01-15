## Agent Review Bundle Summary
- Goal: Centralize schema_version constants/SQL, remove cross-backend test coupling, and expand idempotence coverage without expanding schema scope.
- Changes: Added shared schema_version module, wired adapters/tests to shared constants, added Postgres idempotence test with configurable fake cursor.
- Files: src/pypnm/db/schema_version.py; src/pypnm/db/sqlite_adapter.py; src/pypnm/db/postgres_adapter.py; tests/test_database_manager.py.
- Tests: python3 -m compileall src; ruff check .; ruff format --check .; pytest -q.
- Notes: Skipped hardware integration and Postgres DSN-dependent tests due to missing environment flags/DSN.

# FILE: src/pypnm/db/schema_version.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

SCHEMA_VERSION_SEED: int = 1

SCHEMA_VERSION_DDL: str = (
    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
)
SCHEMA_VERSION_COUNT: str = "SELECT COUNT(*) FROM schema_version"
SQLITE_SCHEMA_VERSION_INSERT: str = "INSERT INTO schema_version (version) VALUES (?)"
POSTGRES_SCHEMA_VERSION_INSERT: str = "INSERT INTO schema_version (version) VALUES (%s)"

# FILE: src/pypnm/db/sqlite_adapter.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.db.database_adapter import DatabaseAdapter
from pypnm.db.schema_version import (
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
                SQLITE_SCHEMA_VERSION_INSERT, (SCHEMA_VERSION_SEED,)
            )
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
from pypnm.db.schema_version import (
    POSTGRES_SCHEMA_VERSION_INSERT,
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
            cursor.execute(POSTGRES_SCHEMA_VERSION_INSERT, (SCHEMA_VERSION_SEED,))
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
from pypnm.db.postgres_adapter import PostgresDatabaseAdapter
from pypnm.db.schema_version import (
    POSTGRES_SCHEMA_VERSION_INSERT,
    SCHEMA_VERSION_COUNT,
    SCHEMA_VERSION_DDL,
    SCHEMA_VERSION_SEED,
)
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
    def __init__(self, fetch_queue: list[tuple[int]] | None = None) -> None:
        self.executed: list[tuple[str, tuple[object, ...] | None]] = []
        self._fetch_queue: list[tuple[int]] = fetch_queue or [(0,)]

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
    assert SCHEMA_VERSION_DDL in queries
    assert SCHEMA_VERSION_COUNT in queries
    assert POSTGRES_SCHEMA_VERSION_INSERT in queries
    assert cursor.executed[-1][1] == (SCHEMA_VERSION_SEED,)
    assert connection.committed is True


def test_postgres_adapter_apply_schema_skips_seed_when_present() -> None:
    cursor = FakeCursor(fetch_queue=[(1,)])
    connection = FakeConnection(cursor)

    def _connect(_: DatabaseDsn) -> FakeConnection:
        return connection

    adapter = PostgresDatabaseAdapter(
        DatabaseDsn("postgresql://stub"), connect_fn=_connect
    )
    adapter.connect()
    adapter.apply_schema()

    queries = [entry[0] for entry in cursor.executed]
    assert SCHEMA_VERSION_DDL in queries
    assert SCHEMA_VERSION_COUNT in queries
    assert POSTGRES_SCHEMA_VERSION_INSERT not in queries
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
