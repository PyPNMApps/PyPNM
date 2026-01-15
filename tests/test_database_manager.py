# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.db.database_manager import DatabaseManager
from pypnm.db.postgres_adapter import PostgresDatabaseAdapter
from pypnm.db.schema_version import (
    POSTGRES_SCHEMA_VERSION_INSERT,
    SCHEMA_META_ID_SEED,
    SCHEMA_VERSION_DDL,
    SCHEMA_VERSION_SEED,
)
from pypnm.db.sqlite_adapter import SQLiteDatabaseAdapter
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath


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


def test_database_manager_env_override_sqlite_wins_over_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager({"Database.backend": "postgres"})
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    monkeypatch.setenv("PYPNM_DB_BACKEND", "sqlite")

    adapter = DatabaseManager.get_adapter()
    assert isinstance(adapter, SQLiteDatabaseAdapter)


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


def test_database_manager_handles_env_postgres_blank_dsn(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("PYPNM_DB_BACKEND", "postgres")
    monkeypatch.setenv("PYPNM_DB_POSTGRES_DSN", "")

    logger_name = "DatabaseManager"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        adapter = DatabaseManager.get_adapter()

    assert isinstance(adapter, SQLiteDatabaseAdapter)
    assert "Invalid Database configuration" in caplog.text


def test_database_manager_handles_env_postgres_whitespace_dsn(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setenv("PYPNM_DB_BACKEND", "postgres")
    monkeypatch.setenv("PYPNM_DB_POSTGRES_DSN", "   ")

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
        count, minimum = adapter.schema_meta_stats()
        assert count == 1
        assert minimum == SCHEMA_VERSION_SEED
    finally:
        adapter.close()


class FakeCursor:
    def __init__(self, fetch_queue: list[tuple[object, ...]] | None = None) -> None:
        self.executed: list[tuple[str, tuple[object, ...] | None]] = []
        self._fetch_queue: list[tuple[object, ...]] = fetch_queue or [(0,)]

    def execute(self, query: str, params: tuple[object, ...] | None = None) -> None:
        self.executed.append((query, params))

    def fetchone(self) -> tuple[object, ...] | None:
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
    assert POSTGRES_SCHEMA_VERSION_INSERT in queries
    assert cursor.executed[-1][1] == (SCHEMA_META_ID_SEED, SCHEMA_VERSION_SEED)
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


def test_database_manager_initialize_postgres_optional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.environ.get("PYPNM_TEST_POSTGRES", "").strip() != "1":
        pytest.skip("PYPNM_TEST_POSTGRES not set")
    dsn = os.environ.get("PYPNM_DB_POSTGRES_DSN", "").strip()
    if dsn == "":
        pytest.skip("PYPNM_DB_POSTGRES_DSN not set")
    pytest.importorskip("psycopg")
    monkeypatch.setenv("PYPNM_DB_BACKEND", "postgres")
    monkeypatch.setenv("PYPNM_DB_POSTGRES_DSN", dsn)
    try:
        assert DatabaseManager.initialize() is True
    finally:
        DatabaseManager.close()


class CloseTrackingAdapter:
    def __init__(self) -> None:
        self.closed: bool = False

    def connect(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def apply_schema(self) -> None:
        return None

    def healthcheck(self) -> bool:
        return True


def test_database_manager_close_invokes_adapter_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = CloseTrackingAdapter()
    monkeypatch.setattr(DatabaseManager, "_adapter", adapter)

    DatabaseManager.close()
    assert adapter.closed is True
    assert DatabaseManager._adapter is None


class FailingAdapter:
    def __init__(self, stage: str) -> None:
        self._stage = stage

    def connect(self) -> None:
        if self._stage == "connect":
            raise RuntimeError("connect failed")

    def close(self) -> None:
        return None

    def apply_schema(self) -> None:
        if self._stage == "apply_schema":
            raise RuntimeError("apply_schema failed")

    def healthcheck(self) -> bool:
        if self._stage == "healthcheck":
            raise RuntimeError("healthcheck failed")
        return True


def test_database_manager_initialize_connect_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = FailingAdapter("connect")
    monkeypatch.setattr(
        DatabaseManager, "get_adapter", classmethod(lambda cls: adapter)
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )

    assert DatabaseManager.initialize() is False


def test_database_manager_initialize_apply_schema_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = FailingAdapter("apply_schema")
    monkeypatch.setattr(
        DatabaseManager, "get_adapter", classmethod(lambda cls: adapter)
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )

    assert DatabaseManager.initialize() is False


def test_database_manager_initialize_healthcheck_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = FailingAdapter("healthcheck")
    monkeypatch.setattr(
        DatabaseManager, "get_adapter", classmethod(lambda cls: adapter)
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )

    assert DatabaseManager.initialize() is False
