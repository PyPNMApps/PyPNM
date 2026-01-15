# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest
from tests.postgres_test_utils import require_postgres

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


def _configure_operation_capture_legacy_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    db_path = tmp_path / "pypnm-legacy.sqlite3"
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute(
            ""
            "CREATE TABLE IF NOT EXISTS capture_groups ("
            "    capture_group_id  TEXT    PRIMARY KEY,"
            "    created_epoch     INTEGER NOT NULL"
            ");"
        )
        connection.execute(
            ""
            "CREATE TABLE IF NOT EXISTS operation_captures ("
            "    operation_capture_id TEXT PRIMARY KEY,"
            "    capture_group_id     TEXT    NOT NULL "
            "        REFERENCES capture_groups(capture_group_id) ON DELETE RESTRICT,"
            "    created_epoch        INTEGER NOT NULL "
            "        DEFAULT (CAST(strftime('%s','now') AS INTEGER))"
            ");"
        )
        connection.commit()
    finally:
        connection.close()

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


def test_operation_capture_repository_legacy_column_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_operation_capture_legacy_db(tmp_path, monkeypatch)
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute(
            "INSERT INTO capture_groups (capture_group_id, created_epoch) VALUES (?, ?);",
            ("cg-legacy", DEFAULT_CREATED_EPOCH),
        )
        connection.commit()
    finally:
        connection.close()

    operation_repo = OperationCaptureRepository.from_system_config()
    capture_group_id = GroupId("cg-legacy")
    operation_id = OperationId("op-legacy")
    operation_repo.create_operation_capture(
        operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )

    assert operation_repo.get_capture_group_id(operation_id) == capture_group_id
    assert operation_repo._operation_id_column == "operation_capture_id"


def test_operation_capture_repository_fk_enforced_on_missing_capture_group_postgres(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    postgres_dsn, psycopg = require_postgres()
    _configure_operation_capture_postgres(tmp_path, monkeypatch, postgres_dsn)
    suffix = _unique_suffix()
    capture_group_id = GroupId(f"cg-op-missing-{suffix}")
    operation_id = OperationId(f"op-missing-{suffix}")

    operation_repo = OperationCaptureRepository.from_system_config()
    with pytest.raises(psycopg.IntegrityError):
        operation_repo.create_operation_capture(
            operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
        )
