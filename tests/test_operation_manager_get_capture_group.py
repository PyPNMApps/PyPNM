# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_manager import OperationManager
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

DEFAULT_CREATED_EPOCH: int = 1


def _configure_operation_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base_dir = tmp_path / ".data"
    db_dir = base_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    sqlite_db = db_dir / "pypnm.sqlite3"
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_backend",
        classmethod(lambda cls: DatabaseBackend.SQLITE),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_sqlite_path",
        classmethod(lambda cls: DatabasePath(str(sqlite_db))),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "database_postgres_dsn",
        classmethod(lambda cls: DatabaseDsn("")),
    )
    DatabaseSchemaManager.from_system_config().initialize_schema()
    return sqlite_db


def _guard_json_ledgers(monkeypatch: pytest.MonkeyPatch) -> None:
    original_open = Path.open

    def _guarded_open(
        self: Path, *args: tuple[object, ...], **kwargs: dict[str, object]
    ) -> object:
        if self.name in ("capture_group.json", "operation_capture.json"):
            raise AssertionError(f"Unexpected JSON ledger access: {self}")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _guarded_open)


def test_get_capture_group_prefers_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-199")
    capture_group_id = GroupId("group-199")

    capture_repo = CaptureGroupRepository.from_system_config()
    capture_repo.get_or_create_capture_group(
        capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )
    operation_repo = OperationCaptureRepository.from_system_config()
    operation_repo.create_operation_capture(
        operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id
    operation_repo = OperationCaptureRepository.from_system_config()
    assert operation_repo.get_capture_group_id(operation_id) == capture_group_id


def test_get_capture_group_returns_none_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-202")

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved is None


def test_get_capture_group_does_not_touch_json_ledgers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_db(tmp_path, monkeypatch)
    _guard_json_ledgers(monkeypatch)
    operation_id = OperationId("op-203")

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved is None
