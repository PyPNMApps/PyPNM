# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.db.operation_capture_repository import OperationCaptureRepository
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath


def _configure_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
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


def test_operation_manager_writes_capture_group_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    group = CaptureGroup()
    group_id = group.create_group()

    manager = OperationManager(capture_group_id=group_id)
    operation_id = manager.register()

    operation_repo = OperationCaptureRepository.from_system_config()
    resolved = operation_repo.get_capture_group_id(operation_id)
    assert resolved == group_id
