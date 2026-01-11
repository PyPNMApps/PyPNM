# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.db.capture_group_repository import (
    CaptureGroupRepository,
    OperationCaptureRepository,
)
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
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

    operation_db = db_dir / "operation_capture.json"
    sqlite_db = db_dir / "pypnm.sqlite3"
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )
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
    return operation_db


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
    operation_repo.upsert_operation_capture(
        operation_id, capture_group_id, TimestampSec(DEFAULT_CREATED_EPOCH)
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id
    operation_repo = OperationCaptureRepository.from_system_config()
    assert operation_repo.get_capture_group_id(operation_id) == capture_group_id


def test_get_capture_group_returns_group_id_for_canonical_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_db = _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-200")
    capture_group_id = GroupId("group-200")

    operation_db.write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group_id": str(capture_group_id),
                    "created": DEFAULT_CREATED_EPOCH,
                }
            }
        ),
        encoding="utf-8",
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id
    operation_repo = OperationCaptureRepository.from_system_config()
    assert operation_repo.get_capture_group_id(operation_id) == capture_group_id


def test_get_capture_group_returns_group_id_for_legacy_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_db = _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-201")
    capture_group_id = GroupId("group-201")

    operation_db.write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group": str(capture_group_id),
                    "created": DEFAULT_CREATED_EPOCH,
                }
            }
        ),
        encoding="utf-8",
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id


def test_get_capture_group_returns_none_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_db(tmp_path, monkeypatch)
    operation_id = OperationId("op-202")

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved is None
