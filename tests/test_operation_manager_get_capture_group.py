# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import GroupId, OperationId


def _configure_operation_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base_dir = tmp_path / ".data"
    db_dir = base_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    operation_db = db_dir / "operation_capture.json"
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )
    return operation_db


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
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )

    resolved = OperationManager.get_capture_group(operation_id)
    assert resolved == capture_group_id


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
                    "created": 1,
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
