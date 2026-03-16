# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_kind import (
    MultiCaptureOperation,
    MultiCaptureOperationModel,
)
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.common.classes.file_capture import (
    capture_group as capture_group_module,
)
from pypnm.lib.types import GroupId


class _FakeCaptureGroup:
    def __init__(self, group_id: GroupId | None = None) -> None:
        self._group_id = group_id

    def list_groups(self) -> list[GroupId]:
        return [GroupId("group-1")]


def test_operation_manager_register_persists_operation_block(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(capture_group_module, "CaptureGroup", _FakeCaptureGroup)

    db_path = tmp_path / "operation_capture.json"
    manager = OperationManager(capture_group_id=GroupId("group-1"), db_path=db_path)
    operation = MultiCaptureOperationModel(
        name=MultiCaptureOperation.MULTI_RXMER,
        measure_mode="ofdm_performance_1",
    )

    operation_id = manager.register(
        operation=operation,
        metadata={"mac_address": "aa:bb:cc:dd:ee:ff"},
    )

    persisted = json.loads(db_path.read_text(encoding="utf-8"))

    assert persisted[operation_id]["capture_group_id"] == "group-1"
    assert persisted[operation_id]["operation"] == {
        "name": "multi_rxmer",
        "measure_mode": "ofdm_performance_1",
    }
    assert persisted[operation_id]["metadata"] == {
        "mac_address": "aa:bb:cc:dd:ee:ff",
    }
