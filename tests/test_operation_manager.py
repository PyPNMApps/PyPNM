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
from pypnm.api.routes.advance.common.operation_state import OperationState
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


def test_operation_manager_lists_records_by_operation_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(capture_group_module, "CaptureGroup", _FakeCaptureGroup)

    db_path = tmp_path / "operation_capture.json"
    db_path.write_text(
        json.dumps(
            {
                "op-rxmer": {
                    "capture_group_id": "group-1",
                    "created": 1,
                    "operation": {
                        "name": "multi_rxmer",
                        "measure_mode": "continuous",
                    },
                    "metadata": {"mac_address": "aa:bb:cc:dd:ee:ff"},
                },
                "op-chan-est": {
                    "capture_group_id": "group-2",
                    "created": 2,
                    "operation": {
                        "name": "multi_ds_channel_estimation",
                        "measure_mode": "standard",
                    },
                    "metadata": {"mac_address": "00:00:00:dd:ee:ff"},
                },
            },
        ),
        encoding="utf-8",
    )

    records = OperationManager.list_operation_records_by_name("multi_rxmer", db_path=db_path)

    assert list(records.keys()) == ["op-rxmer"]
    assert records["op-rxmer"].operation.name == MultiCaptureOperation.MULTI_RXMER
    assert records["op-rxmer"].operation.measure_mode == "continuous"


def test_operation_manager_update_operation_status_persists_runtime_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(capture_group_module, "CaptureGroup", _FakeCaptureGroup)

    db_path = tmp_path / "operation_capture.json"
    manager = OperationManager(capture_group_id=GroupId("group-1"), db_path=db_path)
    operation_id = manager.register(
        operation=MultiCaptureOperationModel(
            name=MultiCaptureOperation.MULTI_RXMER,
            measure_mode="continuous",
        ),
    )

    updated = OperationManager.update_operation_status(
        operation_id=operation_id,
        state=OperationState.COMPLETED,
        collected=7,
        time_remaining=0,
        db_path=db_path,
    )

    persisted = json.loads(db_path.read_text(encoding="utf-8"))

    assert updated is True
    assert persisted[operation_id]["operation_status"]["state"] == "completed"
    assert persisted[operation_id]["operation_status"]["collected"] == 7
    assert persisted[operation_id]["operation_status"]["time_remaining"] == 0
    assert isinstance(persisted[operation_id]["operation_status"]["updated"], int)
