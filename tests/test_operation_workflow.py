# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import OperationId


class _FakeCaptureService(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])


def _configure_operation_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(capture_group_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )


@pytest.mark.asyncio
async def test_start_creates_running_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    service = _FakeCaptureService(duration=0, interval=1)
    _, operation_id = await service.start()

    store = OperationStore()
    status = store.get_operation(operation_id)
    assert status is not None
    assert status.state == OperationExecutionState.RUNNING

    await asyncio.sleep(0)
    completed = store.get_operation(operation_id)
    assert completed is not None
    assert completed.state == OperationExecutionState.COMPLETED
    assert completed.progress_current >= 1


@pytest.mark.asyncio
async def test_cancel_marks_canceled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    service = _FakeCaptureService(duration=1, interval=0)
    _, operation_id = await service.start()

    canceled = OperationWorkflowService.cancel(operation_id, service)
    assert canceled.state == OperationExecutionState.CANCELED

    await asyncio.sleep(0)
    store = OperationStore()
    status = store.get_operation(operation_id)
    assert status is not None
    assert status.state == OperationExecutionState.CANCELED


def test_result_requires_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    store = OperationStore()
    operation_id = OperationId("op-test-1")
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.RUNNING,
        progress_current=0,
        progress_total=1,
        message="Operation running",
        error=None,
        artifact_paths=None,
    )

    with pytest.raises(ValueError):
        OperationWorkflowService.get_result(operation_id)

    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )
    status = OperationWorkflowService.get_result(operation_id)
    assert status.state == OperationExecutionState.COMPLETED
