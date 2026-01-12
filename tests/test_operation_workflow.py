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
from pypnm.api.routes.common.extended.common_messaging_service import (
    MessageResponse,
    MessageResponseType,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.db_schema_manager import DatabaseSchemaManager
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import DatabaseBackend, DatabaseDsn, DatabasePath, OperationId


class _FakeCaptureService(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])


class _FakeCaptureServiceEmptyTxn(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        payload = [
            {
                "status": ServiceStatusCode.SUCCESS.name,
                "message_type": MessageResponseType.PNM_FILE_TRANSACTION.name,
                "message": {
                    "transaction_id": "",
                    "filename": "rxmer.bin",
                },
            }
        ]
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=payload)


class _FakeCaptureServiceWhitespaceTxn(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        payload = [
            {
                "status": ServiceStatusCode.SUCCESS.name,
                "message_type": MessageResponseType.PNM_FILE_TRANSACTION.name,
                "message": {
                    "transaction_id": "   ",
                    "filename": "rxmer.bin",
                },
            }
        ]
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=payload)


def _configure_operation_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    sqlite_db = db_dir / "pypnm.sqlite3"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
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


@pytest.mark.asyncio
async def test_capture_service_skips_empty_transaction_id_linking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    service = _FakeCaptureServiceEmptyTxn(duration=0, interval=0)
    group_id, _ = await service.start()

    await asyncio.sleep(0)

    repo = CaptureGroupRepository.from_system_config()
    assert repo.list_transactions(group_id) == []
    assert "Skipping capture_group link for empty transaction_id" in caplog.text


@pytest.mark.asyncio
async def test_capture_service_skips_whitespace_transaction_id_linking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    service = _FakeCaptureServiceWhitespaceTxn(duration=0, interval=0)
    group_id, _ = await service.start()

    await asyncio.sleep(0)

    repo = CaptureGroupRepository.from_system_config()
    assert repo.list_transactions(group_id) == []
    assert "Skipping capture_group link for empty transaction_id" in caplog.text
