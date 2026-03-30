# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import asyncio

import pytest

from pypnm.api.routes.advance.common import capture_service
from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_kind import (
    MultiCaptureOperation,
    MultiCaptureOperationModel,
)
from pypnm.api.routes.common.classes.file_capture.capture_sample import CaptureSample
from pypnm.api.routes.common.extended.common_messaging_service import (
    MessageResponse,
    MessageResponseType,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.types import GroupId, OperationId


class _FakeCaptureGroup:
    def __init__(self) -> None:
        self.added: list[str] = []

    def create_group(self) -> GroupId:
        return GroupId("group-1")

    def add_transaction(self, txn_id: str) -> None:
        self.added.append(txn_id)


class _FakeOperationManager:
    register_calls: list[dict[str, object]] = []
    update_calls: list[dict[str, object]] = []

    def __init__(self, capture_group_id: GroupId) -> None:
        self._capture_group_id = capture_group_id

    def register(
        self,
        operation: MultiCaptureOperationModel | None = None,
        metadata: dict[str, object] | None = None,
    ) -> OperationId:
        self.__class__.register_calls.append({"operation": operation, "metadata": metadata})
        return OperationId("op-1")

    @classmethod
    def update_operation_status(
        cls,
        operation_id: OperationId,
        state: capture_service.OperationState,
        collected: int,
        time_remaining: int,
    ) -> bool:
        cls.update_calls.append(
            {
                "operation_id": operation_id,
                "state": state,
                "collected": collected,
                "time_remaining": time_remaining,
            },
        )
        return True


class _FakeCaptureService(AbstractCaptureService):
    OPERATION_NAME = MultiCaptureOperation.MULTI_DS_CHANNEL_ESTIMATION
    MEASURE_MODE = "standard"

    async def _capture_message_response(self) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=None)


class _SlowCaptureService(AbstractCaptureService):
    OPERATION_NAME = MultiCaptureOperation.MULTI_DS_CHANNEL_ESTIMATION
    MEASURE_MODE = "standard"

    async def _capture_message_response(self) -> MessageResponse:
        await asyncio.sleep(5)
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=None)


@pytest.mark.asyncio
async def test_capture_service_skips_empty_transaction_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(capture_service, "CaptureGroup", _FakeCaptureGroup)
    monkeypatch.setattr(capture_service, "OperationManager", _FakeOperationManager)
    _FakeOperationManager.register_calls = []
    _FakeOperationManager.update_calls = []

    service = _FakeCaptureService(duration=0, interval=0)
    await service.start()

    await asyncio.sleep(0)

    assert isinstance(service._cap_group, _FakeCaptureGroup)
    assert service._cap_group.added == []
    assert _FakeOperationManager.register_calls == [
        {
            "operation": MultiCaptureOperationModel(
                name=MultiCaptureOperation.MULTI_DS_CHANNEL_ESTIMATION,
                measure_mode="standard",
            ),
            "metadata": {},
        },
    ]
    assert "op-1" not in service._ops
    assert _FakeOperationManager.update_calls[-1]["operation_id"] == "op-1"
    assert _FakeOperationManager.update_calls[-1]["state"] == capture_service.OperationState.COMPLETED


def test_process_captures_backfills_missing_system_description(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakePnmFileTransaction:
        def __init__(self) -> None:
            self._record = {
                "device_details": {
                    "system_description": {},
                },
            }
            self.updated: list[tuple[str, dict[str, str]]] = []

        def get_record(self, txn_id: str) -> dict[str, object]:
            return self._record

        def update_record_system_description(self, transaction_id: str, system_description: dict[str, str]) -> bool:
            self.updated.append((transaction_id, dict(system_description)))
            self._record["device_details"]["system_description"] = dict(system_description)
            return True

    fake_txn = _FakePnmFileTransaction()
    monkeypatch.setattr(capture_service, "PnmFileTransaction", lambda: fake_txn)

    svc = _FakeCaptureService(
        duration=0,
        interval=0,
        system_description={
            "HW_REV": "1.0",
            "VENDOR": "LANCity",
            "BOOTR": "NONE",
            "SW_REV": "1.0.0",
            "MODEL": "LCPET-3",
        },
    )

    msg_rsp = MessageResponse(
        ServiceStatusCode.SUCCESS,
        payload=[
            {
                "status": ServiceStatusCode.SUCCESS.name,
                "message_type": MessageResponseType.PNM_FILE_TRANSACTION.name,
                "message": {
                    "transaction_id": "tx1",
                    "filename": "sample.bin",
                },
            },
        ],
    )

    samples = svc._process_captures(msg_rsp)

    assert len(samples) == 1
    assert samples[0].error is None
    assert fake_txn.updated
    assert fake_txn.updated[0][0] == "tx1"


def test_capture_service_builds_operation_model() -> None:
    service = _FakeCaptureService(duration=0, interval=0)

    assert service.get_operation_model() == MultiCaptureOperationModel(
        name=MultiCaptureOperation.MULTI_DS_CHANNEL_ESTIMATION,
        measure_mode="standard",
    )


@pytest.mark.asyncio
async def test_capture_service_stop_cancels_background_task(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(capture_service, "CaptureGroup", _FakeCaptureGroup)
    monkeypatch.setattr(capture_service, "OperationManager", _FakeOperationManager)
    _FakeOperationManager.register_calls = []
    _FakeOperationManager.update_calls = []

    service = _SlowCaptureService(duration=30, interval=0)
    _, operation_id = await service.start()

    await asyncio.sleep(0)

    task = service._ops[operation_id]["task"]
    assert isinstance(task, asyncio.Task)
    assert task.done() is False

    service.stop(operation_id)

    await asyncio.sleep(0)

    assert operation_id not in service._ops
    assert task.cancelled() is True or task.done() is True
    assert _FakeOperationManager.update_calls[-1]["state"] == capture_service.OperationState.STOPPED


def test_release_operation_memory_keeps_collected_count(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _FakeCaptureService(duration=0, interval=0)
    persisted_status_calls: list[dict[str, object]] = []
    service._ops["op-1"] = {
        "state": capture_service.OperationState.COMPLETED,
        "collected": 2,
        "samples": [
            CaptureSample(timestamp=1, transaction_id="tx1", filename="a.bin", error=None),
            CaptureSample(timestamp=2, transaction_id="tx2", filename="b.bin", error=None),
        ],
        "task": object(),
        "time_remaining": 0,
    }

    released_calls: list[str] = []
    monkeypatch.setattr(capture_service.ProcessMemory, "release_unused_memory", lambda: released_calls.append("released"))
    monkeypatch.setattr(
        capture_service.OperationManager,
        "update_operation_status",
        lambda **kwargs: persisted_status_calls.append(kwargs) or True,
    )

    service.release_operation_memory(OperationId("op-1"))

    assert "op-1" not in service._ops
    assert persisted_status_calls[0]["collected"] == 2
    assert released_calls == ["released"]
