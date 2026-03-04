# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import asyncio

import pytest

from pypnm.api.routes.advance.common import capture_service
from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
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
    def __init__(self, capture_group_id: GroupId) -> None:
        self._capture_group_id = capture_group_id

    def register(self, metadata: dict[str, object] | None = None) -> OperationId:
        return OperationId("op-1")


class _FakeCaptureService(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=None)


@pytest.mark.asyncio
async def test_capture_service_skips_empty_transaction_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(capture_service, "CaptureGroup", _FakeCaptureGroup)
    monkeypatch.setattr(capture_service, "OperationManager", _FakeOperationManager)

    service = _FakeCaptureService(duration=0, interval=0)
    await service.start()

    await asyncio.sleep(0)

    assert isinstance(service._cap_group, _FakeCaptureGroup)
    assert service._cap_group.added == []


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
