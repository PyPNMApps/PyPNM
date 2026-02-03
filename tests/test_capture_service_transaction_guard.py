# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import asyncio

import pytest

from pypnm.api.routes.advance.common import capture_service
from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
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

    def register(self) -> OperationId:
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
