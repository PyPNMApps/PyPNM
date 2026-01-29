# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.types import ChannelId, InterfaceIndex


class _FakeCableModem:
    def __init__(
        self,
        ds_stack: list[tuple[InterfaceIndex, ChannelId]],
        us_stack: list[tuple[InterfaceIndex, ChannelId]],
    ) -> None:
        self._ds_stack = ds_stack
        self._us_stack = us_stack

    async def getDocsIf31CmDsOfdmChannelIdIndexStack(self) -> list[tuple[InterfaceIndex, ChannelId]]:
        return list(self._ds_stack)

    async def getDocsIf31CmUsOfdmaChannelIdIndexStack(self) -> list[tuple[InterfaceIndex, ChannelId]]:
        return list(self._us_stack)


@pytest.mark.asyncio
async def test_validate_ds_channel_ids_empty_is_noop() -> None:
    cm = _FakeCableModem(ds_stack=[(InterfaceIndex(1), ChannelId(10))], us_stack=[])
    precheck = CableModemServicePreCheck(cable_modem=cm, validate_pnm_ready_status=False)

    status, _ = await precheck.validate_ds_channel_ids_exist([])

    assert status == ServiceStatusCode.SUCCESS


@pytest.mark.asyncio
async def test_validate_ds_channel_ids_invalid() -> None:
    cm = _FakeCableModem(ds_stack=[(InterfaceIndex(1), ChannelId(10))], us_stack=[])
    precheck = CableModemServicePreCheck(cable_modem=cm, validate_pnm_ready_status=False)

    status, _ = await precheck.validate_ds_channel_ids_exist([ChannelId(10), ChannelId(12)])

    assert status == ServiceStatusCode.INVALID_CHANNEL_ID


@pytest.mark.asyncio
async def test_validate_us_channel_ids_valid() -> None:
    cm = _FakeCableModem(ds_stack=[], us_stack=[(InterfaceIndex(1), ChannelId(20))])
    precheck = CableModemServicePreCheck(cable_modem=cm, validate_pnm_ready_status=False)

    status, _ = await precheck.validate_us_channel_ids_exist([ChannelId(20)])

    assert status == ServiceStatusCode.SUCCESS
