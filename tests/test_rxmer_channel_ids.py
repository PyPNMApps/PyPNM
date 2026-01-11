# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.rxmer.router import RxMerRouter
from pypnm.lib.inet import Inet
from pypnm.lib.types import ChannelId, InterfaceIndex
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


class _FakeCableModem:
    def __init__(self) -> None:
        self._mac = "aa:bb:cc:dd:ee:ff"
        self._inet = "192.168.0.100"

    @property
    def get_mac_address(self) -> str:
        return self._mac

    @property
    def get_inet_address(self) -> str:
        return self._inet

    async def getDocsIf31CmDsOfdmChannelIdIndexStack(self) -> list[tuple[InterfaceIndex, ChannelId]]:
        return [
            (InterfaceIndex(1), ChannelId(1)),
            (InterfaceIndex(2), ChannelId(2)),
            (InterfaceIndex(3), ChannelId(3)),
        ]

    async def getDocsIf31CmUsOfdmaChannelIdIndexStack(self) -> list[tuple[InterfaceIndex, ChannelId]]:
        return []

    async def getIfTypeIndex(self, *_args: object, **_kwargs: object) -> list[InterfaceIndex]:
        return [InterfaceIndex(1)]


@pytest.mark.asyncio
async def test_rxmer_channel_ids_absent_preserves_all_channels() -> None:
    modem = _FakeCableModem()
    service = CommonMeasureService(
        DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        modem,
        (Inet("0.0.0.0"), Inet("::")),
    )
    status, idx_channel = await service._get_indexes_via_pnm_test_type(None)
    assert status == ServiceStatusCode.SUCCESS
    assert idx_channel == [
        (InterfaceIndex(1), ChannelId(1)),
        (InterfaceIndex(2), ChannelId(2)),
        (InterfaceIndex(3), ChannelId(3)),
    ]


@pytest.mark.asyncio
async def test_rxmer_channel_ids_filter_scope() -> None:
    modem = _FakeCableModem()
    service = CommonMeasureService(
        DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        modem,
        (Inet("0.0.0.0"), Inet("::")),
    )
    params = DownstreamOfdmParameters(channel_id=[ChannelId(2), ChannelId(3)])
    status, idx_channel = await service._get_indexes_via_pnm_test_type(params)
    assert status == ServiceStatusCode.SUCCESS
    assert idx_channel == [
        (InterfaceIndex(2), ChannelId(2)),
        (InterfaceIndex(3), ChannelId(3)),
    ]


def test_rxmer_router_resolves_channel_ids() -> None:
    router = RxMerRouter()
    assert router._resolve_interface_parameters(None) is None
    assert router._resolve_interface_parameters([]) is None
    params = router._resolve_interface_parameters([ChannelId(4)])
    assert isinstance(params, DownstreamOfdmParameters)
    assert params.channel_id == [ChannelId(4)]
