# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmFecEntry import (
    DocsPnmCmDsOfdmFecEntry,
    DocsPnmCmDsOfdmFecEntryFields,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmModProfEntry import (
    DocsPnmCmDsOfdmModProfEntry,
    DocsPnmCmDsOfdmModProfFields,
)
from pypnm.lib.inet import Inet
from pypnm.lib.types import ChannelId, InterfaceIndex
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


def _mod_profile_entry(index: int) -> DocsPnmCmDsOfdmModProfEntry:
    return DocsPnmCmDsOfdmModProfEntry(
        index=index,
        channel_id=index,
        entry=DocsPnmCmDsOfdmModProfFields(
            docsPnmCmDsOfdmModProfFileEnable=True,
            docsPnmCmDsOfdmModProfMeasStatus="sample_ready",
            docsPnmCmDsOfdmModProfFileName=f"mod_prof_{index}.bin",
        ),
    )


def _fec_entry(index: int) -> DocsPnmCmDsOfdmFecEntry:
    return DocsPnmCmDsOfdmFecEntry(
        index=index,
        entry=DocsPnmCmDsOfdmFecEntryFields(
            docsPnmCmDsOfdmFecSumType="10-minute interval",
            docsPnmCmDsOfdmFecFileEnable=True,
            docsPnmCmDsOfdmFecMeasStatus="sample_ready",
            docsPnmCmDsOfdmFecFileName=f"fec_{index}.bin",
        ),
    )


class _FakeOfdmModem:
    def __init__(self) -> None:
        self._mac = "aa:bb:cc:dd:ee:ff"
        self._inet = "192.168.0.100"

    @property
    def get_mac_address(self) -> str:
        return self._mac

    @property
    def get_inet_address(self) -> str:
        return self._inet

    async def getDocsIf31CmDsOfdmChannelIdIndexStack(
        self,
    ) -> list[tuple[InterfaceIndex, ChannelId]]:
        return [
            (InterfaceIndex(10), ChannelId(193)),
            (InterfaceIndex(11), ChannelId(194)),
        ]

    async def getDocsIf31CmUsOfdmaChannelIdIndexStack(
        self,
    ) -> list[tuple[InterfaceIndex, ChannelId]]:
        return []

    async def getDocsPnmCmDsOfdmModProfEntry(self) -> list[DocsPnmCmDsOfdmModProfEntry]:
        return [
            _mod_profile_entry(10),
            _mod_profile_entry(11),
        ]


class _FakeFecModem:
    def __init__(self) -> None:
        self._mac = "aa:bb:cc:dd:ee:ff"
        self._inet = "192.168.0.100"

    @property
    def get_mac_address(self) -> str:
        return self._mac

    @property
    def get_inet_address(self) -> str:
        return self._inet

    async def getDocsIf31CmDsOfdmChannelIdIndexStack(
        self,
    ) -> list[tuple[InterfaceIndex, ChannelId]]:
        return [
            (InterfaceIndex(20), ChannelId(193)),
            (InterfaceIndex(21), ChannelId(194)),
        ]

    async def getDocsIf31CmUsOfdmaChannelIdIndexStack(
        self,
    ) -> list[tuple[InterfaceIndex, ChannelId]]:
        return []

    async def getDocsPnmCmDsOfdmFecEntry(self) -> list[DocsPnmCmDsOfdmFecEntry]:
        return [
            _fec_entry(20),
            _fec_entry(21),
        ]


@pytest.mark.asyncio
async def test_mod_profile_channel_ids_filter_by_mapping() -> None:
    modem = _FakeOfdmModem()
    service = CommonMeasureService(
        DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
        modem,
        (Inet("0.0.0.0"), Inet("::")),
    )
    entries = await service.getPnmMeasurementStatistics(channel_ids=[ChannelId(193)])
    assert [entry.index for entry in entries] == [10]


@pytest.mark.asyncio
async def test_fec_summary_channel_ids_filter_by_mapping() -> None:
    modem = _FakeFecModem()
    service = CommonMeasureService(
        DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
        modem,
        (Inet("0.0.0.0"), Inet("::")),
    )
    entries = await service.getPnmMeasurementStatistics(channel_ids=[ChannelId(193)])
    assert [entry.index for entry in entries] == [20]
