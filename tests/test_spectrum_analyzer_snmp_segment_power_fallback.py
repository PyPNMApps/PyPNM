# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging

import pytest

from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.lib.types import FrequencyHz, PowerdBmV


class _FakeCableModem:
    async def getSpectrumMeasTotalSegmentPower(self) -> list[tuple[int, float]]:
        return [(0, 1.54), (1, 2.55)]


@pytest.mark.asyncio
async def test_build_snmp_segment_power_fallback_maps_indices() -> None:
    service = CommonMeasureService.__new__(CommonMeasureService)
    service.cm = _FakeCableModem()  # type: ignore[assignment]
    service.logger = logging.getLogger("CommonMeasureService")
    service.log_prefix = "MAC: aa:bb:cc:dd:ee:ff - INET: 192.168.0.100"
    entries = await service._build_snmp_segment_power_fallback()

    assert len(entries) == 1
    assert entries[0].segment_frequencies == [FrequencyHz(0), FrequencyHz(1)]
    assert entries[0].power_dbmv == [PowerdBmV(1.5), PowerdBmV(2.5)]
