# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.common.extended.common_messaging_service import (
    MessageResponse,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.spectrumAnalyzer import service as spectrum_service
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.abstract.com_spec_chan_ana import (
    CommonChannelSpectumBwLut,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.service import (
    DsOfdmChannelSpectrumAnalyzer,
    DsScQamChannelSpectrumAnalyzer,
)
from pypnm.lib.types import ChannelId, FrequencyHz, ResolutionBw


class _FakeCableModem:
    def __init__(self) -> None:
        self._mac = "aa:bb:cc:dd:ee:ff"

    @property
    def get_mac_address(self) -> str:
        return self._mac


class _TestScqamAnalyzer(DsScQamChannelSpectrumAnalyzer):
    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        return {
            ChannelId(4): (
                FrequencyHz(400_000_000),
                FrequencyHz(405_000_000),
                FrequencyHz(410_000_000),
            ),
            ChannelId(5): (
                FrequencyHz(500_000_000),
                FrequencyHz(505_000_000),
                FrequencyHz(510_000_000),
            ),
        }

    async def updatePnmMeasurementStatistics(self, channel_id: ChannelId) -> bool:
        return True


class _TestOfdmAnalyzer(DsOfdmChannelSpectrumAnalyzer):
    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        return {
            ChannelId(4): (
                FrequencyHz(600_000_000),
                FrequencyHz(610_000_000),
                FrequencyHz(620_000_000),
            ),
            ChannelId(5): (
                FrequencyHz(700_000_000),
                FrequencyHz(710_000_000),
                FrequencyHz(720_000_000),
            ),
        }

    async def updatePnmMeasurementStatistics(self, channel_id: ChannelId) -> bool:
        return True


@pytest.mark.asyncio
async def test_scqam_channel_filtering(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[object] = []

    class _FakeScQamChanSpecAnalyzerService:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self._params = None

        def setSpectrumCaptureParameters(self, capture_parameters: object) -> None:
            self._params = capture_parameters
            captured.append(capture_parameters)

        async def set_and_go(self) -> MessageResponse:
            return MessageResponse(ServiceStatusCode.SUCCESS)

    monkeypatch.setattr(
        spectrum_service,
        "ScQamChanSpecAnalyzerService",
        _FakeScQamChanSpecAnalyzerService,
    )

    analyzer = _TestScqamAnalyzer(
        cable_modem=_FakeCableModem(),
        number_of_averages=1,
        resolution_bandwidth_hz=ResolutionBw(25_000),
        channel_ids=[ChannelId(4)],
    )

    await analyzer.start()

    assert len(captured) == 1


@pytest.mark.asyncio
async def test_ofdm_channel_filtering(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[object] = []

    class _FakeOfdmChanSpecAnalyzerService:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self._params = None

        def setSpectrumCaptureParameters(self, capture_parameters: object) -> None:
            self._params = capture_parameters
            captured.append(capture_parameters)

        async def set_and_go(self) -> MessageResponse:
            return MessageResponse(ServiceStatusCode.SUCCESS)

    monkeypatch.setattr(
        spectrum_service,
        "OfdmChanSpecAnalyzerService",
        _FakeOfdmChanSpecAnalyzerService,
    )

    analyzer = _TestOfdmAnalyzer(
        cable_modem=_FakeCableModem(),
        number_of_averages=1,
        resolution_bandwidth_hz=ResolutionBw(25_000),
        channel_ids=[ChannelId(4)],
    )

    await analyzer.start()

    assert len(captured) == 1
