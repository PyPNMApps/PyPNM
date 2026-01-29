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
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import (
    SpecAnCaptureParaFriendly,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.service import (
    DsOfdmChannelSpectrumAnalyzer,
    DsScQamChannelSpectrumAnalyzer,
    SpectrumAnalyzerFriendlyCaptureBuilder,
)
from pypnm.lib.types import ChannelId, FrequencyHz, ResolutionBw
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import WindowFunction


class _FakeCableModem:
    def __init__(self) -> None:
        self._mac = "aa:bb:cc:dd:ee:ff"

    @property
    def get_mac_address(self) -> str:
        return self._mac


class _TestOfdmAnalyzer(DsOfdmChannelSpectrumAnalyzer):
    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        return {
            ChannelId(4): (
                FrequencyHz(100_000_000),
                FrequencyHz(110_000_000),
                FrequencyHz(120_000_000),
            )
        }

    async def updatePnmMeasurementStatistics(self, channel_id: ChannelId) -> bool:
        return True


class _TestScqamAnalyzer(DsScQamChannelSpectrumAnalyzer):
    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        return {
            ChannelId(4): (
                FrequencyHz(200_000_000),
                FrequencyHz(205_000_000),
                FrequencyHz(210_000_000),
            )
        }

    async def updatePnmMeasurementStatistics(self, channel_id: ChannelId) -> bool:
        return True


@pytest.mark.asyncio
async def test_ofdm_channel_uses_friendly_rbw_builder(monkeypatch: pytest.MonkeyPatch) -> None:
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
    )

    await analyzer.start()

    assert len(captured) == 1

    friendly = SpecAnCaptureParaFriendly(
        inactivity_timeout=30,
        first_segment_center_freq=FrequencyHz(100_000_000),
        last_segment_center_freq=FrequencyHz(120_000_000),
        resolution_bandwidth_hz=ResolutionBw(25_000),
        noise_bw=150,
        window_function=WindowFunction.HANN,
        num_averages=1,
        spectrum_retrieval_type=1,
    )
    expected = SpectrumAnalyzerFriendlyCaptureBuilder.build(friendly)
    assert captured[0].num_bins_per_segment == expected.num_bins_per_segment
    assert captured[0].segment_freq_span == expected.segment_freq_span


@pytest.mark.asyncio
async def test_scqam_channel_uses_friendly_rbw_builder(monkeypatch: pytest.MonkeyPatch) -> None:
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
    )

    await analyzer.start()

    assert len(captured) == 1

    friendly = SpecAnCaptureParaFriendly(
        inactivity_timeout=60,
        first_segment_center_freq=FrequencyHz(200_000_000),
        last_segment_center_freq=FrequencyHz(210_000_000),
        resolution_bandwidth_hz=ResolutionBw(25_000),
        noise_bw=150,
        window_function=WindowFunction.HANN,
        num_averages=1,
        spectrum_retrieval_type=1,
    )
    expected = SpectrumAnalyzerFriendlyCaptureBuilder.build(friendly)
    assert captured[0].num_bins_per_segment == expected.num_bins_per_segment
    assert captured[0].segment_freq_span == expected.segment_freq_span
