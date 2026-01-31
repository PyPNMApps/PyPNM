# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.docs.pnm.spectrumAnalyzer.router import SpectrumAnalyzerRouter
from pypnm.docsis.data_type.DocsIf31CmDsOfdmChanEntry import (
    DocsIf31CmDsOfdmChanChannelEntry,
    DocsIf31CmDsOfdmChanEntry,
)
from pypnm.docsis.data_type.DocsIfDownstreamChannel import (
    DocsIfDownstreamChannelEntry,
    DocsIfDownstreamEntry,
)
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
    DocsIf3CmSpectrumAnalysisEntryFields,
)
from pypnm.lib.types import ChannelId


def _measurement_entry(index: int) -> DocsIf3CmSpectrumAnalysisEntry:
    return DocsIf3CmSpectrumAnalysisEntry(
        index=index,
        entry=DocsIf3CmSpectrumAnalysisEntryFields(
            docsIf3CmSpectrumAnalysisCtrlCmdEnable=True,
            docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout=60,
            docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency=100,
            docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency=200,
            docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan=100,
            docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment=10,
            docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth=150,
            docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction=1,
            docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages=1,
            docsIf3CmSpectrumAnalysisCtrlCmdFileEnable=True,
            docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus="inactive",
            docsIf3CmSpectrumAnalysisCtrlCmdFileName="file",
        ),
    )


def test_measurement_stats_include_ofdm_channel_stats() -> None:
    measurement_stats = {ChannelId(3): [_measurement_entry(0)]}
    channel_entry = DocsIf31CmDsOfdmChanChannelEntry(
        index=1,
        channel_id=3,
        entry=DocsIf31CmDsOfdmChanEntry(
            docsIf31CmDsOfdmChanChannelId=ChannelId(3),
        ),
    )

    out = SpectrumAnalyzerRouter._build_measurement_stats_with_channel_stats(
        measurement_stats,
        [channel_entry],
    )

    assert len(out) == 1
    assert out[0]["channel_id"] == ChannelId(3)
    assert out[0]["channel_stats"]["channel_id"] == 3


def test_measurement_stats_include_scqam_channel_stats() -> None:
    measurement_stats = {ChannelId(4): [_measurement_entry(1)]}
    channel_entry = DocsIfDownstreamChannelEntry(
        index=2,
        channel_id=4,
        entry=DocsIfDownstreamEntry(
            docsIfDownChannelId=ChannelId(4),
        ),
    )

    out = SpectrumAnalyzerRouter._build_measurement_stats_with_channel_stats(
        measurement_stats,
        [channel_entry],
    )

    assert len(out) == 1
    assert out[0]["channel_id"] == ChannelId(4)
    assert out[0]["channel_stats"]["channel_id"] == 4


def test_measurement_stats_without_channel_stats() -> None:
    measurement_stats = {ChannelId(5): [_measurement_entry(2)]}

    out = SpectrumAnalyzerRouter._build_measurement_stats_with_channel_stats(
        measurement_stats,
        [],
    )

    assert len(out) == 1
    assert out[0]["channel_id"] == ChannelId(5)
    assert "channel_stats" not in out[0]


def test_measurement_stats_include_measure_segment_power() -> None:
    measurement_stats = {ChannelId(6): [_measurement_entry(3)]}
    measure_segment_power_by_channel = {
        ChannelId(6): [
            {
                "segment_frequencies": [100, 200],
                "power_dbmv": [1.1, 2.2],
            }
        ]
    }

    out = SpectrumAnalyzerRouter._build_measurement_stats_with_channel_stats(
        measurement_stats,
        [],
        measure_segment_power_by_channel,
    )

    assert len(out) == 1
    assert out[0]["channel_id"] == ChannelId(6)
    assert out[0]["measure_segment_power"] == [
        {
            "segment_frequencies": [100, 200],
            "power_dbmv": [1.1, 2.2],
        }
    ]
