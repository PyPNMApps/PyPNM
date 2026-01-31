# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.docsis.data_type.DocsIf3CmSpectrumAnalysisMeasEntry import (
    DocsIf3CmSpectrumAnalysisMeasEntry,
    DocsIf3CmSpectrumAnalysisMeasEntryFields,
)
from pypnm.lib.types import FrequencyHz, PowerdBmV


def test_build_snmp_meas_entry_payload_concatenates_amp_data() -> None:
    entries = [
        DocsIf3CmSpectrumAnalysisMeasEntry(
            index=0,
            entry=DocsIf3CmSpectrumAnalysisMeasEntryFields(
                docsIf3CmSpectrumAnalysisMeasFrequency=FrequencyHz(100_000_000),
                docsIf3CmSpectrumAnalysisMeasAmplitudeData=b"\x01\x02",
                docsIf3CmSpectrumAnalysisMeasTotalSegmentPower=PowerdBmV(1.23),
            ),
        ),
        DocsIf3CmSpectrumAnalysisMeasEntry(
            index=1,
            entry=DocsIf3CmSpectrumAnalysisMeasEntryFields(
                docsIf3CmSpectrumAnalysisMeasFrequency=FrequencyHz(200_000_000),
                docsIf3CmSpectrumAnalysisMeasAmplitudeData=b"\x03",
                docsIf3CmSpectrumAnalysisMeasTotalSegmentPower=PowerdBmV(2.36),
            ),
        ),
    ]

    amp_data, segment_power = CommonMeasureService._build_snmp_meas_entry_payload(entries)

    assert amp_data == b"\x01\x02\x03"
    assert len(segment_power) == 1
    assert segment_power[0].segment_frequencies == [
        FrequencyHz(100_000_000),
        FrequencyHz(200_000_000),
    ]
    assert segment_power[0].power_dbmv == [
        PowerdBmV(1.2),
        PowerdBmV(2.3),
    ]
