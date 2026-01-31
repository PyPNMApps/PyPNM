# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import math

import pytest

from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import WindowFunction


def test_basic_analysis_spectrum_analyzer_channel_power_dbmv() -> None:
    measurement = {
        "device_details": SystemDescriptor.empty().to_dict(),
        "first_segment_center_frequency": 100,
        "last_segment_center_frequency": 102,
        "segment_frequency_span": 2,
        "num_bins_per_segment": 2,
        "equivalent_noise_bandwidth": 0.0,
        "window_function": WindowFunction.HANN.value,
        "bin_frequency_spacing": 1,
        "amplitude_bin_segments_float": [[0.0, 0.0]],
    }

    model = Analysis.basic_analysis_spectrum_analyzer(measurement, None)
    expected = round(10.0 * math.log10(2.0), 2)
    assert model.signal_analysis.channel_power_dbmv == expected


def test_basic_analysis_spectrum_analyzer_snmp_channel_power_dbmv() -> None:
    measurement = {
        "device_details": SystemDescriptor.empty().to_dict(),
        "frequency": [100, 101],
        "amplitude": [0.0, 0.0],
        "equivalent_noise_bandwidth": 0.0,
    }

    model = Analysis.basic_analysis_spectrum_analyzer_snmp(measurement, None, None)
    expected = round(10.0 * math.log10(2.0), 2)
    assert model.signal_analysis.channel_power_dbmv == expected
