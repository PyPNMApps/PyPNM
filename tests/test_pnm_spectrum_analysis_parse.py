# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.pnm.parser.CmSpectrumAnalysis import CmSpectrumAnalysis

DATA_DIR = Path(__file__).parent / "files"
SPEC_PATH = DATA_DIR / "spectrum_analyzer.bin"


@pytest.fixture(scope="session")
def spectrum_bytes() -> bytes:
    return SPEC_PATH.read_bytes()


@pytest.mark.pnm
def test_spectrum_analyzer_parses_and_model_shape(spectrum_bytes: bytes) -> None:
    sa = CmSpectrumAnalysis(spectrum_bytes)
    m = sa.to_model()

    # header basics
    assert m.num_bins_per_segment >= 1
    assert m.segment_frequency_span > 0
    assert m.bin_frequency_spacing > 0

    # numeric types can be int or float depending on decode
    assert isinstance(m.first_segment_center_frequency, (int, float))
    assert isinstance(m.last_segment_center_frequency, (int, float))
    assert isinstance(m.spectrum_analysis_data_length, int)

    # serialized in dict/json via field_serializer
    assert isinstance(m.spectrum_analysis_data, (bytes, str))

    # segments present & each segment is a list[float]
    assert len(m.amplitude_bin_segments_float) >= 1
    for seg in m.amplitude_bin_segments_float:
        assert isinstance(seg, list)
        assert all(isinstance(v, float) for v in seg)
        assert len(seg) <= m.num_bins_per_segment

    if len(m.amplitude_bin_segments_float) > 1:
        for seg in m.amplitude_bin_segments_float[:-1]:
            assert len(seg) == m.num_bins_per_segment


@pytest.mark.pnm
def test_spectrum_analyzer_json_and_dict_roundtrip(spectrum_bytes: bytes) -> None:
    sa = CmSpectrumAnalysis(spectrum_bytes)

    d = sa.to_dict()
    j = sa.to_json()
    parsed = json.loads(j)

    # top-level keys align
    assert set(parsed.keys()) == set(d.keys())

    # In both dict and JSON, spectrum_analysis_data is hex string (due to field_serializer)
    assert isinstance(d["spectrum_analysis_data"], str)
    assert isinstance(parsed["spectrum_analysis_data"], str)
    assert parsed["spectrum_analysis_data"] == d["spectrum_analysis_data"]


@pytest.mark.pnm
def test_bin_frequency_spacing_consistency(spectrum_bytes: bytes) -> None:
    sa = CmSpectrumAnalysis(spectrum_bytes)
    m = sa.to_model()

    expect = int(m.segment_frequency_span / m.num_bins_per_segment)
    assert m.bin_frequency_spacing == expect
