# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.lib.file_processor import FileProcessor
from pypnm.pnm.parser.CmSpectrumAnalysis import (
    CmSpectrumAnalysis,
    CmSpectrumAnalyzerModel,
)

DATA_DIR: Path = Path(__file__).parent / "files"
SPECTRUM_PATH: Path = DATA_DIR / "spectrum_analyzer.bin"
US_PREEQ_PATH: Path = DATA_DIR / "us_pre_equalizer_coef.bin"


@pytest.mark.pnm
def test_cm_spectrum_analysis_parses_and_populates_core_fields() -> None:
    """
    Ensure CmSpectrumAnalysis Parses The Downstream Spectrum Analyzer Capture.

    This test verifies that:

    1. The reference binary file exists and can be read.
    2. The payload decodes into a CmSpectrumAnalyzerModel instance.
    3. The model can be serialized to a non-empty dictionary.
    4. Core header fields (frequencies, bins, bandwidth) are sane.
    5. Amplitude segments are present and contain float dB values.
    """
    assert SPECTRUM_PATH.is_file()

    raw_payload: bytes = FileProcessor(SPECTRUM_PATH).read_file()
    parser = CmSpectrumAnalysis(raw_payload)
    model: CmSpectrumAnalyzerModel = parser.to_model()

    dumped = model.model_dump()
    assert isinstance(dumped, dict)
    assert dumped

    assert model.channel_id >= 0
    assert isinstance(model.mac_address, str)
    assert model.first_segment_center_frequency > 0
    assert model.last_segment_center_frequency > 0
    assert model.segment_frequency_span > 0
    assert model.num_bins_per_segment > 0
    assert model.equivalent_noise_bandwidth > 0
    assert model.bin_frequency_spacing > 0
    assert model.spectrum_analysis_data_length >= 0

    # Amplitude segments should be present, non-empty, all floats
    assert model.amplitude_bin_segments_float
    for segment in model.amplitude_bin_segments_float:
        assert isinstance(segment, list)
        assert segment
        assert all(isinstance(v, (int, float)) for v in segment)


@pytest.mark.pnm
def test_cm_spectrum_analysis_bin_spacing_and_data_length_consistency() -> None:
    """
    Verify Bin Spacing And Data Length Are Consistent With Amplitude Segments.

    This test checks that:

    - bin_frequency_spacing matches segment_frequency_span / num_bins_per_segment.
    - The total number of decoded bins equals spectrum_analysis_data_length / 2
      (since each amplitude is a signed 16-bit integer in hundredths of a dB).
    """
    assert SPECTRUM_PATH.is_file()

    raw_payload: bytes = FileProcessor(SPECTRUM_PATH).read_file()
    parser = CmSpectrumAnalysis(raw_payload)
    model: CmSpectrumAnalyzerModel = parser.to_model()

    # Bin spacing relationship
    expected_bin_spacing: int = int(
        model.segment_frequency_span / model.num_bins_per_segment
    )
    assert model.bin_frequency_spacing == expected_bin_spacing

    # Total bins vs raw data length
    from pypnm.pnm.parser.CmSpectrumAnalysis import CmSpectrumAnalysis as _CSA

    total_bins_from_segments: int = sum(
        len(seg) for seg in model.amplitude_bin_segments_float
    )
    expected_total_bins: int = (
        model.spectrum_analysis_data_length // _CSA.AMPLITUDE_BIN_SIZE
    )

    # For a well-formed capture these should match
    assert total_bins_from_segments == expected_total_bins


@pytest.mark.pnm
def test_cm_spectrum_analysis_rejects_non_spectrum_pnm_files() -> None:
    """
    Ensure CmSpectrumAnalysis Raises ValueError For Non-Spectrum PNM Streams.

    An upstream OFDMA pre-equalization capture is used as a negative test
    input to confirm that CmSpectrumAnalysis validates the PNM file type
    and rejects mismatched PNM streams.
    """
    assert US_PREEQ_PATH.is_file()

    raw_payload: bytes = FileProcessor(US_PREEQ_PATH).read_file()

    with pytest.raises(ValueError) as excinfo:
        CmSpectrumAnalysis(raw_payload)

    msg: str = str(excinfo.value)
    assert "PNM File Stream is not RxMER file type" in msg
