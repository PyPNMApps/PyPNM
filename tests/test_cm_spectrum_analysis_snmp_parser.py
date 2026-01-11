# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import math
from collections.abc import Sequence
from pathlib import Path
from struct import pack

import pytest

from pypnm.lib.file_processor import FileProcessor
from pypnm.pnm.parser.CmSpectrumAnalysisSnmp import (
    CmSpectrumAnalysisSnmp,
    CmSpectrumAnalysisSnmpModel,
)

DATA_DIR: Path = Path(__file__).parent / "files"
SPECTRUM_SNMP_PATH: Path = DATA_DIR / "spectrum_analyzer_snmp.bin"


@pytest.mark.pnm
def test_cm_spectrum_analysis_snmp_parses_real_fixture_and_is_consistent() -> None:
    """
    Ensure CmSpectrumAnalysisSnmp Parses The Real SNMP Spectrum Capture Correctly.

    This test verifies that:

    1. The reference SNMP binary file exists and can be read.
    2. The payload decodes into a CmSpectrumAnalysisSnmpModel instance.
    3. total_samples matches the length of frequency and amplitude arrays.
    4. Spectrum configuration (start, end, span) is consistent with frequency.
    5. Amplitude array contains finite numeric values.
    """
    assert SPECTRUM_SNMP_PATH.is_file()

    raw_payload: bytes = FileProcessor(SPECTRUM_SNMP_PATH).read_file()
    parser = CmSpectrumAnalysisSnmp(raw_payload)
    model: CmSpectrumAnalysisSnmpModel = parser.to_model()

    # Basic structural sanity
    assert isinstance(model, CmSpectrumAnalysisSnmpModel)
    assert model.total_samples >= 0

    freq: Sequence[float] = model.frequency
    amp: Sequence[float] = model.amplitude
    total_samples: int = model.total_samples

    assert len(freq) == len(amp) == total_samples

    # Spectrum config vs frequency vector
    cfg = model.spectrum_config
    if total_samples > 0:
        assert math.isclose(cfg.start_frequency, freq[0], rel_tol=0, abs_tol=1.0)
        assert math.isclose(cfg.end_frequency, freq[-1], rel_tol=0, abs_tol=1.0)
        expected_span = cfg.end_frequency - cfg.start_frequency
        assert math.isclose(cfg.frequency_span, expected_span, rel_tol=0, abs_tol=2.0)

    # Amplitudes must be finite
    for value in amp[: min(64, len(amp))]:
        assert math.isfinite(float(value))


@pytest.mark.pnm
def test_cm_spectrum_analysis_snmp_handles_empty_payload_gracefully() -> None:
    """
    Verify That An Empty SNMP Payload Produces A Zeroed Model.

    For an empty payload, the parser should:

    - Set total_samples to 0.
    - Return empty frequency and amplitude vectors.
    - Populate spectrum_config with zeroed values.
    """
    parser = CmSpectrumAnalysisSnmp(b"")
    model: CmSpectrumAnalysisSnmpModel = parser.to_model()

    assert model.total_samples == 0
    assert model.frequency == []
    assert model.amplitude == []
    assert model.amplitude_bytes == b""

    cfg = model.spectrum_config
    assert cfg.start_frequency == 0
    assert cfg.end_frequency == 0
    assert cfg.frequency_span == 0
    assert cfg.total_bins == 0
    assert cfg.bin_spacing == 0
    assert cfg.resolution_bandwidth == 0


@pytest.mark.pnm
def test_cm_spectrum_analysis_snmp_decodes_synthetic_single_group_payload() -> None:
    """
    Validate Header Math And Amplitude Scaling Using A Synthetic Payload.

    A single AmplitudeData group is constructed with known parameters:

        ch_center_freq = CENTER_FREQ_HZ
        freq_span      = FREQ_SPAN_HZ
        num_bins       = NUM_BINS
        bin_spacing    = BIN_SPACING_HZ
        res_bw         = RES_BW_HZ

    and simple signed 16-bit amplitude values. The test verifies:

    - Frequency vector matches the expected start and spacing.
    - total_samples equals num_bins.
    - Amplitude scaling from s16 to dBmV (division by AMPLITUDE_SCALE_DBMV)
      is respected.
    """
    CENTER_FREQ_HZ: int = 100_000_000
    FREQ_SPAN_HZ: int = 4_000_000
    NUM_BINS: int = 4
    BIN_SPACING_HZ: int = 1_000_000
    RES_BW_HZ: int = 100_000

    # Simple signed amplitudes in ADC units
    raw_amps: list[int] = [0, 100, -200, 300]

    header = pack(
        ">5I",
        CENTER_FREQ_HZ,
        FREQ_SPAN_HZ,
        NUM_BINS,
        BIN_SPACING_HZ,
        RES_BW_HZ,
    )
    amp_bytes = pack(f">{NUM_BINS}h", *raw_amps)
    payload = header + amp_bytes

    parser = CmSpectrumAnalysisSnmp(payload)
    model: CmSpectrumAnalysisSnmpModel = parser.to_model()

    assert model.total_samples == NUM_BINS
    assert len(model.frequency) == NUM_BINS
    assert len(model.amplitude) == NUM_BINS

    # Frequency math: start = center - span/2, increment by bin_spacing
    start_freq_expected = float(CENTER_FREQ_HZ - (FREQ_SPAN_HZ // 2))
    expected_freqs = [
        start_freq_expected + i * float(BIN_SPACING_HZ) for i in range(NUM_BINS)
    ]
    for got, exp in zip(model.frequency, expected_freqs, strict=True):
        assert math.isclose(got, exp, rel_tol=0, abs_tol=0.5)

    # Amplitude scaling: value / AMPLITUDE_SCALE_DBMV
    scale = CmSpectrumAnalysisSnmp.AMPLITUDE_SCALE_DBMV
    for got, raw in zip(model.amplitude, raw_amps, strict=True):
        assert math.isclose(got, raw / scale, rel_tol=0, abs_tol=1e-6)

    # Config fields vs header
    cfg = model.spectrum_config
    assert cfg.total_bins == NUM_BINS
    assert cfg.bin_spacing == BIN_SPACING_HZ
    assert cfg.resolution_bandwidth == RES_BW_HZ
