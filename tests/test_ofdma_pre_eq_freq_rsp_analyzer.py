# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import numpy as np
import pytest
from pydantic import ValidationError

from pypnm.lib.signal_processing.ofdma_pre_eq_freq_rsp_analyzer import (
    OfdmaPreEqFrequencyResponseAnalysisResult,
    OfdmaPreEqFrequencyResponseAnalyzer,
)
from pypnm.lib.types import FrequencyHz


def _sample_iq() -> np.ndarray:
    return np.array(
        [
            1.00 + 0.00j,
            0.80 + 0.05j,
            0.55 + 0.00j,
            0.30 - 0.02j,
            0.55 + 0.01j,
            0.80 + 0.03j,
            1.00 + 0.00j,
        ],
        dtype=np.complex128,
    )


def test_constructor_accepts_ndarray_and_list() -> None:
    arr = _sample_iq()
    analyzer_a = OfdmaPreEqFrequencyResponseAnalyzer(iq=arr)
    analyzer_b = OfdmaPreEqFrequencyResponseAnalyzer(iq=list(arr))

    assert analyzer_a.coefficients.dtype == np.complex128
    assert analyzer_b.coefficients.dtype == np.complex128
    assert np.allclose(analyzer_a.coefficients, analyzer_b.coefficients)


def test_coefficients_property_returns_copy() -> None:
    analyzer = OfdmaPreEqFrequencyResponseAnalyzer(iq=_sample_iq())

    copied = analyzer.coefficients
    copied[0] = 999.0 + 999.0j

    assert analyzer.coefficients[0] != copied[0]


def test_constructor_validation_errors() -> None:
    with pytest.raises(ValueError, match="one-dimensional"):
        OfdmaPreEqFrequencyResponseAnalyzer(iq=np.zeros((2, 2), dtype=np.complex128))

    with pytest.raises(ValueError, match="must not be empty"):
        OfdmaPreEqFrequencyResponseAnalyzer(iq=np.array([], dtype=np.complex128))

    with pytest.raises(ValueError, match="greater than zero"):
        OfdmaPreEqFrequencyResponseAnalyzer(iq=_sample_iq(), epsilon=0.0)

    with pytest.raises(ValueError, match="must be finite"):
        OfdmaPreEqFrequencyResponseAnalyzer(iq=_sample_iq(), epsilon=float("inf"))


def test_active_mask_and_safe_inverse() -> None:
    iq = np.array([1.0 + 0j, 1e-9 + 0j, 0.5 + 0j], dtype=np.complex128)
    analyzer = OfdmaPreEqFrequencyResponseAnalyzer(iq=iq, epsilon=1e-12)

    mask = analyzer.active_mask()
    assert mask.tolist() == [True, False, True]

    ch = analyzer.channel_estimate_complex()
    assert ch[0] == pytest.approx(1.0 + 0.0j)
    assert ch[1] == 0.0 + 0.0j
    assert ch[2] == pytest.approx(2.0 + 0.0j)


def test_magnitude_db_matches_channel_inverse_db_fast_path() -> None:
    analyzer = OfdmaPreEqFrequencyResponseAnalyzer(iq=_sample_iq())

    full = analyzer.channel_estimate_magnitude_db(floor_db=-120.0)
    fast = analyzer.channel_estimate_magnitude_db_fast(floor_db=-120.0)

    assert np.allclose(full, fast, atol=1e-12)


def test_frequency_axis_generation_and_validation() -> None:
    analyzer = OfdmaPreEqFrequencyResponseAnalyzer(iq=_sample_iq())

    start_hz: FrequencyHz = FrequencyHz(5_000_000)
    spacing_hz: FrequencyHz = FrequencyHz(25_000)

    axis = analyzer.frequency_axis_hz(start_hz=start_hz, spacing_hz=spacing_hz)
    assert axis.tolist() == pytest.approx(
        [5_000_000.0, 5_025_000.0, 5_050_000.0, 5_075_000.0, 5_100_000.0, 5_125_000.0, 5_150_000.0]
    )

    with pytest.raises(ValueError, match="start_hz must be finite"):
        analyzer.frequency_axis_hz(start_hz=FrequencyHz(float("inf")), spacing_hz=spacing_hz)  # type: ignore[arg-type]


def test_analyze_returns_expected_model_and_shapes() -> None:
    analyzer = OfdmaPreEqFrequencyResponseAnalyzer(iq=_sample_iq())
    result = analyzer.analyze(
        start_hz=FrequencyHz(5_000_000),
        spacing_hz=FrequencyHz(25_000),
        floor_db=-120.0,
    )

    assert isinstance(result, OfdmaPreEqFrequencyResponseAnalysisResult)
    assert result.coefficients.shape == (7,)
    assert result.active_mask.shape == (7,)
    assert result.magnitude_linear.shape == (7,)
    assert result.magnitude_db.shape == (7,)
    assert result.channel_estimate_complex.shape == (7,)
    assert result.channel_estimate_magnitude_linear.shape == (7,)
    assert result.channel_estimate_magnitude_db.shape == (7,)
    assert result.frequency_hz.shape == (7,)


def test_result_model_forbids_extra_fields() -> None:
    coeffs = _sample_iq()
    mask = np.ones(coeffs.shape, dtype=np.bool_)
    mags = np.abs(coeffs).astype(np.float64)
    freq = np.arange(coeffs.size, dtype=np.float64)

    with pytest.raises(ValidationError):
        OfdmaPreEqFrequencyResponseAnalysisResult.model_validate(
            {
                "coefficients": coeffs,
                "active_mask": mask,
                "magnitude_linear": mags,
                "magnitude_db": mags,
                "channel_estimate_complex": coeffs,
                "channel_estimate_magnitude_linear": mags,
                "channel_estimate_magnitude_db": mags,
                "frequency_hz": freq,
                "extra_field": 1,
            }
        )
