# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import math
from typing import cast

import numpy as np
import pytest

from pypnm.lib.signal_processing.magnitude_metrics import (
    MagnitudeSummaryMetrics,
    compute_magnitude_summary,
)
from pypnm.lib.types import ComplexArray, FloatSeries, FrequencyHz


def _build_complex_from_db(y_db: FloatSeries) -> ComplexArray:
    """Synthesize [re, im] pairs whose power equals 10^(y_db/10)."""
    pow_lin = (10.0 ** (np.asarray(y_db, dtype=float) / 10.0)).tolist()
    return cast(ComplexArray, [[float(math.sqrt(p)), 0.0] for p in pow_lin])


def test_db_overlay_and_residuals_behave_as_expected() -> None:
    """
    Validates the two new visualizations:
      1) dB overlay (measured vs best-fit): check that fitted line matches OLS on synthetic data.
      2) Residual ripple: check RMS and P2P against residuals of OLS.
    """
    # Synthesize y_db = a + b*x + sinusoidal ripple
    x_mhz = np.linspace(100.0, 130.0, 241)  # 100..130 MHz
    x_hz: FrequencyHz = cast(FrequencyHz, (x_mhz * 1e6).tolist())

    a = -20.0
    b = -0.015  # dB/MHz
    A = 0.4
    k = 4.0

    idx = np.arange(x_mhz.size, dtype=float)
    ripple = A * np.sin(2.0 * math.pi * k * (idx / max(1.0, (idx.size - 1))))
    y_db: FloatSeries = (a + b * x_mhz + ripple).tolist()

    coeffs = _build_complex_from_db(y_db)

    # --- What the report's "overlay" plot shows ---
    m: MagnitudeSummaryMetrics = compute_magnitude_summary(x_hz, coeffs)
    # OLS on the same data (truth for slope & yhat)
    X = np.column_stack([np.ones_like(x_mhz), x_mhz])
    beta, *_ = np.linalg.lstsq(X, np.asarray(y_db, dtype=float), rcond=None)
    a_hat, b_hat = float(beta[0]), float(beta[1])
    yhat = a_hat + b_hat * x_mhz

    # Fitted line should match OLS
    assert m.slope_db_per_mhz == pytest.approx(b_hat, rel=1e-6, abs=1e-8)
    assert m.fitted_line_db == pytest.approx(yhat.tolist(), rel=1e-10)

    # --- What the report's "residual ripple" plot shows ---
    residuals = np.asarray(y_db, dtype=float) - yhat
    rms_expected = float(np.sqrt(np.mean(residuals**2)))
    p2p_expected = float(np.max(residuals) - np.min(residuals))
    assert m.rms_ripple_db == pytest.approx(rms_expected, rel=1e-12, abs=0.0)
    assert m.p2p_ripple_db == pytest.approx(p2p_expected, rel=1e-12, abs=0.0)
