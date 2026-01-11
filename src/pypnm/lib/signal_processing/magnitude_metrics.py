# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from typing import cast

import numpy as np
from pydantic import BaseModel, Field

from pypnm.lib.signal_processing.db_linear_converter import DbLinearConverter
from pypnm.lib.types import ComplexArray, FloatSeries, FrequencyHz


class MagnitudeSummaryMetrics(BaseModel):
    """
    DOCSIS D.4.3 Magnitude Summary Metrics, computed over:
      - x: subcarrier frequencies in MHz
      - y: channel estimate magnitudes in dB

    Fields:
      slope_db_per_mhz : slope (m) of best-fit line in dB/MHz
      mean_db          : mean(y) in dB (A_mean)
      rms_ripple_db    : RMS of residuals (y - ŷ) in dB (R_rms)
      p2p_ripple_db    : peak-to-peak of residuals in dB (R_pp)
      fitted_line_db   : best-fit ŷ values in dB aligned to x
    """

    slope_db_per_mhz: float = Field(..., description="Slope m in dB/MHz")
    mean_db: float = Field(..., description="Mean amplitude A_mean in dB")
    rms_ripple_db: float = Field(..., description="RMS ripple R_rms in dB")
    p2p_ripple_db: float = Field(..., description="Peak-to-peak ripple R_pp in dB")
    fitted_line_db: FloatSeries = Field(
        ..., description="Best-fit ŷ (dB) for each subcarrier"
    )


def _to_mhz(freq_hz: FrequencyHz) -> FloatSeries:
    arr = np.asarray(freq_hz, dtype=float)
    return (arr / 1e6).tolist()


def compute_magnitude_summary(
    freq_hz: FrequencyHz,
    coeffs_complex: ComplexArray,
) -> MagnitudeSummaryMetrics:
    """
    Compute DOCSIS D.4.3 magnitude summary metrics for channel estimate coefficients.

    Inputs:
      freq_hz         : subcarrier frequencies (Hz), length N
      coeffs_complex  : complex coefficients as [real, imag] pairs, length N

    Process:
      1) Convert frequencies to MHz
      2) Compute magnitudes in dB: y_db = 10*log10(re^2 + im^2)
      3) Fit best-fit line ŷ = a + b * x_mhz (ordinary least squares)
      4) Metrics:
          - slope_db_per_mhz = b
          - mean_db          = mean(y_db)
          - rms_ripple_db    = sqrt(mean( (y_db - ŷ)^2 ))
          - p2p_ripple_db    = max(y_db - ŷ) - min(y_db - ŷ)

    Returns:
      MagnitudeSummaryMetrics
    """
    if len(freq_hz) != len(coeffs_complex):
        raise ValueError(
            f"Length mismatch: freq={len(freq_hz)} vs coeffs={len(coeffs_complex)}"
        )

    # X in MHz
    x_mhz = np.asarray(_to_mhz(freq_hz), dtype=float)
    # Y in dB (power)
    y_db = np.asarray(DbLinearConverter.complex_to_db(coeffs_complex), dtype=float)

    # OLS: y = a + b x
    X = np.column_stack([np.ones_like(x_mhz), x_mhz])
    beta, *_ = np.linalg.lstsq(X, y_db, rcond=None)
    a_hat, b_hat = float(beta[0]), float(beta[1])

    y_hat = a_hat + b_hat * x_mhz
    residuals = y_db - y_hat

    rms = float(np.sqrt(np.mean(residuals**2))) if residuals.size else 0.0
    p2p = float(np.max(residuals) - np.min(residuals)) if residuals.size else 0.0
    mean_db = float(np.mean(y_db)) if y_db.size else 0.0

    return MagnitudeSummaryMetrics(
        slope_db_per_mhz=b_hat,
        mean_db=mean_db,
        rms_ripple_db=rms,
        p2p_ripple_db=p2p,
        fitted_line_db=cast(FloatSeries, y_hat.tolist()),
    )
