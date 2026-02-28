# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from typing import ClassVar

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from pypnm.lib.signal_processing.db_linear_converter import DbLinearConverter
from pypnm.lib.types import (
    BoolArray,
    ComplexSeries,
    FrequencyHz,
    NDArrayC128,
    NDArrayF64,
    String,
)


class OfdmaPreEqFrequencyResponseAnalysisResult(BaseModel):
    """Container for OFDMA pre-equalization analysis outputs."""

    coefficients: NDArrayC128 = Field(..., description="Input pre-equalization coefficients.")
    active_mask: BoolArray = Field(..., description="Mask of tones considered safe to invert.")
    magnitude_linear: NDArrayF64 = Field(..., description="Applied pre-equalization magnitude in linear scale.")
    magnitude_db: NDArrayF64 = Field(..., description="Applied pre-equalization magnitude in dB.")
    channel_estimate_complex: NDArrayC128 = Field(..., description="Approximate channel estimate from inverse coefficients.")
    channel_estimate_magnitude_linear: NDArrayF64 = Field(..., description="Estimated channel magnitude in linear scale.")
    channel_estimate_magnitude_db: NDArrayF64 = Field(..., description="Estimated channel magnitude in dB.")
    frequency_hz: NDArrayF64 = Field(..., description="Frequency axis in Hertz aligned to subcarrier index.")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        validate_assignment=True,
        extra="forbid",
        arbitrary_types_allowed=True,
    )


class OfdmaPreEqFrequencyResponseAnalyzer:
    """
    Analyze DOCSIS upstream OFDMA pre-equalization coefficients.

    This class assumes the input array already represents per-subcarrier
    complex OFDMA pre-equalization coefficients, where each element is:

        W[k] = I[k] + jQ[k]

    From that input, it computes:

    1. Applied pre-equalization magnitude
    2. Applied pre-equalization magnitude in dB
    3. Approximate complex channel estimate via inverse:
           H_est[k] ≈ 1 / W[k]
    4. Approximate channel magnitude
    5. Approximate channel magnitude in dB
    6. Frequency axis for plotting

    This is useful when you want to compare:

    - What the modem is applying      -> |W[k]|
    - What the channel likely is      -> |1 / W[k]|

    Notes:
    - This is an approximation. Real DOCSIS implementations are constrained by
      coefficient quantization, adaptation filtering, power limits, and inactive
      or punctured tones.
    - Zero or near-zero coefficients are masked to avoid unstable inversion.
    """

    __slots__ = ("_coefficients", "_epsilon")

    def __init__(self, iq: NDArrayC128 | ComplexSeries, epsilon: float = 1e-12) -> None:
        """
        Initialize the analyzer.

        Parameters
        ----------
        iq:
            Complex OFDMA pre-equalization coefficients. Each element must be a
            complex value representing one subcarrier coefficient.
        epsilon:
            Minimum magnitude squared used to determine whether a coefficient is
            safe to invert.
        """
        self._coefficients = self._coerce_complex_array(iq)
        self._epsilon = self._validate_epsilon(epsilon)

    @property
    def coefficients(self) -> NDArrayC128:
        """
        Return a copy of the stored complex coefficients.

        Returns
        -------
        NDArrayC128
            Complex coefficient vector.
        """
        return self._coefficients.copy()

    def active_mask(self) -> BoolArray:
        """
        Return a boolean mask indicating which coefficients are safe to invert.

        A tone is considered active if its magnitude squared is greater than or
        equal to the configured epsilon threshold.

        Returns
        -------
        BoolArray
            Boolean mask with True for active/invertible tones.
        """
        mag_sq = self.magnitude_squared()
        return mag_sq >= self._epsilon

    def magnitude_squared(self) -> NDArrayF64:
        """
        Compute |W[k]|^2 for each coefficient.

        Returns
        -------
        NDArrayF64
            Magnitude squared for each subcarrier coefficient.
        """
        return np.abs(self._coefficients) ** 2

    def magnitude_linear(self) -> NDArrayF64:
        """
        Compute |W[k]| for each coefficient.

        Returns
        -------
        NDArrayF64
            Linear magnitude of the applied pre-equalization coefficients.
        """
        return np.abs(self._coefficients)

    def magnitude_db(self, floor_db: float = -120.0) -> NDArrayF64:
        """
        Compute 20*log10(|W[k]|) for each coefficient.

        Parameters
        ----------
        floor_db:
            Floor applied to tones whose magnitude is effectively zero.

        Returns
        -------
        NDArrayF64
            Magnitude in dB for the applied pre-equalization coefficients.
        """
        magnitude = self.magnitude_linear()
        return np.asarray(DbLinearConverter.magnitude_to_db(magnitude, floor_db=floor_db), dtype=np.float64)

    def channel_estimate_complex(self) -> NDArrayC128:
        """
        Estimate the channel response via complex inversion.

        This computes the approximate inverse relationship:

            H_est[k] ≈ 1 / W[k]

        For numerical stability, tones below the epsilon threshold are returned
        as 0 + j0.

        Returns
        -------
        NDArrayC128
            Approximate complex channel estimate.
        """
        coeffs = self._coefficients
        mag_sq = self.magnitude_squared()
        mask = mag_sq >= self._epsilon

        result = np.zeros_like(coeffs, dtype=np.complex128)
        result[mask] = np.conjugate(coeffs[mask]) / mag_sq[mask]
        return result

    def channel_estimate_magnitude_linear(self) -> NDArrayF64:
        """
        Compute the linear magnitude of the approximate channel estimate.

        This is equivalent to:

            |H_est[k]| ≈ 1 / |W[k]|

        for active tones.

        Returns
        -------
        NDArrayF64
            Linear magnitude of the estimated channel response.
        """
        return np.abs(self.channel_estimate_complex())

    def channel_estimate_magnitude_db(self, floor_db: float = -120.0) -> NDArrayF64:
        """
        Compute 20*log10(|H_est[k]|) for each estimated channel value.

        Parameters
        ----------
        floor_db:
            Floor applied to tones whose estimated channel magnitude is
            effectively zero.

        Returns
        -------
        NDArrayF64
            Magnitude in dB for the estimated channel response.
        """
        magnitude = self.channel_estimate_magnitude_linear()
        return np.asarray(DbLinearConverter.magnitude_to_db(magnitude, floor_db=floor_db), dtype=np.float64)

    def channel_estimate_magnitude_db_fast(self, floor_db: float = -120.0) -> NDArrayF64:
        """
        Compute the estimated channel magnitude in dB using the inverse-magnitude shortcut.

        For active tones:

            20*log10(|H_est[k]|) ≈ -20*log10(|W[k]|)

        This method avoids explicitly forming the complex inverse and is useful
        when only the magnitude plot is needed.

        Parameters
        ----------
        floor_db:
            Floor applied to inactive tones.

        Returns
        -------
        NDArrayF64
            Estimated channel magnitude in dB.
        """
        mask = self.active_mask()
        result = np.full(self._coefficients.shape, floor_db, dtype=np.float64)
        result[mask] = -self.magnitude_db(floor_db=floor_db)[mask]
        return result

    def frequency_axis_hz(self, start_hz: FrequencyHz, spacing_hz: FrequencyHz) -> NDArrayF64:
        """
        Build a frequency axis for the coefficient array.

        Parameters
        ----------
        start_hz:
            Frequency of the first coefficient in Hz.
        spacing_hz:
            Subcarrier spacing in Hz.

        Returns
        -------
        NDArrayF64
            Frequency axis in Hz aligned with the coefficient indices.
        """
        self._validate_frequency_value(start_hz, "start_hz")
        self._validate_frequency_value(spacing_hz, "spacing_hz")

        count = self._coefficients.size
        indices = np.arange(count, dtype=np.float64)
        return start_hz + (indices * spacing_hz)

    def analyze(
        self,
        start_hz: FrequencyHz,
        spacing_hz: FrequencyHz,
        floor_db: float = -120.0,
    ) -> OfdmaPreEqFrequencyResponseAnalysisResult:
        """
        Run the full OFDMA pre-equalization analysis pipeline.

        Parameters
        ----------
        start_hz:
            Frequency of the first coefficient in Hz.
        spacing_hz:
            Subcarrier spacing in Hz.
        floor_db:
            Floor used for dB conversions.

        Returns
        -------
        OfdmaPreEqFrequencyResponseAnalysisResult
            Full analysis output, including applied pre-eq views, approximate
            channel estimate views, active-tone mask, and frequency axis.
        """
        return OfdmaPreEqFrequencyResponseAnalysisResult(
            coefficients=self.coefficients,
            active_mask=self.active_mask(),
            magnitude_linear=self.magnitude_linear(),
            magnitude_db=self.magnitude_db(floor_db=floor_db),
            channel_estimate_complex=self.channel_estimate_complex(),
            channel_estimate_magnitude_linear=self.channel_estimate_magnitude_linear(),
            channel_estimate_magnitude_db=self.channel_estimate_magnitude_db(floor_db=floor_db),
            frequency_hz=self.frequency_axis_hz(start_hz=start_hz, spacing_hz=spacing_hz),
        )

    @staticmethod
    def _coerce_complex_array(iq: NDArrayC128 | ComplexSeries) -> NDArrayC128:
        """
        Convert the input into a one-dimensional complex128 NumPy array.

        Parameters
        ----------
        iq:
            Input coefficient sequence.

        Returns
        -------
        NDArrayC128
            One-dimensional complex128 array.

        Raises
        ------
        ValueError
            If the input is empty or not one-dimensional.
        """
        array = np.asarray(iq, dtype=np.complex128)

        if array.ndim != 1:
            raise ValueError("iq must be a one-dimensional array of complex values")
        if array.size == 0:
            raise ValueError("iq must not be empty")

        return array

    @staticmethod
    def _validate_epsilon(epsilon: float) -> float:
        """
        Validate the inversion threshold.

        Parameters
        ----------
        epsilon:
            Threshold value.

        Returns
        -------
        float
            Validated threshold.

        Raises
        ------
        ValueError
            If epsilon is not positive and finite.
        """
        value = float(epsilon)

        if not np.isfinite(value):
            raise ValueError("epsilon must be finite")
        if value <= 0.0:
            raise ValueError("epsilon must be greater than zero")

        return value

    @staticmethod
    def _validate_frequency_value(value: FrequencyHz, name: String) -> None:
        """
        Validate a frequency-related value.

        Parameters
        ----------
        value:
            Numeric value to validate.
        name:
            Parameter name for error reporting.

        Raises
        ------
        ValueError
            If the value is not finite.
        """
        numeric = float(value)

        if not np.isfinite(numeric):
            raise ValueError(f"{name} must be finite")
