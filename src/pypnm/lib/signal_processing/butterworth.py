# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from typing import ClassVar, cast

import numpy as np
from pydantic import BaseModel, ConfigDict, Field
from scipy.signal import butter, filtfilt

from pypnm.lib.types import FrequencyHz, NDArrayC128, NDArrayF64

DEFAULT_BUTTERWORTH_ORDER: int = 4
NYQUIST_DENOMINATOR: float = 2.0
MIN_NORMALIZED_CUTOFF: float = 0.0
MAX_NORMALIZED_CUTOFF: float = 1.0


class PreEqButterworthConfig(BaseModel):
    sample_rate_hz: FrequencyHz = Field(
        ...,
        description="Effective sample rate in Hertz along the complex coefficient index (e.g. OFDM subcarrier spacing).",
    )
    cutoff_hz: FrequencyHz = Field(
        ...,
        description="Low-pass Butterworth cutoff frequency in Hertz applied across coefficient index.",
    )
    order: int = Field(
        DEFAULT_BUTTERWORTH_ORDER,
        description="Butterworth filter order controlling roll-off steepness.",
    )
    zero_phase: bool = Field(
        True,
        description="Apply zero-phase filtering (filtfilt) when True; causal filtering when False.",
    )

    model_config: ClassVar[ConfigDict] = ConfigDict(
        validate_assignment=True,
        extra="forbid",
        arbitrary_types_allowed=True,
    )


class PreEqButterworthResult(BaseModel):
    sample_rate_hz: FrequencyHz = Field(
        ...,
        description="Effective sample rate in Hertz along the complex coefficient index.",
    )
    cutoff_hz: FrequencyHz = Field(
        ...,
        description="Low-pass Butterworth cutoff frequency in Hertz used during filtering.",
    )
    order: int = Field(
        ..., description="Butterworth filter order used during processing."
    )
    zero_phase: bool = Field(
        ...,
        description="Indicates whether zero-phase (filtfilt) filtering was applied.",
    )
    original_coefficients: NDArrayC128 = Field(
        ...,
        description="Original complex coefficients (e.g. pre-equalization taps or channel-estimation values).",
    )
    filtered_coefficients: NDArrayC128 = Field(
        ...,
        description="Filtered complex coefficients after Butterworth low-pass smoothing.",
    )

    model_config: ClassVar[ConfigDict] = ConfigDict(
        validate_assignment=True,
        extra="forbid",
        arbitrary_types_allowed=True,
    )


class MagnitudeButterworthResult(BaseModel):
    sample_rate_hz: FrequencyHz = Field(
        ...,
        description="Effective sample rate in Hertz along the scalar series index (e.g. OFDM subcarrier spacing).",
    )
    cutoff_hz: FrequencyHz = Field(
        ...,
        description="Low-pass Butterworth cutoff frequency in Hertz used during filtering.",
    )
    order: int = Field(
        ..., description="Butterworth filter order used during processing."
    )
    zero_phase: bool = Field(
        ...,
        description="Indicates whether zero-phase (filtfilt) filtering was applied.",
    )
    original_values: NDArrayF64 = Field(
        ...,
        description="Original real-valued samples (e.g. RxMER per subcarrier, magnitude, or SNR series).",
    )
    filtered_values: NDArrayF64 = Field(
        ...,
        description="Filtered real-valued samples after Butterworth low-pass smoothing.",
    )

    model_config: ClassVar[ConfigDict] = ConfigDict(
        validate_assignment=True,
        extra="forbid",
        arbitrary_types_allowed=True,
    )


class PreEqButterworthFilter:
    """
    Apply a Complex-Domain Butterworth Low-Pass Filter to OFDM Coefficients.

    This class encapsulates the setup and execution of a Butterworth low-pass filter that operates
    directly on complex-valued coefficient vectors. It is intended for both:

    - Pre-Equalization coefficients (Tx-side pre-distortion taps across subcarriers).
    - Channel Estimation coefficients H[k] (Rx-side channel frequency response samples).

    The filter is configured using a `PreEqButterworthConfig` model, which defines the effective
    sample rate along the coefficient index, cutoff frequency, filter order, and whether
    zero-phase filtering is applied.

    Interpretation of `sample_rate_hz`
    ----------------------------------
    The `sample_rate_hz` field represents the spacing in Hertz between adjacent complex samples
    along the coefficient index:

    - For Channel Estimation: use the OFDM subcarrier spacing in Hertz.
    - For Pre-Equalization: also typically the OFDM subcarrier spacing in Hertz.

    With this interpretation, the cutoff frequency `cutoff_hz` is specified in the same units and
    controls how aggressively high-frequency variation across subcarriers is suppressed.

    Typical Usage
    -------------
    1) Channel Estimation (H[k]):
       - Determine OFDM subcarrier spacing Δf (e.g., 50 kHz).
       - Choose `cutoff_hz` below Nyquist to smooth noise without flattening genuine structure.
       - Construct the filter using `from_subcarrier_spacing()`.

    2) Pre-Equalization Coefficients:
       - Use the same Δf interpretation as channel estimation.
       - Decide a cutoff that preserves plant-induced structure while removing high-frequency noise.

    3) Call `apply()` with a 1D NDArrayC128 of coefficients. The result is a
       `PreEqButterworthResult` containing original and filtered coefficients plus configuration
       metadata.
    """

    def __init__(self, config: PreEqButterworthConfig) -> None:
        """
        Initialize the PreEqButterworthFilter with a validated configuration.

        Parameters
        ----------
        config : PreEqButterworthConfig
            Configuration object defining effective sample rate along the coefficient index,
            cutoff frequency, filter order, and zero-phase behavior for the Butterworth low-pass
            filter.

        Raises
        ------
        ValueError
            Raised when the derived normalized cutoff frequency is outside the open interval
            (0.0, 1.0), which would indicate an inconsistent relationship between `sample_rate_hz`
            and `cutoff_hz`.
        """
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.config = config
        self._normalized_cutoff = self._compute_normalized_cutoff()

    @classmethod
    def from_subcarrier_spacing(
        cls,
        subcarrier_spacing_hz: FrequencyHz,
        cutoff_hz: FrequencyHz,
        order: int = DEFAULT_BUTTERWORTH_ORDER,
        zero_phase: bool = True,
    ) -> PreEqButterworthFilter:
        """
        Construct a Butterworth filter using OFDM subcarrier spacing as the sample rate.

        This helper is intended for both Channel Estimation and Pre-Equalization pipelines,
        where coefficients are indexed by subcarrier and uniformly spaced in frequency.

        Parameters
        ----------
        subcarrier_spacing_hz : FrequencyHz
            OFDM subcarrier spacing in Hertz. This value is used as `sample_rate_hz`
            for the internal configuration.
        cutoff_hz : FrequencyHz
            Low-pass cutoff frequency in Hertz along the subcarrier index dimension.
        order : int, optional
            Butterworth filter order; larger values increase roll-off steepness but
            raise computational cost. Defaults to `DEFAULT_BUTTERWORTH_ORDER`.
        zero_phase : bool, optional
            When True, apply zero-phase filtering using `filtfilt`; when False,
            use a causal IIR filtering path. Defaults to True.

        Returns
        -------
        PreEqButterworthFilter
            An initialized Butterworth filter instance ready to process complex
            coefficient vectors indexed by subcarrier.
        """
        config = PreEqButterworthConfig(
            sample_rate_hz=subcarrier_spacing_hz,
            cutoff_hz=cutoff_hz,
            order=order,
            zero_phase=zero_phase,
        )
        return cls(config=config)

    def apply(self, coefficients: NDArrayC128) -> PreEqButterworthResult:
        """
        Apply the configured Butterworth low-pass filter to complex coefficients.

        Parameters
        ----------
        coefficients : NDArrayC128
            One-dimensional complex-valued array containing coefficients across subcarriers.
            This may represent:
            - Pre-Equalization taps (Tx-side).
            - Channel Estimation coefficients H[k] (Rx-side).

        Returns
        -------
        PreEqButterworthResult
            Structured result containing the original and filtered complex coefficients
            along with the configuration parameters used for filtering.

        Raises
        ------
        ValueError
            Raised when the input coefficient array is empty or not one-dimensional.
        """
        coeffs_array = np.asarray(coefficients, dtype=np.complex128)
        if coeffs_array.size == 0:
            raise ValueError(
                "PreEqButterworthFilter.apply() received an empty coefficient array."
            )

        if coeffs_array.ndim != 1:
            raise ValueError(
                "PreEqButterworthFilter.apply() expects a one-dimensional ComplexArray."
            )

        b, a = cast(
            tuple[np.ndarray, np.ndarray],
            butter(
                self.config.order,
                self._normalized_cutoff,
                btype="low",
                analog=False,
            ),
        )

        if self.config.zero_phase:
            filtered = filtfilt(b, a, coeffs_array)
        else:
            from scipy.signal import lfilter

            filtered = lfilter(b, a, coeffs_array)

        return PreEqButterworthResult(
            sample_rate_hz=self.config.sample_rate_hz,
            cutoff_hz=self.config.cutoff_hz,
            order=self.config.order,
            zero_phase=self.config.zero_phase,
            original_coefficients=coeffs_array,
            filtered_coefficients=np.asarray(filtered, dtype=np.complex128),
        )

    def _compute_normalized_cutoff(self) -> float:
        """Compute normalized cutoff frequency relative to the Nyquist frequency."""
        sample_rate = float(self.config.sample_rate_hz)
        cutoff = float(self.config.cutoff_hz)

        nyquist = sample_rate / NYQUIST_DENOMINATOR
        if nyquist <= 0.0:
            raise ValueError(
                "Sample rate must be positive to compute a valid Nyquist frequency."
            )

        normalized = cutoff / nyquist

        if not (MIN_NORMALIZED_CUTOFF < normalized < MAX_NORMALIZED_CUTOFF):
            raise ValueError(
                f"Normalized cutoff {normalized:.6f} is outside the valid range "
                f"({MIN_NORMALIZED_CUTOFF}, {MAX_NORMALIZED_CUTOFF}) for a digital Butterworth filter."
            )

        return normalized


class MagnitudeButterworthFilter:
    """
    Apply a Real-Valued Butterworth Low-Pass Filter to Scalar Series (e.g. RxMER).

    This class mirrors `PreEqButterworthFilter` but operates on real-valued sequences such as:

    - RxMER per subcarrier (MERdB vs. subcarrier index).
    - Magnitude of channel estimates |H[k]|.
    - Any other 1D scalar diagnostic series sampled uniformly in frequency.

    The same `PreEqButterworthConfig` model is reused, interpreting `sample_rate_hz` as the
    spacing in Hertz between adjacent scalar samples along the index.
    """

    def __init__(self, config: PreEqButterworthConfig) -> None:
        """
        Initialize the MagnitudeButterworthFilter with a validated configuration.

        Parameters
        ----------
        config : PreEqButterworthConfig
            Configuration object defining effective sample rate along the series index,
            cutoff frequency, filter order, and zero-phase behavior for the Butterworth low-pass
            filter.

        Raises
        ------
        ValueError
            Raised when the derived normalized cutoff frequency is outside the open interval
            (0.0, 1.0), indicating an inconsistent relationship between `sample_rate_hz`
            and `cutoff_hz`.
        """
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.config = config
        self._normalized_cutoff = self._compute_normalized_cutoff()

    @classmethod
    def from_subcarrier_spacing(
        cls,
        subcarrier_spacing_hz: FrequencyHz,
        cutoff_hz: FrequencyHz,
        order: int = DEFAULT_BUTTERWORTH_ORDER,
        zero_phase: bool = True,
    ) -> MagnitudeButterworthFilter:
        """
        Construct a Butterworth filter using OFDM subcarrier spacing as the sample rate.

        This helper is intended for scalar series indexed by subcarrier, such as RxMER per tone
        or magnitude of H[k], where samples are uniformly spaced in frequency.

        Parameters
        ----------
        subcarrier_spacing_hz : FrequencyHz
            OFDM subcarrier spacing in Hertz. This value is used as `sample_rate_hz`
            for the internal configuration.
        cutoff_hz : FrequencyHz
            Low-pass cutoff frequency in Hertz along the subcarrier index dimension.
        order : int, optional
            Butterworth filter order; larger values increase roll-off steepness but
            raise computational cost. Defaults to `DEFAULT_BUTTERWORTH_ORDER`.
        zero_phase : bool, optional
            When True, apply zero-phase filtering using `filtfilt`; when False,
            use a causal IIR filtering path. Defaults to True.

        Returns
        -------
        MagnitudeButterworthFilter
            An initialized Butterworth filter instance ready to process scalar series
            indexed by subcarrier.
        """
        config = PreEqButterworthConfig(
            sample_rate_hz=subcarrier_spacing_hz,
            cutoff_hz=cutoff_hz,
            order=order,
            zero_phase=zero_phase,
        )
        return cls(config=config)

    def apply(self, values: NDArrayF64) -> MagnitudeButterworthResult:
        """
        Apply the configured Butterworth low-pass filter to a real-valued series.

        Parameters
        ----------
        values : NDArrayF64
            One-dimensional real-valued array containing samples across subcarriers or
            frequency bins. This may represent RxMER (in dB), magnitude of H[k], or
            any scalar diagnostic series sampled uniformly in frequency.

        Returns
        -------
        MagnitudeButterworthResult
            Structured result containing the original and filtered scalar series
            along with the configuration parameters used for filtering.

        Raises
        ------
        ValueError
            Raised when the input array is empty or not one-dimensional.
        """
        values_array = np.asarray(values, dtype=np.float64)
        if values_array.size == 0:
            raise ValueError(
                "MagnitudeButterworthFilter.apply() received an empty value array."
            )

        if values_array.ndim != 1:
            raise ValueError(
                "MagnitudeButterworthFilter.apply() expects a one-dimensional NDArrayF64."
            )

        b, a = cast(
            tuple[np.ndarray, np.ndarray],
            butter(
                self.config.order,
                self._normalized_cutoff,
                btype="low",
                analog=False,
            ),
        )

        if self.config.zero_phase:
            filtered = filtfilt(b, a, values_array)
        else:
            from scipy.signal import lfilter

            filtered = lfilter(b, a, values_array)

        return MagnitudeButterworthResult(
            sample_rate_hz=self.config.sample_rate_hz,
            cutoff_hz=self.config.cutoff_hz,
            order=self.config.order,
            zero_phase=self.config.zero_phase,
            original_values=values_array,
            filtered_values=np.asarray(filtered, dtype=np.float64),
        )

    def _compute_normalized_cutoff(self) -> float:
        """Compute normalized cutoff frequency relative to the Nyquist frequency."""
        sample_rate = float(self.config.sample_rate_hz)
        cutoff = float(self.config.cutoff_hz)

        nyquist = sample_rate / NYQUIST_DENOMINATOR
        if nyquist <= 0.0:
            raise ValueError(
                "Sample rate must be positive to compute a valid Nyquist frequency."
            )

        normalized = cutoff / nyquist

        if not (MIN_NORMALIZED_CUTOFF < normalized < MAX_NORMALIZED_CUTOFF):
            raise ValueError(
                f"Normalized cutoff {normalized:.6f} is outside the valid range "
                f"({MIN_NORMALIZED_CUTOFF}, {MAX_NORMALIZED_CUTOFF}) for a digital Butterworth filter."
            )

        return normalized
