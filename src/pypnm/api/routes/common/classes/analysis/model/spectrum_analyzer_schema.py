# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.analysis.model.schema import BaseAnalysisModel
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import SpecAnCapturePara
from pypnm.lib.types import FrequencySeriesHz, MagnitudeSeries

"""
    Default to a 7-point moving average.
    Rationale: an odd window centers the filter (no bias), and N=7 reduces
    random noise by ≈1/√7 (~0.38×) without over-smoothing narrow (1-2 bin)
    features typical in DOCSIS spectra. Override via `window_average_points`.
"""
DEFAULT_POINT_AVG: int = 7

class WindowAverage(BaseModel):
    """
    Represents the calculated moving average of spectrum analyzer magnitude data.

    Attributes:
        points (int): The number of points used in the moving average window.
        magnitudes (MagnitudeSeries): The resulting magnitude values after applying
                                      the moving average filter, maintaining the same
                                      length as the input signal.
    """
    points: int                 = Field(default=DEFAULT_POINT_AVG, description="Number of points used in the moving average window.")
    magnitudes: MagnitudeSeries = Field(..., description="Magnitude values after applying moving average filtering.")


class SpecAnaAnalysisResults(BaseModel):
    """
    Represents the results of spectrum analyzer analysis.

    Attributes:
        bin_bandwidth (int): The frequency resolution (Hz) of each FFT bin.
        segment_length (int): The number of data points per capture segment.
        frequencies (FrequencySeriesHz): List of frequency points corresponding to each FFT bin.
        magnitudes (MagnitudeSeries): Raw magnitude data (typically in dB) for each frequency bin.
        window_average (WindowAverage): Moving average smoothed magnitude data for enhanced visualization.
    """
    bin_bandwidth: int              = Field(..., description="Frequency resolution of each FFT bin in Hz.")
    segment_length: int             = Field(..., description="Number of data points in each capture segment.")
    frequencies: FrequencySeriesHz  = Field(..., description="Frequency points for each FFT bin, in Hz.")
    magnitudes: MagnitudeSeries     = Field(..., description="Raw magnitude values for each frequency point, in dB.")
    window_average: WindowAverage   = Field(..., description="Smoothed magnitudes computed using a moving average window.")
    channel_power_dbmv: float       = Field(..., description="Total channel power computed from magnitudes, in dBmV.")


class SpectrumAnalyzerAnalysisModel(BaseAnalysisModel):
    """
    Complete spectrum analyzer analysis payload.

    This model combines the capture parameters used to collect spectrum data and
    the computed results from the analysis process.

    Attributes:
        capture_parameters (SpecAnCapturePara): Configuration details for the spectrum capture,
                                                such as start/stop frequencies, dwell time, etc.
        results (SpecAnaAnalysisResults): Computed spectrum analysis output including
                                          raw and smoothed magnitude data.
    """
    capture_parameters: SpecAnCapturePara   = Field(..., description="Configuration used for spectrum capture.")
    signal_analysis: SpecAnaAnalysisResults = Field(..., description="Computed analysis results of the spectrum capture.")
