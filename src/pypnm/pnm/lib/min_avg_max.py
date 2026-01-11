# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from typing import Any

import numpy as np
from pydantic import BaseModel, Field

from pypnm.lib.types import (
    FloatSeries,
    NDArrayF64,
    TwoDFloatSeries,
)
from pypnm.pnm.lib.signal_statistics import SignalStatistics, SignalStatisticsModel

# ---------------------------------------------------------------------
# Type aliases for clarity and consistency
# ---------------------------------------------------------------------
AmplitudeMatrix = (
    TwoDFloatSeries  # List[List[float]] — multiple captures (rows × subcarriers)
)
AmplitudeVector = FloatSeries  # List[float] — one per-subcarrier statistic
PrecisionInt = int  # Rounding precision


# ---------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------
class MinAvgMaxSignalStatisticsModel(BaseModel):
    """Aggregate statistics across per-index minima, averages, and maxima."""

    min: SignalStatisticsModel = Field(
        ..., description="Aggregate stats over per-index minima"
    )
    avg: SignalStatisticsModel = Field(
        ..., description="Aggregate stats over per-index averages"
    )
    max: SignalStatisticsModel = Field(
        ..., description="Aggregate stats over per-index maxima"
    )


class MinAvgMaxModel(BaseModel):
    """
    Pydantic model representing per-index minimum, average, and maximum arrays with metadata.
    """

    min: AmplitudeVector = Field(..., description="Per-index minimum values")
    avg: AmplitudeVector = Field(..., description="Per-index average values")
    max: AmplitudeVector = Field(..., description="Per-index maximum values")
    precision: PrecisionInt = Field(
        ..., ge=0, description="Rounding precision (decimal places)"
    )
    signal_statistics: MinAvgMaxSignalStatisticsModel = Field(
        ..., description="Aggregate stats of min/avg/max arrays"
    )


# ---------------------------------------------------------------------
# Core Computation Class
# ---------------------------------------------------------------------
class MinAvgMax:
    """
    Compute minimum, average, and maximum values across multiple amplitude series,
    rounding each statistic to a specified number of decimal places.

    Each series must have equal length.

    Parameters
    ----------
    amplitude : AmplitudeMatrix
        List of amplitude lists, each representing one capture (must have equal length).
    precision : int, optional
        Number of decimal places for rounding (default = 2).

    Raises
    ------
    ValueError
        If amplitude is empty, has inconsistent lengths, or cannot be cast to float.
    """

    def __init__(self, amplitude: AmplitudeMatrix, precision: PrecisionInt = 2) -> None:
        arr: NDArrayF64 = np.array(amplitude, dtype=float)

        if arr.ndim != 2 or arr.shape[0] == 0 or arr.shape[1] == 0:
            raise ValueError(
                "`amplitude` must be a 2D array (M×N) with consistent subcarrier count"
            )

        self.precision: PrecisionInt = precision

        raw_min: NDArrayF64 = arr.min(axis=0)
        raw_avg: NDArrayF64 = arr.mean(axis=0)
        raw_max: NDArrayF64 = arr.max(axis=0)

        self.min_values: AmplitudeVector = [
            round(float(v), self.precision) for v in raw_min
        ]
        self.avg_values: AmplitudeVector = [
            round(float(v), self.precision) for v in raw_avg
        ]
        self.max_values: AmplitudeVector = [
            round(float(v), self.precision) for v in raw_max
        ]

    # -----------------------------------------------------------------
    # Accessors
    # -----------------------------------------------------------------
    def length(self) -> int:
        """Number of subcarriers in each per-index series."""
        return len(self.avg_values)

    # -----------------------------------------------------------------
    # Conversion Helpers
    # -----------------------------------------------------------------
    def to_model(self) -> MinAvgMaxModel:
        """
        Build a fully-typed `MinAvgMaxModel` including nested SignalStatistics.
        """
        sig_min = SignalStatisticsModel.model_validate(
            SignalStatistics(self.min_values).compute()
        )
        sig_avg = SignalStatisticsModel.model_validate(
            SignalStatistics(self.avg_values).compute()
        )
        sig_max = SignalStatisticsModel.model_validate(
            SignalStatistics(self.max_values).compute()
        )

        return MinAvgMaxModel(
            min=self.min_values,
            avg=self.avg_values,
            max=self.max_values,
            precision=self.precision,
            signal_statistics=MinAvgMaxSignalStatisticsModel(
                min=sig_min, avg=sig_avg, max=sig_max
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Return the same structured result as a plain dictionary.
        """
        return self.to_model().model_dump()
