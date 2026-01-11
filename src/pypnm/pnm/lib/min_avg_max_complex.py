# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from typing import Any

import numpy as np
from pydantic import BaseModel, Field

from pypnm.lib.types import ComplexMatrix, FloatSeries, NDArrayF64
from pypnm.pnm.lib.signal_statistics import SignalStatistics, SignalStatisticsModel

# ──────────────────────────────────────────────────────────────────────────────
# Type aliases
# ──────────────────────────────────────────────────────────────────────────────
PrecisionInt = int  # Decimal places for rounding


# ──────────────────────────────────────────────────────────────────────────────
# Pydantic Models
# ──────────────────────────────────────────────────────────────────────────────
class MinAvgMaxComplexVector(BaseModel):
    """Per-index statistics for real or imaginary components."""

    min: FloatSeries = Field(..., description="Minimum per-index values")
    avg: FloatSeries = Field(..., description="Average per-index values")
    max: FloatSeries = Field(..., description="Maximum per-index values")


class MinAvgMaxComplexSignalStats(BaseModel):
    """Signal statistics for min/avg/max across real and imaginary parts."""

    min: SignalStatisticsModel = Field(..., description="Aggregate stats of min values")
    avg: SignalStatisticsModel = Field(..., description="Aggregate stats of avg values")
    max: SignalStatisticsModel = Field(..., description="Aggregate stats of max values")


class MinAvgMaxComplexModel(BaseModel):
    """Full complex statistics split into real and imaginary components."""

    real: MinAvgMaxComplexVector = Field(..., description="Real part statistics")
    imag: MinAvgMaxComplexVector = Field(..., description="Imaginary part statistics")
    precision: PrecisionInt = Field(
        ..., ge=0, description="Rounding precision (decimal places)"
    )
    signal_statistics_real: MinAvgMaxComplexSignalStats = Field(
        ..., description="Aggregate stats for real part"
    )
    signal_statistics_imag: MinAvgMaxComplexSignalStats = Field(
        ..., description="Aggregate stats for imaginary part"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Core Computation Class
# ──────────────────────────────────────────────────────────────────────────────
class MinAvgMaxComplex:
    """
    Compute min/avg/max values for real and imaginary components separately
    across multiple complex-valued per-subcarrier vectors.

    Each input vector must have equal length.

    Accepted input layouts
    ----------------------
    - 1D complex vector: (K,)
    - 2D complex matrix: (M, K)
    - 2D real/imag pairs: (K, 2)      → single snapshot, (re, im)
    - 3D real/imag pairs: (M, K, 2)   → M snapshots, (re, im)

    Parameters
    ----------
    complex_values : ComplexMatrix
        Complex-valued data in one of the supported layouts.
    precision : int, optional
        Rounding precision for outputs (default = 4).

    Raises
    ------
    ValueError
        If input is empty or cannot be interpreted as a non-empty (MxN) complex matrix.
    """

    def __init__(
        self, complex_values: ComplexMatrix, precision: PrecisionInt = 4
    ) -> None:
        arr = np.array(complex_values)

        if arr.size == 0:
            raise ValueError("Input must contain at least one complex sample.")

        # Normalize to a 2D complex matrix of shape (M, N).
        if arr.ndim == 1:
            arr_complex = np.asarray(arr, dtype=np.complex128).reshape(1, -1)

        elif arr.ndim == 2:
            if arr.shape[1] == 2 and not np.iscomplexobj(arr):
                re = arr[:, 0].astype(np.float64)
                im = arr[:, 1].astype(np.float64)
                arr_complex = (re + 1j * im).reshape(1, -1)
            else:
                arr_complex = np.asarray(arr, dtype=np.complex128)

        elif arr.ndim == 3 and arr.shape[2] == 2 and not np.iscomplexobj(arr):
            re = arr[..., 0].astype(np.float64)
            im = arr[..., 1].astype(np.float64)
            arr_complex = re + 1j * im

        else:
            raise ValueError(
                "Input must be complex (K,), (M×K), (K×2) or (M×K×2) real/imag array."
            )

        if (
            arr_complex.ndim != 2
            or arr_complex.shape[0] == 0
            or arr_complex.shape[1] == 0
        ):
            raise ValueError(
                "Input must resolve to a non-empty complex matrix of shape (M×N)."
            )

        self.precision: PrecisionInt = precision
        self.real: NDArrayF64 = np.real(arr_complex)
        self.imag: NDArrayF64 = np.imag(arr_complex)

        self.min_real: FloatSeries = [
            round(float(v), precision) for v in self.real.min(axis=0)
        ]
        self.avg_real: FloatSeries = [
            round(float(v), precision) for v in self.real.mean(axis=0)
        ]
        self.max_real: FloatSeries = [
            round(float(v), precision) for v in self.real.max(axis=0)
        ]

        self.min_imag: FloatSeries = [
            round(float(v), precision) for v in self.imag.min(axis=0)
        ]
        self.avg_imag: FloatSeries = [
            round(float(v), precision) for v in self.imag.mean(axis=0)
        ]
        self.max_imag: FloatSeries = [
            round(float(v), precision) for v in self.imag.max(axis=0)
        ]

        # Magnitude-based stats (for MinAvgMaxModel)
        mag: NDArrayF64 = np.abs(arr_complex)
        avg_complex = arr_complex.mean(axis=0)

        # Min/max over |H_m[k]|, avg as |mean_m H_m[k]| (coherent average then magnitude)
        self.min_mag: FloatSeries = [
            round(float(v), precision) for v in mag.min(axis=0)
        ]
        self.max_mag: FloatSeries = [
            round(float(v), precision) for v in mag.max(axis=0)
        ]
        self.avg_mag: FloatSeries = [
            round(float(v), precision) for v in np.abs(avg_complex)
        ]

    def length(self) -> int:
        """Number of subcarriers in each vector."""
        return len(self.avg_real)

    def to_model(self) -> MinAvgMaxComplexModel:
        """Convert result to a full Pydantic model."""
        stat_real_min = SignalStatistics(self.min_real).compute()
        stat_real_avg = SignalStatistics(self.avg_real).compute()
        stat_real_max = SignalStatistics(self.max_real).compute()

        stat_imag_min = SignalStatistics(self.min_imag).compute()
        stat_imag_avg = SignalStatistics(self.avg_imag).compute()
        stat_imag_max = SignalStatistics(self.max_imag).compute()

        return MinAvgMaxComplexModel(
            real=MinAvgMaxComplexVector(
                min=self.min_real, avg=self.avg_real, max=self.max_real
            ),
            imag=MinAvgMaxComplexVector(
                min=self.min_imag, avg=self.avg_imag, max=self.max_imag
            ),
            precision=self.precision,
            signal_statistics_real=MinAvgMaxComplexSignalStats(
                min=SignalStatisticsModel.model_validate(stat_real_min),
                avg=SignalStatisticsModel.model_validate(stat_real_avg),
                max=SignalStatisticsModel.model_validate(stat_real_max),
            ),
            signal_statistics_imag=MinAvgMaxComplexSignalStats(
                min=SignalStatisticsModel.model_validate(stat_imag_min),
                avg=SignalStatisticsModel.model_validate(stat_imag_avg),
                max=SignalStatisticsModel.model_validate(stat_imag_max),
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the result as a dictionary (nested keys)."""
        return self.to_model().model_dump()
