# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from typing import Final

import numpy as np
from pydantic import BaseModel, Field

from pypnm.lib.types import ArrayLike, FloatSeries, NDArrayF64

__all__: Final = ["LinearRegression1D", "LinearRegression1DResult"]


class LinearRegression1DResult(BaseModel):
    """Typed result payload for a 1D linear regression fit."""

    slope: float = Field(..., description="Fitted slope m in y = m*x + b")
    intercept: float = Field(..., description="Fitted intercept b in y = m*x + b")
    r2: float = Field(..., description="Coefficient of determination on training data")
    rmse: float = Field(..., description="Root Mean Squared Error on training data")
    n: int = Field(..., description="Number of samples used after filtering")


class LinearRegression1D:
    """
    Robust 1D linear regression (y = m*x + b) with validation, metrics, and a small API.

    Features
    --------
    - Optional x-values; if omitted, uses 0..N-1.
    - Filters out non-finite (NaN/Inf) pairs before fitting.
    - Clear errors for length mismatch, insufficient points, or near-zero x-variance.
    - Provides slope, intercept, R², RMSE, residuals, fitted values, and predictions.
    - Convenience accessors for the regression line (full series or just endpoints).
    - Exposes a typed result model via `to_model()`; `to_dict()` returns `model_dump()`.
    """

    __slots__ = ("x", "y", "n", "slope", "intercept", "r2", "rmse")

    def __init__(
        self,
        y_values: ArrayLike,
        x_values: ArrayLike | None = None,
        *,
        dtype: type = np.float64,
    ) -> None:
        """
        Initialize and fit a least-squares line to (x, y).

        Parameters
        ----------
        y_values : ArrayLike
            Sequence/array of y-values.
        x_values : ArrayLike | None, optional
            Sequence/array of x-values. If None, uses range(len(y_values)).
        dtype : type, optional
            Numpy dtype for coercion (default: np.float64).

        Raises
        ------
        ValueError
            If shapes mismatch, insufficient finite points, or x-variance is ~0.
        """
        y_arr: NDArrayF64 = np.asarray(y_values, dtype=dtype)
        x_arr: NDArrayF64 = (
            np.arange(y_arr.size, dtype=dtype)
            if x_values is None
            else np.asarray(x_values, dtype=dtype)
        )

        if x_arr.shape != y_arr.shape:
            raise ValueError("x and y must have the same length and shape.")

        mask: NDArrayF64 = np.isfinite(x_arr) & np.isfinite(y_arr)  # type: ignore[assignment]
        x_clean = x_arr[mask]
        y_clean = y_arr[mask]

        if x_clean.size < 2:
            raise ValueError("At least two finite (x, y) points are required.")

        x_var = np.var(x_clean)
        if not np.isfinite(x_var) or x_var <= np.finfo(dtype).eps:
            raise ValueError("x has zero or near-zero variance; cannot fit a line.")

        A: NDArrayF64 = np.vstack([x_clean, np.ones_like(x_clean)]).T
        theta, *_ = np.linalg.lstsq(A, y_clean, rcond=None)
        slope, intercept = float(theta[0]), float(theta[1])

        y_hat = slope * x_clean + intercept
        residuals = y_clean - y_hat
        ss_res = float(np.sum(residuals**2))
        y_mean = float(np.mean(y_clean))
        ss_tot = float(np.sum((y_clean - y_mean) ** 2))
        eps = float(np.finfo(dtype).eps)

        r2 = (1.0 if ss_res <= eps else 0.0) if ss_tot <= eps else 1.0 - ss_res / ss_tot

        rmse = float(np.sqrt(ss_res / x_clean.size))

        self.x = x_clean.astype(np.float64, copy=False)
        self.y = y_clean.astype(np.float64, copy=False)
        self.n = int(x_clean.size)
        self.slope = slope
        self.intercept = intercept
        self.r2 = float(r2)
        self.rmse = float(rmse)

    # --------------------------
    # Public API
    # --------------------------

    def to_model(self) -> LinearRegression1DResult:
        """Return a typed result model."""
        return LinearRegression1DResult(
            slope=self.slope,
            intercept=self.intercept,
            r2=self.r2,
            rmse=self.rmse,
            n=self.n,
        )

    def to_dict(self) -> dict[str, float]:
        """Return a dictionary representation via `to_model().model_dump()`."""
        return self.to_model().model_dump()

    def to_list(self) -> FloatSeries:
        """Return `[slope, intercept, r2]` for compact consumption."""
        return [self.slope, self.intercept, self.r2]

    def predict(self, x_new: ArrayLike) -> NDArrayF64:
        """Predict y for new x values as float64 ndarray."""
        x_arr: NDArrayF64 = np.asarray(x_new, dtype=np.float64)
        return self.slope * x_arr + self.intercept

    def fitted_values(self) -> NDArrayF64:
        """Return fitted y-hat for training x as float64 ndarray."""
        return self.slope * self.x + self.intercept

    def residuals(self) -> NDArrayF64:
        """Return residuals y - y_hat for training data as float64 ndarray."""
        return self.y - self.fitted_values()

    def params(self) -> tuple[float, float]:
        """Return `(slope, intercept)`."""
        return self.slope, self.intercept

    def regression_line(
        self, y_axis_only: bool = True
    ) -> NDArrayF64 | tuple[NDArrayF64, NDArrayF64]:
        """
        Return the fitted regression line.

        Parameters
        ----------
        y_axis_only : bool
            If True, return only ŷ over training x.
            If False, return (x, ŷ) as a tuple.
        """
        y_hat = self.fitted_values()
        return y_hat if y_axis_only else (self.x, y_hat)

    def regression_endpoints(self) -> tuple[tuple[float, float], tuple[float, float]]:
        """
        Return two endpoints of the fitted line at the min and max of training x.

        Returns
        -------
        ((float, float), (float, float))
            (x_min, y_hat_min), (x_max, y_hat_max)
        """
        x0 = float(self.x.min())
        x1 = float(self.x.max())
        return (x0, self.slope * x0 + self.intercept), (
            x1,
            self.slope * x1 + self.intercept,
        )

    def __repr__(self) -> str:
        return (
            f"LinearRegression1D(n={self.n}, slope={self.slope:.6g}, "
            f"intercept={self.intercept:.6g}, r2={self.r2:.6g}, rmse={self.rmse:.6g})"
        )
