# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import numpy as np

from pypnm.lib.types import FloatSeries

Number = int | float


class MovingAverage:
    r"""
    Sliding-window moving average filter with robust edge handling and
    non-finite-value masking.

    This class preserves the input length and supports two padding/edge behaviors:
    - ``mode="reflect"`` (default): centered window with reflection padding at edges.
      Works well for signals where you want symmetric treatment near boundaries.
    - ``mode="same"``: uses NumPy's ``convolve(..., mode="same")`` semantics,
      which effectively reduces support at the edges (partial overlap).

    Non-finite values (NaN/±Inf) are **excluded** from the average by keeping a
    parallel validity mask and normalizing by the count of finite samples under
    the window. If an entire window is non-finite, the output at that index is 0.0.

    Parameters
    ----------
    n_points : int
        Window size (number of points used in the average). Must be >= 1.
        Both odd and even sizes are supported. For even sizes, the window is centered
        using ``left = n_points // 2`` and ``right = n_points - 1 - left``.
    mode : {"reflect", "same"}, default "reflect"
        Edge handling. See description above.
    dtype : optional, default float
        Numpy dtype to use internally (e.g., ``np.float64``). Defaults to Python float.

    Notes
    -----
    - Output length equals input length.
    - With ``mode="reflect"``, edges are padded via reflection **before** convolution
      and then a 'valid' convolution is computed to return a same-length result.
    - With ``mode="same"``, the kernel is applied directly to the input using
      NumPy's 'same' mode; in this case, non-finite masking is still applied via
      a parallel convolution of the validity mask.

    Examples
    --------
    >>> ma = MovingAverage(7, mode="reflect")
    >>> ma.apply([1.0, 2.0, float("nan"), 4.0])
    [~smoothed values, length 4~]
    """

    def __init__(
        self, n_points: int, mode: str = "reflect", dtype: np.dtype | None = None
    ) -> None:
        if n_points < 1:
            raise ValueError("n_points must be >= 1")
        if mode not in ("reflect", "same"):
            raise ValueError('mode must be one of {"reflect", "same"}')

        self.n_points: int = int(n_points)
        self.mode: str = mode
        self.dtype: np.dtype = np.dtype(float if dtype is None else dtype)
        self._kernel: np.ndarray = (
            np.ones(self.n_points, dtype=self.dtype) / self.n_points
        )

        # Precompute asymmetric left/right extents for even windows
        self._k_left: int = self.n_points // 2
        self._k_right: int = self.n_points - 1 - self._k_left

    @property
    def kernel(self) -> np.ndarray:
        """Return a copy of the averaging kernel."""
        return self._kernel.copy()

    def apply(self, values: FloatSeries) -> FloatSeries:
        """
        Apply the moving average to a list/sequence of floats.

        Parameters
        ----------
        values : FloatSeries
            Input sequence of floats.

        Returns
        -------
        FloatSeries
            Smoothed sequence, same length as input.

        Notes
        -----
        - Non-finite inputs (NaN/±Inf) are excluded from the average.
        - If a window contains no finite samples, the output at that index is 0.0.
        """
        # Handle empty quickly
        if not values:
            return []

        arr = np.asarray(values, dtype=self.dtype)
        finite_mask = np.isfinite(arr).astype(self.dtype)
        vals = np.where(np.isfinite(arr), arr, 0.0).astype(self.dtype)

        if self.mode == "reflect":
            # Reflect-pad values and mask, then 'valid' convolution to return same length
            pad_width = (self._k_left, self._k_right)
            vals_pad = np.pad(vals, pad_width=pad_width, mode="reflect")
            msk_pad = np.pad(finite_mask, pad_width=pad_width, mode="reflect")

            num = np.convolve(vals_pad, self._kernel, mode="valid")
            den = np.convolve(msk_pad, self._kernel, mode="valid")

        else:  # "same"
            num = np.convolve(vals, self._kernel, mode="same")
            den = np.convolve(finite_mask, self._kernel, mode="same")

        # Avoid division by zero; where den==0, output 0.0
        out = np.divide(num, den, out=np.zeros_like(num), where=den > 0)
        return out.tolist()

    def __call__(self, values: FloatSeries) -> FloatSeries:
        """Alias for :meth:`apply`."""
        return self.apply(values)

    def __repr__(self) -> str:  # minimal, informative
        return f"{self.__class__.__name__}(n_points={self.n_points}, mode='{self.mode}', dtype={self.dtype})"
