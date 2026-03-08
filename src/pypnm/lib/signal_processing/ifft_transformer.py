# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import numpy as np

from pypnm.lib.signal_processing.window import SignalWindow
from pypnm.lib.types import ArrayLikeF64, NDArrayC128, NDArrayF64, TwoDFloatSeries


class FrequencyDomainIfftTransformer:
    """
    Transform real-valued frequency-domain metrics into a time-like domain.

    Processing pipeline:
    1) Accept one array or multiple arrays (snapshots).
    2) Average snapshots when multiple arrays are provided.
    3) Apply a window (Hann by default) to reduce spectral leakage.
    4) Zero-pad to the next power of two (optional).
    5) Run inverse FFT.
    """

    def __init__(self, *, window: SignalWindow | str = SignalWindow.HANN, pad_to_power_of_two: bool = True) -> None:
        self.window = SignalWindow.coerce(window)
        self.pad_to_power_of_two = pad_to_power_of_two

    def transform(self, samples: ArrayLikeF64 | TwoDFloatSeries | NDArrayF64) -> NDArrayC128:
        """
        Convert input metric(s) into a time-like signal via iFFT.

        Parameters
        ----------
        samples : Sequence[float] | Sequence[Sequence[float]] | np.ndarray
            A 1-D real-valued array, or a 2-D collection of same-length arrays.

        Returns
        -------
        np.ndarray
            Complex-valued iFFT result.
        """
        arr = self._as_1d_average(samples)
        window = self._window_values(arr.size)
        windowed = arr * window

        n_fft = arr.size
        if self.pad_to_power_of_two:
            n_fft = self._next_power_of_two(arr.size)

        return np.fft.ifft(windowed, n=n_fft)

    def __call__(self, samples: ArrayLikeF64 | TwoDFloatSeries | NDArrayF64) -> NDArrayC128:
        """Alias for :meth:`transform`."""
        return self.transform(samples)

    def _as_1d_average(self, samples: ArrayLikeF64 | TwoDFloatSeries | NDArrayF64) -> NDArrayF64:
        try:
            arr = np.asarray(samples, dtype=np.float64)
        except ValueError as exc:
            raise ValueError("samples must be a 1-D array or a rectangular 2-D array of equal-length series") from exc

        if arr.ndim == 1:
            out = arr
        elif arr.ndim == 2:
            if arr.shape[0] < 1 or arr.shape[1] < 1:
                raise ValueError("samples must not be empty")
            out = np.mean(arr, axis=0)
        else:
            raise ValueError(f"samples must be 1-D or 2-D; got shape {arr.shape}")

        if out.size < 1:
            raise ValueError("samples must not be empty")
        if not np.isfinite(out).all():
            raise ValueError("samples must contain only finite real values")
        return out

    def _window_values(self, n: int) -> NDArrayF64:
        if self.window is SignalWindow.HANN:
            return np.hanning(n).astype(np.float64, copy=False)
        if self.window in (SignalWindow.NONE, SignalWindow.RECTANGULAR):
            return np.ones(n, dtype=np.float64)
        raise ValueError(f"Unsupported window '{self.window}'. Supported: hann, none")

    @staticmethod
    def _next_power_of_two(n: int) -> int:
        if n < 1:
            raise ValueError("n must be >= 1")
        return 1 << (n - 1).bit_length()
