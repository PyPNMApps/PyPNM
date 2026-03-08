# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray
from scipy.signal import windows as scipy_windows

from pypnm.lib.types import StringEnum


class SignalWindow(StringEnum):
    """Supported window functions for generic signal-processing transforms."""

    OTHER = "other"
    HANN = "hann"
    BLACKMAN_HARRIS = "blackman_harris"
    RECTANGULAR = "rectangular"
    HAMMING = "hamming"
    FLAT_TOP = "flat_top"
    GAUSSIAN = "gaussian"
    CHEBYSHEV = "chebyshev"
    BLACKMAN = "blackman"
    BARTLETT = "bartlett"
    NONE = "none"

    @classmethod
    def coerce(cls, value: SignalWindow | str) -> SignalWindow:
        if isinstance(value, cls):
            return value

        key = value.strip().lower()
        if key in ("hann", "hanning"):
            return cls.HANN
        if key in ("other",):
            return cls.OTHER
        if key in ("blackman_harris", "blackmanharris"):
            return cls.BLACKMAN_HARRIS
        if key in ("none", "rect", "rectangular"):
            return cls.NONE
        if key in ("hamming",):
            return cls.HAMMING
        if key in ("flat_top", "flattop"):
            return cls.FLAT_TOP
        if key in ("gaussian", "gauss"):
            return cls.GAUSSIAN
        if key in ("chebyshev", "cheb"):
            return cls.CHEBYSHEV
        if key in ("blackman",):
            return cls.BLACKMAN
        if key in ("bartlett", "triangular"):
            return cls.BARTLETT
        raise ValueError(f"Unsupported window '{value}'.")


def window_values(
    n: int,
    window: SignalWindow | str,
    *,
    gaussian_std: float = 7.0,
    chebyshev_at: float = 100.0,
) -> NDArray[np.float64]:
    """Build a 1-D window vector for supported signal-processing window types."""
    if n < 1:
        raise ValueError("n must be >= 1")

    win = SignalWindow.coerce(window)
    if win is SignalWindow.HANN:
        return np.hanning(n).astype(np.float64, copy=False)
    if win is SignalWindow.HAMMING:
        return np.hamming(n).astype(np.float64, copy=False)
    if win is SignalWindow.BLACKMAN:
        return np.blackman(n).astype(np.float64, copy=False)
    if win is SignalWindow.BARTLETT:
        return np.bartlett(n).astype(np.float64, copy=False)
    if win in (SignalWindow.NONE, SignalWindow.RECTANGULAR, SignalWindow.OTHER):
        return np.ones(n, dtype=np.float64)
    if win is SignalWindow.BLACKMAN_HARRIS:
        return scipy_windows.blackmanharris(n, sym=True).astype(np.float64, copy=False)
    if win is SignalWindow.FLAT_TOP:
        return scipy_windows.flattop(n, sym=True).astype(np.float64, copy=False)
    if win is SignalWindow.GAUSSIAN:
        return scipy_windows.gaussian(n, std=float(gaussian_std), sym=True).astype(np.float64, copy=False)
    if win is SignalWindow.CHEBYSHEV:
        return scipy_windows.chebwin(n, at=float(chebyshev_at), sym=True).astype(np.float64, copy=False)

    raise ValueError(f"Unsupported window '{window}'.")
