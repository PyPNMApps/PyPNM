# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import math

import numpy as np
import pytest

from pypnm.lib.signal_processing.averager import MovingAverage


def test_reflect_mode_preserves_length_and_edges() -> None:
    x = [1.0, 2.0, 3.0, 4.0]
    ma = MovingAverage(3, mode="reflect")
    y = ma.apply(x)
    assert isinstance(y, list)
    assert len(y) == len(x)
    # manual 3-point reflect at ends:
    # idx0 uses [2,1,2] -> (2+1+2)/3 = 5/3
    # idx1 uses [1,2,3] -> 2
    # idx2 uses [2,3,4] -> 3
    # idx3 uses [3,4,3] -> 10/3
    expect = [5/3, 2.0, 3.0, 10/3]
    assert np.allclose(y, expect, atol=1e-12)


def test_same_mode_matches_mask_normalized_convolve_when_all_finite() -> None:
    x = [0.0, 1.0, 2.0, 3.0, 4.0]
    ma = MovingAverage(5, mode="same")
    y = np.asarray(ma.apply(x))

    kernel = np.ones(5, dtype=float) / 5.0
    x_arr = np.asarray(x, dtype=float)
    mask = np.ones_like(x_arr, dtype=float)

    num = np.convolve(x_arr, kernel, mode="same")
    den = np.convolve(mask,  kernel, mode="same")
    ref = np.divide(num, den, out=np.zeros_like(num), where=den > 0)

    assert np.allclose(y, ref, atol=1e-12)

def test_nan_masking_excludes_non_finite_samples() -> None:
    x = [1.0, float("nan"), 3.0, float("inf"), 5.0]
    ma = MovingAverage(3, mode="reflect")
    y = np.asarray(ma.apply(x))
    # Where a window has some finite values, average only those; if none finite, 0.0
    assert y.shape == (5,)
    # center index=2 window -> [nan,3,inf] → only 3 counts
    assert y[2] == pytest.approx(3.0)
    # index=1 window -> [1,nan,3] → average of (1,3)=2
    assert y[1] == pytest.approx(2.0)
    # index=3 window -> [3,inf,5] → average of (3,5)=4
    assert y[3] == pytest.approx(4.0)
    # ensure finite where expected
    assert math.isfinite(y[0]) and math.isfinite(y[4])


def test_even_window_is_supported_and_length_preserved() -> None:
    x = [1.0, 2.0, 4.0, 8.0]
    ma = MovingAverage(4, mode="reflect")  # even window
    y = ma.apply(x)
    assert len(y) == len(x)
    # sanity: mean should be within min/max
    for yi in y:
        assert min(x) <= yi <= max(x)


def test_kernel_property_returns_copy_not_internal() -> None:
    ma = MovingAverage(7)
    k1 = ma.kernel
    k1[0] = 123.456  # mutate the copy
    k2 = ma.kernel
    assert not np.allclose(k1, k2)  # internal unaffected
    # kernel still normalized
    assert np.isclose(np.sum(k2), 1.0)


def test_invalid_params_raise() -> None:
    with pytest.raises(ValueError):
        MovingAverage(0)
    with pytest.raises(ValueError):
        MovingAverage(3, mode="bad")
