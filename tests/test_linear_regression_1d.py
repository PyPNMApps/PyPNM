# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

# tests/test_linear_regression_1d.py
from __future__ import annotations

from typing import cast

import numpy as np
import pytest

from pypnm.lib.signal_processing.linear_regression import LinearRegression1D
from pypnm.lib.types import ArrayLike


def test_perfect_line_with_explicit_x() -> None:
    x = np.linspace(-5.0, 5.0, 21)
    m_true = 2.5
    b_true = -1.2
    y = m_true * x + b_true

    lr = LinearRegression1D(y_values    =   cast(ArrayLike, y),
                            x_values    =   cast(ArrayLike, x))

    assert lr.n == x.size
    assert lr.slope == pytest.approx(m_true, rel=0, abs=1e-12)
    assert lr.intercept == pytest.approx(b_true, rel=0, abs=1e-12)
    assert lr.r2 == pytest.approx(1.0, rel=0, abs=1e-12)
    assert lr.rmse == pytest.approx(0.0, rel=0, abs=1e-12)

    # Endpoints should lie exactly on the line
    (x0, y0), (x1, y1) = lr.regression_endpoints()
    assert y0 == pytest.approx(m_true * x0 + b_true, abs=1e-12)
    assert y1 == pytest.approx(m_true * x1 + b_true, abs=1e-12)


def test_default_x_is_range_len_y() -> None:
    y = np.array([0.0, 1.0, 2.0, 3.0], dtype=float)  # x should be [0,1,2,3]
    lr = LinearRegression1D(y_values     =   cast(ArrayLike, y))

    # Slope should be 1, intercept 0 for this y over x=[0..3]
    assert lr.slope == pytest.approx(1.0, abs=1e-12)
    assert lr.intercept == pytest.approx(0.0, abs=1e-12)
    assert lr.r2 == pytest.approx(1.0, abs=1e-12)


def test_filters_nonfinite_pairs() -> None:
    x = np.array([0.0, 1.0, 2.0, np.nan, 4.0, 5.0, np.inf], dtype=float)
    y = np.array([0.0, 2.0, 4.0, 6.0, np.nan, 10.0, 12.0], dtype=float)

    # Finite overlapping pairs are: (0,0), (1,2), (2,4), (5,10)
    lr = LinearRegression1D(y_values     =   cast(ArrayLike, y),
                            x_values    =   cast(ArrayLike, x))

    assert lr.n == 4
    assert lr.slope == pytest.approx(2.0, abs=1e-12)
    assert lr.intercept == pytest.approx(0.0, abs=1e-12)
    preds = lr.predict([0.0, 1.0, 2.0, 5.0])
    assert np.allclose(preds, [0.0, 2.0, 4.0, 10.0])


def test_constant_y_robust_r2() -> None:
    # y is constant; r2 should be 1 if perfectly fit, else 0 (implementation treats as perfect)
    x = np.linspace(0.0, 1.0, 10)
    y = np.full_like(x, 3.14)
    lr = LinearRegression1D(y_values     =   cast(ArrayLike, y),
                            x_values    =   cast(ArrayLike, x))

    # Any slope with intercept ~3.14 fits; least squares gives slope≈0, intercept≈3.14
    assert lr.r2 in (0.0, 1.0)  # implementation returns 1.0 for zero residuals
    assert lr.rmse == pytest.approx(0.0, abs=1e-12)
    assert lr.intercept == pytest.approx(3.14, abs=1e-12)


def test_near_zero_variance_x_raises() -> None:
    x = np.ones(5, dtype=float) * 7.0
    y = np.linspace(0.0, 1.0, 5)
    with pytest.raises(ValueError):
        LinearRegression1D(y_values     =   cast(ArrayLike, y),
                            x_values    =   cast(ArrayLike, x))


def test_min_points_and_shape_checks() -> None:
    # Mismatched shape
    with pytest.raises(ValueError):
        LinearRegression1D(y_values=[1.0, 2.0], x_values=[0.0])

    # After filtering non-finite, fewer than 2 points
    with pytest.raises(ValueError):
        LinearRegression1D(y_values=[np.nan, np.inf], x_values=[0.0, 1.0])


def test_to_list_and_to_dict_and_repr() -> None:
    x = np.array([0.0, 1.0, 2.0], dtype=float)
    y = np.array([1.0, 3.0, 5.0], dtype=float)  # slope=2, intercept=1
    lr = LinearRegression1D(y_values    =   cast(ArrayLike, y),
                            x_values    =   cast(ArrayLike, x))

    lst = lr.to_list()
    dct = lr.to_dict()
    rep = repr(lr)

    assert lst[0] == pytest.approx(2.0, abs=1e-12)
    assert lst[1] == pytest.approx(1.0, abs=1e-12)
    assert 0.0 <= lst[2] <= 1.0

    assert dct["slope"] == pytest.approx(2.0, abs=1e-12)
    assert dct["intercept"] == pytest.approx(1.0, abs=1e-12)
    assert "r2" in dct and "rmse" in dct and "n" in dct

    assert "LinearRegression1D" in rep
    assert "slope=" in rep and "intercept=" in rep and "r2=" in rep


def test_regression_line_and_residuals() -> None:
    x = np.array([0.0, 1.0, 2.0, 3.0], dtype=float)
    y = np.array([1.0, 2.9, 5.1, 7.2], dtype=float)  # near slope=2, intercept=1
    lr = LinearRegression1D(y_values    =   cast(ArrayLike, y),
                            x_values    =   cast(ArrayLike, x))

    yhat_only = lr.regression_line(y_axis_only=True)
    x_fit, yhat = lr.regression_line(y_axis_only=False)
    res = lr.residuals()

    assert isinstance(yhat_only, np.ndarray) and yhat_only.shape == y.shape
    assert isinstance(x_fit, np.ndarray) and isinstance(yhat, np.ndarray)
    assert x_fit.shape == y.shape and yhat.shape == y.shape
    assert res.shape == y.shape
    assert np.allclose(yhat_only, yhat)
