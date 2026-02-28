# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

from __future__ import annotations

import json
import math

import numpy as np
import pytest

from pypnm.pnm.lib.signal_statistics import SignalStatistics, SignalStatisticsModel


def _isclose(a, b, rtol=1e-12, atol=1e-12):
    return float(np.isclose(a, b, rtol=rtol, atol=atol))


def _allclose(a, b, rtol=1e-12, atol=1e-12):
    return bool(np.allclose(a, b, rtol=rtol, atol=atol))


def test_rejects_empty_input() -> None:
    with pytest.raises(ValueError):
        SignalStatistics([]).compute()  # type: ignore[arg-type]


def test_basic_stats_on_simple_vector() -> None:
    x = np.array([1.0, 2.0, 3.0, 4.0])
    s = SignalStatistics(x).compute()

    # mean / median
    assert _isclose(s.mean, np.mean(x))
    assert _isclose(s.median, np.median(x))

    # std/variance (population)
    assert _isclose(s.std, np.std(x))
    assert _isclose(s.variance, np.var(x))
    assert _isclose(s.std**2, s.variance)

    # power = mean(x^2)
    assert _isclose(s.power, np.mean(x**2))

    # peak-to-peak
    assert _isclose(s.peak_to_peak, np.ptp(x))

    # mean absolute deviation around mean
    mad = np.mean(np.abs(x - x.mean()))
    assert _isclose(s.mean_abs_deviation, mad)

    # crest factor = max(|x|)/sqrt(power)
    peak = np.abs(x).max()
    expect_cf = peak / math.sqrt(np.mean(x**2))
    assert _isclose(s.crest_factor, expect_cf)

    # zero crossing rate / count
    crossings = int(np.sum(x[:-1] * x[1:] < 0))
    expect_zcr = crossings / (len(x) - 1)
    assert s.zero_crossings == crossings
    assert _isclose(s.zero_crossing_rate, expect_zcr)


def test_handles_single_sample() -> None:
    x = np.array([3.5])
    s = SignalStatistics(x).compute()

    # With one sample:
    assert _isclose(s.mean, 3.5)
    assert _isclose(s.median, 3.5)
    assert _isclose(s.std, 0.0)
    assert _isclose(s.variance, 0.0)
    assert _isclose(s.power, 3.5**2)
    assert _isclose(s.peak_to_peak, 0.0)
    assert _isclose(s.mean_abs_deviation, 0.0)
    # zero-crossing metrics defined this way in implementation:
    assert s.zero_crossings == 0
    assert _isclose(s.zero_crossing_rate, 0.0)

    # skewness/kurtosis are NaN when std == 0
    assert math.isnan(s.skewness)
    assert math.isnan(s.kurtosis)

    # crest factor with one nonzero value equals 1.0
    assert _isclose(s.crest_factor, 1.0)


def test_constant_signal_properties() -> None:
    x = np.ones(256) * -7.0
    s = SignalStatistics(x).compute()

    assert _isclose(s.mean, -7.0)
    assert _isclose(s.median, -7.0)
    assert _isclose(s.std, 0.0)
    assert _isclose(s.variance, 0.0)
    assert _isclose(s.power, 49.0)
    assert _isclose(s.peak_to_peak, 0.0)
    assert _isclose(s.mean_abs_deviation, 0.0)
    assert s.zero_crossings == 0
    assert _isclose(s.zero_crossing_rate, 0.0)
    assert math.isnan(s.skewness)
    assert math.isnan(s.kurtosis)
    # crest factor = |peak|/sqrt(power) = 7 / 7 = 1
    assert _isclose(s.crest_factor, 1.0)


def test_random_signal_matches_numpy() -> None:
    rng = np.random.default_rng(12345)
    x = rng.normal(loc=0.0, scale=2.0, size=10_000)
    s = SignalStatistics(x).compute()

    # basic alignment with numpy (population stats)
    assert _isclose(s.mean, np.mean(x), rtol=1e-9, atol=1e-9)
    assert _isclose(s.std, np.std(x), rtol=1e-9, atol=1e-9)
    assert _isclose(s.variance, np.var(x), rtol=1e-9, atol=1e-9)
    assert _isclose(s.power, np.mean(x**2), rtol=1e-9, atol=1e-9)

    # zero-crossings sanity: for zero-mean Gaussian, ZCR ~ 0.5
    assert 0.45 <= s.zero_crossing_rate <= 0.55


def test_nd_shapes_are_flattened() -> None:
    x2d = np.array([[1.0, -2.0, 3.0], [4.0, -5.0, 6.0]])
    s = SignalStatistics(x2d).compute()
    x1d = x2d.flatten()
    s_ref = SignalStatistics(x1d).compute()

    # Every numeric field should match after flatten
    for field in SignalStatisticsModel.model_fields:
        v = getattr(s, field)
        v_ref = getattr(s_ref, field)
        if isinstance(v, float) and math.isnan(v):
            assert isinstance(v_ref, float) and math.isnan(v_ref)
        else:
            assert _isclose(v, v_ref)


def test_model_serialization_roundtrip() -> None:
    x = np.array([0.0, 1.0, -1.0, 2.0, -2.0])
    s = SignalStatistics(x).compute()

    # dict keys present
    d = s.model_dump()
    for key in SignalStatisticsModel.model_fields:
        assert key in d

    # JSON round-trip
    j = s.model_dump_json()
    parsed = json.loads(j)
    assert set(parsed.keys()) == set(d.keys())
