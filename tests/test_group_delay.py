# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

# tests/test_group_delay.py
from __future__ import annotations

import math

import numpy as np
import pytest

from pypnm.lib.signal_processing.group_delay import GroupDelay, GroupDelayResult


def _mk_H_from_tau(
    n: int,
    df_hz: float,
    f0_hz: float,
    tau_s: float,
) -> list[tuple[float, float]]:
    """
    Build H[k] = exp(-j*2π f[k] τ), where f[k] = f0 + k*df.
    Returns list of (real, imag) pairs.
    """
    k = np.arange(n, dtype=float)
    f = f0_hz + k * df_hz
    phase = -2.0 * math.pi * f * tau_s
    H = np.exp(1j * phase)
    return [(float(z.real), float(z.imag)) for z in H]


def _mk_H_from_tau_with_freqvec(
    f_hz: np.ndarray, tau_s: float
) -> list[tuple[float, float]]:
    phase = -2.0 * math.pi * f_hz * tau_s
    H = np.exp(1j * phase)
    return [(float(z.real), float(z.imag)) for z in H]


def test_group_delay_constant_tau_with_df() -> None:
    n = 256
    df = 25_000.0
    f0 = 300e6
    tau = 2.0e-6  # 2 microseconds

    H_pairs = _mk_H_from_tau(n, df, f0, tau)
    gd = GroupDelay(H_pairs, df_hz=df, f0_hz=f0, unwrap=True, edge_order=2)

    f_axis, tau_s = gd.to_tuple()

    assert f_axis.shape == (n,)
    assert tau_s.shape == (n,)
    # Should be ~constant around tau (edges can be slightly worse due to gradient)
    mid = slice(n // 8, -n // 8)
    assert np.allclose(tau_s[mid], tau, rtol=0, atol=5e-9)  # 5 ns tolerance


def test_group_delay_constant_tau_with_freq_vector() -> None:
    n = 257  # odd length to exercise gradient edges
    f = np.linspace(100e6, 200e6, n)
    tau = 1.25e-6

    H_pairs = _mk_H_from_tau_with_freqvec(f, tau)
    gd = GroupDelay(H_pairs, freq_hz=f, unwrap=True, edge_order=2)

    f_axis, tau_s = gd.to_tuple()
    assert np.allclose(f_axis, f)

    mid = slice(n // 8, -n // 8)
    assert np.allclose(tau_s[mid], tau, rtol=0, atol=8e-9)


def test_unwrap_effect() -> None:
    # Force many wraps by making tau large
    n = 128
    df = 50_000.0
    f0 = 0.0
    tau = 8e-6

    H_pairs = _mk_H_from_tau(n, df, f0, tau)
    gd_wrap = GroupDelay(H_pairs, df_hz=df, f0_hz=f0, unwrap=False)
    gd_unwrap = GroupDelay(H_pairs, df_hz=df, f0_hz=f0, unwrap=True)

    # Without unwrap the gradient of wrapped phase is corrupted → big error
    err_wrap = np.nanmedian(np.abs(gd_wrap.group_delay_s - tau))
    err_unwrap = np.nanmedian(np.abs(gd_unwrap.group_delay_s - tau))
    assert err_unwrap < 1e-7 and err_wrap > err_unwrap


def test_active_mask_and_nan_propagation_and_smoothing() -> None:
    n = 101
    df = 25_000.0
    f0 = 200e6
    tau = 3e-6

    H_pairs = _mk_H_from_tau(n, df, f0, tau)

    # Deactivate a center block and corrupt some bins with NaNs (magnitude ~ 0)
    mask = np.ones(n, dtype=bool)
    mask[40:60] = False
    H_arr = np.array(H_pairs, dtype=float)
    H_arr[10, :] = np.nan
    H_arr[90, :] = np.nan
    H_list = [tuple(x) for x in H_arr.tolist()]

    gd = GroupDelay(H_list, df_hz=df, f0_hz=f0, active_mask=mask, smooth_win=5)

    # Inactive and NaN bins should produce NaN outputs
    assert np.isnan(gd.group_delay_s[10])
    assert np.isnan(gd.group_delay_s[90])
    assert np.all(np.isnan(gd.group_delay_s[40:60]))

    # Valid region should still be close to tau
    valid = ~np.isnan(gd.group_delay_s)
    assert valid.sum() < n  # some invalids exist
    assert np.allclose(gd.group_delay_s[valid], tau, rtol=0, atol=1e-7)

    # Result object shape & mean (µs) on valid bins
    res = gd.to_result()
    assert isinstance(res, GroupDelayResult)
    assert len(res.freq_hz) == n
    assert len(res.group_delay_s) == n
    assert len(res.group_delay_us) == n
    assert len(res.valid_mask) == n
    # mean over valid in µs ≈ tau * 1e6
    assert res.mean_group_delay_us == pytest.approx(tau * 1e6, abs=1e-2)


def test_from_channel_estimate_constructor() -> None:
    n = 64
    df = 25_000.0
    f0 = 150e6
    tau = 0.5e-6

    H_pairs = _mk_H_from_tau(n, df, f0, tau)
    gd = GroupDelay.from_channel_estimate(H_pairs, df_hz=df, f0_hz=f0, smooth_win=3)

    mid = slice(n // 6, -n // 6)
    assert np.allclose(gd.group_delay_s[mid], tau, atol=5e-9)


def test_validation_errors() -> None:
    n = 8
    df = 25_000.0
    f = np.linspace(0, 1e6, n)
    H_pairs = _mk_H_from_tau(n, df, 0.0, 1e-6)

    # Need exactly one of freq_hz / df_hz
    with pytest.raises(ValueError):
        GroupDelay(H_pairs, df_hz=None, freq_hz=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        GroupDelay(H_pairs, df_hz=df, freq_hz=f)       # both given

    # freq vector length mismatch
    with pytest.raises(ValueError):
        GroupDelay(H_pairs, freq_hz=f[:-1])

    # freq vector with duplicates
    f_bad = f.copy()
    f_bad[3] = f_bad[2]
    with pytest.raises(ValueError):
        GroupDelay(H_pairs, freq_hz=f_bad)

    # df invalid
    with pytest.raises(ValueError):
        GroupDelay(H_pairs, df_hz=0.0)
    with pytest.raises(ValueError):
        GroupDelay.from_channel_estimate(H_pairs, df_hz=float("nan"))

    # H must be (N,2) and N>=2
    with pytest.raises(ValueError):
        GroupDelay([(1.0, 0.0)], df_hz=df)  # too short
    with pytest.raises(ValueError):
        GroupDelay([(1.0, 0.0, 0.0)], df_hz=df)  # wrong shape type: ignore[list-item]


def test_smooth_win_validation() -> None:
    n = 16
    df = 25_000.0
    H_pairs = _mk_H_from_tau(n, df, 0.0, 1e-6)

    with pytest.raises(ValueError):
        GroupDelay(H_pairs, df_hz=df, smooth_win=2)  # even
    with pytest.raises(ValueError):
        GroupDelay(H_pairs, df_hz=df, smooth_win=1)  # <3
    with pytest.raises(ValueError):
        GroupDelay(H_pairs, df_hz=df, smooth_win="5")
