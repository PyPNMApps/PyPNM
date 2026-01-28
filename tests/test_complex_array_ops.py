# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_complex_array_ops.py
from __future__ import annotations

import math

import numpy as np
import pytest

from pypnm.lib.signal_processing.complex_array_ops import ComplexArrayOps


def pairs(*vals: float) -> list[tuple[float, float]]:
    """Build (re, im) pairs from flat numbers: r1,i1,r2,i2,..."""
    assert len(vals) % 2 == 0
    it = iter(vals)
    return [(float(r), float(i)) for r, i in zip(it, it)]


def test_init_and_len_and_repr() -> None:
    x = pairs(1, 0, 0, 1, -1, 0)
    ops = ComplexArrayOps(x)
    assert len(ops) == 3
    r = repr(ops)
    assert "ComplexArrayOps" in r
    assert "RMS=" in r and "MeanPwr=" in r


def test_invalid_shape_raises() -> None:
    with pytest.raises(ValueError):
        ComplexArrayOps([(1.0,)] * 2)
    with pytest.raises(ValueError):
        ComplexArrayOps([])


def test_as_array_and_to_pairs_roundtrip() -> None:
    x = pairs(1, 2, 3, 4, -5, 0)
    ops = ComplexArrayOps(x)
    arr = ops.as_array()
    assert arr.dtype == np.complex128
    assert np.allclose(arr.real, [1, 3, -5])
    assert np.allclose(arr.imag, [2, 4, 0])

    back = ops.to_pairs()
    assert back == x


def test_magnitude_power_and_db() -> None:
    x = pairs(3, 4, 0, 0)
    ops = ComplexArrayOps(x)

    mag = ops.magnitude()
    pwr = ops.power()
    pwr_db = ops.power_db()
    pwr_db_eps = ops.power_db(eps=1e-12)
    pwr_db_epsilon = ops.power_db(epsilon=1e-12)
    pwr_db_mean = ops.power_db_normalized(normalize="mean")
    pwr_db_unit = ops.power_db_normalized(normalize="unit")

    assert np.allclose(mag, [5.0, 0.0])
    assert np.allclose(pwr, [25.0, 0.0])

    assert np.isfinite(pwr_db[1])
    assert pwr_db[0] > pwr_db[1]
    assert np.allclose(pwr_db_eps, pwr_db_epsilon)
    assert np.isclose(float(np.mean(pwr_db_mean)), 0.0, atol=1e-12)
    assert np.isfinite(pwr_db_unit).all()


def test_phase_and_unwrap() -> None:
    # With default discont=π, unwrap does NOT add 2π for jump exactly π
    x = pairs(1, 0, -1, 0, 1, 0)
    ops = ComplexArrayOps(x)
    ph = ops.phase()
    ph_u = ops.phase(unwrap=True)

    assert np.allclose(ph, [0.0, np.pi, 0.0])
    assert np.allclose(ph_u, [0.0, np.pi, 0.0])


def test_power_db_normalized_unit_mean_matches_expected() -> None:
    x = pairs(1, 0, 2, 0)
    ops = ComplexArrayOps(x)

    pwr_db_unit = ops.power_db_normalized(normalize="unit", epsilon=1e-12)
    pwr_linear = 10.0 ** (pwr_db_unit / 10.0)
    assert np.isclose(float(np.mean(pwr_linear)), 1.0, atol=1e-12)

    with pytest.raises(ValueError):
        ops.power_db_normalized(normalize="bad-mode")


def test_rms_and_mean_power_with_mask() -> None:
    x = pairs(1, 0, 0, 2, 0, 0)  # powers: 1, 4, 0 → mean=5/3
    ops = ComplexArrayOps(x)

    assert ops.mean_power() == pytest.approx(5.0 / 3.0, abs=1e-12)
    assert ops.rms() == pytest.approx(math.sqrt(5.0 / 3.0), abs=1e-12)

    mask = np.array([True, False, True])
    assert ops.mean_power(mask=mask) == pytest.approx(0.5, abs=1e-12)
    assert ops.rms(mask=mask) == pytest.approx(math.sqrt(0.5), abs=1e-12)

    with pytest.raises(ValueError):
        ops.mean_power(mask=[True])


def test_conjugate_and_scale() -> None:
    x = pairs(1, -2, -3, 4)
    ops = ComplexArrayOps(x)

    conj = ops.conj()
    assert np.allclose(conj.as_array(), np.conjugate(ops.as_array()))
    assert not np.shares_memory(conj.as_array(), ops.as_array())

    scaled = ops.scale(2.0 - 1.0j)
    assert np.allclose(scaled.as_array(), (2.0 - 1.0j) * ops.as_array())

    def test_reciprocal_exact_and_eps() -> None:
        x = pairs(1, 0, 0, 1, 0, 0)
        ops = ComplexArrayOps(x)

        inv = ops.reciprocal()

        # Silence intentional divide-by-zero for the zero sample
        with np.errstate(divide="ignore", invalid="ignore"):
            target = 1.0 / ops.as_array()  # inf+nanj for the last zero sample

        assert np.allclose(inv.as_array(), target, equal_nan=True)

        inv_eps = ops.reciprocal(eps=1e-9)
        assert np.isfinite(inv_eps.as_array()[-1])
        assert np.allclose(inv_eps.as_array()[:-1], target[:-1], rtol=1e-12, atol=1e-12)

def test_normalize_rms_global_and_masked() -> None:
    x = pairs(3, 4, 0, 0)  # RMS = 5/sqrt(2)
    ops = ComplexArrayOps(x)

    target = 1.0
    norm = ops.normalize_rms(target=target)
    assert norm.rms() == pytest.approx(target, abs=1e-12)

    mask = np.array([True, False])
    norm_m = ops.normalize_rms(target=2.0, mask=mask)
    assert norm_m.rms(mask=mask) == pytest.approx(2.0, abs=1e-12)


def test_fft_ifft_roundtrip() -> None:
    x = np.zeros((8, 2), dtype=float)
    x[0] = (1.0, 0.0)
    ops = ComplexArrayOps([tuple(row) for row in x])

    X = ops.fft()
    x_rt = X.ifft()
    assert np.allclose(x_rt.as_array(), ops.as_array(), atol=1e-12)


def test_real_imag_accessors() -> None:
    x = pairs(1.2, -3.4, 5.6, 7.8)
    ops = ComplexArrayOps(x)
    assert np.allclose(ops.real(), [1.2, 5.6])
    assert np.allclose(ops.imag(), [-3.4, 7.8])


def test_copy_is_independent() -> None:
    x = pairs(1, 2, 3, 4)
    ops = ComplexArrayOps(x)
    cpy = ops.copy()
    assert np.allclose(cpy.as_array(), ops.as_array())
    cpy_scaled = cpy.scale(2.0)
    assert np.allclose(ops.as_array(), np.array([1 + 2j, 3 + 4j], dtype=np.complex128))
    assert np.allclose(cpy_scaled.as_array(), 2.0 * cpy.as_array())
