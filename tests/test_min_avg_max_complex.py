# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import math

import numpy as np
import pytest

from pypnm.pnm.lib.min_avg_max_complex import MinAvgMaxComplex


def test_basic_real_imag_and_magnitude_stats() -> None:
    """
    Verify per-subcarrier min/avg/max for real, imag, and magnitude
    on a small 2x2 complex matrix with hand-computable values.
    """
    H = np.array(
        [
            [1 + 2j, 3 + 4j],
            [5 + 6j, -1 - 2j],
        ],
        dtype=np.complex128,
    )

    stats = MinAvgMaxComplex(H, precision=2)

    # Real part
    assert stats.min_real == [1.0, -1.0]
    assert stats.avg_real == [3.0, 1.0]
    assert stats.max_real == [5.0, 3.0]

    # Imag part
    assert stats.min_imag == [2.0, -2.0]
    assert stats.avg_imag == [4.0, 1.0]
    assert stats.max_imag == [6.0, 4.0]

    # Magnitude statistics (rounded to 2 decimals)
    # k = 0: |1+2j|, |5+6j|, |(1+2j + 5+6j)/2| = |3+4j|
    mag0_0 = math.sqrt(1.0**2 + 2.0**2)       # ≈ 2.236...
    mag0_1 = math.sqrt(5.0**2 + 6.0**2)       # ≈ 7.810...
    avg0   = math.hypot(3.0, 4.0)             # = 5.0

    # k = 1: |3+4j|, |-1-2j|, |(3+4j -1-2j)/2| = |1+1j|
    mag1_0 = math.hypot(3.0, 4.0)             # = 5.0
    mag1_1 = math.sqrt(1.0**2 + 2.0**2)       # ≈ 2.236...
    avg1   = math.hypot(1.0, 1.0)             # ≈ 1.414...

    expected_min_mag = [round(min(mag0_0, mag0_1), 2), round(min(mag1_0, mag1_1), 2)]
    expected_max_mag = [round(max(mag0_0, mag0_1), 2), round(max(mag1_0, mag1_1), 2)]
    expected_avg_mag = [round(avg0, 2), round(avg1, 2)]

    assert stats.min_mag == pytest.approx(expected_min_mag)
    assert stats.max_mag == pytest.approx(expected_max_mag)
    assert stats.avg_mag == pytest.approx(expected_avg_mag)


def test_single_snapshot_vector_is_reshaped_correctly() -> None:
    """
    A 1D complex vector must be treated as a single snapshot (shape 1×K),
    so per-subcarrier min/avg/max all collapse to the same value.
    """
    H = np.array([1 + 1j, 2 + 0j, -1 - 2j], dtype=np.complex128)

    stats = MinAvgMaxComplex(H, precision=3)

    # With only one snapshot, min = avg = max for each component
    assert stats.min_real == stats.avg_real == stats.max_real
    assert stats.min_imag == stats.avg_imag == stats.max_imag

    # Magnitude path should also satisfy min = max = avg
    assert stats.min_mag == pytest.approx(stats.avg_mag)
    assert stats.max_mag == pytest.approx(stats.avg_mag)

    # Length should match number of subcarriers
    assert stats.length() == H.size


def test_real_imag_pair_layouts_match_complex_layout() -> None:
    """
    Ensure that (K,2) and (M,K,2) real/imag layouts are interpreted consistently
    with the pure complex layouts.
    """
    H = np.array([1 + 2j, -3 + 4j, 0 - 1j], dtype=np.complex128)

    # Baseline: 1D complex vector
    base = MinAvgMaxComplex(H, precision=4)

    # (K,2) layout: single snapshot, (re, im)
    pairs_2d = np.column_stack([H.real, H.imag])
    from_2d_pairs = MinAvgMaxComplex(pairs_2d, precision=4)

    assert from_2d_pairs.min_real == base.min_real
    assert from_2d_pairs.avg_real == base.avg_real
    assert from_2d_pairs.max_real == base.max_real

    assert from_2d_pairs.min_imag == base.min_imag
    assert from_2d_pairs.avg_imag == base.avg_imag
    assert from_2d_pairs.max_imag == base.max_imag

    assert from_2d_pairs.min_mag == pytest.approx(base.min_mag)
    assert from_2d_pairs.avg_mag == pytest.approx(base.avg_mag)
    assert from_2d_pairs.max_mag == pytest.approx(base.max_mag)

    # (M,K,2) layout: duplicate the same snapshot twice
    pairs_3d = np.stack([pairs_2d, pairs_2d], axis=0)
    from_3d_pairs = MinAvgMaxComplex(pairs_3d, precision=4)

    # With identical snapshots, stats should still match the baseline
    assert from_3d_pairs.min_real == base.min_real
    assert from_3d_pairs.max_real == base.max_real
    assert from_3d_pairs.avg_real == base.avg_real

    assert from_3d_pairs.min_imag == base.min_imag
    assert from_3d_pairs.max_imag == base.max_imag
    assert from_3d_pairs.avg_imag == base.avg_imag

    assert from_3d_pairs.min_mag == pytest.approx(base.min_mag)
    assert from_3d_pairs.max_mag == pytest.approx(base.max_mag)
    assert from_3d_pairs.avg_mag == pytest.approx(base.avg_mag)


def test_empty_input_raises_value_error() -> None:
    """Passing an empty container must raise a ValueError."""
    with pytest.raises(ValueError):
        MinAvgMaxComplex([], precision=2)


def test_to_model_and_to_dict_round_trip() -> None:
    """
    Verify that to_model() and to_dict() expose the same numerical
    content as the internal lists on the MinAvgMaxComplex instance.
    """
    H = np.array(
        [
            [1 + 0.5j, 2 - 0.5j],
            [0 - 1j, -1 + 2j],
        ],
        dtype=np.complex128,
    )

    stats = MinAvgMaxComplex(H, precision=3)
    model = stats.to_model()

    assert model.precision == 3
    assert model.real.min == stats.min_real
    assert model.real.avg == stats.avg_real
    assert model.real.max == stats.max_real

    assert model.imag.min == stats.min_imag
    assert model.imag.avg == stats.avg_imag
    assert model.imag.max == stats.max_imag

    dumped: dict[str, object] = stats.to_dict()
    assert "real" in dumped
    assert "imag" in dumped
    assert "precision" in dumped

    real_dict = dumped["real"]
    imag_dict = dumped["imag"]

    assert isinstance(real_dict, dict)
    assert isinstance(imag_dict, dict)

    assert real_dict["min"] == pytest.approx(stats.min_real)
    assert real_dict["avg"] == pytest.approx(stats.avg_real)
    assert real_dict["max"] == pytest.approx(stats.max_real)

    assert imag_dict["min"] == pytest.approx(stats.min_imag)
    assert imag_dict["avg"] == pytest.approx(stats.avg_imag)
    assert imag_dict["max"] == pytest.approx(stats.max_imag)
