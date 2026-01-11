# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import math
from typing import cast

import numpy as np
import pytest

from pypnm.lib.signal_processing.db_linear_converter import DbLinearConverter
from pypnm.lib.types import ComplexArray, FloatSeries

# ---------- Absolute linear/dB roundtrips ----------

def test_db_to_linear_basic() -> None:
    db: FloatSeries = [-10.0, 0.0, 10.0, 20.0]
    lin = DbLinearConverter.db_to_linear(db)
    assert lin == pytest.approx([0.1, 1.0, 10.0, 100.0], rel=1e-12, abs=0.0)
    assert len(lin) == len(db)


def test_linear_to_db_basic_absolute() -> None:
    lin: FloatSeries = [0.1, 1.0, 10.0, 100.0]
    db = DbLinearConverter.linear_to_db(lin)  # absolute
    assert db == pytest.approx([-10.0, 0.0, 10.0, 20.0], rel=1e-12, abs=0.0)
    assert len(db) == len(lin)


def test_linear_to_db_handles_zero_small_and_negative() -> None:
    lin: FloatSeries = [0.0, 1e-12, 1e-6, 1.0, -0.5]
    db = DbLinearConverter.linear_to_db(lin)
    assert math.isinf(db[0]) and db[0] < 0.0  # -inf for zero
    assert db[1:4] == pytest.approx([-120.0, -60.0, 0.0], rel=1e-9, abs=1e-12)
    assert math.isnan(db[4])  # negative → NaN


def test_roundtrip_linear_db_linear_absolute() -> None:
    lin: FloatSeries = [1e-12, 1e-6, 1e-3, 0.1, 1.0, 10.0, 1e3, 1e6]
    db = DbLinearConverter.linear_to_db(lin)
    lin_rt = DbLinearConverter.db_to_linear(db)
    assert lin_rt == pytest.approx(lin, rel=1e-10, abs=0.0)


def test_roundtrip_db_linear_db_absolute() -> None:
    db: FloatSeries = [-140.0, -120.0, -60.0, -10.0, 0.0, 3.0, 10.0, 30.0, 60.0]
    lin = DbLinearConverter.db_to_linear(db)
    db_rt = DbLinearConverter.linear_to_db(lin)
    assert db_rt == pytest.approx(db, rel=1e-10, abs=1e-12)


# ---------- Relative dB (reference) ----------

def test_linear_to_db_with_reference_value() -> None:
    vals: FloatSeries = [1.0, 0.5, 0.25]
    out_abs = DbLinearConverter.linear_to_db(vals)  # absolute
    out_rel = DbLinearConverter.linear_to_db(vals, ref=max(vals))  # relative to max
    # use a slightly looser tolerance to avoid false failures from fp noise
    assert out_abs == pytest.approx([0.0, -3.0102999566, -6.0205999133], rel=1e-10, abs=1e-10)
    assert out_rel == pytest.approx([0.0, -3.0102999566, -6.0205999133], rel=1e-10, abs=1e-10)


# ---------- Complex power (linear) ----------

def test_complex_to_linear_power_basic() -> None:
    pairs: ComplexArray = [[1.0, 0.0], [0.0, 1.0], [3.0, 4.0]]
    out = DbLinearConverter.complex_to_Linear(pairs)
    assert out == pytest.approx([1.0, 1.0, 25.0], rel=0.0, abs=0.0)
    assert len(out) == len(pairs)


def test_complex_to_linear_accepts_numpy_and_empty() -> None:
    arr = np.array([[0.0, 0.0], [0.5, -0.5], [1.0, 1.0]], dtype=float)
    pairs: ComplexArray = cast(ComplexArray, arr.tolist())
    out = DbLinearConverter.complex_to_Linear(pairs)
    assert isinstance(out, list)
    assert out == pytest.approx([0.0, 0.5, 2.0], rel=1e-12)
    assert DbLinearConverter.complex_to_Linear(cast(ComplexArray, [])) == []


def test_complex_to_linear_shape_validation() -> None:
    with pytest.raises(ValueError):
        DbLinearConverter.complex_to_Linear(cast(ComplexArray, [[1.0]]))
    with pytest.raises(ValueError):
        DbLinearConverter.complex_to_Linear(cast(ComplexArray, [[1.0, 0.0, 2.0]]))


# ---------- Complex power (dB), absolute vs relative ----------

def test_complex_to_db_basic_absolute_and_zero() -> None:
    pairs: ComplexArray = [[1.0, 0.0], [0.0, 1.0], [3.0, 4.0], [0.0, 0.0]]
    out = DbLinearConverter.complex_to_db(pairs)  # absolute
    assert out[0:2] == pytest.approx([0.0, 0.0], rel=1e-12)
    expected_db: float = 10.0 * math.log10(25.0)
    assert out[2] == pytest.approx(expected_db, rel=1e-12)
    assert math.isinf(out[3]) and out[3] < 0.0


def test_complex_to_db_relative_max_is_nonpositive() -> None:
    pairs: ComplexArray = [[1.0, 0.0], [0.5, 0.5], [3.0, 4.0]]  # powers: 1, 0.5, 25
    out = DbLinearConverter.complex_to_db(pairs, ref="max")
    assert len(out) == 3
    # Peak becomes 0 dB; others are ≤ 0 dB
    assert out[2] == pytest.approx(0.0, abs=1e-12)
    assert out[0] < 0.0 and out[1] < 0.0


def test_complex_to_db_matches_linear_composition() -> None:
    pairs: ComplexArray = [[0.5, -0.5], [2.0, 2.0], [1e-6, 0.0]]
    direct = DbLinearConverter.complex_to_db(pairs)
    composed = DbLinearConverter.linear_to_db(
        DbLinearConverter.complex_to_Linear(pairs)
    )
    assert direct == pytest.approx(composed, rel=1e-12)


def test_complex_to_db_accepts_numpy_and_empty() -> None:
    arr = np.array([[0.0, 0.0], [1.0, 1.0], [0.5, -0.5]], dtype=float)
    pairs: ComplexArray = cast(ComplexArray, arr.tolist())
    out = DbLinearConverter.complex_to_db(pairs, ref="max")
    assert isinstance(out, list)
    assert math.isinf(DbLinearConverter.complex_to_db(cast(ComplexArray, [[0.0, 0.0]]))[0])
    assert DbLinearConverter.complex_to_db(cast(ComplexArray, [])) == []


def test_complex_to_db_shape_validation() -> None:
    with pytest.raises(ValueError):
        DbLinearConverter.complex_to_db(cast(ComplexArray, [[1.0]]))
    with pytest.raises(ValueError):
        DbLinearConverter.complex_to_db(cast(ComplexArray, [[1.0, 0.0, 2.0]]))
