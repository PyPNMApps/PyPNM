# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

# tests/test_moving_average.py
from __future__ import annotations

import pytest

try:
    from pypnm.pnm.lib.moving_average import MovingAverage
except Exception:
    pytest.skip(
        "MovingAverage not importable in this environment", allow_module_level=True
    )


def test_empty_returns_empty_list() -> None:
    ma = MovingAverage()
    assert ma.size() == 0
    assert ma.get_average(window=3) == []


def test_size_and_add() -> None:
    ma = MovingAverage()
    ma.add(1.0)
    ma.add(2.0)
    ma.add(3.0)
    assert ma.size() == 3


def test_get_average_basic_window_2() -> None:
    ma = MovingAverage([1.0, 2.0, 3.0, 4.0])
    assert ma.get_average(window=2) == [1.0, 1.5, 2.5, 3.5]


def test_get_average_larger_window_than_data() -> None:
    ma = MovingAverage([10.0, 20.0, 30.0])
    assert ma.get_average(window=10) == [10.0, 15.0, 20.0]


def test_exclude_value_skips_output_but_includes_in_window() -> None:
    ma = MovingAverage([1.0, -1.0, 3.0], exclude_value=-1.0)
    assert ma.get_average(window=2) == [1.0, 1.0]
