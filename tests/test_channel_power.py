# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

# tests/test_channel_power.py
from __future__ import annotations

import math

import pytest

try:
    from pypnm.pnm.lib.channel_power import ChannelPower
except ImportError as e:
    pytest.skip(f"ChannelPower not importable: {e}", allow_module_level=True)


def test_to_antilog_and_to_log10_roundtrip() -> None:
    x_db = 7.0
    anti = ChannelPower.to_antilog(x_db)
    log10_val = ChannelPower.to_log_10(anti)
    # Implementation returns log10(linear), i.e., x_db/10
    assert log10_val == pytest.approx(x_db / 10.0, rel=1e-12)


def test_channel_power_two_equal_zeros_db() -> None:
    vals = [0.0, 0.0]
    total = ChannelPower.calculate_channel_power(vals)
    # Implementation returns log10(sum(10^(dB/10))) — no *10 factor
    expected = math.log10(10.0 ** (0.0 / 10.0) + 10.0 ** (0.0 / 10.0))
    assert total == pytest.approx(expected, rel=1e-12)


def test_channel_power_mixed_values() -> None:
    vals = [-3.0, 0.0, 3.0]
    total = ChannelPower.calculate_channel_power(vals)
    expected = math.log10(sum(10.0 ** (v / 10.0) for v in vals))
    assert total == pytest.approx(expected, rel=1e-12)


def test_channel_power_monotonicity() -> None:
    base = [0.0]
    more = [0.0, -10.0]
    p1 = ChannelPower.calculate_channel_power(base)
    p2 = ChannelPower.calculate_channel_power(more)
    assert p2 >= p1 - 1e-12
