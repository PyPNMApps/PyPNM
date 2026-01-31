## Agent Review Bundle Summary
- Goal: Add tests for ChannelPowerDbmv impedance handling and edge cases.
- Changes: Added ChannelPowerDbmv tests and updated SPDX year in channel power tests.
- Files: src/pypnm/pnm/lib/channel_power.py, tests/test_channel_power.py
- Tests: ruff check src; pytest -q
- Notes: Hardware SNMP integration tests skipped (PNM_CM_IT not set).

# FILE: src/pypnm/pnm/lib/channel_power.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import math
from enum import IntEnum

from pypnm.lib.types import FloatSeries


class ChannelPower:

    @staticmethod
    def calculate_channel_power(dB_values: FloatSeries) -> float:
        """
        Calculate the total channel power.

        Args:
            dB_values (FloatSeries): Series of dB values.

        Returns:
            float: Total channel power in dB.
        """
        d_total_antilog = 0.0

        # Convert to Anti-Log and summation
        for d in dB_values:
            d_total_antilog += ChannelPower.to_antilog(d)

        return ChannelPower.to_log_10(d_total_antilog)

    @staticmethod
    def to_antilog(log: float) -> float:
        """
        Convert a logarithmic value to its anti-logarithmic equivalent.

        Args:
            log (float): Logarithmic value.

        Returns:
            float: Anti-logarithmic value.
        """
        return 10 ** (log / 10.0)

    @staticmethod
    def to_log_10(anti_log: float) -> float:
        """
        Convert an anti-logarithmic value to its logarithmic equivalent.

        Args:
            anti_log (float): Anti-logarithmic value.

        Returns:
            float: Logarithmic value.
        """
        return math.log10(anti_log)


class ChannelPowerDbmv:

    class ImpedanceOhm(IntEnum):
        FIFTY = 50
        SEVENTY_FIVE = 75

    _DBMV_TO_DBMW_OFFSET_75_OHM = 48.75
    _DBMV_TO_DBMW_OFFSET_50_OHM = 47.0

    @staticmethod
    def calculate_channel_power_dbmv(
        dBmv_values: FloatSeries,
        impedance_ohm: ImpedanceOhm = ImpedanceOhm.SEVENTY_FIVE,
    ) -> float:
        """
        Calculate total channel power from per-bin dBmV values.

        Args:
            dBmv_values (FloatSeries): Per-bin power values in dBmV.
            impedance_ohm (int): Reference impedance for dBmV conversion.

        Returns:
            float: Total channel power in dBmV.
        """
        offset = ChannelPowerDbmv._get_dbmv_offset(impedance_ohm)
        total_mw = 0.0

        for d_bmv in dBmv_values:
            total_mw += 10 ** ((d_bmv - offset) / 10.0)

        if total_mw <= 0.0:
            return float("-inf")

        return (10.0 * math.log10(total_mw)) + offset

    @staticmethod
    def _get_dbmv_offset(impedance_ohm: ImpedanceOhm) -> float:
        """
        Get the dBmV to dBm offset based on impedance.

        Args:
            impedance_ohm (int): Reference impedance for dBmV conversion.

        Returns:
            float: Offset applied to convert between dBmV and dBm.
        """
        match impedance_ohm:
            case ChannelPowerDbmv.ImpedanceOhm.SEVENTY_FIVE:
                return ChannelPowerDbmv._DBMV_TO_DBMW_OFFSET_75_OHM
            case ChannelPowerDbmv.ImpedanceOhm.FIFTY:
                return ChannelPowerDbmv._DBMV_TO_DBMW_OFFSET_50_OHM
            case _:
                raise ValueError(f"Unsupported impedance: {impedance_ohm}")

# FILE: tests/test_channel_power.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

# tests/test_channel_power.py
from __future__ import annotations

import math

import pytest

try:
    from pypnm.pnm.lib.channel_power import ChannelPower, ChannelPowerDbmv
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


def test_channel_power_dbmv_two_equal_bins_75_ohm() -> None:
    vals = [0.0, 0.0]
    total = ChannelPowerDbmv.calculate_channel_power_dbmv(
        vals,
        ChannelPowerDbmv.ImpedanceOhm.SEVENTY_FIVE,
    )
    expected = 10.0 * math.log10(2.0)
    assert total == pytest.approx(expected, rel=1e-12)


def test_channel_power_dbmv_two_equal_bins_50_ohm() -> None:
    vals = [0.0, 0.0]
    total = ChannelPowerDbmv.calculate_channel_power_dbmv(
        vals,
        ChannelPowerDbmv.ImpedanceOhm.FIFTY,
    )
    expected = 10.0 * math.log10(2.0)
    assert total == pytest.approx(expected, rel=1e-12)


def test_channel_power_dbmv_empty_returns_negative_inf() -> None:
    total = ChannelPowerDbmv.calculate_channel_power_dbmv([])
    assert total == float("-inf")


def test_channel_power_dbmv_invalid_impedance_raises() -> None:
    with pytest.raises(ValueError):
        ChannelPowerDbmv.calculate_channel_power_dbmv(
            [0.0],
            25,
        )
