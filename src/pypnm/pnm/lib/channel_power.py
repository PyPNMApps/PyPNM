# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import math

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
