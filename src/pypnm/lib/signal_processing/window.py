# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.lib.types import StringEnum


class SignalWindow(StringEnum):
    """Supported window functions for generic signal-processing transforms."""

    HANN = "hann"
    NONE = "none"
    RECTANGULAR = "rectangular"

    @classmethod
    def coerce(cls, value: SignalWindow | str) -> SignalWindow:
        if isinstance(value, cls):
            return value

        key = value.strip().lower()
        if key in ("hann", "hanning"):
            return cls.HANN
        if key in ("none", "rect", "rectangular"):
            return cls.NONE
        raise ValueError(f"Unsupported window '{value}'. Supported: hann, none")
