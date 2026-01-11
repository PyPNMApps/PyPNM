# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from enum import IntEnum


class DsOfdmModulationType(IntEnum):
    UNKNOWN = -1
    other = 1
    zeroValued = 2
    qpsk = 3
    qam16 = 4
    qam64 = 5
    qam128 = 6
    qam256 = 7
    qam512 = 8
    qam1024 = 9
    qam2048 = 10
    qam4096 = 11
    qam8192 = 12
    qam16384 = 13

    @classmethod
    def from_value(cls, value: int) -> DsOfdmModulationType:
        """Convert integer to corresponding DsOfdmModulationType enum member."""
        member = cls._value2member_map_.get(value, cls.UNKNOWN)
        return member  # type: ignore[return-value]

    @classmethod
    def get_name(cls, value: int) -> str:
        """
        Return the string name of the enum corresponding to the given integer value.
        Returns 'UNKNOWN' if the value is not defined.
        """
        return cls._value2member_map_.get(value, cls.UNKNOWN).name
