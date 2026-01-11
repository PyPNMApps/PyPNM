from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from enum import IntEnum


class ClabsDocsisVersion(IntEnum):
    """
    Enum representing DOCSIS RF specification versions.
    Maps to the ClabsDocsisVersion textual convention used in SNMP MIBs.
    """

    OTHER = 0
    DOCSIS_10 = 1
    DOCSIS_11 = 2
    DOCSIS_20 = 3
    DOCSIS_30 = 4
    DOCSIS_31 = 5
    DOCSIS_40 = 6

    def __str__(self) -> str:
        return self.name.replace("DOCSIS_", "DOCSIS ").replace("_", ".")

    @classmethod
    def from_value(cls, value: int) -> ClabsDocsisVersion:
        try:
            return cls(value)
        except ValueError:
            return cls.OTHER
