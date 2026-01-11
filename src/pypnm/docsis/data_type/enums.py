from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from enum import Enum


class MeasStatusType(Enum):
    """
    Enumeration of measurement status types as defined in DOCSIS 3.1 CM-OSSI.
    """

    OTHER = 1  # Any state not described below
    INACTIVE = 2  # Test not started or in progress
    BUSY = 3  # Test is in progress
    SAMPLE_READY = 4  # Test completed, data ready
    ERROR = 5  # Error occurred, data may be invalid
    RESOURCE_UNAVAILABLE = 6  # Test could not start due to lack of resources
    SAMPLE_TRUNCATED = 7  # Requested data exceeds supported file size
    INTERFACE_MODIFICATION = (
        8  # Interface numbering changed due to DBC or primary backup switch
    )

    def __str__(self) -> str:
        return self.name.lower()
