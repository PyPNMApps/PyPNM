# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from enum import Enum


class EchoDetectorType(Enum):
    """Echo detector types."""

    IFFT = 0
