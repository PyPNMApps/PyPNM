from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from pypnm.lib.types import StringEnum


class OutputType(StringEnum):
    JSON = "json"
    ARCHIVE = "archive"


class AnalysisType(StringEnum):
    BASIC = "basic"
