from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpRequest,
)


class CodewordErrorRateSample(BaseModel):
    """
    Represents a single sample of codeword error rate data.
    """

    sample_time_elapsed: int = Field(
        default=5,
        description="Time elapse between Codeword Counters, default is 5 seconds.",
    )


class CodewordErrorRateRequest(SnmpRequest):
    capture_parameters: CodewordErrorRateSample = Field(
        ..., description="Parameters for capturing codeword error rate data."
    )
