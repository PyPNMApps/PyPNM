# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CableModemPnmConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_response import (
    BaseDeviceResponse,
)
from pypnm.lib.types import OperationId


class CaptureParameters(BaseModel):
    """Parameters controlling a multi-sample RxMER capture operation."""

    measurement_duration: int = Field(
        ...,
        ge=1,
        description="Total duration in seconds over which to collect RxMER samples.",
    )
    sample_interval: int = Field(
        ..., ge=1, description="Interval in seconds between successive RxMER captures."
    )


class MultiCaptureParametersRequest(BaseModel):
    """Wrapper for capture parameter payload."""

    parameters: CaptureParameters = Field(
        ..., description="Capture parameter set applied to this operation."
    )


class MultiCaptureRequest(BaseModel):
    """Top-level request to start a multi-capture operation."""

    cable_modem: CableModemPnmConfig = Field(
        ..., description="Target cable modem addressing and SNMP/TFTP parameters."
    )
    capture: MultiCaptureParametersRequest = Field(
        ..., description="Multi-capture parameters (duration, interval, etc.)."
    )


class MultiCaptureParametersResponse(BaseDeviceResponse):
    """Details about a multi-capture operation’s current state."""

    operation_id: OperationId = Field(
        ..., description="Unique identifier for this multi-capture operation."
    )
    state: str = Field(
        ...,
        description="Current state of the operation (e.g., 'running', 'completed', 'stopped').",
    )
    collected: int = Field(..., description="Number of samples collected so far.")
    time_remaining: int = Field(..., description="Remaining time in seconds.")
    message: str | None = Field(
        default="", description="Optional human-readable message or error detail."
    )
