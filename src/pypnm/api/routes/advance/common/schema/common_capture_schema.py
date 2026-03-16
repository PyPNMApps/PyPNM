# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.advance.common.operation_kind import MultiCaptureOperationModel
from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CableModemPnmConfig,
    CommonResponse,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_response import (
    BaseDeviceResponse,
)
from pypnm.lib.types import GroupId, MacAddressStr, OperationId, TimestampSec


class CaptureParameters(BaseModel):
    """Parameters controlling a multi-sample RxMER capture operation."""
    measurement_duration: int = Field(..., ge=1, description="Total duration in seconds over which to collect RxMER samples.")
    sample_interval:      int = Field(..., ge=1, description="Interval in seconds between successive RxMER captures.")

class MultiCaptureParametersRequest(BaseModel):
    """Wrapper for capture parameter payload."""
    parameters: CaptureParameters = Field(..., description="Capture parameter set applied to this operation.")

class MultiCaptureRequest(BaseModel):
    """Top-level request to start a multi-capture operation."""
    cable_modem: CableModemPnmConfig            = Field(..., description="Target cable modem addressing and SNMP/TFTP parameters.")
    capture:     MultiCaptureParametersRequest  = Field(..., description="Multi-capture parameters (duration, interval, etc.).")

class MultiCaptureParametersResponse(BaseDeviceResponse):
    """Details about a multi-capture operation’s current state."""
    operation_id:   OperationId  = Field(..., description="Unique identifier for this multi-capture operation.")
    state:          str  = Field(..., description="Current state of the operation (e.g., 'running', 'completed', 'stopped').")
    collected:      int  = Field(..., description="Number of samples collected so far.")
    time_remaining: int  = Field(..., description="Remaining time in seconds.")
    message:        str | None = Field(default="", description="Optional human-readable message or error detail.")


class MultiCapturePersistedMetadataModel(BaseModel):
    """Known persisted metadata attached to a multi-capture operation record."""

    mac_address: MacAddressStr | None = Field(default=None, description="Cable modem MAC address captured when the operation was started.")
    system_description: dict[str, str] = Field(default_factory=dict, description="Persisted system-description fields captured when the operation was started.")


class MultiCapturePersistedRecordModel(BaseModel):
    """Persisted multi-capture operation record stored by operation ID."""

    capture_group_id: GroupId = Field(..., description="Capture-group identifier associated with the persisted operation.")
    created: TimestampSec = Field(..., description="Unix epoch seconds when the operation record was created.")
    operation: MultiCaptureOperationModel = Field(..., description="Canonical operation identity and measure-mode metadata.")
    metadata: MultiCapturePersistedMetadataModel = Field(default_factory=MultiCapturePersistedMetadataModel, description="Additional persisted metadata such as MAC address and system description.")


class MultiCaptureOperationIdResponse(CommonResponse):
    """Collection of persisted operation records keyed by operation ID."""

    operations: dict[OperationId, MultiCapturePersistedRecordModel] = Field(default_factory=dict, description="Persisted operation records keyed by operation ID for the requested operation family.")
