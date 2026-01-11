# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonResponse,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.lib.operations.operation_models import OperationStatusModel
from pypnm.lib.types import (
    GroupId,
    InetAddressStr,
    MacAddressStr,
    OperationId,
    PathArray,
)


class MultiRxMerStartRequest(BaseModel):
    mac_address: MacAddressStr = Field(..., description="Cable modem MAC address")
    ip_address: InetAddressStr = Field(..., description="Cable modem IP address")
    duration: float = Field(..., ge=0, description="Capture duration in seconds")
    interval: float = Field(..., ge=0, description="Capture interval in seconds")


class MultiRxMerStartResponse(CommonResponse):
    operation_id: OperationId = Field(
        ..., description="Operation ID for status/result/cancel calls"
    )
    capture_group_id: GroupId = Field(..., description="Capture group identifier")


class MultiRxMerResultRequest(BaseModel):
    operation_id: OperationId = Field(..., description="Operation ID for result lookup")


class MultiRxMerResultResponse(CommonResponse):
    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )
    capture_group_id: GroupId = Field(..., description="Capture group identifier")
    transactions: list[TransactionRecordModel] = Field(
        ..., description="Resolved transaction record models."
    )
    artifact_paths: PathArray | None = Field(
        None, description="Resolved artifact paths from the operation."
    )


__all__ = [
    "MultiRxMerStartRequest",
    "MultiRxMerStartResponse",
    "MultiRxMerResultRequest",
    "MultiRxMerResultResponse",
]
