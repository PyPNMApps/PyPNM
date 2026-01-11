# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonResponse,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.operations.operation_models import OperationStatusModel
from pypnm.lib.types import OperationId


class OperationStartRequest(BaseModel):
    """
    Request body for creating a generic operation entry.
    """

    progress_total: int = Field(..., ge=1, description="Total expected work units.")
    message: str | None = Field(
        default=None, description="Optional message for operation creation."
    )


class OperationRequest(BaseModel):
    """
    Request body carrying an operation identifier.
    """

    operation_id: OperationId = Field(
        ..., description="Operation ID for status/cancel/result calls."
    )


class OperationStartResponse(CommonResponse):
    """
    Response returned after creating a generic operation entry.
    """

    service_status: ServiceStatusCode = Field(
        default=ServiceStatusCode.SUCCESS,
        description="Canonical ServiceStatusCode for this response.",
    )
    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )
    time_remaining: int = Field(
        ..., description="Seconds remaining for the operation (0 when unknown)."
    )


class OperationStatusResponse(CommonResponse):
    """
    Response containing the latest operation status record.
    """

    service_status: ServiceStatusCode = Field(
        default=ServiceStatusCode.SUCCESS,
        description="Canonical ServiceStatusCode for this response.",
    )
    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )
    time_remaining: int = Field(
        ..., description="Seconds remaining for the operation (0 when unknown)."
    )


class OperationCancelResponse(CommonResponse):
    """
    Response returned after a cancel request.
    """

    service_status: ServiceStatusCode = Field(
        default=ServiceStatusCode.SUCCESS,
        description="Canonical ServiceStatusCode for this response.",
    )
    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )


class OperationResultResponse(CommonResponse):
    """
    Response returned for result requests.
    """

    service_status: ServiceStatusCode = Field(
        default=ServiceStatusCode.SUCCESS,
        description="Canonical ServiceStatusCode for this response.",
    )
    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )


__all__ = [
    "OperationStartRequest",
    "OperationRequest",
    "OperationStartResponse",
    "OperationStatusResponse",
    "OperationCancelResponse",
    "OperationResultResponse",
]
