# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field
from pypnm.lib.operations.operation_models import OperationStatusModel

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonResponse,
)
from pypnm.lib.types import OperationId


class OperationRequest(BaseModel):
    """
    Request body carrying a PyPNM operation identifier.
    """

    operation_id: OperationId = Field(
        ..., description="Operation ID for status/cancel/result calls."
    )


class OperationStatusResponse(CommonResponse):
    """
    Response containing the latest operation status record.
    """

    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )


class OperationCancelResponse(CommonResponse):
    """
    Response returned after a cancel request.
    """

    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )


class OperationResultResponse(CommonResponse):
    """
    Response returned for result requests.
    """

    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )


__all__ = [
    "OperationRequest",
    "OperationStatusResponse",
    "OperationCancelResponse",
    "OperationResultResponse",
]
