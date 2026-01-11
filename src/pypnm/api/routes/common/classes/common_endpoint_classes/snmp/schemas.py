# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonRequest,
    CommonResponse,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    BaseDeviceConnectRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_response import (
    BaseDeviceResponse,
)


class SnmpRequest(BaseDeviceConnectRequest):
    """
    Request model used to trigger measurement-related SNMP operations on a cable modem.
    Inherits MAC and IP from CommonRequest.
    """


class SnmpResponse(BaseDeviceResponse):
    """
    Generic SNMP response model supporting raw or structured output.

    Attributes:
        results (Optional[Union[bytes, str, Dict[str, Any], Any]]):
            - `bytes` for raw binary payloads.
            - `str` for plain-text outputs.
            - `Dict[str, Any]` or any structured data.
    """

    results: bytes | str | dict[str, Any] | Any | BaseModel | None = Field(
        default={},
        description=(
            "Raw or structured data resulting from the SNMP operation: "
            "bytes, text, or a structured dict/model."
        ),
    )


class SnmpAnalysisSpec(BaseModel):
    """
    Describes the specification of an SNMP analysis request.
    """

    type: int = Field(
        ..., description="Type identifier for the SNMP analysis to be performed."
    )


class SnmpAnalysisRequest(CommonRequest):
    """
    Request model for triggering SNMP-based analysis with specific parameters.
    """

    analysis: SnmpAnalysisSpec = Field(
        ..., description="Specification of the analysis to be run on the target device."
    )


class SnmpAnalysisResponse(CommonResponse):
    """
    Response model for SNMP-based analysis operations.
    """

    data: bytes | str | None = Field(
        default=None,
        description="Structured or raw result of the SNMP analysis operation.",
    )
