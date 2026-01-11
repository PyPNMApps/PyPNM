# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonAnalysisRequest,
    CommonRequest,
    CommonResponse,
    CommonSingleCaptureAnalysisRequest,
)
from pypnm.lib.types import ChannelId, FileNameStr, TransactionId


class PnmRequest(CommonRequest):
    """Request model used to trigger measurement-related operations on a cable modem."""

    pass


class PnmResponse(CommonResponse):
    """Generic response container for most PNM operations."""

    data: bytes | str | None | None = Field(
        default=None,
        description="Raw or structured data resulting from the operation (e.g., text, JSON, or binary).",
    )


class PnmFileRequest(CommonRequest):
    """Request model used when the operation requires access to a specific PNM file."""

    file_name: FileNameStr = Field(
        ..., description="Name of the file associated with the MAC address."
    )
    transaction_id: TransactionId = Field(
        description="Transaction identifier to track file operations or correlate requests."
    )


class PnmChannelEntryResponse(CommonResponse):
    """Response model containing detailed OFDM or OFDMA channel entry data."""

    index: int = Field(
        default=0,
        description="Index in the channel table (e.g., OFDM/OFDMA channel number).",
    )
    channel_id: ChannelId = Field(
        description="Logical channel ID assigned by the CMTS."
    )
    entry: dict[str, Any] = Field(
        default={}, description="Dictionary of all fields for this channel entry."
    )


class PnmFileResponse(CommonResponse):
    """Response model for file-related operations, such as retrieving or listing PNM files."""

    file_name: FileNameStr = Field(
        ..., description="Name of the PNM-related file returned by the operation."
    )
    data: bytes | str | Any | None = Field(
        default=None,
        description="Contents of the file or relevant metadata (could be binary or string).",
    )


class PnmAnalysisResponse(CommonResponse):
    """Response model that contains data structured for plotting PNM metrics."""

    data: dict[Any, Any] = Field(
        ...,
        description="Structured data (e.g., series of x/y points or histogram bins) used to generate plots.",
    )


class PnmAnalysisRequest(CommonAnalysisRequest):
    """Request model that contains data structured for plotting PNM metrics."""


class PnmSingleCaptureRequest(CommonSingleCaptureAnalysisRequest):
    """Request model that contains data structured for plotting PNM metrics."""


class PnmDataResponse(CommonResponse):
    """Flexible response container for PNM operations returning generic dictionary data."""

    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Dictionary of key-value data returned from the PNM operation.",
    )


class PnmMeasurementResponse(CommonResponse):
    """Response model used for returning measurement values collected from the modem."""

    measurement: dict[Any, Any] = Field(
        default_factory=dict,
        description="Raw or structured data resulting from the operation (e.g., text, JSON, or binary).",
    )

    @field_validator("measurement", mode="before")
    def wrap_measurement_in_key(cls, v: object) -> dict[Any, Any] | dict[str, Any]:
        """
        Ensures that if the input is not a dictionary, it gets wrapped under a 'data' key.
        """
        if isinstance(v, dict):
            return v
        return {"data": v}
