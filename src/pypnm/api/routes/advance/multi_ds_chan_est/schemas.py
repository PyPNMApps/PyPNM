# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from pypnm.api.routes.advance.analysis.signal_analysis.multi_chan_est_singnal_analysis import (
    MultiChanEstAnalysisType,
)
from pypnm.api.routes.advance.common.schema.common_capture_schema import (
    MultiCaptureParametersResponse,
    MultiCaptureRequest,
)
from pypnm.api.routes.advance.multi_rxmer.schemas import ChanEstMeasureParameters
from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonAnalysisResponse,
    CommonMatPlotConfigRequest,
    CommonOutput,
    CommonResponse,
)
from pypnm.lib.types import GroupId, OperationId


################################# HELPER MODEL ############################
class AnalysisDataModel(BaseModel):
    """Typed container for analysis output."""

    analysis_type: str = Field(..., description="Executed analysis type name.")
    results: list[dict[str, Any]] = Field(
        ...,
        description="List of per-channel analysis results (min/avg/max, group delay, anomalies, etc.).",
    )


class MultiChanEstAnalysisContainerModel(BaseModel):
    """Model for Multi-ChannelEstimation analysis types."""

    type: MultiChanEstAnalysisType = Field(
        default=MultiChanEstAnalysisType.MIN_AVG_MAX,
        description="Analysis type to perform, implementation-specific integer value",
    )
    output: CommonOutput = Field(
        default=CommonOutput(), description="Output type control: json or archive"
    )
    plot: CommonMatPlotConfigRequest = Field(
        default=CommonMatPlotConfigRequest(),
        description="Plot configuration for multi-ChannelEstimation analysis",
    )


class MultiChanEstAnalysisModel(BaseModel):
    """Request schema for performing signal analysis on a completed Multi-ChannelEstimation capture."""

    analysis: MultiChanEstAnalysisContainerModel = Field(
        default=MultiChanEstAnalysisContainerModel(),
        description="Analysis type to perform, implementation-specific integer value",
    )


################################# REQUEST #################################


class MultiChanEstAnalysisRequest(BaseModel):
    """Request schema for performing signal analysis on a completed Multi-ChannelEstimation capture."""

    analysis: MultiChanEstAnalysisContainerModel = Field(
        default=MultiChanEstAnalysisContainerModel(),
        description="Analysis type to perform, implementation-specific integer value",
    )
    operation_id: OperationId = Field(
        ..., description="Operation ID to query status/results."
    )


################################# RESPONSE #################################


class MultiChanEstRequest(MultiCaptureRequest):
    """Request schema for initiating a Multi-ChannelEstimation operation."""

    measure: ChanEstMeasureParameters = Field(
        ...,
        description="Measurement parameters for the Multi-ChannelEstimation operation.",
    )


class MultiChanEstimationResponseStatus(MultiCaptureParametersResponse):
    """Status details about a Multi-ChannelEstimation capture operation."""

    pass


class MultiChanEstimationStartResponse(CommonResponse):
    """Response returned when a multi-ChannelEstimation capture is kicked off."""

    group_id: GroupId = Field(..., description="Capture group ID for this session")
    operation_id: OperationId = Field(
        ..., description="Operation ID to query status/results"
    )


class MultiChanEstStatusResponse(CommonResponse):
    """Response schema for checking the status of a Multi-ChannelEstimation capture operation."""

    operation: MultiChanEstimationResponseStatus = Field(
        ...,
        description="Detailed operation-level state and sample count (operation_id, state, collected, time_remaining, message).",
    )


class MultiChanEstimationAnalysisResponse(CommonAnalysisResponse):
    """Response schema for Multi-ChannelEstimation signal analysis."""

    data: AnalysisDataModel = Field(
        ...,
        description="Structured analysis result container including the analysis_type and its corresponding per-channel results.",
    )
