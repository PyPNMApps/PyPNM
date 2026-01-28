# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdma_pre_eq_signal_analysis import (
    MultiOfdmaPreEqAnalysisType,
)
from pypnm.api.routes.advance.common.schema.common_capture_schema import (
    MultiCaptureParametersResponse,
    MultiCaptureRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonAnalysisResponse,
    CommonMatPlotConfigRequest,
    CommonOutput,
    CommonResponse,
)
from pypnm.lib.types import GroupId, OperationId


class MultiUsOfdmaPreEqMeasureModes(IntEnum):
    STANDARD = 0


class UsOfdmaPreEqMeasureParameters(BaseModel):
    mode: MultiUsOfdmaPreEqMeasureModes = Field(default=MultiUsOfdmaPreEqMeasureModes.STANDARD, description="Measurement mode: 0 for standard US OFDMA pre-equalization capture")
class AnalysisDataModel(BaseModel):
    """Typed container for analysis output."""
    analysis_type: str              = Field(..., description="Executed analysis type name.")
    results: list[dict[str, Any]]   = Field(..., description="List of per-channel analysis results (min/avg/max, group delay, anomalies, etc.).")

class MultiUsOfdmaPreEqAnalysisContainerModel(BaseModel):
    """Model for Multi-US-OFDMA Pre-Equalization analysis types."""
    type: MultiOfdmaPreEqAnalysisType   = Field(default=MultiOfdmaPreEqAnalysisType.MIN_AVG_MAX, description="Analysis type to perform, implementation-specific integer value")
    output: CommonOutput                = Field(default=CommonOutput(), description="Output type control: json or archive")
    plot: CommonMatPlotConfigRequest    = Field(default=CommonMatPlotConfigRequest(), description="Plot configuration for multi-ChannelEstimation analysis")

class MultiUsOfdmaPreEqAnalysisModel(BaseModel):
    """Request schema for performing signal analysis on a completed Multi-ChannelEstimation capture."""
    analysis: MultiUsOfdmaPreEqAnalysisContainerModel = Field(default=MultiUsOfdmaPreEqAnalysisContainerModel(), description="Analysis type to perform, implementation-specific integer value")

################################# REQUEST #################################

class MultiUsOfdmaPreEqAnalysisRequest(BaseModel):
    """Request schema for performing signal analysis on a completed Multi-ChannelEstimation capture."""
    analysis: MultiUsOfdmaPreEqAnalysisContainerModel = Field(default=MultiUsOfdmaPreEqAnalysisContainerModel(), description="Analysis type to perform, implementation-specific integer value")
    operation_id: OperationId               = Field(..., description="Operation ID to query status/results.")

################################# RESPONSE #################################

class MultiUsOfdmaPreEqRequest(MultiCaptureRequest):
    """Request schema for initiating a Multi-ChannelEstimation operation."""
    measure:UsOfdmaPreEqMeasureParameters = Field(..., description="Measurement parameters for the Multi-ChannelEstimation operation.")

class MultiUsOfdmaPreEqResponseStatus(MultiCaptureParametersResponse):
    """Status details about a Multi-ChannelEstimation capture operation."""
    pass

class MultiUsOfdmaPreEqStartResponse(CommonResponse):
    """Response returned when a multi-ChannelEstimation capture is kicked off."""
    group_id: GroupId           = Field(..., description="Capture group ID for this session")
    operation_id: OperationId   = Field(..., description="Operation ID to query status/results")

class MultiUsOfdmaPreEqStatusResponse(CommonResponse):
    """Response schema for checking the status of a Multi-ChannelEstimation capture operation."""
    operation: MultiUsOfdmaPreEqResponseStatus = Field(..., description="Detailed operation-level state and sample count (operation_id, state, collected, time_remaining, message).")

class MultiUsOfdmaPreEqAnalysisResponse(CommonAnalysisResponse):
    """Response schema for Multi-ChannelEstimation signal analysis."""
    data: AnalysisDataModel = Field(..., description="Structured analysis result container including the analysis_type and its corresponding per-channel results.")
