# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field

from pypnm.api.routes.advance.analysis.signal_analysis.multi_chan_est_singnal_analysis import (
    MultiChanEstAnalysisType,
)
from pypnm.api.routes.advance.common.operation_state import OperationState
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
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.lib.operations.operation_models import OperationStatusModel
from pypnm.lib.types import GroupId, OperationId, PathArray


################################# HELPER MODEL ############################
class AnalysisDataModel(BaseModel):
    """Typed container for analysis output."""

    analysis_type: str = Field(..., description="Executed analysis type name.")
    results: list[dict[str, Any]] = Field(
        ...,
        description="List of per-channel analysis results (min/avg/max, group delay, anomalies, etc.).",
    )


class MultiChanEstModes(IntEnum):
    STANDARD = 0


class MultiChanEstMeasureParameters(BaseModel):
    mode: MultiChanEstModes = Field(
        default=MultiChanEstModes.STANDARD,
        description="Measurement mode: 0 for standard channel estimation capture",
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

    measure: MultiChanEstMeasureParameters | None = Field(
        default=None,
        description="Legacy measurement parameters (deprecated; currently unused).",
    )


class MultiChanEstimationResponseStatus(MultiCaptureParametersResponse):
    """Status details about a Multi-ChannelEstimation capture operation."""

    pass


class MultiChanEstimationStartResponse(CommonResponse):
    """Response returned when a multi-ChannelEstimation capture is kicked off."""

    group_id: GroupId = Field(..., description="Legacy capture group ID (deprecated).")
    capture_group_id: GroupId = Field(
        ..., description="Capture group ID for this session (canonical)."
    )
    operation_id: OperationId = Field(
        ..., description="Operation ID to query status/results"
    )
    operation_state: OperationState | None = Field(
        default=None, description="Operation state (legacy convenience field)."
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


class MultiChanEstimationResultResponse(CommonResponse):
    """Response schema for completed Multi-ChannelEstimation capture results."""

    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )
    capture_group_id: GroupId = Field(..., description="Capture group identifier.")
    transactions: list[TransactionRecordModel] = Field(
        ..., description="Resolved transaction record models."
    )
    artifact_paths: PathArray | None = Field(
        None, description="Optional artifact paths persisted for the operation."
    )
