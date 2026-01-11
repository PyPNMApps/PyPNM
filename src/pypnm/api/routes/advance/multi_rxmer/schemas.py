# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field

from pypnm.api.routes.advance.analysis.signal_analysis.multi_rxmer_signal_analysis import (
    MultiRxMerAnalysisType,
)
from pypnm.api.routes.advance.common.schema.common_capture_schema import (
    MultiCaptureRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonAnalysisResponse,
    CommonMatPlotConfigRequest,
    CommonOutput,
    CommonResponse,
)
from pypnm.lib.types import OperationId


class MultiRxMerMeasureModes(IntEnum):
    CONTINUOUS = 0
    OFDM_PERFORMANCE_1 = 1


class MultiChanEstModes(IntEnum):
    STANDARD = 0


class ChanEstMeasureParameters(BaseModel):
    mode: MultiChanEstModes = Field(
        default=MultiChanEstModes.STANDARD,
        description="Measurement mode: 0 for standard channel estimation capture",
    )


class RxMerMeasureParameters(BaseModel):
    mode: MultiRxMerMeasureModes = Field(
        default=MultiRxMerMeasureModes.OFDM_PERFORMANCE_1,
        description="Measurement mode: 0 for continuous, 1 for OFDM performance context",
    )


class MultiRxMerRequest(MultiCaptureRequest):
    measure: RxMerMeasureParameters


class MultiRxMerResponseStatus(BaseModel):
    """
    Details about a Multi-RxMER capture operation’s current state.
    """

    operation_id: str = Field(
        ..., description="Unique identifier for this multi-RxMER operation."
    )
    state: str = Field(
        ...,
        description="Current state of the operation (e.g., 'running', 'completed', 'stopped').",
    )
    collected: int = Field(..., description="Number of RxMER samples collected so far.")
    time_remaining: int = Field(..., description="Measure time remaining in seconds.")
    message: str | None = Field(
        None, description="Optional human-readable message or error detail."
    )


class MultiRxMerResponse(CommonResponse):
    """
    Standard wrapper for Multi-RxMER operation responses.

    Inherits:
      - `mac_address` (str)
      - `status`   (success|error)
      - `message`  (overall error or info)

    Adds:
      - `operation` for the nested operation-status details.
    """

    operation: MultiRxMerResponseStatus = Field(
        ..., description="Nested object describing the multi-RxMER operation status."
    )


class MultiRxMerResultsResponse(CommonResponse):
    """
    Returns the final list of capture samples for a completed or in-progress operation.
    """

    samples: list[dict] = Field(
        ...,
        description="Timestamped transaction info for each RxMER capture iteration.",
    )


class MultiRxMerStartResponse(CommonResponse):
    """
    Response returned when a multi-RxMER capture is kicked off.

    Inherits:
      - mac_address  (echoed back)
      - status       ("success" or "error")
      - message      (optional error/info)

    Adds:
      - operation_id: Unique identifier for the background capture session.
    """

    group_id: str = Field(..., description="Capture group ID for this session")
    operation_id: str = Field(..., description="Operation ID to query status/results")


class MultiRxMerStatusResponse(CommonResponse):
    """
    Response schema for checking the status of a Multi-RxMER capture operation.

    Inherits:
        mac_address (str):
            The target cable modem’s MAC address, echoed from the request.
        status (Literal["success", "error"]):
            Overall HTTP-level outcome of this call.
        message (Optional[str]):
            Optional informational or error message at the call level.

    Adds:
        operation (MultiRxMerResponseStatus):
            Detailed operation-level result, including:

            - operation_id (str):
                The 16-hex ID for this capture session.
            - state (OperationState):
                Current capture state: RUNNING, STOPPED, COMPLETED, or UNKNOWN.
            - collected (int):
                Number of `CaptureSample`s successfully gathered so far.
            - message (Optional[str]):
                Optional operation-specific message or warning.

    Example:
    ```json
    {
        "mac_address": "00:11:22:33:44:55",
        "status": "success",
        "message": null,
        "operation": {
            "operation_id": "abcd1234efgh5678",
            "state": "RUNNING",
            "collected": 5,
            "message": null
        }
    }
    ```
    """

    operation: MultiRxMerResponseStatus = Field(
        ...,
        description=(
            "Detailed operation-level state and sample count:\n"
            "- `operation_id`: capture run ID\n"
            "- `state`: RUNNING|STOPPED|COMPLETED|UNKNOWN\n"
            "- `collected`: number of samples so far\n"
            "- `message`: optional per-operation message"
        ),
    )


class MultiRxMerAnalysisRequest(BaseModel):
    analysis: MultiRxMerAnalysisConfig = Field(
        ..., description="Multi-RxMER analysis configuration"
    )
    operation_id: OperationId = Field(
        ..., description="Operation ID to query status/results"
    )


class MultiRxMerAnalysisResponse(CommonAnalysisResponse):
    """
    Response schema for Multi-RxMER signal analysis, keyed by channel ID.
    """

    data: dict[int, dict[str, Any]] = Field(
        ...,
        description=(
            "Mapping from channel_id to its analysis results "
            "(frequency, min, avg, max lists)."
        ),
    )


class MultiRxMerAnalysisConfig(BaseModel):
    type: MultiRxMerAnalysisType = Field(
        default=MultiRxMerAnalysisType.MIN_AVG_MAX,
        description="Analysis type to perform, implementation-specific integer value",
    )
    output: CommonOutput = Field(description="Output type control: json or archive")
    plot: CommonMatPlotConfigRequest = Field(
        description="Plot configuration for multi-RxMER analysis"
    )


__all__ = [
    "MultiRxMerMeasureModes",
    "RxMerMeasureParameters",
    "MultiRxMerRequest",
    "MultiRxMerResponseStatus",
    "MultiRxMerResponse",
    "MultiRxMerResultsResponse",
    "MultiRxMerStartResponse",
    "MultiRxMerStatusResponse",
    "MultiRxMerAnalysisRequest",
    "MultiRxMerAnalysisResponse",
    "MultiRxMerAnalysisConfig",
]
