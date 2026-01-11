# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.types import OperationId, PathArray, TimeStamp


class OperationStatusModel(BaseModel):
    """
    Filesystem-backed operation status record.
    """

    operation_id: OperationId = Field(
        ..., description="Operation identifier used for status/cancel/result calls."
    )
    state: OperationExecutionState = Field(
        ..., description="Execution state for the operation lifecycle."
    )
    created_ts: TimeStamp = Field(
        ..., description="Creation timestamp (epoch seconds)."
    )
    updated_ts: TimeStamp = Field(
        ..., description="Last update timestamp (epoch seconds)."
    )
    progress_current: int = Field(
        ..., description="Current completed units for the operation."
    )
    progress_total: int = Field(
        ..., description="Total expected units for the operation."
    )
    message: str = Field(..., description="Human-readable operation status message.")
    error: str | None = Field(
        None, description="Optional error details when failures occur."
    )
    artifact_paths: PathArray | None = Field(
        None, description="Optional list of generated artifact paths."
    )


__all__ = ["OperationStatusModel"]
