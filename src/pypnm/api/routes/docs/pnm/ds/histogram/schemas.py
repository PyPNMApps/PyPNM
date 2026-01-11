# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmMeasurementResponse,
    PnmRequest,
    PnmSingleCaptureRequest,
)


class HistogramCaptureSettings(BaseModel):
    sample_duration: int = Field(
        default=10, description="Histogram Sample Duration in seconds"
    )


class PnmHistogramRequest(PnmRequest):
    capture_settings: HistogramCaptureSettings = Field(
        description="Histogram Capture Settings"
    )


class PnmHistogramResponse(PnmMeasurementResponse):
    """Generic response container for most PNM operations."""


class PnmHistogramAnalysisRequest(PnmSingleCaptureRequest):
    capture_settings: HistogramCaptureSettings = Field(
        description="Histogram Capture Settings"
    )
