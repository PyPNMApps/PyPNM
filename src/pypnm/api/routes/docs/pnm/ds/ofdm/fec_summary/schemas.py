from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmDataResponse,
    PnmRequest,
    PnmSingleCaptureRequest,
)
from pypnm.docsis.cm_snmp_operation import FecSummaryType


class PnmFecSummaryRequest(PnmRequest):
    """Request model used to trigger measurement-related operations on a cable modem."""

    fec_summary_type: int = Field(
        default=int(FecSummaryType.TEN_MIN.value),
        description="FEC Summuary 10 Min = 2, 24 Hr = 3",
    )


class PnmFecSummaryResponse(PnmDataResponse):
    """Generic response container for most PNM operations."""


class FecSummaryCaptureSettings(BaseModel):
    fec_summary_type: FecSummaryType = Field(
        default=FecSummaryType.TEN_MIN, description="FEC Summuary 10 Min = 2, 24 Hr = 3"
    )


class PnmFecSummaryAnalysisRequest(PnmSingleCaptureRequest):
    capture_settings: FecSummaryCaptureSettings
