from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    AnalysisType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CableModemPnmConfig,
    CommonMatPlotUiConfig,
    CommonOutput,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmDataResponse,
)
from pypnm.docsis.data_type.DsCmConstDisplay import (
    CmDsConstellationDisplayConst as ConsDisplaConstant,
)


class ConsDisplayAnalysisRequest(BaseModel):
    cable_modem: CableModemPnmConfig = Field(description="Cable modem configuration")
    analysis: ConsDisplayCaptureAnalysisType = Field(
        description="Analysis configuration for constellation display"
    )


class ConsDisplayMatPlotConfigOptions(BaseModel):
    display_cross_hair: bool = Field(
        default=True,
        description="Enable or disable crosshair on the constellation plot",
    )


class ConsDisplayMatPlotConfigRequest(BaseModel):
    ui: CommonMatPlotUiConfig = Field(
        default=CommonMatPlotUiConfig(),
        description="Matplotlib UI configuration for plot generation",
    )
    options: ConsDisplayMatPlotConfigOptions = Field(
        default=ConsDisplayMatPlotConfigOptions(),
        description="Plot configuration options",
    )


class ConsDisplayCaptureAnalysisType(BaseModel):
    type: AnalysisType = Field(
        default=AnalysisType.BASIC, description="Analysis type to perform"
    )
    output: CommonOutput = Field(
        description="Output format selection for single capture analysis"
    )
    plot: ConsDisplayMatPlotConfigRequest = Field(
        description="Plot configuration for single capture analysis"
    )


class ConstellationDisplaySettings(BaseModel):
    modulation_order_offset: int = Field(
        default=ConsDisplaConstant.MODULATION_OFFSET.value, description=""
    )
    number_sample_symbol: int = Field(
        default=ConsDisplaConstant.NUM_SAMPLE_SYMBOL.value, description=""
    )


class PnmConstellationDisplayAnalysisRequest(ConsDisplayAnalysisRequest):
    """Generic response container for most PNM operations."""

    capture_settings: ConstellationDisplaySettings = Field(
        description="Constellation display settings"
    )


class PnmConstellationDisplayResponse(PnmDataResponse):
    """Generic response container for most PNM operations."""
