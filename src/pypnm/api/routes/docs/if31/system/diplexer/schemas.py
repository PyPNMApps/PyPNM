from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_response import (
    BaseDeviceResponse,
)


class DiplexerConfig(BaseModel):
    """
    Response model for DOCSIS 3.1 diplexer configuration.
    Represents frequency split capabilities and configuration for upstream and downstream bands.
    """

    diplexer_capability: int = Field(
        ..., description="Bitmask representing supported diplexer configurations."
    )
    cfg_band_edge: int = Field(
        ..., description="Configured diplexer band edge frequency in kHz."
    )
    ds_lower_capability: int = Field(
        ..., description="Lower frequency limit capability for downstream band in kHz."
    )
    cfg_ds_lower_band_edge: int = Field(
        ..., description="Configured lower edge of downstream band in kHz."
    )
    ds_upper_capability: int = Field(
        ..., description="Upper frequency limit capability for downstream band in kHz."
    )
    cfg_ds_upper_band_edge: int = Field(
        ..., description="Configured upper edge of downstream band in kHz."
    )


class DiplexerConfigResult(BaseModel):
    diplexer: DiplexerConfig


class DiplexerResponse(BaseDeviceResponse):
    results: DiplexerConfigResult = Field(
        ..., description="Configured upper edge of downstream band in kHz."
    )
