# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field

from pypnm.lib.types import FloatSeries, FrequencyHz, FrequencySeriesHz, ProfileId


class CarrierItemModel(BaseModel):
    """Per-carrier record."""

    frequency: FrequencyHz = Field(..., description="Carrier center frequency (Hz)")
    modulation: str = Field(
        ..., description="Modulation-Order-Type (e.g., 'qam_256', 'plc', 'exclusion')"
    )
    shannon_min_mer: float = Field(
        ..., description="Minimum supported Shannon MER (dB) for the modulation"
    )


class CarrierValuesSplitModel(BaseModel):
    """Parallel-array layout (compact, vector-friendly)."""

    layout: Literal["split"] = Field("split", description="Layout discriminator")
    frequency: FrequencySeriesHz = Field(
        default_factory=list, description="Frequencies (Hz)"
    )
    modulation: list[str] = Field(
        default_factory=list, description="Per-carrier modulation names"
    )
    shannon_min_mer: FloatSeries = Field(
        default_factory=list, description="Per-carrier Shannon minimum MER (dB)"
    )


class CarrierValuesListModel(BaseModel):
    """Verbose list layout (easier for debugging/logging)."""

    layout: Literal["list"] = Field("list", description="Layout discriminator")
    carriers: list[CarrierItemModel] = Field(
        default_factory=list, description="Per-carrier records"
    )


CarrierValuesModel = Annotated[
    CarrierValuesSplitModel | CarrierValuesListModel, Field(discriminator="layout")
]


class ProfileAnalysisEntryModel(BaseModel):
    """Per-profile container of carrier values."""

    profile_id: ProfileId = Field(..., ge=0, description="Profile identifier")
    carrier_values: CarrierValuesModel
