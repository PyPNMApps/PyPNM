# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from pypnm.lib.types import FrequencyHz


class SpecAnalysisSnmpConfigModel(BaseModel):
    """
    Parsed spectrum configuration header from the SNMP AmplitudeData payload.

    This captures the effective frequency range, bin structure, and resolution
    parameters derived from the first successfully parsed spectrum group.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)
    start_frequency: FrequencyHz = Field(
        ..., ge=0, description="Lower frequency edge of the parsed spectrum in Hz."
    )
    end_frequency: FrequencyHz = Field(
        ..., ge=0, description="Upper frequency edge of the parsed spectrum in Hz."
    )
    frequency_span: FrequencyHz = Field(
        ..., ge=0, description="Total covered spectrum span in Hz (end - start)."
    )
    total_bins: int = Field(
        ..., ge=0, description="Number of bins in the first parsed spectrum group."
    )
    bin_spacing: FrequencyHz = Field(
        ..., ge=0, description="Frequency spacing between adjacent bins in Hz."
    )
    resolution_bandwidth: FrequencyHz = Field(
        ...,
        ge=0,
        description="Resolution bandwidth used for the spectrum measurement in Hz.",
    )
