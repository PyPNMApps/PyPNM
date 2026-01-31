# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import SpecAnCapturePara
from pypnm.lib.types import FrequencyHz, PowerdBmV, StringEnum


class CommonMessagingServiceExtension(StringEnum):
    SPECTRUM_ANALYSIS_SNMP_CAPTURE_PARAMETER = "spectrum_analysis_snmp_capture_parameters"
    SPECTRUM_ANALYSIS_SNMP_SEGMENT_POWER = "measure_segment_power"

class SpectrumAnalysisSnmpSegmentPowerEntry(BaseModel):
    segment_frequencies: list[FrequencyHz] = Field(default_factory=list, description="Segment center frequencies in Hz for the spectrum analyzer measurement.")
    power_dbmv: list[PowerdBmV] = Field(default_factory=list, description="Total segment power values in dBmV for the spectrum analyzer measurement.")

class CommonMsgServiceExtParams(BaseModel):
    spectrum_analysis_snmp_capture_parameters: SpecAnCapturePara = Field(..., description="Spectrum analyzer SNMP capture parameters for the transaction.")
    spectrum_analysis_snmp_segment_power: list[SpectrumAnalysisSnmpSegmentPowerEntry] = Field(default_factory=list, description="Spectrum analyzer SNMP segment power entries captured with amplitude data.")

class CommonMessagingServiceExtensionModel(BaseModel):
    extension: CommonMsgServiceExtParams = Field(..., description="Extension metadata for transaction messages.")
