# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CableModemPnmConfig,
    CommonSingleCaptureAnalysisType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
    PnmDataResponse,
    PnmSingleCaptureRequest,
)
from pypnm.lib.types import FrequencyHz
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import (
    SpectrumRetrievalType,
    WindowFunction,
)


class SpecAnMovingAvgParameters(BaseModel):
    points: int = Field(default=10, description="")


class SpecAnCapturePara(BaseModel):
    inactivity_timeout: int = Field(
        default=60,
        description="Timeout in seconds for inactivity during spectrum analysis.",
    )
    first_segment_center_freq: FrequencyHz = Field(
        default=FrequencyHz(300_000_000),
        description="First segment center frequency in Hz.",
    )
    last_segment_center_freq: FrequencyHz = Field(
        default=FrequencyHz(900_000_000),
        description="Last segment center frequency in Hz.",
    )
    segment_freq_span: FrequencyHz = Field(
        default=FrequencyHz(1_000_000),
        description="Frequency span of each segment in Hz.",
    )
    num_bins_per_segment: int = Field(
        default=256, description="Number of FFT bins per segment."
    )
    noise_bw: int = Field(default=150, description="Equivalent noise bandwidth in kHz.")
    window_function: WindowFunction = Field(
        default=WindowFunction.HANN,
        description="FFT window function to apply. See WindowFunction enum for options.",
    )
    num_averages: int = Field(default=1, description="Number of averages per segment.")
    spectrum_retrieval_type: SpectrumRetrievalType = Field(
        default=SpectrumRetrievalType.FILE,
        description=f"Method of spectrum data retrieval: "
        f"PNM ({SpectrumRetrievalType.FILE}) | "
        f"SNMP({SpectrumRetrievalType.SNMP}).",
    )


class SpectrumAnalysisExtention(BaseModel):
    moving_average: SpecAnMovingAvgParameters = Field(
        default=SpecAnMovingAvgParameters(), description=""
    )


class ExtendCommonSingleCaptureAnalysisType(CommonSingleCaptureAnalysisType):
    spectrum_analysis: SpectrumAnalysisExtention = Field(
        description="Spectrum Analysis Extension"
    )


class ExtendSingleCaptureSpecAnaRequest(BaseModel):
    cable_modem: CableModemPnmConfig = Field(description="Cable modem configuration")
    analysis: ExtendCommonSingleCaptureAnalysisType = Field(
        description="Analysis type to perform"
    )


class ExtendPnmSingleCaptureRequest(PnmSingleCaptureRequest):
    moving_average: int = Field(..., description="")


# -------------- MAIN REQUEST ------------------


class SingleCaptureSpectrumAnalyzer(ExtendSingleCaptureSpecAnaRequest):
    capture_parameters: SpecAnCapturePara = Field(
        ..., description="Spectrum capture Parameters."
    )


class CmSpecAnaAnalysisRequest(ExtendPnmSingleCaptureRequest):
    capture_parameters: SpecAnCapturePara = Field(
        ..., description="Spectrum capture Parameters."
    )


# -------------- MAIN-RESPONSE------------------


class CmSpecAnaAnalysisResponse(PnmDataResponse):
    """Generic response container for most PNM operations."""


# -------------- MAIN-OFDM-REQUEST ------------------


class OfdmSpecAna(BaseModel):
    number_of_averages: int = Field(
        default=10, description="Number of samples to calculate the average per-bin"
    )
    spectrum_retrieval_type: SpectrumRetrievalType = Field(
        default=SpectrumRetrievalType.FILE,
        description=f"Method of spectrum data retrieval: "
        f"PNM ({SpectrumRetrievalType.FILE}) | "
        f"SNMP({SpectrumRetrievalType.SNMP}).",
    )


class OfdmSpecAnaAnalysisRequest(ExtendSingleCaptureSpecAnaRequest):
    capture_parameters: OfdmSpecAna = Field(default=OfdmSpecAna(), description="")


# -------------- MAIN-OFDM-RESPONSE------------------


class OfdmSpecAnaAnalysisResponse(PnmAnalysisResponse):
    pass


# -------------- MAIN-SCQAM-REQUEST ------------------


class ScQamSpecAna(BaseModel):
    number_of_averages: int = Field(
        default=10, description="Number of samples to calculate the average per-bin"
    )
    spectrum_retrieval_type: SpectrumRetrievalType = Field(
        default=SpectrumRetrievalType.FILE,
        description=f"Method of spectrum data retrieval: "
        f"PNM ({SpectrumRetrievalType.FILE}) | "
        f"SNMP({SpectrumRetrievalType.SNMP}).",
    )


class ScQamSpecAnaAnalysisRequest(ExtendSingleCaptureSpecAnaRequest):
    capture_parameters: ScQamSpecAna = Field(default=ScQamSpecAna(), description="")


# -------------- MAIN-SCQAM-RESPONSE------------------


class ScQamSpecAnaAnalysisResponse(PnmAnalysisResponse):
    pass
