from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import SpectrumAnalysisExtention


class SpectrumAnalysisProcess(SpectrumAnalysisExtention):
    pass


class AnalysisProcessParameters(SpectrumAnalysisProcess):
    """
    Extend the differnt types of processing of Analysis
    Use Models that are defined in the FastAPI request/response schemas
    """

    pass
