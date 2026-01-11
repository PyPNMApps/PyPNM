# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from typing import TYPE_CHECKING, Union

from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader

if TYPE_CHECKING:
    from pypnm.pnm.parser.CmDsConstDispMeas import CmDsConstDispMeas
    from pypnm.pnm.parser.CmDsHist import CmDsHist
    from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef
    from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
    from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
    from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer
    from pypnm.pnm.parser.CmLatencyRpt import CmLatencyRpt
    from pypnm.pnm.parser.CmSpectrumAnalysis import CmSpectrumAnalysis
    from pypnm.pnm.parser.CmSymbolCapture import CmSymbolCapture
    from pypnm.pnm.parser.CmUsOfdmaPreEq import CmUsOfdmaPreEq

PnmParserClass = Union[
    "CmSymbolCapture",
    "CmDsOfdmChanEstimateCoef",
    "CmDsConstDispMeas",
    "CmDsOfdmRxMer",
    "CmDsHist",
    "CmUsOfdmaPreEq",
    "CmDsOfdmFecSummary",
    "CmSpectrumAnalysis",
    "CmDsOfdmModulationProfile",
    "CmLatencyRpt",
]


class PnmFileTypeObjectFetcher(PnmHeader):
    """
    Factory that inspects a PNM byte-stream header and returns an instance
    of the appropriate parser for that PNM file type.

    Usage:
        fetcher = PnmFileTypeObjectFetcher(byte_stream)
        parser  = fetcher.get_parser()
        model   = parser.to_model()
    """

    def __init__(self, byte_stream: bytes) -> None:
        super().__init__(byte_stream)
        self._byte_stream = byte_stream
        self._parser: PnmParserClass | None = None
        self._process()

    def _process(self) -> None:
        """
        Determine The PNM File Type And Instantiate Its Parser.

        Uses lazy imports to avoid circular dependencies with individual
        PNM parser modules.
        """
        pnm_type = self.get_pnm_file_type()

        if pnm_type == PnmFileType.SYMBOL_CAPTURE:
            from pypnm.pnm.parser.CmSymbolCapture import CmSymbolCapture as ParserClass
        elif pnm_type == PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT:
            from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import (
                CmDsOfdmChanEstimateCoef as ParserClass,
            )
        elif pnm_type == PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY:
            from pypnm.pnm.parser.CmDsConstDispMeas import (
                CmDsConstDispMeas as ParserClass,
            )
        elif pnm_type == PnmFileType.RECEIVE_MODULATION_ERROR_RATIO:
            from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer as ParserClass
        elif pnm_type == PnmFileType.DOWNSTREAM_HISTOGRAM:
            from pypnm.pnm.parser.CmDsHist import CmDsHist as ParserClass
        elif (
            pnm_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS
            or pnm_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE
        ):
            from pypnm.pnm.parser.CmUsOfdmaPreEq import CmUsOfdmaPreEq as ParserClass
        elif pnm_type == PnmFileType.OFDM_FEC_SUMMARY:
            from pypnm.pnm.parser.CmDsOfdmFecSummary import (
                CmDsOfdmFecSummary as ParserClass,
            )
        elif pnm_type == PnmFileType.SPECTRUM_ANALYSIS:
            from pypnm.pnm.parser.CmSpectrumAnalysis import (
                CmSpectrumAnalysis as ParserClass,
            )
        elif pnm_type == PnmFileType.OFDM_MODULATION_PROFILE:
            from pypnm.pnm.parser.CmDsOfdmModulationProfile import (
                CmDsOfdmModulationProfile as ParserClass,
            )
        elif pnm_type == PnmFileType.LATENCY_REPORT:
            from pypnm.pnm.parser.CmLatencyRpt import CmLatencyRpt as ParserClass
        else:
            raise ValueError(f"Unsupported PNM file type: {pnm_type}")

        self._parser = ParserClass(self._byte_stream)

    def get_parser(self) -> PnmParserClass:
        """
        Return The Parser Instance For This PNM File.

        Raises
        ------
        RuntimeError
            If the parser was not initialized (e.g., unsupported PNM type).
        """
        if self._parser is None:
            raise RuntimeError(
                "PNM parser not available; unsupported file type or initialization error"
            )
        return self._parser
