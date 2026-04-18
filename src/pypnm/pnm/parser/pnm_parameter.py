# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, NoReturn

from pydantic import BaseModel, Field

from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import MacAddressStr
from pypnm.pnm.parser.CmDsConstDispMeas import CmDsConstDispMeas
from pypnm.pnm.parser.CmDsHist import CmDsHist
from pypnm.pnm.parser.CmDsOfdmChanEstimateCoef import CmDsOfdmChanEstimateCoef
from pypnm.pnm.parser.CmDsOfdmFecSummary import CmDsOfdmFecSummary
from pypnm.pnm.parser.CmDsOfdmModulationProfile import CmDsOfdmModulationProfile
from pypnm.pnm.parser.CmDsOfdmRxMer import CmDsOfdmRxMer
from pypnm.pnm.parser.CmSpectrumAnalysis import CmSpectrumAnalysis
from pypnm.pnm.parser.CmUsOfdmaPreEq import CmUsOfdmaPreEq
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader

PnmParsers = CmDsConstDispMeas | CmDsOfdmChanEstimateCoef | CmDsOfdmFecSummary | CmDsOfdmRxMer | CmSpectrumAnalysis | CmUsOfdmaPreEq | CmDsHist

class PnmParserParametersModel(BaseModel):
    file_type: PnmFileType     = Field(..., description="PNM file type enum (e.g., PNN2, PNN3, ...).")
    mac_address: MacAddressStr = Field(default_factory=MacAddress.null, description="Cable modem MAC address extracted from the PNM payload, if present.")


class GetPnmParserAndParameters(PnmHeader):
    """
    Parses raw PNM file byte streams, dispatches to type-specific parsers,
    and exposes core parameters plus the concrete parser instance.

    Inherits
    --------
    PnmHeader
        Provides `file_type` and `file_type_num` properties.

    Public Methods
    --------------
    to_model()
        Return parameters as a PnmParserParametersModel.
    to_dict()
        Return parameters as a plain dictionary (model_dump()).
    get_parser()
        Return (parser_instance, parameters_model) as a typed tuple.
    """

    def __init__(self, byte_stream: bytes) -> None:
        """
        Initialize the parser with raw PNM data.

        Parameters
        ----------
        byte_stream : bytes
            Full contents of a PNM file, header + payload.
        """
        super().__init__(byte_stream)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.byte_stream = byte_stream

        if isinstance(self._file_type, (bytes, bytearray)):
            file_type_str = self._file_type.decode("ascii", errors="ignore")
        else:
            file_type_str = str(self._file_type)

        if isinstance(self._file_type_num, (bytes, bytearray)):
            file_type_num_str = self._file_type_num.decode("ascii", errors="ignore")
        else:
            file_type_num_str = str(self._file_type_num)

        self.pnm_type = f"{file_type_str}{file_type_num_str}"
        self.logger.debug("Processing PNM-Type: (%s)", self.pnm_type)

        self._parameters_model: PnmParserParametersModel | None = None
        self._parser: PnmParsers | None = None

    def to_model(self) -> PnmParserParametersModel:
        """
        Process the PNM file and return a structured PnmParserParametersModel.

        Behavior
        --------
        - On first call, this method parses and caches both the parameter model
          and the concrete parser instance.
        - Subsequent calls return the cached model.
        - Parsing errors are propagated as exceptions.
        """
        if self._parameters_model is not None:
            return self._parameters_model

        try:
            file_type_enum = PnmFileType(self.pnm_type)
        except ValueError:
            self.logger.error("Unsupported PNM file type code: %s", self.pnm_type)
            raise

        parsed = self._process()
        self.logger.info("%s", parsed)
        self._parser = parsed

        mac_address = getattr(parsed, "_mac_address", MacAddress.null())

        self._parameters_model = PnmParserParametersModel(
            file_type=file_type_enum,
            mac_address=mac_address,
        )
        return self._parameters_model

    def to_dict(self) -> dict[str, Any]:
        """
        Process the PNM file and return core parameters as a plain dict.

        Returns
        -------
        Dict[str, Any]
            Dictionary with keys:
              - file_type: PnmFileType enum value (serializes to its value in JSON).
              - mac_address: MAC address string (may be empty/null string).
        """
        return self.to_model().model_dump()

    def get_parser(self) -> tuple[PnmParsers, PnmParserParametersModel]:
        """
        Return a (parser_instance, parameters_model) tuple for this PNM file.

        Behavior
        --------
        - If parsing has not yet occurred, this method triggers parsing via to_model().
        - Any parsing errors are propagated to the caller.
        """
        params: PnmParserParametersModel
        if self._parser is None or self._parameters_model is None:
            params = self.to_model()
        else:
            params = self._parameters_model

        assert self._parser is not None
        return self._parser, params

    def _process(self) -> PnmParsers:
        """
        Determine PNM type and call the associated parser.

        Returns
        -------
        Any
            The object returned by the specific _process_* method.

        Raises
        ------
        ValueError
            For unknown PNM codes.
        NotImplementedError
            For unimplemented handlers.
        """
        try:
            file_type_enum = PnmFileType(self.pnm_type)
        except ValueError as exc:
            raise ValueError(f"Unsupported PNM file type code: {self.pnm_type}") from exc

        self.logger.debug("PNM-File-Type-Enum: %s", file_type_enum)

        dispatch_map = {
            PnmFileType.SYMBOL_CAPTURE:                      self._process_symbol_capture,
            PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT:   self._process_ofdm_channel_estimate,
            PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY:    self._process_constellation_display,
            PnmFileType.RECEIVE_MODULATION_ERROR_RATIO:      self._process_rxmer,
            PnmFileType.DOWNSTREAM_HISTOGRAM:                self._process_histogram,
            PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS: self._process_upstream_pre_eq,
            PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE: self._process_upstream_pre_eq_update,
            PnmFileType.OFDM_FEC_SUMMARY:                    self._process_fec_summary,
            PnmFileType.SPECTRUM_ANALYSIS:                   self._process_spectrum_analysis,
            PnmFileType.OFDM_MODULATION_PROFILE:             self._process_modulation_profile,
            PnmFileType.LATENCY_REPORT:                      self._process_latency_report,
        }

        handler = dispatch_map.get(file_type_enum)
        if handler is None:
            raise NotImplementedError(f"Handler not implemented for {file_type_enum.name}")
        return handler()

    # Handlers in enum order
    def _process_ofdm_channel_estimate(self) -> CmDsOfdmChanEstimateCoef:
        """OFDM channel estimate coefficient parser."""
        return CmDsOfdmChanEstimateCoef(self.byte_stream)

    def _process_constellation_display(self) -> CmDsConstDispMeas:
        """Downstream constellation display parser."""
        return CmDsConstDispMeas(self.byte_stream)

    def _process_rxmer(self) -> CmDsOfdmRxMer:
        """Receive modulation error ratio (RxMER) parser."""
        return CmDsOfdmRxMer(self.byte_stream)

    def _process_histogram(self) -> CmDsHist:
        """Downstream histogram parser"""
        return CmDsHist(self.byte_stream)

    def _process_upstream_pre_eq(self) -> CmUsOfdmaPreEq:
        """OFDMA upstream pre-equalizer coefficients parser."""
        return CmUsOfdmaPreEq(self.byte_stream)

    def _process_upstream_pre_eq_update(self) -> CmUsOfdmaPreEq:
        """OFDMA upstream pre-equalizer last-update coefficients parser."""
        return CmUsOfdmaPreEq(self.byte_stream)

    def _process_fec_summary(self) -> CmDsOfdmFecSummary:
        """OFDM FEC summary parser."""
        return CmDsOfdmFecSummary(self.byte_stream)

    def _process_modulation_profile(self) -> CmDsOfdmModulationProfile:
        """OFDM modulation profile parser."""
        return CmDsOfdmModulationProfile(self.byte_stream)

    def _process_latency_report(self) -> NoReturn:
        """Latency report parser (not implemented)."""
        raise NotImplementedError("Latency report parsing not implemented.")

    def _process_spectrum_analysis(self) -> CmSpectrumAnalysis:
        """Spectrum analysis parser."""
        return CmSpectrumAnalysis(self.byte_stream)

    """This method may never be implemented by CableLabs, no real intrest from operators"""
    def _process_symbol_capture(self) -> NoReturn:
        """Symbol capture parser (not implemented) — this always raises NotImplementedError."""
        raise NotImplementedError("Symbol capture parsing not implemented.")
