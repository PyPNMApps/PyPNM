## Agent Review Bundle Summary
- Goal: Add channel power (dBmV) to spectrum analyzer analysis outputs and document rounding.
- Changes: Rounded channel_power_dbmv in PNM and SNMP spectrum analysis, updated tests, and documented rounding.
- Files: src/pypnm/api/routes/common/classes/analysis/analysis.py, tests/test_spectrum_analyzer_channel_power_dbmv.py, docs/api/fast-api/single/spectrum-analyzer/spectrum-analyzer.md
- Tests: ruff check src; pytest -q
- Notes: Hardware SNMP integration tests skipped (PNM_CM_IT not set).

# FILE: src/pypnm/api/routes/common/classes/analysis/analysis.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
import math
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any, cast

import numpy as np

from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.echo_detector import (
    EchoDetector,
    EchoDetectorReport,
)
from pypnm.api.routes.advance.analysis.signal_analysis.detection.echo.type import (
    EchoDetectorType,
)
from pypnm.api.routes.common.classes.analysis.model.mod_profile_schema import (
    CarrierItemModel,
    CarrierValuesListModel,
    CarrierValuesModel,
    CarrierValuesSplitModel,
    ProfileAnalysisEntryModel,
)
from pypnm.api.routes.common.classes.analysis.model.process import (
    AnalysisProcessParameters,
)
from pypnm.api.routes.common.classes.analysis.model.schema import (
    BaseAnalysisModel,
    ChanEstCarrierModel,
    ConstellationDisplayAnalysisModel,
    DsChannelEstAnalysisModel,
    DsHistogramAnalysisModel,
    DsModulationProfileAnalysisModel,
    DsRxMerAnalysisModel,
    EchoDatasetModel,
    FecSummaryCodeWordModel,
    GrpDelayStatsModel,
    OfdmaUsPreEqCarrierModel,
    OfdmFecSummaryAnalysisModel,
    OfdmFecSummaryProfileModel,
    RegressionModel,
    RxMerCarrierValuesModel,
    UsOfdmaUsPreEqAnalysisModel,
)
from pypnm.api.routes.common.classes.analysis.model.spectrum_analyzer_schema import (
    DEFAULT_POINT_AVG,
    MagnitudeSeries,
    SpecAnaAnalysisResults,
    SpectrumAnalyzerAnalysisModel,
    WindowAverage,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.types import (
    CommonMessagingServiceExtension as CMSE,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import SpecAnCapturePara
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cm_snmp_operation import Generate
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.constants import (
    CABLE_VF,
    INVALID_CHANNEL_ID,
    INVALID_PROFILE_ID,
    INVALID_SCHEMA_TYPE,
    INVALID_START_VALUE,
    SPEED_OF_LIGHT,
    CableType,
)
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.log_files import LogFile
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.qam.lut_mgr import QamLutManager
from pypnm.lib.qam.types import QamModulation
from pypnm.lib.signal_processing.averager import MovingAverage
from pypnm.lib.signal_processing.butterworth import (
    DEFAULT_BUTTERWORTH_ORDER,
    MagnitudeButterworthFilter,
)
from pypnm.lib.signal_processing.complex_array_ops import ComplexArrayOps
from pypnm.lib.signal_processing.group_delay import GroupDelay
from pypnm.lib.signal_processing.linear_regression import LinearRegression1D
from pypnm.lib.signal_processing.shan.series import Shannon, ShannonSeries
from pypnm.lib.types import (
    ArrayLike,
    ChannelId,
    ComplexArray,
    FloatSeries,
    FrequencyHz,
    FrequencySeriesHz,
    IntSeries,
    MacAddressStr,
    ProfileId,
    SpectrumAnalysisSnmpCaptureParameters,
)
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import WindowFunction
from pypnm.pnm.data_type.DsOfdmModulationType import DsOfdmModulationType
from pypnm.pnm.lib.channel_power import ChannelPowerDbmv
from pypnm.pnm.lib.signal_statistics import SignalStatistics, SignalStatisticsModel
from pypnm.pnm.parser.CmDsOfdmModulationProfile import (
    CmDsOfdmModulationProfile,
    ModulationOrderType,
    RangeModulationProfileSchemaModel,
    SkipModulationProfileSchemaModel,
)
from pypnm.pnm.parser.model.parser_rtn_models import (
    CmDsConstDispMeasModel,
    CmDsHistModel,
    CmDsOfdmChanEstimateCoefModel,
    CmDsOfdmFecSummaryModel,
    CmDsOfdmModulationProfileModel,
    CmDsOfdmRxMerModel,
    CmUsOfdmaPreEqModel,
)
from pypnm.pnm.parser.pnm_file_type import PnmFileType


class RxMerCarrierType(Enum):
    """
    RxMER carrier classification labels.

    Members
    -------
    EXCLUSION : str
        "0". Subcarriers marked as excluded (e.g., guard bands, PLC gaps).
    CLIPPED : str
        "1". Values clipped/saturated (e.g., 0.0 dB or 63.5 dB).
    NORMAL : str
        "2". Valid, non-clipped RxMER readings.
    """
    EXCLUSION   = "0"
    CLIPPED     = "1"
    NORMAL      = "2"

# RxMER special sentinel values used for classification:
RXMER_EXCLUSION = 63.75
RXMER_CLIPPED_LOW = 0.0
RXMER_CLIPPED_HIGH = 63.5

# Constants for Signal Processing
CHAN_EST_BW_CUTOFF_FRACTION: float = 0.25

class AnalysisType(Enum):
    """
    Analysis mode selector.

    Notes
    -----
    BASIC
        Provides (frequency, magnitude) and selected meta-data depending on the
        detected PNM file type. Additional per-type metrics may be included
        (e.g., group delay, Shannon limits, histogram counts).
    """
    BASIC               = 0


class Analysis:
    """Core analysis runner.

    This orchestrator normalizes the payload's ``data`` into a list of
    measurement dictionaries and dispatches to the appropriate analysis
    routine based on the inferred PNM file type. For echo detection, the
    provided ``cable_type`` controls the velocity factor used to convert
    echo time delays to physical distances.

    Parameters
    ----------
    analysis_type : AnalysisType
        Selected analysis mode (e.g., ``AnalysisType.BASIC``).
    msg_response : MessageResponse
        Wrapped transport of the measurement payload; must expose
        ``payload_to_dict()`` with a top-level ``"data"`` entry.
    cable_type : CableType, default CableType.RG6
        Cable type used by echo-detection analysis to determine the
        propagation velocity factor for distance calculations.

    """

    def __init__(self, analysis_type: AnalysisType,
                 msg_response: MessageResponse,
                 cable_type: CableType = CableType.RG6,
                 skip_automatic_process: bool = False) -> None:

        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.analysis_type: AnalysisType        = analysis_type
        self.msg_response: MessageResponse      = msg_response
        self._cable_type: CableType             = cable_type
        payload: dict[int | str, Any]           = msg_response.payload_to_dict() or {}
        _raw_data                               = payload.get("data", [])

        self._result_model:list[BaseAnalysisModel] = []
        self._processed_pnm_type:list[PnmFileType] = []
        self._skip_automatic_process = skip_automatic_process

        # Defining DataTypes
        self._analysis_para:AnalysisProcessParameters = AnalysisProcessParameters()

        if isinstance(_raw_data, Mapping):
            self.measurement_data: list[dict[str, Any]] = [dict(_raw_data)]
        elif isinstance(_raw_data, Sequence) and not isinstance(_raw_data, (str, bytes, bytearray)):
            self.measurement_data = [dict(m) for m in _raw_data]
        else:
            self.measurement_data = []

        # Extract spectrum_analysis_snmp_capture_parameters from the first measurement dict.
        self._msg_rsp_extension: SpectrumAnalysisSnmpCaptureParameters = {}
        if self.measurement_data:
            msg_rsp_extension = self.measurement_data[0].get(
                CMSE.SPECTRUM_ANALYSIS_SNMP_CAPTURE_PARAMETER.value,
                {},
            )
            if isinstance(msg_rsp_extension, dict):
                self._msg_rsp_extension = cast(SpectrumAnalysisSnmpCaptureParameters, msg_rsp_extension)

        self._analysis_dict: list[dict[str, Any]] = []

        if self.logger.isEnabledFor(logging.DEBUG):
            self.save_message_response(self.msg_response)

        if not skip_automatic_process:
            self._process(self._analysis_para)

    def process(self, analysis_para: AnalysisProcessParameters) -> None:
        self._analysis_para = analysis_para
        self._process(analysis_para)

    def _process(self, analysis_para: AnalysisProcessParameters) -> None:
        """Iterate and dispatch analysis per measurement.

        For each normalized measurement, this method assembles the combined
        PNM file type string from the header fields and routes to the
        corresponding *basic* analysis handler.

        Notes
        -----
        Unknown or missing file types are logged; the measurement is
        serialized for troubleshooting via :class:`LogFile`.
        """

        for idx, measurement in enumerate(self.measurement_data):

            if "pnm_file_type" in measurement and PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA.name in measurement["pnm_file_type"]:
                self.logger.debug('Processing SNMP Spectrum Analysis Data')

                pnm_file_type = PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA.value
                if self.analysis_type == AnalysisType.BASIC:
                    self.logger.debug('Performing Basic Analysis on SNMP Spectrum Analysis Data')
                    self._basic_analysis(pnm_file_type, measurement, analysis_para)

                continue

            pnm_header: dict[str, Any] = measurement.get("pnm_header") or {}
            channel_id: int =  measurement.get("channel_id", INVALID_CHANNEL_ID)

            self.logger.debug(f"PNM-HEADER[{idx}]: {pnm_header}")

            file_type       = str(pnm_header.get("file_type", ""))
            file_ver        = str(pnm_header.get("file_type_version", ""))
            pnm_file_type   = f'{file_type}{file_ver}'

            if not pnm_file_type:
                self.logger.error('PNM FileType not Found')
                LogFile.write(fname=f'unknown-pnm-filetype-{Generate.time_stamp()}.dict' , data=measurement)
                pass

            if self.analysis_type == AnalysisType.BASIC:
                self.logger.debug(f'Performing Basic Analysis on PNM: {pnm_file_type} on Channel: {channel_id}')
                self._basic_analysis(pnm_file_type, measurement, analysis_para)

            else:
                self.logger.error(f'Unknown AnalysisType: {self.analysis_type}')
                raise

    def _basic_analysis(self, pnm_file_type: str,
                        measurement: dict[str, Any],
                        analysis_para: AnalysisProcessParameters) -> None:
        """
        Route to the appropriate BASIC analysis handler.

        Parameters
        ----------
        pnm_file_type : str
            Concatenated PNM file type identifier, e.g.
            ``PnmFileType.RECEIVE_MODULATION_ERROR_RATIO.value``.
        measurement : dict
            Single measurement dictionary. Expected keys vary by file type,
            but generally include:
                - ``pnm_header`` : dict with ``file_type`` and version
                - ``channel_id`` : int
                - ``device_details`` : dict
                - per-type fields such as subcarrier spacing, values, profiles, etc.

        Notes
        -----
        This method only dispatches. See the specific handlers for field
        expectations and returned structures:

        """
        # TODO: unify return type?
        # model:BaseAnalysisModel

        if pnm_file_type == PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT.value:
            self.logger.debug("Processing: OFDM_CHANNEL_ESTIMATE_COEFFICIENT")
            model = self.basic_analysis_ds_chan_est(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT)

        elif pnm_file_type == PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY.value:
            self.logger.debug("Processing: DOWNSTREAM_CONSTELLATION_DISPLAY")
            model = self.basic_analysis_ds_constellation_display(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY)

        elif pnm_file_type == PnmFileType.RECEIVE_MODULATION_ERROR_RATIO.value:
            self.logger.debug("Processing: RECEIVE_MODULATION_ERROR_RATIO")
            model = self.basic_analysis_rxmer(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.RECEIVE_MODULATION_ERROR_RATIO)

        elif pnm_file_type == PnmFileType.DOWNSTREAM_HISTOGRAM.value:
            self.logger.debug("Processing: DOWNSTREAM_HISTOGRAM")
            model = self.basic_analysis_ds_histogram(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.DOWNSTREAM_HISTOGRAM)

        elif pnm_file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS.value:
            self.logger.debug("Processing: UPSTREAM_PRE_EQUALIZER_COEFFICIENTS")
            model = self.basic_analysis_us_ofdma_pre_equalization(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS)

        elif pnm_file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE.value:
            self.logger.debug("Processing: UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE")
            model = self.basic_analysis_us_ofdma_pre_equalization(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE)

        elif pnm_file_type == PnmFileType.OFDM_FEC_SUMMARY.value:
            self.logger.debug("Processing: OFDM_FEC_SUMMARY")
            model = self.basic_analysis_ds_ofdm_fec_summary(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.OFDM_FEC_SUMMARY)

        elif pnm_file_type == PnmFileType.SPECTRUM_ANALYSIS.value:
            self.logger.debug("Processing: SPECTRUM_ANALYSIS")
            model = self.basic_analysis_spectrum_analyzer(measurement, analysis_para)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.SPECTRUM_ANALYSIS)

        elif pnm_file_type == PnmFileType.OFDM_MODULATION_PROFILE.value:
            self.logger.debug("Processing: OFDM_MODULATION_PROFILE")
            model = self.basic_analysis_ds_modulation_profile(measurement)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.OFDM_MODULATION_PROFILE)

        elif pnm_file_type == PnmFileType.LATENCY_REPORT.value:
            self.logger.warning("Stub: Processing: LATENCY_REPORT")
            self.__add_pnmType(PnmFileType.LATENCY_REPORT)
            pass

        elif pnm_file_type == PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA.value:
            self.logger.debug("Processing: Basic Analysis -> CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA")
            capture_parameters_update = self._msg_rsp_extension
            model = self.basic_analysis_spectrum_analyzer_snmp(measurement, capture_parameters_update, analysis_para)
            self.__update_result_model(model)
            self.__update_result_dict(model.model_dump())
            self.__add_pnmType(PnmFileType.CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA)

        else:
            self.logger.error(f"Unknown PNM file type: ({pnm_file_type})")

    def get_pnm_type(self) -> list[PnmFileType]:
        return self._processed_pnm_type

    def get_results(self, full_dict: bool = True) -> dict[str, Any] | list[dict[str, Any]]:
        """
        Return accumulated analysis results.

        Behavior
        --------
        - full_dict=True  -> always: {"analysis": [dict, dict, ...]}
        - full_dict=False -> if exactly one result: dict
                            else: {"analysis": [dict, dict, ...]}
        """
        results: list[dict[str, Any]] = self._analysis_dict

        if full_dict:
            return {"analysis": results}

        if len(results) == 1 and isinstance(results[0], dict):
            return results[0]

        return {"analysis": results}

    def get_model(self) -> BaseAnalysisModel | list[BaseAnalysisModel]:
        """Get the accumulated analysis results (typed models).

        Returns
        -------
        BaseAnalysisModel or list of BaseAnalysisModel
            The collected Pydantic models for analyses that produce them.
        """
        return self._result_model

    def get_dicts(self) -> list[dict[str,Any]]:
        return self._analysis_dict

    def save_message_response(self, msg_response: MessageResponse) -> None:
        """Persist the raw message response (debug aid).

        Parameters
        ----------
        msg_response : MessageResponse
            Source container that will be serialized to disk. The filename
            includes the MAC address (if present) and a timestamp.
        """
        msg_rsp_dict:dict[Any, Any] = msg_response.payload_to_dict()
        mac = msg_rsp_dict.get('mac_address')
        fname = f'{SystemConfigSettings().message_response_dir()}/{mac}_{Generate.time_stamp()}.msg'
        self.logger.debug(f'Saving Message Response: {fname}')

        fp = FileProcessor(fname)
        fp.write_file(msg_rsp_dict)
        fp.close()

    def __update_result_model(self, model:BaseAnalysisModel) -> None :
        """Append a typed analysis model to the results cache.

        Parameters
        ----------
        model : BaseAnalysisModel
            The model instance to record.
        """
        self._result_model.append(model)

    def __update_result_dict(self, model_dict:dict[str,Any]) -> None:
        """Append a plain-dict analysis result to the results cache.

        Parameters
        ----------
        model : dict
            The dictionary result to record.
        """
        self._analysis_dict.append(model_dict)

    def __add_pnmType(self, pft:PnmFileType) -> None:
        self._processed_pnm_type.append(pft)

    @classmethod
    def get_analysis_from_model(
        cls,
        model: BaseAnalysisModel,
        analysis_type: AnalysisType = AnalysisType.BASIC,
        cable_type: CableType = CableType.RG6,
    ) -> Analysis:
        """
        Construct an Analysis instance from an existing analysis model.

        The returned Analysis is equivalent to an already-processed BASIC analysis
        for a single measurement. The internal result caches are populated so that
        get_model(), get_results(), and get_dicts() can be used directly.

        Parameters
        ----------
        model : BaseAnalysisModel
            A concrete analysis model instance such as
            DsRxMerAnalysisModel, DsChannelEstAnalysisModel, etc.
        analysis_type : AnalysisType, default AnalysisType.BASIC
            Logical analysis mode to tag on the Analysis instance.
        cable_type : CableType, default CableType.RG6
            Cable type metadata retained on the Analysis instance.

        Returns
        -------
        Analysis
            An Analysis object whose result caches are populated from `model`.
        """
        # Infer the corresponding PNM file type from the model class
        pnm_type: PnmFileType | None
        if isinstance(model, DsChannelEstAnalysisModel):
            pnm_type = PnmFileType.OFDM_CHANNEL_ESTIMATE_COEFFICIENT
        elif isinstance(model, ConstellationDisplayAnalysisModel):
            pnm_type = PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY
        elif isinstance(model, DsRxMerAnalysisModel):
            pnm_type = PnmFileType.RECEIVE_MODULATION_ERROR_RATIO
        elif isinstance(model, DsHistogramAnalysisModel):
            pnm_type = PnmFileType.DOWNSTREAM_HISTOGRAM
        elif isinstance(model, UsOfdmaUsPreEqAnalysisModel):
            pnm_type = PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS
        elif isinstance(model, OfdmFecSummaryAnalysisModel):
            pnm_type = PnmFileType.OFDM_FEC_SUMMARY
        elif isinstance(model, DsModulationProfileAnalysisModel):
            pnm_type = PnmFileType.OFDM_MODULATION_PROFILE
        else:
            pnm_type = None

        # Bypass __init__ so we don't need a MessageResponse; populate internals manually.
        analysis = object.__new__(cls)  # type: ignore[call-arg]

        analysis.logger                  = logging.getLogger(f"{cls.__name__}")
        analysis.analysis_type           = analysis_type
        analysis.msg_response            = None
        analysis._cable_type             = cable_type
        analysis._skip_automatic_process = True
        analysis._analysis_para          = AnalysisProcessParameters()

        # No raw measurement data when constructed from a model
        analysis.measurement_data        = []

        # Populate result caches from the provided model
        analysis._result_model           = [model]
        analysis._analysis_dict          = [
            model.model_dump()
        ] if hasattr(model, "model_dump") else [dict(model)]

        analysis._processed_pnm_type     = [pnm_type] if pnm_type is not None else []

        return analysis

    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

    @classmethod
    def basic_analysis_rxmer(cls, measurement: dict[str, Any]) -> DsRxMerAnalysisModel:
        """
        Perform basic RxMER (Receive Modulation Error Ratio) analysis.

        Computes frequency per subcarrier, propagates magnitudes, and assigns a
        carrier status classification for each element (``EXCLUSION``, ``CLIPPED``,
        or ``NORMAL``). Also provides a simple regression line over the magnitudes
        and Shannon-series metadata.

        Parameters
        ----------
        measurement : dict
            Expected keys (subset):
                - ``channel_id`` : int
                - ``pnm_header`` : dict
                - ``device_details`` : dict
                - ``mac_address`` : str
                - ``subcarrier_spacing`` : int (Hz)
                - ``first_active_subcarrier_index`` : int
                - ``subcarrier_zero_frequency`` : int (Hz)
                - ``values`` : List[float] (RxMER in dB)

        Returns
        -------
        DsRxMerAnalysisModel
            Typed model with ``carrier_values.frequency``, ``carrier_values.magnitude``,
            and ``carrier_values.carrier_status`` aligned by index, plus regression
            and modulation statistics.

        Raises
        ------
        ValueError
            If required parameters are missing/negative, or lengths mismatch.
        """
        out: DsRxMerAnalysisModel

        channel_id:ChannelId                = measurement.get("channel_id", INVALID_CHANNEL_ID)
        pnm_header                          = measurement.get("pnm_header",{})
        device_details                      = measurement.get("device_details",{})
        mac_address:MacAddressStr           = measurement.get("mac_address",MacAddress.null())
        subcarrier_spacing:int              = measurement.get("subcarrier_spacing",-1)
        first_active_subcarrier_index:int   = measurement.get("first_active_subcarrier_index",-1)
        subcarrier_zero_frequency:int       = measurement.get("subcarrier_zero_frequency", -1)
        values                              = measurement.get("values", [])

        if first_active_subcarrier_index < 0 or subcarrier_zero_frequency < 0 or subcarrier_spacing <0:
            raise ValueError(f"Active index: {first_active_subcarrier_index} or "
                             f"zero frequency: {subcarrier_zero_frequency} or "
                             f"spacing: {subcarrier_spacing} ALL must be non-negative")

        if not values:
            raise ValueError("No RxMER values provided in measurement.")

        base_freq = (subcarrier_spacing * first_active_subcarrier_index) + subcarrier_zero_frequency
        freqs:FloatSeries = [base_freq + (i * subcarrier_spacing) for i in range(len(values))]
        magnitudes:FloatSeries = values

        def classify(v: int) -> int:
            if v == RXMER_EXCLUSION:
                return int(RxMerCarrierType.EXCLUSION.value)
            elif v in (RXMER_CLIPPED_LOW, RXMER_CLIPPED_HIGH):
                return int(RxMerCarrierType.CLIPPED.value)
            else:
                return int(RxMerCarrierType.NORMAL.value)

        # carrier_status will be List[int]
        carrier_status: list[int] = [classify(v) for v in values]

        if not (len(freqs) == len(magnitudes) == len(carrier_status)):
            raise ValueError(
                f"Length mismatch detected: frequencies({len(freqs)}), "
                f"magnitudes({len(magnitudes)}), carrier_status({len(carrier_status)})"
            )

        ss = ShannonSeries(magnitudes)

        regession_model = RegressionModel(
            slope   = cast(FloatSeries, LinearRegression1D(cast(ArrayLike,magnitudes),
                                                           cast(ArrayLike,freqs)).regression_line())
        )

        csm:dict[str, Any] = {
            RxMerCarrierType.EXCLUSION.name.lower(): RxMerCarrierType.EXCLUSION.value,
            RxMerCarrierType.CLIPPED.name.lower(): RxMerCarrierType.CLIPPED.value,
            RxMerCarrierType.NORMAL.name.lower(): RxMerCarrierType.NORMAL.value,
        }

        cv = RxMerCarrierValuesModel(
            carrier_status_map  = csm,
            carrier_count       = len(freqs),
            magnitude           = magnitudes,
            frequency           = freqs,
            carrier_status      = carrier_status)

        out = DsRxMerAnalysisModel(
            device_details                  = device_details,
            pnm_header                      = pnm_header,
            channel_id                      = channel_id,
            mac_address                     = mac_address,
            subcarrier_spacing              = subcarrier_spacing,
            first_active_subcarrier_index   = first_active_subcarrier_index,
            subcarrier_zero_frequency       = subcarrier_zero_frequency,
            carrier_values                  = cv,
            regression                      = regession_model,
            modulation_statistics           = ss.to_model()
        )

        return out

    @classmethod
    def basic_analysis_ds_chan_est(cls, measurement: dict[str, Any], cable_type: CableType = CableType.RG6) -> DsChannelEstAnalysisModel:
        """
        Perform downstream channel-estimation analysis.

        Computes:
        - Per-subcarrier frequency axis (Hz)
        - Magnitude sequence (dB) from complex coefficients
        - Group delay (µs) from phase slope across subcarriers
        - Echo detection via IFFT of H(f) → h(t) with conservative thresholds

        Expected Keys (subset) in `measurement`
        ---------------------------------------
        channel_id : int
            Downstream channel ID.
        subcarrier_spacing : int
            Δf in Hz between subcarriers.
        first_active_subcarrier_index : int
            Index of the first active subcarrier relative to subcarrier 0.
        subcarrier_zero_frequency : int
            Frequency (Hz) of subcarrier 0.
        occupied_channel_bandwidth : int
            Occupied bandwidth for metadata.
        values : ComplexArray
            List of complex-like samples for H(f). [(re, im), ...] or [complex, ...].

        Returns
        -------
        DsChannelEstAnalysisModel
            Typed model with carrier values, signal statistics, and echo results.
        """
        log = logging.getLogger(f"{cls.__name__}")

        channel_id: ChannelId                   = measurement.get("channel_id",                    INVALID_CHANNEL_ID)
        subcarrier_spacing: FrequencyHz         = measurement.get("subcarrier_spacing",            INVALID_START_VALUE)
        first_active_subcarrier_index: int      = measurement.get("first_active_subcarrier_index", INVALID_START_VALUE)
        subcarrier_zero_frequency: FrequencyHz  = measurement.get("subcarrier_zero_frequency",     INVALID_START_VALUE)
        occupied_channel_bandwidth: FrequencyHz = measurement.get("occupied_channel_bandwidth",    INVALID_START_VALUE)

        if (first_active_subcarrier_index < 0) or (subcarrier_zero_frequency < 0) or (subcarrier_spacing <= 0):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        values: ComplexArray = measurement.get("values", [])
        if not values:
            raise ValueError("No complex channel estimation values provided in measurement.")

        start_freq: FrequencyHz    = cast(FrequencyHz, (subcarrier_spacing * first_active_subcarrier_index) + subcarrier_zero_frequency)
        freqs: FrequencySeriesHz   = cast(FrequencySeriesHz, [start_freq + (i * subcarrier_spacing) for i in range(len(values))])

        gd = GroupDelay.from_channel_estimate(Hhat=values, df_hz=subcarrier_spacing, f0_hz=start_freq)
        gd_results = gd.to_result()

        cao = ComplexArrayOps(values)
        magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

        complex_arr = np.asarray(
            [
                complex(v[0], v[1])
                if not isinstance(v, complex) and isinstance(v, (list, tuple)) and len(v) == 2
                else complex(v)
                for v in values
            ],
            dtype=np.complex128,
        )

        try:
            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(subcarrier_spacing) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz = FrequencyHz(subcarrier_spacing),
                cutoff_hz             = cutoff_hz,
                order                 = DEFAULT_BUTTERWORTH_ORDER,
                zero_phase            = True,
            )

            mag_result = mag_filter.apply(np.asarray(magnitudes_db_raw, dtype=np.float64))
            magnitudes_db: FloatSeries = mag_result.filtered_values.tolist()
        except Exception:
            magnitudes_db = magnitudes_db_raw

        signal_stats_model: SignalStatisticsModel = SignalStatistics(magnitudes_db).compute()

        group_delay_stats: GrpDelayStatsModel = GrpDelayStatsModel(
            group_delay_unit = "microsecond",
            magnitude        = ComplexArrayOps.to_list(gd_results.group_delay_us),
        )

        magn_linear = np.power(10.0, np.asarray(magnitudes_db, dtype=np.float64) / 20.0)
        phases      = np.angle(complex_arr)
        H_smooth    = magn_linear * np.exp(1j * phases)

        N = len(values)
        n_fft = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        fs = float(N) * float(subcarrier_spacing)
        max_delay_s = 3.5e-6

        v = SPEED_OF_LIGHT * CABLE_VF.get(cable_type.name, 0.87)
        max_dist_m = 0.5 * v * max_delay_s
        i_stop = int(max_delay_s * fs)
        log.debug(
            "EchoDetector window: fs=%.3f Hz, n_fft=%d, i_stop=%d bins, max_delay=%.2fus, max_dist≈%.1f m",
            fs, n_fft, i_stop, max_delay_s * 1e6, max_dist_m
        )

        det = EchoDetector(
            freq_data               = H_smooth.tolist(),
            subcarrier_spacing_hz   = float(subcarrier_spacing),
            n_fft                   = 4096,
            cable_type              = cable_type.name,
            channel_id              = channel_id,
        )

        max_delay_s_used = 3.5e-6
        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode        = "db_down",
            threshold_db_down     = 60.0,
            normalize_power       = True,
            guard_bins            = 16,
            min_separation_s      = 8.0 / det.fs,
            max_delay_s           = max_delay_s_used,
            max_peaks             = 3,
            include_time_response = False,
            direct_at_zero        = True,
            window                = "hann",
        )

        i_stop     = int(np.ceil(max_delay_s_used * det.fs))
        edge_guard = 8
        if echo_report.echoes:
            echo_report.echoes = [
                e for e in echo_report.echoes
                if (e.bin_index < (i_stop - edge_guard))
            ]

        echo_rpt = EchoDatasetModel(type = EchoDetectorType.IFFT, report = echo_report)

        carrier_values: ChanEstCarrierModel = ChanEstCarrierModel(
            carrier_count               = len(freqs),
            frequency_unit              = "Hz",
            frequency                   = freqs,
            complex                     = values,
            complex_dimension           = int(complex_arr.ndim),
            magnitudes                  = magnitudes_db,
            group_delay                 = group_delay_stats,
            occupied_channel_bandwidth  = occupied_channel_bandwidth,
        )

        result_model: DsChannelEstAnalysisModel = DsChannelEstAnalysisModel(
            device_details                  = measurement.get("device_details", {}),
            pnm_header                      = measurement.get("pnm_header", {}),
            mac_address                     = measurement.get("mac_address", ""),
            channel_id                      = ChannelId(measurement.get("channel_id", INVALID_START_VALUE)),
            subcarrier_spacing              = subcarrier_spacing,
            first_active_subcarrier_index   = first_active_subcarrier_index,
            subcarrier_zero_frequency       = subcarrier_zero_frequency,
            carrier_values                  = carrier_values,
            signal_statistics               = signal_stats_model,
            echo                            = echo_rpt,
        )

        return result_model

    @classmethod
    def basic_analysis_ds_modulation_profile(cls, measurement: Mapping[str, Any], split_carriers: bool = True) -> DsModulationProfileAnalysisModel:
        """
        Analyze the Downstream OFDM Modulation Profile and return a typed model.

        Parameters
        ----------
        measurement : Mapping[str, Any]
            Expected keys (subset):
            - subcarrier_spacing : int (Hz)
            - first_active_subcarrier_index : int
            - subcarrier_zero_frequency : int (Hz)
            - mac_address : str
            - channel_id : int
            - device_details : Mapping[str, Any] (optional passthrough)
            - pnm_header : Mapping[str, Any] (optional passthrough)
            - profiles : list of dicts:
                    {
                        "profile_id": int,
                        "schemes": list[SchemeModel-like]
                    }

            Each scheme item is one of:
            - schema_type = 0 (range):
                    {
                        "schema_type": 0,
                        "modulation_order": "qam_256" | "plc" | "exclusion" | "continuous_pilot" | ...,
                        "num_subcarriers": int
                    }
            - schema_type = 1 (skip):
                    {
                        "schema_type": 1,
                        "main_modulation_order": "...",
                        "skip_modulation_order": "...",
                        "num_subcarriers": int
                    }

        split_carriers : bool, default True
            Controls how per-carrier results are represented in the output:

            * True  → **split layout** (compact parallel arrays). Best for fast analytics,
                    vectorized ops, plotting, and storage efficiency.
            * False → **list layout** (verbose per-carrier records). Best for inspection/logging.

        Returns
        -------
        DsModulationProfileAnalysisModel

        Raises
        ------
        ValueError
            If spacing/indices/frequencies are invalid.
        """
        spacing: FrequencyHz       = FrequencyHz(measurement.get("subcarrier_spacing", INVALID_START_VALUE))
        active_index: int          = int(measurement.get("first_active_subcarrier_index", INVALID_START_VALUE))
        zero_freq: FrequencyHz     = FrequencyHz(measurement.get("subcarrier_zero_frequency", INVALID_START_VALUE))

        if active_index < 0 or zero_freq < 0 or spacing <= 0:
            raise ValueError(
                f"Invalid parameters: spacing={spacing}, active_index={active_index}, zero_freq={zero_freq}")

        #Calculate Start Frequency
        start_freq = zero_freq + spacing * active_index

        out = DsModulationProfileAnalysisModel(
            device_details      = measurement.get("device_details", {}),
            pnm_header          = measurement.get("pnm_header", {}),
            mac_address         = MacAddressStr(measurement.get("mac_address", MacAddress.null())),
            channel_id          = ChannelId(measurement.get("channel_id", INVALID_CHANNEL_ID)),
            frequency_unit      = "Hz",
            shannon_min_unit    = "dB",
            profiles            = [],
        )

        # --- Per-profile assembly ---
        for profile in measurement.get("profiles", []) or []:
            profile_id  = ProfileId(profile.get("profile_id", INVALID_PROFILE_ID))
            schemes     = profile.get("schemes", []) or []

            freq_list: FrequencySeriesHz    = []
            mod_list:  list[str]    = []
            shan_list: list[float]  = []
            carrier_items: list[CarrierItemModel] = []

            freq_ptr = start_freq

            for scheme in schemes:
                schema_type = int(scheme.get("schema_type", INVALID_SCHEMA_TYPE))

                # Determine which modulation name & count to use
                if schema_type == CmDsOfdmModulationProfile.RANGE_MODULATION:
                    mod_name: str   = str(scheme.get("modulation_order"))
                    count: int      = int(scheme.get("num_subcarriers", 0))

                elif schema_type == CmDsOfdmModulationProfile.SKIP_MODULATION:
                    mod_name = str(scheme.get("main_modulation_order"))
                    count    = int(scheme.get("num_subcarriers", 0))

                else:
                    # Unknown schema; skip conservatively
                    logging.warning(f'basic_analysis_ds_modulation_profile() -> Unknown Schema: {schema_type}')
                    continue

                for _ in range(count):
                    # Compute Shannon minimum MER (perfect FEC) per modulation-order-type

                    if mod_name in (ModulationOrderType.continuous_pilot.name,
                                    ModulationOrderType.exclusion.name):
                        s_min = 0.0

                    elif mod_name == ModulationOrderType.plc.name:
                        # Treat PLC as 16-QAM (4 bits/s/Hz) at the Shannon min
                        s_min = Shannon.bits_to_snr(4)

                    else:
                        # Map strings like 'qam_256' → Shannon SNR (dB)
                        s_min = Shannon.snr_from_modulation(mod_name)

                    s_min = round(float(s_min), 2)
                    f_val = int(freq_ptr)

                    if split_carriers:
                        freq_list.append(f_val)
                        mod_list.append(mod_name)
                        shan_list.append(s_min)
                    else:
                        carrier_items.append(
                            CarrierItemModel(
                                frequency       = f_val,
                                modulation      = mod_name,
                                shannon_min_mer = s_min,
                            )
                        )

                    freq_ptr += spacing

            # Attach carrier values according to layout
            if split_carriers:
                carrier_values: CarrierValuesModel = CarrierValuesSplitModel(
                    layout          =   "split",
                    frequency       =   freq_list,
                    modulation      =   mod_list,
                    shannon_min_mer =   shan_list,
                )

            else:
                carrier_values = CarrierValuesListModel(
                    layout      =   "list",
                    carriers    =   carrier_items,
                )

            out.profiles.append(
                ProfileAnalysisEntryModel(
                    profile_id      =   profile_id,
                    carrier_values  =   carrier_values,
                )
            )

        return out

    @classmethod
    def basic_analysis_us_ofdma_pre_equalization(cls, measurement: dict[str, Any]) -> UsOfdmaUsPreEqAnalysisModel:
        """
        Perform Upstream OFDMA Pre-Equalization Analysis.

        Computes:
        - Per-subcarrier frequency axis (Hz)
        - Magnitude sequence (dB) from complex coefficients
        - Group delay (µs) from phase slope across subcarriers
        - IFFT-based echo detection over a constrained delay window
        - Complex samples passthrough
        - Signal statistics over the magnitude sequence

        Expected Keys (subset) in `measurement`
        ---------------------------------------
        channel_id : int
            Upstream OFDMA channel ID.
        subcarrier_spacing : int
            Δf in Hz between subcarriers.
        first_active_subcarrier_index : int
            Index of the first active subcarrier relative to subcarrier 0.
        subcarrier_zero_frequency : int
            Frequency (Hz) of subcarrier 0.
        occupied_channel_bandwidth : int
            Occupied bandwidth for metadata.
        values : ComplexArray
            List of complex-like samples for H(f). [(re, im), ...] or [complex, ...].

        Returns
        -------
        UsOfdmaUsPreEqAnalysisModel
            Typed model with carrier values, signal statistics, and echo results.
        """
        log = logging.getLogger(f"{cls.__name__}")

        channel_id: ChannelId                   = measurement.get("channel_id",                    INVALID_CHANNEL_ID)
        subcarrier_spacing: FrequencyHz         = measurement.get("subcarrier_spacing",            INVALID_START_VALUE)
        first_active_subcarrier_index: int      = measurement.get("first_active_subcarrier_index", INVALID_START_VALUE)
        subcarrier_zero_frequency: FrequencyHz  = measurement.get("subcarrier_zero_frequency",     INVALID_START_VALUE)
        occupied_channel_bandwidth: FrequencyHz = measurement.get("occupied_channel_bandwidth",    INVALID_START_VALUE)

        if (first_active_subcarrier_index < 0) or (subcarrier_zero_frequency < 0) or (subcarrier_spacing <= 0):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        values: ComplexArray = measurement.get("values", [])
        if not values:
            raise ValueError("No complex pre-equalization values provided in measurement.")

        start_freq: FrequencyHz  = cast(FrequencyHz, (subcarrier_spacing * first_active_subcarrier_index) + subcarrier_zero_frequency)
        freqs: FrequencySeriesHz = cast(FrequencySeriesHz, [start_freq + (i * subcarrier_spacing) for i in range(len(values))])

        gd = GroupDelay.from_channel_estimate(Hhat=values, df_hz=subcarrier_spacing, f0_hz=start_freq)
        gd_results = gd.to_result()

        cao = ComplexArrayOps(values)
        magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

        complex_arr = np.asarray(
            [
                complex(v[0], v[1])
                if (not isinstance(v, complex)) and isinstance(v, (list, tuple)) and len(v) == 2
                else complex(v)
                for v in values
            ],
            dtype=np.complex128,
        )

        try:
            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(subcarrier_spacing) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz = FrequencyHz(subcarrier_spacing),
                cutoff_hz             = cutoff_hz,
                order                 = DEFAULT_BUTTERWORTH_ORDER,
                zero_phase            = True,
            )

            mag_result = mag_filter.apply(np.asarray(magnitudes_db_raw, dtype=np.float64))
            magnitudes_db: FloatSeries = mag_result.filtered_values.tolist()
        except Exception:
            magnitudes_db = magnitudes_db_raw

        signal_stats_model: SignalStatisticsModel = SignalStatistics(magnitudes_db).compute()

        group_delay_stats: GrpDelayStatsModel = GrpDelayStatsModel(
            group_delay_unit = "microsecond",
            magnitude        = ComplexArrayOps.to_list(gd_results.group_delay_us),
        )

        magn_linear = np.power(10.0, np.asarray(magnitudes_db, dtype=np.float64) / 20.0)
        phases      = np.angle(complex_arr)
        H_smooth    = magn_linear * np.exp(1j * phases)

        N      = len(values)
        n_fft  = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        fs = float(N) * float(subcarrier_spacing)
        max_delay_s_used = 3.5e-6

        cable_type_name = "RG6"
        v               = SPEED_OF_LIGHT * CABLE_VF.get(cable_type_name, 0.87)
        max_dist_m      = 0.5 * v * max_delay_s_used
        i_stop          = int(max_delay_s_used * fs)
        log.debug(
            "US OFDMA Pre-Eq EchoDetector window: fs=%.3f Hz, n_fft=%d, i_stop=%d bins, "
            "max_delay=%.2fus, max_dist≈%.1f m",
            fs, n_fft, i_stop, max_delay_s_used * 1e6, max_dist_m
        )

        det = EchoDetector(
            freq_data               = H_smooth.tolist(),
            subcarrier_spacing_hz   = float(subcarrier_spacing),
            n_fft                   = 4096,
            cable_type              = cable_type_name,
            channel_id              = channel_id,
        )

        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode        = "db_down",
            threshold_db_down     = 60.0,
            normalize_power       = True,
            guard_bins            = 16,
            min_separation_s      = 8.0 / det.fs,
            max_delay_s           = max_delay_s_used,
            max_peaks             = 3,
            include_time_response = False,
            direct_at_zero        = True,
            window                = "hann",
        )

        i_stop     = int(np.ceil(max_delay_s_used * det.fs))
        edge_guard = 8
        if echo_report.echoes:
            echo_report.echoes = [
                e for e in echo_report.echoes
                if (e.bin_index < (i_stop - edge_guard))
            ]

        echo_rpt = EchoDatasetModel(
            type    = EchoDetectorType.IFFT,
            report  = echo_report,
        )

        carrier_values: OfdmaUsPreEqCarrierModel = OfdmaUsPreEqCarrierModel(
            carrier_count               = len(freqs),
            frequency_unit              = "Hz",
            frequency                   = freqs,
            complex                     = values,
            complex_dimension           = int(complex_arr.ndim),
            magnitudes                  = magnitudes_db,
            group_delay                 = group_delay_stats,
            occupied_channel_bandwidth  = occupied_channel_bandwidth,
        )

        result_model: UsOfdmaUsPreEqAnalysisModel = UsOfdmaUsPreEqAnalysisModel(
            device_details                  = measurement.get("device_details", {}),
            pnm_header                      = measurement.get("pnm_header", {}),
            mac_address                     = MacAddressStr(measurement.get("mac_address", "")),
            channel_id                      = ChannelId(channel_id),
            subcarrier_spacing              = subcarrier_spacing,
            first_active_subcarrier_index   = first_active_subcarrier_index,
            subcarrier_zero_frequency       = subcarrier_zero_frequency,
            carrier_values                  = carrier_values,
            signal_statistics               = signal_stats_model,
            echo                            = echo_rpt,
        )

        if log.isEnabledFor(logging.DEBUG):
            LogFile.write(
                f'UsOfdmaUsPreEqAnalysisModel_{result_model.mac_address}_{result_model.channel_id}.log',
                result_model,
            )

        return result_model

    @classmethod
    def basic_analysis_ds_constellation_display(cls, measurement: dict[str, Any]) -> ConstellationDisplayAnalysisModel:
        """
        Build a minimal constellation analysis payload from a downstream OFDM
        measurement dictionary.

        CM Output Assumption
        --------------------
        The DOCSIS spec states the constellation display samples are provided as
        s2.13 **soft decisions scaled to ~unit average power** at the slicer input.
        Because your LUT hard points are likewise normalized, **do not rescale**
        the CM-provided soft points here.

        Parameters
        ----------
        measurement : dict
            Expected keys (subset):
            - ``samples`` : ComplexArray (list of [real, imag]) — required
            - ``pnm_header`` : dict
            - ``mac_address`` : str
            - ``channel_id`` : int
            - ``num_sample_symbols`` : int (defaults to len(samples))
            - ``actual_modulation_order`` : int | str (e.g., 256 or "QAM-256")

        Returns
        -------
        ConstellationDisplayAnalysisModel
            Typed model carrying device/header info, inferred QAM order,
            **hard** constellation points from the LUT, and the **unscaled soft**
            decision coordinates provided by the CM.

        Raises
        ------
        ValueError
            If ``samples`` is missing or empty.
        """
        samples: ComplexArray = measurement.get("samples") or []
        if not samples:
            raise ValueError("measurement['samples'] is required and must be a non-empty ComplexArray.")

        # Map actual modulation order → QamModulation
        amo: int | str = measurement.get("actual_modulation_order", DsOfdmModulationType.UNKNOWN)
        qm: QamModulation = QamModulation.from_DsOfdmModulationType(amo)

        # Hard points come from LUT (already normalized)
        hard = QamLutManager().get_hard_decisions(qm)

        # IMPORTANT: Do NOT rescale the CM soft decisions; they are already unit-power normalized (s2.13).
        soft = samples

        return ConstellationDisplayAnalysisModel(
            device_details      = measurement.get("device_details", SystemDescriptor.empty()),
            pnm_header          = measurement.get("pnm_header", {}),
            mac_address         = measurement.get("mac_address", MacAddress.null()),
            channel_id          = measurement.get("channel_id", INVALID_CHANNEL_ID),
            num_sample_symbols  = measurement.get("num_sample_symbols", len(samples)),
            modulation_order    = qm,       # QamModulation
            hard                = hard,     # LUT hard points (normalized)
            soft                = soft      # CM soft decisions (already normalized) ← changed
        )

    @classmethod
    def basic_analysis_ds_histogram(cls, measurement: dict[str, Any]) -> DsHistogramAnalysisModel:
        """
        Build a :class:`DsHistogramAnalysisModel` from a downstream histogram payload.

        Parameters
        ----------
        measurement : dict
            Expected keys (subset):
                - ``device_details`` : dict
                - ``pnm_header`` : dict
                - ``mac_address`` : str
                - ``channel_id`` : int
                - ``symmetry`` : int
                - ``dwell_count`` : int
                - ``hit_counts`` : List[int]

        Returns
        -------
        DsHistogramAnalysisModel
            Typed model with histogram metrics and metadata.
        """
        return DsHistogramAnalysisModel(
            device_details  = measurement.get("device_details", SystemDescriptor.empty()),
            pnm_header      = measurement.get("pnm_header", {}),
            mac_address     = measurement.get("mac_address", MacAddress.null()),
            channel_id      = measurement.get("channel_id", INVALID_CHANNEL_ID),
            symmetry        = measurement.get("symmetry", -1),
            dwell_counts    = measurement.get("dwell_count_values", []),
            hit_counts      = measurement.get("hit_count_values", []),
        )

    @classmethod
    def basic_analysis_ds_ofdm_fec_summary(cls, measurement: dict[str, Any]) -> OfdmFecSummaryAnalysisModel:
        """
        Build an OfdmFecSummaryAnalysisModel from a DS OFDM FEC summary payload.

        Accepts EITHER:
        - parser shape:   fec_summary_data[*].codeword_entries.{timestamp,total_codewords,corrected,uncorrectable}
        - analysis shape: profiles[*].codewords.{timestamps,total_codewords,corrected,uncorrected}

        Truncates to the shortest parallel length per profile and logs length issues.
        """
        log = logging.getLogger(getattr(cls, "__name__", "OfdmFecSummaryAnalysis"))

        # Prefer parser shape; fall back to analysis shape.
        raw_profiles = measurement.get("fec_summary_data")
        alt_profiles = measurement.get("profiles")

        profiles_src = "fec_summary_data" if raw_profiles else ("profiles" if alt_profiles else None)
        prof_iter = raw_profiles if raw_profiles is not None else (alt_profiles or [])

        if profiles_src is None:
            log.warning("FEC Summary: no 'fec_summary_data' or 'profiles' in measurement; returning empty model.")
            return OfdmFecSummaryAnalysisModel(
                device_details = measurement.get("device_details", {}),
                pnm_header     = measurement.get("pnm_header", {}),
                mac_address    = measurement.get("mac_address", MacAddress.null()),
                channel_id     = ChannelId(measurement.get("channel_id", INVALID_CHANNEL_ID)),
                profiles       = [],
            )

        out_profiles: list[OfdmFecSummaryProfileModel] = []

        for idx, prof in enumerate(prof_iter):
            # Profile id + declared sets field name differs per shape.
            profile_id = ProfileId(prof.get("profile_id", prof.get("profile", INVALID_CHANNEL_ID)))
            declared_sets = int(prof.get("number_of_sets", 0))

            # Choose inner block by shape:
            # - parser shape:   codeword_entries.{timestamp, total_codewords, corrected, uncorrectable}
            # - analysis shape: codewords.{timestamps, total_codewords, corrected, uncorrected}
            cwe = prof.get("codeword_entries")
            if cwe is None:
                cwe = prof.get("codewords") or {}

            # Try both key spellings for timestamps
            ts_raw  = cwe.get("timestamp")
            if ts_raw is None:
                ts_raw = cwe.get("timestamps")

            # Coerce to ints; be tolerant of None/empty lists
            ts_list  = [int(x) for x in (ts_raw or [])]
            tot_list = [int(x) for x in (cwe.get("total_codewords") or [])]
            cor_list = [int(x) for x in (cwe.get("corrected") or [])]
            unc_list = [int(x) for x in (cwe.get("uncorrectable") or [])]

            n = min(len(ts_list), len(tot_list), len(cor_list), len(unc_list)) if any(
                (ts_list, tot_list, cor_list, unc_list)
            ) else 0

            if n and any(len(lst) != n for lst in (ts_list, tot_list, cor_list, unc_list)):
                log.warning(
                    "FEC Summary: profile=%s (%s[%d]) series mismatch; truncating to %d "
                    "(ts=%d, total=%d, corrected=%d, uncorrectable=%d)",
                    profile_id, profiles_src, idx, n, len(ts_list), len(tot_list), len(cor_list), len(unc_list)
                )
                ts_list, tot_list, cor_list, unc_list = (
                    ts_list[:n], tot_list[:n], cor_list[:n], unc_list[:n]
                )

            if declared_sets and declared_sets != n:
                log.debug(
                    "FEC Summary: profile=%s declared number_of_sets=%d, computed=%d; using computed.",
                    profile_id, declared_sets, n
                )

            # Helpful debug when n == 0 so you can see the shape that arrived
            if n == 0:
                log.debug(
                    "FEC Summary: profile=%s has no aligned data (src=%s[%d]); "
                    "lens ts/total/corr/unc = %d/%d/%d/%d; keys=%s",
                    profile_id, profiles_src, idx,
                    len(ts_list), len(tot_list), len(cor_list), len(unc_list),
                    list(cwe.keys())
                )

            cw = FecSummaryCodeWordModel(
                timestamps      = ts_list,
                total_codewords = tot_list,
                corrected       = cor_list,
                uncorrected     = unc_list,
            )

            out_profiles.append(
                OfdmFecSummaryProfileModel(
                    profile         = profile_id,
                    number_of_sets  = n,
                    codewords       = cw,
                )
            )

        # Optional top-level sanity
        declared_num_profiles = int(measurement.get("num_profiles", len(out_profiles)))
        if declared_num_profiles != len(out_profiles):
            log.debug("FEC Summary: num_profiles declared=%d, parsed=%d", declared_num_profiles, len(out_profiles))

        return OfdmFecSummaryAnalysisModel(
            device_details = measurement.get("device_details", {}),
            pnm_header     = measurement.get("pnm_header", {}),
            mac_address    = measurement.get("mac_address", MacAddress.null()),
            channel_id     = ChannelId(measurement.get("channel_id", INVALID_CHANNEL_ID)),
            profiles       = out_profiles,
        )

    @classmethod
    def basic_analysis_spectrum_analyzer(cls, measurement: dict[str, Any], analysis_parameters: AnalysisProcessParameters | None) -> SpectrumAnalyzerAnalysisModel:
        """
        Build SpectrumAnalyzerAnalysisModel from converted PNM measurement:
        """
        log = logging.getLogger(f"{cls.__name__}")
        # --- core params ---
        first_seg_cf  = int(measurement.get("first_segment_center_frequency", 0))
        last_seg_cf   = int(measurement.get("last_segment_center_frequency", 0))
        seg_span_hz   = int(measurement.get("segment_frequency_span", 0))
        bins_per_seg  = int(measurement.get("num_bins_per_segment", 0))
        enbw_hz       = float(measurement.get("equivalent_noise_bandwidth", 0.0))
        noise_bw_khz  = int(round(enbw_hz / 1_000.0)) if enbw_hz > 0.0 else 0

        wf_raw        = int(measurement.get("window_function", WindowFunction.HANN.value))
        try:
            wf_enum: WindowFunction = WindowFunction(wf_raw)
        except Exception:
            wf_enum = WindowFunction.HANN

        bin_bw = int(measurement.get("bin_frequency_spacing", 0))
        if bin_bw <= 0 and seg_span_hz > 0 and bins_per_seg > 0:
            bin_bw = max(1, seg_span_hz // bins_per_seg)

        # --- segments & magnitudes ---
        segments = measurement.get("amplitude_bin_segments_float", [])
        num_segments = len(segments)
        if bins_per_seg <= 0 and num_segments:
            bins_per_seg = len(segments[0])

        # Normalize each segment length to bins_per_seg (clip/pad NaN)
        norm_segments: list[list[float]] = []
        for s in segments:
            if len(s) >= bins_per_seg:
                norm_segments.append([float(x) for x in s[:bins_per_seg]])
            else:
                pad = [float("nan")] * (bins_per_seg - len(s))
                norm_segments.append([float(x) for x in s] + pad)

        magnitudes: MagnitudeSeries = [x for seg in norm_segments for x in seg]

        # --- compute frequency axis across segments ---
        frequencies: FrequencySeriesHz = []
        if num_segments > 0 and bins_per_seg > 0 and seg_span_hz > 0 and bin_bw > 0 and first_seg_cf > 0:
            seg_step_hz = (last_seg_cf - first_seg_cf) // (num_segments - 1) if num_segments > 1 else 0
            # start at center - span/2, align to bin center with +bin_bw/2
            seg0_start = first_seg_cf - (seg_span_hz // 2) + (bin_bw // 2)

            freqs: FrequencySeriesHz = []
            for s_idx in range(num_segments):
                start_hz = seg0_start + s_idx * seg_step_hz
                freqs.extend(int(start_hz + i * bin_bw) for i in range(bins_per_seg))
            frequencies = freqs

        # --- align lengths (trim to shortest) ---
        if frequencies and magnitudes and len(frequencies) != len(magnitudes):
            n = min(len(frequencies), len(magnitudes))
            frequencies = frequencies[:n]
            magnitudes  = magnitudes[:n]
        if not frequencies or not magnitudes:
            frequencies, magnitudes = [], []

        # --- windowed average (same length) ---
        # TODO: Need to clean this up, need to move the DEFAULT to the Model in a better way
        if analysis_parameters:
            log.debug("Spectrum Analyzer: applying moving average with parameters: %s", analysis_parameters)
            window_points = analysis_parameters.moving_average.points
        else:
            log.warning("Spectrum Analyzer: applying DEFAULT moving average: %s", DEFAULT_POINT_AVG)
            window_points = DEFAULT_POINT_AVG

        try:
            ma = MovingAverage(max(1, window_points), mode="reflect")
            smoothed = ma.apply(magnitudes) if magnitudes else []
        except Exception:
            smoothed = list(magnitudes)

        if len(smoothed) != len(frequencies):
            smoothed = smoothed[:len(frequencies)]

        window_avg = WindowAverage(points=max(1, window_points), magnitudes=smoothed)

        magnitudes_for_power: MagnitudeSeries = [m for m in magnitudes if math.isfinite(m)]
        channel_power_dbmv = round(
            ChannelPowerDbmv.calculate_channel_power_dbmv(magnitudes_for_power),
            2,
        )

        results = SpecAnaAnalysisResults(
            bin_bandwidth  = bin_bw,
            segment_length = bins_per_seg,
            frequencies    = frequencies,
            magnitudes     = magnitudes,
            window_average = window_avg,
            channel_power_dbmv = channel_power_dbmv,
        )

        capture_parameters: SpecAnCapturePara = SpecAnCapturePara(
            first_segment_center_freq = FrequencyHz(first_seg_cf),
            last_segment_center_freq  = FrequencyHz(last_seg_cf),
            segment_freq_span         = FrequencyHz(seg_span_hz),
            num_bins_per_segment      = bins_per_seg,
            noise_bw                  = noise_bw_khz,
            window_function           = wf_enum,
        )

        return SpectrumAnalyzerAnalysisModel(
            device_details     = measurement.get("device_details", SystemDescriptor.empty()),
            pnm_header         = measurement.get("pnm_header", {}),
            mac_address        = measurement.get("mac_address", MacAddress.null()),
            channel_id         = ChannelId(measurement.get("channel_id", 0)),
            capture_parameters = capture_parameters,
            signal_analysis    = results,
        )

    @classmethod
    def basic_analysis_spectrum_analyzer_snmp(cls, measurement: dict[str, Any],
                                              capture_parameters_update: SpectrumAnalysisSnmpCaptureParameters | None = None,
                                              analysis_parameters: AnalysisProcessParameters | None = None,) -> SpectrumAnalyzerAnalysisModel:
        log = logging.getLogger(f"{cls.__name__}")

        freqs: FrequencySeriesHz = list(measurement.get("frequency", []) or [])
        mags:  MagnitudeSeries   = [float(x) for x in (measurement.get("amplitude", []) or [])]

        if not freqs or not mags:
            raise ValueError("Spectrum Analyzer (SNMP): 'frequency' and 'amplitude' must be non-empty.")
        if len(freqs) != len(mags):
            n = min(len(freqs), len(mags))
            log.warning("Spectrum Analyzer (SNMP): len mismatch freq=%d amp=%d; truncating to %d", len(freqs), len(mags), n)
            freqs, mags = freqs[:n], mags[:n]

        # Infer bin bandwidth from median positive Δf (robust to occasional glitches)
        try:
            if len(freqs) >= 2:
                diffs = np.diff(np.asarray(freqs, dtype=np.int64))
                pos_diffs = diffs[diffs > 0]
                bin_bw = int(np.median(pos_diffs)) if pos_diffs.size else int(diffs[0])
            else:
                bin_bw = 0
        except Exception:
            bin_bw = 0

        first_hz: int = int(freqs[0])
        last_hz:  int = int(freqs[-1])
        span_hz:  int = abs(last_hz - first_hz)
        bins:     int = len(freqs)

        # Moving-average (windowed) smoothing
        if analysis_parameters:
            window_points = int(max(1, analysis_parameters.moving_average.points))
        else:
            window_points = int(max(1, DEFAULT_POINT_AVG))

        try:
            ma = MovingAverage(window_points, mode="reflect")
            smoothed = ma.apply(mags) if mags else []
        except Exception:
            smoothed = list(mags)

        if len(smoothed) != len(freqs):
            smoothed = smoothed[:len(freqs)]

        window_avg = WindowAverage(points=window_points, magnitudes=smoothed)
        magnitudes_for_power: MagnitudeSeries = [m for m in mags if math.isfinite(m)]
        channel_power_dbmv = round(
            ChannelPowerDbmv.calculate_channel_power_dbmv(magnitudes_for_power),
            2,
        )

        # Build results (single-sweep flattened to one "segment")
        results = SpecAnaAnalysisResults(
            bin_bandwidth  = bin_bw,
            segment_length = bins,
            frequencies    = freqs,
            magnitudes     = mags,
            window_average = window_avg,
            channel_power_dbmv = channel_power_dbmv,
        )

        # Endpoints only; no center calculation
        enbw_hz = float(measurement.get("equivalent_noise_bandwidth", 0.0))
        noise_bw_khz = int(round(enbw_hz / 1_000.0)) if enbw_hz > 0.0 else 0

        inactivity_timeout: int = 60

        # Since these values come from SNMP and not PNM, allow overrides
        if capture_parameters_update:
            inactivity_timeout:int = capture_parameters_update.get("inactivity_timeout", 60)
            first_hz = FrequencyHz(capture_parameters_update.get("first_segment_center_freq", first_hz))
            last_hz  = FrequencyHz(capture_parameters_update.get("last_segment_center_freq", last_hz))
            span_hz  = FrequencyHz(capture_parameters_update.get("segment_freq_span", span_hz))
            bins     = int(capture_parameters_update.get("num_bins_per_segment", bins))
            noise_bw_khz = FrequencyHz(capture_parameters_update.get("noise_bw", noise_bw_khz))

        capture_parameters: SpecAnCapturePara = SpecAnCapturePara(
            first_segment_center_freq = FrequencyHz(first_hz),
            last_segment_center_freq  = FrequencyHz(last_hz),
            segment_freq_span         = FrequencyHz(span_hz),
            num_bins_per_segment      = bins,
            noise_bw                  = noise_bw_khz,
            window_function           = WindowFunction.HANN,
            inactivity_timeout        = inactivity_timeout,
        )

        return SpectrumAnalyzerAnalysisModel(
            device_details     = measurement.get("device_details", SystemDescriptor.empty()),
            pnm_header         = measurement.get("pnm_header", {}),
            mac_address        = measurement.get("mac_address", MacAddress.null()),
            channel_id         = ChannelId(measurement.get("channel_id", 0)),
            capture_parameters = capture_parameters,
            signal_analysis    = results,
        )

    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

    @classmethod
    def basic_analysis_rxmer_from_model(cls, model: CmDsOfdmRxMerModel) -> DsRxMerAnalysisModel:
        """
        Perform basic RxMER analysis from a parsed :class:`CmDsOfdmRxMerModel`.

        This is the model-based counterpart to ``basic_analysis_rxmer(...)`` and builds
        a :class:`DsRxMerAnalysisModel` using typed fields instead of a raw measurement
        dictionary. It re-derives the frequency axis, carrier status classification, and
        regression line, while reusing metadata already normalized into the model.
        """
        channel_id: ChannelId                   = model.channel_id
        subcarrier_spacing: FrequencyHz         = model.subcarrier_spacing
        first_active_subcarrier_index: int      = model.first_active_subcarrier_index
        subcarrier_zero_frequency: FrequencyHz  = model.subcarrier_zero_frequency

        if (first_active_subcarrier_index < 0) or (subcarrier_zero_frequency < 0) or (subcarrier_spacing <= 0):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        magnitudes: FloatSeries = model.values
        if not magnitudes:
            raise ValueError("No RxMER values provided in model.")

        base_freq: FrequencyHz   = FrequencyHz((subcarrier_spacing * first_active_subcarrier_index) + subcarrier_zero_frequency)
        freqs: FrequencySeriesHz = [FrequencyHz(base_freq + (i * subcarrier_spacing)) for i in range(len(magnitudes))]

        def classify(v: float) -> int:
            if v == RXMER_EXCLUSION:
                return int(RxMerCarrierType.EXCLUSION.value)
            if v in (RXMER_CLIPPED_LOW, RXMER_CLIPPED_HIGH):
                return int(RxMerCarrierType.CLIPPED.value)
            return int(RxMerCarrierType.NORMAL.value)

        carrier_status: IntSeries = [classify(v) for v in magnitudes]

        if not (len(freqs) == len(magnitudes) == len(carrier_status)):
            raise ValueError(
                f"Length mismatch detected: frequencies({len(freqs)}), "
                f"magnitudes({len(magnitudes)}), carrier_status({len(carrier_status)})"
            )

        regession_model = RegressionModel(
            slope   = cast(FloatSeries, LinearRegression1D(cast(ArrayLike, magnitudes),
                                                           cast(ArrayLike, freqs)).regression_line())
        )

        csm: dict[str, Any] = {
            RxMerCarrierType.EXCLUSION.name.lower(): RxMerCarrierType.EXCLUSION.value,
            RxMerCarrierType.CLIPPED.name.lower():   RxMerCarrierType.CLIPPED.value,
            RxMerCarrierType.NORMAL.name.lower():    RxMerCarrierType.NORMAL.value,
        }

        carrier_values = RxMerCarrierValuesModel(
            carrier_status_map  = csm,
            carrier_count       = len(freqs),
            magnitude           = magnitudes,
            frequency           = freqs,
            carrier_status      = carrier_status,
        )

        return DsRxMerAnalysisModel(
            device_details                  = getattr(model, "device_details", {}),
            pnm_header                      = model.pnm_header.model_dump() if hasattr(model.pnm_header, "model_dump") else getattr(model, "pnm_header", {}),
            mac_address                     = MacAddressStr(getattr(model, "mac_address", MacAddress.null())),
            channel_id                      = channel_id,
            subcarrier_spacing              = subcarrier_spacing,
            first_active_subcarrier_index   = first_active_subcarrier_index,
            subcarrier_zero_frequency       = subcarrier_zero_frequency,
            carrier_values                  = carrier_values,
            regression                      = regession_model,
            modulation_statistics           = model.modulation_statistics,
        )

    @classmethod
    def basic_analysis_ds_chan_est_from_model(cls, model: CmDsOfdmChanEstimateCoefModel,
                                              cable_type: CableType = CableType.RG6,) -> DsChannelEstAnalysisModel:
        """
        Model-based variant of downstream channel-estimation analysis.

        Mirrors `basic_analysis_ds_chan_est()` but accepts a parsed
        `CmDsOfdmChanEstimateCoefModel` instead of a raw measurement dict.

        Computes:
        - Per-subcarrier frequency axis (Hz)
        - Magnitude sequence (dB) from complex coefficients, with optional
          Butterworth low-pass smoothing across subcarriers
        - Group delay (µs) from phase slope across subcarriers
        - IFFT-based echo detection over a constrained delay window
        - Complex samples passthrough
        - Signal statistics over the (smoothed) magnitude sequence
        """
        log = logging.getLogger(f"{cls.__name__}")

        subcarrier_spacing: FrequencyHz         = FrequencyHz(int(getattr(model, "subcarrier_spacing",       INVALID_START_VALUE)))
        first_active_subcarrier_index: int      = int(getattr(model, "first_active_subcarrier_index",        INVALID_START_VALUE))
        subcarrier_zero_frequency: FrequencyHz  = cast(FrequencyHz, int(getattr(model, "subcarrier_zero_frequency", INVALID_START_VALUE)))
        occupied_channel_bandwidth: FrequencyHz = cast(FrequencyHz, int(getattr(model, "occupied_channel_bandwidth", 0)))

        if (first_active_subcarrier_index < 0) or (subcarrier_zero_frequency < 0) or (subcarrier_spacing <= 0):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        values: ComplexArray = cast(ComplexArray, getattr(model, "values", []))
        if not values:
            raise ValueError("No complex channel estimation values provided in model.")

        start_freq: FrequencyHz  = cast(FrequencyHz, (subcarrier_spacing * first_active_subcarrier_index) + subcarrier_zero_frequency)
        freqs: FrequencySeriesHz = cast(FrequencySeriesHz, [start_freq + (i * subcarrier_spacing) for i in range(len(values))])

        gd = GroupDelay.from_channel_estimate(Hhat=values, df_hz=subcarrier_spacing, f0_hz=start_freq)
        gd_results = gd.to_result()

        cao = ComplexArrayOps(values)
        magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

        complex_arr = np.asarray(
            [
                complex(v[0], v[1])
                if not isinstance(v, complex) and isinstance(v, (list, tuple)) and len(v) == 2
                else complex(v)
                for v in values
            ],
            dtype=np.complex128,
        )

        try:
            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(subcarrier_spacing) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz = FrequencyHz(int(subcarrier_spacing)),
                cutoff_hz             = cutoff_hz,
                order                 = DEFAULT_BUTTERWORTH_ORDER,
                zero_phase            = True,
            )

            mag_result = mag_filter.apply(np.asarray(magnitudes_db_raw, dtype=np.float64))
            magnitudes_db: FloatSeries = mag_result.filtered_values.tolist()
        except Exception:
            magnitudes_db = magnitudes_db_raw

        signal_stats_model: SignalStatisticsModel = SignalStatistics(magnitudes_db).compute()

        group_delay_stats: GrpDelayStatsModel = GrpDelayStatsModel(
            group_delay_unit = "microsecond",
            magnitude        = ComplexArrayOps.to_list(gd_results.group_delay_us),
        )

        magn_linear = np.power(10.0, np.asarray(magnitudes_db, dtype=np.float64) / 20.0)
        phases      = np.angle(complex_arr)
        H_smooth    = magn_linear * np.exp(1j * phases)

        N      = len(values)
        n_fft  = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        fs = float(N) * float(subcarrier_spacing)
        max_delay_s_used = 3.5e-6

        v          = SPEED_OF_LIGHT * CABLE_VF.get(cable_type.name, 0.87)
        max_dist_m = 0.5 * v * max_delay_s_used
        i_stop     = int(max_delay_s_used * fs)
        log.debug(
            "DS ChanEst (model) EchoDetector window: fs=%.3f Hz, n_fft=%d, i_stop=%d bins, "
            "max_delay=%.2fus, max_dist≈%.1f m, cable_type=%s",
            fs, n_fft, i_stop, max_delay_s_used * 1e6, max_dist_m, cable_type.name,
        )

        det = EchoDetector(
            freq_data               = H_smooth.tolist(),
            subcarrier_spacing_hz   = float(subcarrier_spacing),
            n_fft                   = 4096,
            cable_type              = cable_type.name,
            channel_id              = cast(ChannelId, int(getattr(model, "channel_id", INVALID_CHANNEL_ID))),
        )

        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode        = "db_down",
            threshold_db_down     = 60.0,
            normalize_power       = True,
            guard_bins            = 16,
            min_separation_s      = 8.0 / det.fs,
            max_delay_s           = max_delay_s_used,
            max_peaks             = 3,
            include_time_response = False,
            direct_at_zero        = True,
            window                = "hann",
        )

        i_stop     = int(np.ceil(max_delay_s_used * det.fs))
        edge_guard = 8
        if echo_report.echoes:
            echo_report.echoes = [
                e for e in echo_report.echoes
                if (e.bin_index < (i_stop - edge_guard))
            ]

        echo_rpt = EchoDatasetModel(type=EchoDetectorType.IFFT, report=echo_report)

        carrier_values: ChanEstCarrierModel = ChanEstCarrierModel(
            carrier_count               = len(freqs),
            frequency_unit              = "Hz",
            frequency                   = freqs,
            complex                     = values,
            complex_dimension           = int(complex_arr.ndim),
            magnitudes                  = magnitudes_db,
            group_delay                 = group_delay_stats,
            occupied_channel_bandwidth  = occupied_channel_bandwidth,
        )

        result_model: DsChannelEstAnalysisModel = DsChannelEstAnalysisModel(
            device_details                  = getattr(model, "device_details", {}),
            pnm_header                      = model.pnm_header.model_dump() if hasattr(model.pnm_header, "model_dump") else {},
            mac_address                     = cast(MacAddressStr, getattr(model, "mac_address", "")),
            channel_id                      = cast(ChannelId, int(getattr(model, "channel_id", INVALID_START_VALUE))),
            subcarrier_spacing              = subcarrier_spacing,
            first_active_subcarrier_index   = first_active_subcarrier_index,
            subcarrier_zero_frequency       = subcarrier_zero_frequency,
            carrier_values                  = carrier_values,
            signal_statistics               = signal_stats_model,
            echo                            = echo_rpt,
        )

        return result_model

    @classmethod
    def basic_analysis_ds_modulation_profile_from_model(cls, model: CmDsOfdmModulationProfileModel,
                                                        split_carriers: bool = True) -> DsModulationProfileAnalysisModel:
        """
        Analyze a Downstream OFDM Modulation Profile using a parsed model
        from :class:`CmDsOfdmModulationProfile`.
        """
        spacing: int      = int(model.subcarrier_spacing)
        active_index: int = int(model.first_active_subcarrier_index)
        zero_freq: int    = int(model.subcarrier_zero_frequency)

        if active_index < 0 or zero_freq < 0 or spacing <= 0:
            raise ValueError(
                f"Invalid parameters: spacing={spacing}, active_index={active_index}, zero_freq={zero_freq}")

        start_freq = zero_freq + spacing * active_index

        result = DsModulationProfileAnalysisModel(
            device_details      = {},
            pnm_header          = model.pnm_header.model_dump() if hasattr(model.pnm_header, "model_dump") else {},
            mac_address         = model.mac_address,
            channel_id          = model.channel_id,
            frequency_unit      = "Hz",
            shannon_min_unit    = "dB",
            profiles            = [],
        )

        for profile in model.profiles:
            profile_id = int(profile.profile_id)
            freq_list: FrequencySeriesHz = []
            mod_list: list[str] = []
            shan_list: list[float] = []
            carrier_items: list[CarrierItemModel] = []
            freq_ptr = start_freq

            for scheme in profile.schemes:
                # ---- branch by schema type / model ----
                if isinstance(scheme, RangeModulationProfileSchemaModel):
                    mod_name = str(scheme.modulation_order)
                    count = int(scheme.num_subcarriers)

                elif isinstance(scheme, SkipModulationProfileSchemaModel):
                    mod_name = str(scheme.main_modulation_order)
                    count = int(scheme.num_subcarriers)

                else:
                    logging.warning(
                        f"Unknown modulation profile schema type: {getattr(scheme, 'schema_type', '?')}"
                    )
                    continue

                for _ in range(count):
                    if mod_name in (
                        ModulationOrderType.continuous_pilot.name,
                        ModulationOrderType.exclusion.name,
                    ):
                        s_min = 0.0
                    elif mod_name == ModulationOrderType.plc.name:
                        s_min = Shannon.bits_to_snr(4)
                    else:
                        s_min = Shannon.snr_from_modulation(mod_name)

                    s_min = round(float(s_min), 2)
                    f_val = int(freq_ptr)

                    if split_carriers:
                        freq_list.append(f_val)
                        mod_list.append(mod_name)
                        shan_list.append(s_min)
                    else:
                        carrier_items.append(
                            CarrierItemModel(
                                frequency       = f_val,
                                modulation      = mod_name,
                                shannon_min_mer = s_min,
                            )
                        )
                    freq_ptr += spacing

            if split_carriers:
                carrier_values: CarrierValuesModel = CarrierValuesSplitModel(
                    layout          = "split",
                    frequency       = freq_list,
                    modulation      = mod_list,
                    shannon_min_mer = shan_list,
                )
            else:
                carrier_values = CarrierValuesListModel(
                    layout      = "list",
                    carriers    = carrier_items,
                )

            result.profiles.append(
                ProfileAnalysisEntryModel(
                    profile_id      = profile_id,
                    carrier_values  = carrier_values,
                )
            )

        return result

    @classmethod
    def basic_analysis_ds_constellation_display_from_model(cls, model: CmDsConstDispMeasModel) -> ConstellationDisplayAnalysisModel:
        """
        Build a constellation analysis payload from a parsed :class:`CmDsConstDispMeasModel`.

        This is the model-based counterpart to ``basic_analysis_ds_constellation_display(...)``.
        It interprets the parsed constellation capture (soft decisions, modulation order,
        and metadata) and returns a fully-typed :class:`ConstellationDisplayAnalysisModel`.

        CM Output Assumption
        --------------------
        DOCSIS defines the constellation display samples as s2.13 soft decisions that
        are already scaled to approximately unit average power at the slicer input.
        Because the LUT hard points are normalized in the same way, **no additional
        scaling is applied** to the soft samples here.

        Parameters
        ----------
        model : CmDsConstDispMeasModel
            Parsed constellation display measurement, including:
            - ``samples``                : ComplexArray of soft decisions
            - ``actual_modulation_order``: int modulation order (e.g., 256)
            - ``num_sample_symbols``     : number of captured symbols
            - common PNM header fields   : ``pnm_header``, ``mac_address``, ``channel_id``.

        Returns
        -------
        ConstellationDisplayAnalysisModel
            Typed model carrying device/header info, inferred QAM order, LUT-hard
            constellation points, and CM-provided soft decisions.

        Raises
        ------
        ValueError
            If ``model.samples`` is empty.
        """
        samples: ComplexArray = model.samples or []
        if not samples:
            raise ValueError("CmDsConstDispMeasModel.samples must be a non-empty ComplexArray.")

        amo: int = int(getattr(model, "actual_modulation_order", 0))
        qm: QamModulation = QamModulation.from_DsOfdmModulationType(amo)

        hard: ComplexArray = QamLutManager().get_hard_decisions(qm)
        soft: ComplexArray = samples

        return ConstellationDisplayAnalysisModel(
            device_details      = getattr(model, "device_details", SystemDescriptor.empty().to_dict()),
            pnm_header          = model.pnm_header.model_dump() if hasattr(model.pnm_header, "model_dump") else getattr(model, "pnm_header", {}),
            mac_address         = MacAddressStr(getattr(model, "mac_address", MacAddress.null())),
            channel_id          = ChannelId(getattr(model, "channel_id", INVALID_CHANNEL_ID)),
            num_sample_symbols  = int(getattr(model, "num_sample_symbols", len(samples))),
            modulation_order    = qm,
            hard                = hard,
            soft                = soft,
        )

    @classmethod
    def basic_analysis_ds_histogram_from_model(cls, model: CmDsHistModel) -> DsHistogramAnalysisModel:
        """
        Build a :class:`DsHistogramAnalysisModel` from a parsed :class:`CmDsHistModel`.

        This is the model-based counterpart to ``basic_analysis_ds_histogram(...)``.
        It preserves the parsed symmetry flag, dwell counts, and hit counts, while
        normalizing PNM header and MAC/channel metadata into the canonical analysis
        model used by the API layer.

        Parameters
        ----------
        model : CmDsHistModel
            Parsed downstream histogram PNM payload, including:
            - ``pnm_header``               : :class:`PnmHeaderParameters`
            - ``mac_address``              : MAC address string
            - ``symmetry``                 : histogram symmetry indicator
            - ``dwell_count_values_length``: declared dwell-count length
            - ``dwell_count_values``       : dwell-count series
            - ``hit_count_values_length``  : declared hit-count length
            - ``hit_count_values``         : hit-count series

        Returns
        -------
        DsHistogramAnalysisModel
            Typed histogram analysis payload suitable for downstream consumers.
        """
        log = logging.getLogger(f"{cls.__name__}")

        dwell_counts = list(model.dwell_count_values or [])
        hit_counts   = list(model.hit_count_values or [])

        if model.dwell_count_values_length and model.dwell_count_values_length != len(dwell_counts):
            new_len = min(model.dwell_count_values_length, len(dwell_counts))
            log.warning(
                "DsHistogram: dwell_count length mismatch; declared=%d, actual=%d, truncating to %d",
                model.dwell_count_values_length,
                len(dwell_counts),
                new_len,
            )
            dwell_counts = dwell_counts[:new_len]

        if model.hit_count_values_length and model.hit_count_values_length != len(hit_counts):
            new_len = min(model.hit_count_values_length, len(hit_counts))
            log.warning(
                "DsHistogram: hit_count length mismatch; declared=%d, actual=%d, truncating to %d",
                model.hit_count_values_length,
                len(hit_counts),
                new_len,
            )
            hit_counts = hit_counts[:new_len]

        return DsHistogramAnalysisModel(
            device_details  = getattr(model, "device_details", {}),
            pnm_header      = model.pnm_header.model_dump() if hasattr(model.pnm_header, "model_dump") else model.pnm_header,
            mac_address     = model.mac_address or MacAddress.null(),
            channel_id      = ChannelId(getattr(model, "channel_id", INVALID_CHANNEL_ID)),
            symmetry        = model.symmetry,
            dwell_counts    = dwell_counts,
            hit_counts      = hit_counts,
        )

    @classmethod
    def basic_analysis_ds_ofdm_fec_summary_from_model(cls, model: CmDsOfdmFecSummaryModel) -> OfdmFecSummaryAnalysisModel:
        """
        Build an :class:`OfdmFecSummaryAnalysisModel` from a parsed
        :class:`CmDsOfdmFecSummaryModel`.

        This is the model-based counterpart to ``basic_analysis_ds_ofdm_fec_summary(...)``.
        It maps the parser-facing structures:

        * :class:`OfdmFecSumDataModel`          → :class:`OfdmFecSummaryProfileModel`
        * :class:`OfdmFecSumCodeWordEntryModel` → :class:`FecSummaryCodeWordModel`

        while carrying forward common analysis metadata from ``CmDsOfdmFecSummaryModel``.

        Parameters
        ----------
        model : CmDsOfdmFecSummaryModel
            Canonical DOCSIS downstream OFDM FEC summary model, including:
            - ``pnm_header``       : :class:`PnmHeaderParameters`
            - ``channel_id``       : ChannelId
            - ``mac_address``      : MAC address string
            - ``summary_type``     : CM-OSSI summary type enum
            - ``num_profiles``     : declared profile count
            - ``fec_summary_data`` : list of :class:`OfdmFecSumDataModel` entries

        Returns
        -------
        OfdmFecSummaryAnalysisModel
            Normalized FEC summary analysis payload used by the API/plotting layers.
        """
        log = logging.getLogger(f"{cls.__name__}")

        profiles: list[OfdmFecSummaryProfileModel] = []

        for _idx, prof in enumerate(model.fec_summary_data or []):
            cwe = prof.codeword_entries

            cw = FecSummaryCodeWordModel(
                timestamps      = list(cwe.timestamp),
                total_codewords = list(cwe.total_codewords),
                corrected       = list(cwe.corrected),
                uncorrected     = list(cwe.uncorrectable),
            )

            profiles.append(
                OfdmFecSummaryProfileModel(
                    profile         = ProfileId(prof.profile_id),
                    number_of_sets  = int(prof.number_of_sets),
                    codewords       = cw,
                )
            )

        declared_num_profiles = int(model.num_profiles)
        if declared_num_profiles != len(profiles):
            log.debug(
                "FEC Summary (model): num_profiles declared=%d, parsed=%d",
                declared_num_profiles,
                len(profiles),
            )

        return OfdmFecSummaryAnalysisModel(
            device_details = {},
            pnm_header     = model.pnm_header.model_dump() if hasattr(model.pnm_header, "model_dump") else model.pnm_header,
            mac_address    = MacAddressStr(model.mac_address or MacAddress.null()),
            channel_id     = ChannelId(model.channel_id if model.channel_id is not None else INVALID_CHANNEL_ID),
            profiles       = profiles,
        )

    @classmethod
    def basic_analysis_us_ofdma_pre_equalization_from_model(cls, model: CmUsOfdmaPreEqModel) -> UsOfdmaUsPreEqAnalysisModel:
        """
        Model-based variant of Upstream OFDMA Pre-Equalization Analysis.

        Mirrors `basic_analysis_us_ofdma_pre_equalization()` but accepts a parsed
        :class:`CmUsOfdmaPreEqModel` instead of a raw measurement dict.

        Computes:
        - Per-subcarrier frequency axis (Hz)
        - Magnitude sequence (dB) from complex coefficients, with optional
          Butterworth low-pass smoothing across subcarriers
        - Group delay (µs) from phase slope across subcarriers
        - IFFT-based echo detection over a constrained delay window
        - Complex samples passthrough
        - Signal statistics over the (smoothed) magnitude sequence
        """
        log = logging.getLogger(f"{cls.__name__}")

        subcarrier_spacing: FrequencyHz         = FrequencyHz(int(getattr(model, "subcarrier_spacing",       INVALID_START_VALUE)))
        first_active_subcarrier_index: int      = int(getattr(model, "first_active_subcarrier_index",        INVALID_START_VALUE))
        subcarrier_zero_frequency: FrequencyHz  = FrequencyHz(int(getattr(model, "subcarrier_zero_frequency", INVALID_START_VALUE)))
        occupied_channel_bandwidth: FrequencyHz = FrequencyHz(int(getattr(model, "occupied_channel_bandwidth", 0)))

        if (first_active_subcarrier_index < 0) or (subcarrier_zero_frequency < 0) or (subcarrier_spacing <= 0):
            raise ValueError(
                f"Active index: {first_active_subcarrier_index} or "
                f"zero frequency: {subcarrier_zero_frequency} or "
                f"spacing: {subcarrier_spacing} must be non-negative"
            )

        values: ComplexArray = cast(ComplexArray, getattr(model, "values", []))
        if not values:
            raise ValueError("No complex pre-equalization values provided in model.")

        start_freq: FrequencyHz  = FrequencyHz((subcarrier_spacing * first_active_subcarrier_index) + subcarrier_zero_frequency)
        freqs: FrequencySeriesHz = cast(FrequencySeriesHz, [start_freq + (i * subcarrier_spacing) for i in range(len(values))])

        gd = GroupDelay.from_channel_estimate(Hhat=values, df_hz=subcarrier_spacing, f0_hz=start_freq)
        gd_results = gd.to_result()

        cao = ComplexArrayOps(values)
        magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

        complex_arr = np.asarray(
            [
                complex(v[0], v[1])
                if (not isinstance(v, complex)) and isinstance(v, (list, tuple)) and len(v) == 2
                else complex(v)
                for v in values
            ],
            dtype=np.complex128,
        )

        try:
            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(subcarrier_spacing) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz = FrequencyHz(int(subcarrier_spacing)),
                cutoff_hz             = cutoff_hz,
                order                 = DEFAULT_BUTTERWORTH_ORDER,
                zero_phase            = True,
            )

            mag_result = mag_filter.apply(np.asarray(magnitudes_db_raw, dtype=np.float64))
            magnitudes_db: FloatSeries = mag_result.filtered_values.tolist()
        except Exception:
            magnitudes_db = magnitudes_db_raw

        signal_stats_model: SignalStatisticsModel = SignalStatistics(magnitudes_db).compute()

        group_delay_stats: GrpDelayStatsModel = GrpDelayStatsModel(
            group_delay_unit = "microsecond",
            magnitude        = ComplexArrayOps.to_list(gd_results.group_delay_us),
        )

        magn_linear = np.power(10.0, np.asarray(magnitudes_db, dtype=np.float64) / 20.0)
        phases      = np.angle(complex_arr)
        H_smooth    = magn_linear * np.exp(1j * phases)

        N      = len(values)
        n_fft  = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        fs = float(N) * float(subcarrier_spacing)
        max_delay_s_used = 3.5e-6

        cable_type_name = "RG6"
        v               = SPEED_OF_LIGHT * CABLE_VF.get(cable_type_name, 0.87)
        max_dist_m      = 0.5 * v * max_delay_s_used
        i_stop          = int(max_delay_s_used * fs)
        log.debug(
            "US OFDMA Pre-Eq (model) EchoDetector window: fs=%.3f Hz, n_fft=%d, i_stop=%d bins, "
            "max_delay=%.2fus, max_dist≈%.1f m",
            fs, n_fft, i_stop, max_delay_s_used * 1e6, max_dist_m
        )

        det = EchoDetector(
            freq_data               = H_smooth.tolist(),
            subcarrier_spacing_hz   = float(subcarrier_spacing),
            n_fft                   = 4096,
            cable_type              = cable_type_name,
            channel_id              = ChannelId(getattr(model, "channel_id", INVALID_CHANNEL_ID)),
        )

        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode        = "db_down",
            threshold_db_down     = 60.0,
            normalize_power       = True,
            guard_bins            = 16,
            min_separation_s      = 8.0 / det.fs,
            max_delay_s           = max_delay_s_used,
            max_peaks             = 3,
            include_time_response = False,
            direct_at_zero        = True,
            window                = "hann",
        )

        i_stop     = int(np.ceil(max_delay_s_used * det.fs))
        edge_guard = 8
        if echo_report.echoes:
            echo_report.echoes = [
                e for e in echo_report.echoes
                if (e.bin_index < (i_stop - edge_guard))
            ]

        echo_rpt = EchoDatasetModel(
            type    = EchoDetectorType.IFFT,
            report  = echo_report,
        )

        carrier_values: OfdmaUsPreEqCarrierModel = OfdmaUsPreEqCarrierModel(
            carrier_count               = len(freqs),
            frequency_unit              = "Hz",
            frequency                   = freqs,
            complex                     = values,
            complex_dimension           = int(complex_arr.ndim),
            magnitudes                  = magnitudes_db,
            group_delay                 = group_delay_stats,
            occupied_channel_bandwidth  = occupied_channel_bandwidth,
        )

        result_model: UsOfdmaUsPreEqAnalysisModel = UsOfdmaUsPreEqAnalysisModel(
            device_details                  = getattr(model, "device_details", {}),
            pnm_header                      = model.pnm_header.model_dump() if hasattr(model.pnm_header, "model_dump") else getattr(model, "pnm_header", {}),
            mac_address                     = MacAddressStr(getattr(model, "mac_address", MacAddress.null())),
            channel_id                      = ChannelId(getattr(model, "channel_id", INVALID_CHANNEL_ID)),
            subcarrier_spacing              = subcarrier_spacing,
            first_active_subcarrier_index   = first_active_subcarrier_index,
            subcarrier_zero_frequency       = subcarrier_zero_frequency,
            carrier_values                  = carrier_values,
            signal_statistics               = signal_stats_model,
            echo                            = echo_rpt,
        )

        if log.isEnabledFor(logging.DEBUG):
            LogFile.write(
                f'UsOfdmaUsPreEqAnalysisModel_{result_model.mac_address}_{result_model.channel_id}.log',
                result_model,
            )

        return result_model

    @classmethod
    def basic_analysis_echo_detection_ifft(cls, model: CmDsOfdmChanEstimateCoefModel, cable_type: CableType = CableType.RG6, ) -> EchoDetectorReport:
        """
        Run FFT/IFFT-based echo detection from a single Channel-Estimation snapshot.

        Overview
        --------
        Builds a time response h(t) from the complex channel-estimation spectrum H(f),
        identifies the direct path, then scans for echo peaks subject to a conservative
        threshold, guard region, and optional time-response attachment.

        Inputs (from model)
        -------------------
        values : ComplexArray
            List of complex-like samples for H(f). Accepted shapes:
            - [(re, im), ...] pairs or
            - [complex, ...]
        subcarrier_spacing : float
            Δf in Hz between OFDM subcarriers.
        channel_id : int
            Downstream channel ID, used for metadata only.

        Parameters
        ----------
        cable_type : CableType, default CableType.RG6
            Cable type to derive the velocity factor for distance conversion.

        Returns
        -------
        EchoDetectorReport
            Structured result including dataset metadata, direct-path info, an array
            of detected echoes (if any), and optional time-response block.

        Notes
        -----
        - n_fft is chosen as the next power of two ≥ N (min 1024) for finer time sampling.
        - Thresholding defaults to “dB-down” mode (70 dB below direct peak), with an
          automatic fallback to 80 dB if nothing is found.
        - Magnitude smoothing uses the same Butterworth pipeline as
          `basic_analysis_ds_chan_est()`, applied to |H(f)| before echo detection.
        """
        log = logging.getLogger(f"{cls.__name__}")

        values = cast(Sequence[complex | Sequence[float]], getattr(model, "values", []))
        if not values:
            raise ValueError("Echo detection requires non-empty channel-estimation values.")

        df_hz = float(getattr(model, "subcarrier_spacing", 0.0))
        if df_hz <= 0.0:
            raise ValueError("Invalid subcarrier spacing for echo detection.")

        channel_id = cast(ChannelId, getattr(model, "channel_id", INVALID_CHANNEL_ID))

        # ── Optional Butterworth smoothing over |H(f)| in dB (same pattern as ds_chan_est) ──
        H = np.asarray(values, dtype=complex)
        freq_data_for_detector: Sequence[complex]

        try:
            cao = ComplexArrayOps(values)
            magnitudes_db_raw: FloatSeries = cao.to_list(cao.power_db())

            cutoff_hz: FrequencyHz = FrequencyHz(
                int(float(df_hz) * CHAN_EST_BW_CUTOFF_FRACTION)
            )

            mag_filter = MagnitudeButterworthFilter.from_subcarrier_spacing(
                subcarrier_spacing_hz = FrequencyHz(int(df_hz)),
                cutoff_hz             = cutoff_hz,
            )

            mag_result = mag_filter.apply(np.asarray(magnitudes_db_raw, dtype=np.float64))
            magnitudes_db_smooth = mag_result.filtered_values

            mag_lin = np.power(10.0, magnitudes_db_smooth / 20.0)
            H_phase = np.exp(1j * np.angle(H))
            H_filtered = mag_lin * H_phase

            freq_data_for_detector = H_filtered.tolist()

            log.debug(
                "Echo IFFT: applied Butterworth smoothing (df=%.3f Hz, cutoff=%.3f Hz, N=%d)",
                df_hz,
                float(cutoff_hz),
                H.shape[0],
            )
        except Exception as exc:
            log.debug(
                "Echo IFFT: Butterworth smoothing skipped due to error: %s; using raw values.",
                exc,)
            freq_data_for_detector = list(map(complex, H))

        # Choose IFFT length for finer time resolution
        N = len(freq_data_for_detector)
        n_fft = 1 << (N - 1).bit_length()
        if n_fft < 1024:
            n_fft = 1024

        # Detector
        det = EchoDetector(
            freq_data             = freq_data_for_detector,
            subcarrier_spacing_hz = df_hz,
            n_fft                 = n_fft,
            cable_type            = cable_type.name,
            channel_id            = ChannelId(channel_id),
        )

        log.debug(
            "Init EchoDetector: N=%d, Δf=%.3f Hz, fs=%.3f Hz, n_fft=%d, cable=%s, chan=%s",
            N, df_hz, N * df_hz, n_fft, cable_type.name, str(channel_id),
        )

        # Conservative defaults, with auto-fallback if nothing exceeds threshold
        echo_report: EchoDetectorReport = det.multi_echo(
            threshold_mode        = "db_down",    # primary threshold strategy
            threshold_db_down     = 70.0,         # 70 dB below the direct path
            guard_bins            = 8,            # keep away from main-lobe skirt
            min_separation_s      = 0.0,          # allow closely spaced echoes if present
            max_delay_s           = 7.7e-6,       # ~1 km one-way at VF≈0.87
            max_peaks             = 5,            # cap number of echoes returned
            include_time_response = False,        # keep payload small by default
            direct_at_zero        = True,         # recenter direct path to t=0
            window                = "hann",       # reduce sidelobes before IFFT
        )

        return echo_report

# FILE: tests/test_spectrum_analyzer_channel_power_dbmv.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import math

import pytest

from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import WindowFunction


def test_basic_analysis_spectrum_analyzer_channel_power_dbmv() -> None:
    measurement = {
        "device_details": SystemDescriptor.empty().to_dict(),
        "first_segment_center_frequency": 100,
        "last_segment_center_frequency": 102,
        "segment_frequency_span": 2,
        "num_bins_per_segment": 2,
        "equivalent_noise_bandwidth": 0.0,
        "window_function": WindowFunction.HANN.value,
        "bin_frequency_spacing": 1,
        "amplitude_bin_segments_float": [[0.0, 0.0]],
    }

    model = Analysis.basic_analysis_spectrum_analyzer(measurement, None)
    expected = round(10.0 * math.log10(2.0), 2)
    assert model.signal_analysis.channel_power_dbmv == expected


def test_basic_analysis_spectrum_analyzer_snmp_channel_power_dbmv() -> None:
    measurement = {
        "device_details": SystemDescriptor.empty().to_dict(),
        "frequency": [100, 101],
        "amplitude": [0.0, 0.0],
        "equivalent_noise_bandwidth": 0.0,
    }

    model = Analysis.basic_analysis_spectrum_analyzer_snmp(measurement, None, None)
    expected = round(10.0 * math.log10(2.0), 2)
    assert model.signal_analysis.channel_power_dbmv == expected

# FILE: docs/api/fast-api/single/spectrum-analyzer/spectrum-analyzer.md
# PNM Operations - Spectrum Analyzer

Downstream Spectrum Capture And Per-Channel Analysis For DOCSIS 3.x/4.0 Cable Modems.

## Overview

[`SpectrumAnalyzerRouter`](http://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/router.py)
exposes four related endpoints that drive downstream spectrum capture and analysis:

* A single spectrum capture endpoint (`/getCapture`) for free-form frequency sweeps.
* A single spectrum capture endpoint with friendly RBW inputs (`/getCapture/friendly`).
* An OFDM-focused endpoint (`/getCapture/ofdm`) that walks all downstream OFDM channels.
* An SC-QAM-focused endpoint (`/getCapture/scqam`) that walks all downstream SC-QAM channels.

Each capture is processed through the common analysis pipeline and can return either a JSON
analysis payload or an archive (ZIP) with Matplotlib plots and CSV exports.

For RBW auto-scale outcomes, see the [Spectrum analyzer RBW permutations](../spectrum-analyzer.md) reference.

> The cable modem must be PNM-ready and the requested frequency range must fall within the
> configured diplexer band. Use the diplexer configuration API to verify allowed frequency
> boundaries.

### Diplexer Configuration Endpoint

| DOCSIS | Endpoint | Description |
|-------|----------|-------------|
| [DOCSIS 3.1](../general/diplexer-configuration.md)                | `POST /docs/if31/system/diplexer`              | Retrieve the diplexer for spectrum capture. |
| [DOCSIS 4.0](../fdd/fdd-system-diplexer-configuration.md) | `POST /docs/fdd/system/diplexer/configuration` | Retrieve the diplexer for spectrum capture. |

## Endpoints

All endpoints share the same base prefix: `/docs/pnm/ds`.

| Purpose                        | Method | Path                                             |
| ------------------------------ | ------ | ------------------------------------------------ |
| Single spectrum capture        | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture`       |
| Single spectrum capture (RBW)  | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture/friendly` |
| All OFDM downstream channels   | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture/ofdm`  |
| All SC-QAM downstream channels | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture/scqam` |

Each endpoint accepts a common cable modem block and analysis controls. Capture-specific
settings are provided under `capture_parameters`.

> Note: A modem can only run either downstream or upstream spectrum at a time. The router
> documented here is downstream (`/ds`) only.

## Common Request Shape

Refer to [Common → Request](../../common/request.md).  
These endpoints add optional `analysis` controls and a `capture_parameters` section.

### Analysis Delta Table

| JSON path                | Type   | Allowed values / format | Default | Description                                                                                               |
| ------------------------ | ------ | ----------------------- | ------- | --------------------------------------------------------------------------------------------------------- |
| `analysis.type`          | string | "basic"                 | "basic" | Selects the analysis mode used during processing.                                                         |
| `analysis.output.type`   | string | "json", "archive"       | "json"  | Output format. **`json`** returns inline `data`; **`archive`** returns a ZIP (CSV exports and PNG plots). |
| `analysis.plot.ui.theme` | string | "light", "dark"         | "dark"  | Theme hint for Matplotlib plots (colors, grid, ticks). Does not affect raw metrics/CSV.                   |
| `analysis.spectrum_analysis.moving_average.points` | int | >= 1 | 10 | Window size for the moving average applied to spectrum magnitudes. |

When `analysis.output.type = "archive"`, the HTTP response body is the file (no `data` JSON payload).

## Single Capture - `/spectrumAnalyzer/getCapture`

Single downstream spectrum capture using the modem's generic spectrum engine. This is the
most flexible entry point and allows arbitrary sweep settings (within diplexer limits).

### Single Capture Example Request

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
      }
    },
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  },
  "analysis": {
    "type": "basic",
    "output": { "type": "json" },
    "plot": { "ui": { "theme": "dark" } },
    "spectrum_analysis": {
      "moving_average": { "points": 10 }
    }
  },
  "capture_parameters": {
    "inactivity_timeout": 60,
    "first_segment_center_freq": 300000000,
    "last_segment_center_freq": 900000000,
    "segment_freq_span": 1000000,
    "num_bins_per_segment": 256,
    "noise_bw": 150,
    "window_function": 1,
    "num_averages": 1,
    "spectrum_retrieval_type": 1
  }
}
```

### Capture Parameters

| JSON path                                      | Type | Description                                                                  |
| ---------------------------------------------- | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.inactivity_timeout`        | int  | Timeout (seconds) before aborting idle spectrum acquisition.                 |
| `capture_parameters.first_segment_center_freq` | int  | Center frequency (Hz) of the first sweep segment.                            |
| `capture_parameters.last_segment_center_freq`  | int  | Center frequency (Hz) of the last sweep segment.                             |
| `capture_parameters.segment_freq_span`         | int  | Frequency span (Hz) covered by each sweep segment.                           |
| `capture_parameters.num_bins_per_segment`      | int  | Number of FFT bins per segment.                                              |
| `capture_parameters.noise_bw`                  | int  | Equivalent noise bandwidth in kHz.                                            |
| `capture_parameters.window_function`           | int  | Window function enum value.                                                    |
| `capture_parameters.num_averages`              | int  | Number of averages per segment for noise reduction.                           |
| `capture_parameters.spectrum_retrieval_type`   | int  | Retrieval mode enum value (FILE = 1, SNMP = 2).                                 |

### Note

`pnm_parameters.capture.channel_ids` is not supported for this endpoint. Use the OFDM or SC-QAM endpoints when channel scoping is required.

#### Window Function Values

| Value | Enum name |
| ----- | --------- |
| 0     | OTHER |
| 1     | HANN |
| 2     | BLACKMAN_HARRIS |
| 3     | RECTANGULAR |
| 4     | HAMMING |
| 5     | FLAT_TOP |
| 6     | GAUSSIAN |
| 7     | CHEBYSHEV |

#### Note

> `spectrum_retrieval_type` Use 1 (PNM_FILE) is preferred for most use cases. Use `2` (SNMP) when PNM file transfer is not available.

## Single Capture (Friendly) - `/spectrumAnalyzer/getCapture/friendly`

This variant accepts a resolution bandwidth and a requested window, then derives
the segment span and bin count using the spectrum-analysis-capture-set rules. The
first and last segment center frequencies are adjusted inward by half a segment
span to satisfy the analyzer's scaled window constraints.

### Friendly Capture Example Request

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
      }
    },
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  },
  "analysis": {
    "type": "basic",
    "output": { "type": "json" },
    "plot": { "ui": { "theme": "dark" } },
    "spectrum_analysis": {
      "moving_average": { "points": 10 }
    }
  },
  "capture_parameters": {
    "inactivity_timeout": 60,
    "first_segment_center_freq": 300000000,
    "last_segment_center_freq": 900000000,
    "resolution_bw": 30000,
    "noise_bw": 150,
    "window_function": 1,
    "num_averages": 1,
    "spectrum_retrieval_type": 1
  }
}
```

### Friendly Capture Parameters

| JSON path                                      | Type | Description                                                                  |
| ---------------------------------------------- | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.inactivity_timeout`        | int  | Timeout (seconds) before aborting idle spectrum acquisition.                 |
| `capture_parameters.first_segment_center_freq` | int  | Requested first segment center frequency (Hz) for the capture window.        |
| `capture_parameters.last_segment_center_freq`  | int  | Requested last segment center frequency (Hz) for the capture window.         |
| `capture_parameters.resolution_bw`             | int  | Resolution bandwidth (Hz) used to derive segment span and bin count.         |
| `capture_parameters.noise_bw`                  | int  | Equivalent noise bandwidth in kHz.                                           |
| `capture_parameters.window_function`           | int  | Window function enum value.                                                  |
| `capture_parameters.num_averages`              | int  | Number of averages per segment.                                              |
| `capture_parameters.spectrum_retrieval_type`   | int  | Retrieval mode enum value (FILE = 1, SNMP = 2).                              |

Note: The computed `segment_freq_span`, `num_bins_per_segment`, and adjusted segment
center frequencies are returned in the analysis payload.

### Abbreviated JSON Response (Output Type `"json"`)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "analysis": [
      {
        "device_details": {
          "system_description": {
            "HW_REV": "1.0",
            "VENDOR": "LANCity",
            "BOOTR": "NONE",
            "SW_REV": "1.0.0",
            "MODEL": "LCPET-3"
          }
        },
        "capture_parameters": {
          "inactivity_timeout": 60,
          "first_segment_center_freq": 300000000,
          "last_segment_center_freq": 900000000,
          "segment_freq_span": 1000000,
          "num_bins_per_segment": 100,
          "noise_bw": 0,
          "window_function": 1,
          "num_averages": 1,
          "spectrum_retrieval_type": 1
        },
        "signal_analysis": {
          "bin_bandwidth": 10000,
          "segment_length": 100,
          "frequencies": [],
          "magnitudes": [],
          "window_average": {
            "points": 20,
            "magnitudes": []
          }
        }
      }
    ],
    "primative": [
      {
        "status": "SUCCESS",
        "pnm_header": {
          "file_type": "PNN",
          "file_type_version": 9,
          "major_version": 1,
          "minor_version": 0,
          "capture_time": 1762839675
        },
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "first_segment_center_frequency": 300000000,
        "last_segment_center_frequency": 900000000,
        "segment_frequency_span": 1000000,
        "num_bins_per_segment": 100,
        "equivalent_noise_bandwidth": 110.0,
        "window_function": 1,
        "bin_frequency_spacing": 10000,
        "spectrum_analysis_data_length": 120200,
        "spectrum_analysis_data": "e570e3...40e340"
      }
    ],
    "measurement_stats": [
      {
        "index": 0,
        "entry": {
          "docsIf3CmSpectrumAnalysisCtrlCmdEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout": 60,
          "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency": 300000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency": 900000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan": 1000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment": 100,
          "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth": 110,
          "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus": "sample_ready",
          "docsIf3CmSpectrumAnalysisCtrlCmdFileName": "spectrum_analyzer_aabbccddeeff_0_1762839621.bin"
        }
      }
    ]
  }
}
```

### Single-Capture Return Structure

Top-level envelope:

| Field         | Type          | Description                                                               |
| ------------- | ------------- | ------------------------------------------------------------------------- |
| `mac_address` | string        | Request echo of the modem MAC.                                            |
| `status`      | int           | 0 on success, non-zero on error.                                          |
| `message`     | string\|null  | Optional message describing status.                                       |
| `data`        | object        | Container for results (`analysis`, `primative`, `measurement_stats`).     |

**Payload: `data.analysis[]`**

| Field                            | Type   | Description                                                           |
| -------------------------------- | ------ | --------------------------------------------------------------------- |
| device_details.*                 | object | System descriptor captured at analysis time.                          |
| capture_parameters.*             | object | Echo of the capture parameters effective for this run.               |
| signal_analysis.bin_bandwidth    | int    | Effective bin bandwidth (Hz) derived from bin spacing/windowing.     |
| signal_analysis.segment_length   | int    | Number of FFT bins per segment used in analysis.                     |
| signal_analysis.frequencies      | array  | Frequency axis for the analyzed spectrum (per-bin center frequency). |
| signal_analysis.magnitudes       | array  | Amplitude values aligned with `frequencies`.                         |
| signal_analysis.channel_power_dbmv | float | Total channel power derived from the magnitudes, in dBmV (rounded to 2 decimals). |
| signal_analysis.window_average.* | object | Optional moving-average smoothing applied to `magnitudes`.           |

**Payload: `data.primative[]`**

| Field                          | Type       | Description                                               |
| ------------------------------ | ---------- | --------------------------------------------------------- |
| status                         | string     | Result for this capture (e.g., `"SUCCESS"`).              |
| pnm_header.*                   | object     | PNM file header (type, version, capture time).            |
| mac_address                    | string     | MAC address.                                              |
| first_segment_center_frequency | int (Hz)   | Center frequency of the first sweep segment.              |
| last_segment_center_frequency  | int (Hz)   | Center frequency of the last sweep segment.               |
| segment_frequency_span         | int (Hz)   | Frequency span covered by each segment.                   |
| num_bins_per_segment           | int        | Number of FFT bins per segment.                           |
| equivalent_noise_bandwidth     | float (Hz) | Equivalent noise bandwidth used for amplitude scaling.    |
| window_function                | int        | Window function index.                                    |
| bin_frequency_spacing          | float (Hz) | Frequency spacing between adjacent bins.                  |
| spectrum_analysis_data_length  | int        | Byte length of `spectrum_analysis_data`.                  |
| spectrum_analysis_data         | string     | Raw spectrum data encoded as hexadecimal text.            |

**Payload: `data.measurement_stats[]`**

| Field                                                     | Type    | Description                                              |
| --------------------------------------------------------- | ------- | -------------------------------------------------------- |
| index                                                               | int     | SNMP table row index.                                    |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdEnable                        | boolean | Whether capture was enabled for this measurement.        |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout             | int     | Inactivity timeout (seconds) used for the capture.       |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency   | int (Hz) | First segment center frequency at capture time.  |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency    | int (Hz) | Last segment center frequency at capture time.   |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan          | int (Hz) | Segment frequency span in Hz.                   |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment             | int     | Number of bins per segment.                      |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth      | int     | Equivalent noise bandwidth in Hz.                |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction                | int     | Window function index.                           |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages              | int     | Number of averages used for this capture.        |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdFileEnable                    | boolean | Whether capture-to-file was enabled.             |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus                    | string  | Measurement status (e.g., `"sample_ready"`).     |
| entry.docsIf3CmSpectrumAnalysisCtrlCmdFileName                      | string  | Device-side filename of the captured spectrum.   |

## OFDM Downstream Capture - `/spectrumAnalyzer/getCapture/ofdm`

This endpoint iterates across all downstream OFDM channels on the modem, performing a
spectrum capture per channel and aggregating the results into a multi-analysis structure.

Each per-channel capture is processed like the single capture. Results are returned as:

* `data.analyses[]` - list of per-channel analysis views (one entry per capture).
* `data.primative` - dictionary of raw capture payloads indexed by channel position.
* `data.measurement_stats[]` - flattened SNMP spectrum-analysis entries with channel context.

Each `measurement_stats[]` entry includes:

* `channel_id` - the downstream channel ID associated with the capture.
* `channel_stats` - the channel entry used to resolve the capture (OFDM or SC-QAM table data).

Per-channel analysis JSON artifacts written under `.data/json/` also include a
`measurement_stats` array, but the `channel_id` field is omitted because the
channel is already encoded in the filename and top-level `channel_id` field.

DOCSIS constraints:

* DOCSIS 3.1: up to **2** downstream OFDM channels.  
* DOCSIS 4.0 FDD/FDX: up to **5** downstream OFDM channels.

### OFDM Capture Example Request

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
      },
      "capture": {
        "channel_ids": [193, 194]
      }
    },
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  },
  "analysis": {
    "type": "basic",
    "output": { "type": "json" },
    "plot": { "ui": { "theme": "dark" } },
    "spectrum_analysis": {
      "moving_average": { "points": 10 }
    }
  },
  "capture_parameters": {
    "number_of_averages": 10,
    "resolution_bandwidth_hz": 25000,
    "spectrum_retrieval_type": 1
  }
}
```

### OFDM Capture Parameters

| JSON path                                   | Type | Description                                                                  |
| ------------------------------------------- | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.number_of_averages`     | int  | Number of samples used to compute the per-bin average.                       |
| `capture_parameters.resolution_bandwidth_hz`| int  | Resolution bandwidth (Hz) used to derive segment span and bin count.         |
| `capture_parameters.spectrum_retrieval_type`| int  | Retrieval mode enum value (FILE = 1, SNMP = 2).                              |

> `resolution_bandwidth_hz` is used to auto-scale RBW settings (segment span and bins per segment).

To scope captures to specific OFDM channels, set `pnm_parameters.capture.channel_ids`. Omit or use an empty list to capture all downstream OFDM channels.

### Abbreviated JSON Response (OFDM View)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "analyses": [
      {
        "device_details": {
          "system_description": {
            "HW_REV": "1.0",
            "VENDOR": "LANCity",
            "BOOTR": "NONE",
            "SW_REV": "1.0.0",
            "MODEL": "LCPET-3"
          }
        },
        "capture_parameters": {
          "inactivity_timeout": 60,
          "first_segment_center_freq": 739000000,
          "last_segment_center_freq": 833000000,
          "segment_freq_span": 1000000,
          "num_bins_per_segment": 100,
          "noise_bw": 0,
          "window_function": 1,
          "num_averages": 1,
          "spectrum_retrieval_type": 1
        },
        "signal_analysis": {
          "bin_bandwidth": 10000,
          "segment_length": 100,
          "frequencies": [],
          "magnitudes": [],
          "window_average": {
            "points": 10,
            "magnitudes": []
          }
        }
      }
    ],
    "primative": {
      "0": [
        {
          "status": "SUCCESS",
          "pnm_header": {
            "file_type": "PNN",
            "file_type_version": 9,
            "major_version": 1,
            "minor_version": 0,
            "capture_time": 1762840213
          },
          "channel_id": 0,
          "mac_address": "aa:bb:cc:dd:ee:ff",
          "first_segment_center_frequency": 739000000,
          "last_segment_center_frequency": 833000000,
          "segment_frequency_span": 1000000,
          "num_bins_per_segment": 100,
          "equivalent_noise_bandwidth": 110.0,
          "window_function": 1,
          "bin_frequency_spacing": 10000,
          "spectrum_analysis_data_length": 19000,
          "spectrum_analysis_data": "",
          "amplitude_bin_segments_float": []
        }
      ],
      "1": []
    },
    "measurement_stats": [
      {
        "channel_id": 193,
        "channel_stats": {
          "index": 10,
          "channel_id": 193,
          "entry": {
            "docsIf31CmDsOfdmChanChannelId": 193
          }
        },
        "index": 0,
        "entry": {
          "docsIf3CmSpectrumAnalysisCtrlCmdEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout": 30,
          "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency": 739000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency": 833000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan": 1000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment": 100,
          "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth": 110,
          "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages": 2,
          "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus": "sample_ready",
          "docsIf3CmSpectrumAnalysisCtrlCmdFileName": "spectrum_analyzer_aabbccddeeff_0_1762840189.bin"
        }
      },
      {
        "channel_id": 194,
        "channel_stats": {
          "index": 11,
          "channel_id": 194,
          "entry": {
            "docsIf31CmDsOfdmChanChannelId": 194
          }
        },
        "index": 0,
        "entry": {
          "docsIf3CmSpectrumAnalysisCtrlCmdEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout": 30,
          "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency": 619000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency": 737000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan": 1000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment": 100,
          "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth": 110,
          "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages": 2,
          "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus": "sample_ready",
          "docsIf3CmSpectrumAnalysisCtrlCmdFileName": "spectrum_analyzer_aabbccddeeff_0_1762840227.bin"
        }
      }
    ]
  }
}
```

### OFDM Multi-Channel Return Structure

**Payload: `data.analyses[]` (OFDM)**

| Field                          | Type   | Description                                                          |
| ------------------------------ | ------ | -------------------------------------------------------------------- |
| `[index]`.device_details.*     | object | System descriptor captured at analysis time for that channel.        |
| `[index]`.capture_parameters.* | object | Effective capture parameters for that OFDM channel.                  |
| `[index]`.signal_analysis.*    | object | Per-channel spectrum analysis (frequencies, magnitudes, smoothing).  |

**Payload: `data.primative` (OFDM)**

| Field           | Type  | Description                                                             |
| --------------- | ----- | ----------------------------------------------------------------------- |
| `"0"`, `"1"`, … | array | Raw per-channel capture payloads for each OFDM channel position.       |

**Payload: `data.measurement_stats[]` (OFDM)**

Reuses the single-capture `measurement_stats` field definitions, with `channel_id`
and `channel_stats` included per OFDM channel.

## SC-QAM Downstream Capture - `/spectrumAnalyzer/getCapture/scqam`

This endpoint iterates across all downstream SC-QAM channels, performing spectrum captures
per channel and aggregating the results into a multi-analysis view similar to the OFDM
endpoint.

DOCSIS constraints:

* DOCSIS 3.1 and DOCSIS 4.0 support up to **32** downstream SC-QAM channels (implementation-dependent).

The response shape for SC-QAM captures mirrors the OFDM multi-channel layout:

* `data.analyses[]` - list of per-channel analysis views.
* `data.primative` - dictionary of raw capture payloads indexed by channel position.
* `data.measurement_stats[]` - flattened SNMP statistics per captured channel with channel context.

### Example Request

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
      },
      "capture": {
        "channel_ids": [1, 2]
      }
    },
    "snmp": {
      "snmpV2C": {
        "community": "private"
      }
    }
  },
  "analysis": {
    "type": "basic",
    "output": { "type": "json" },
    "plot": { "ui": { "theme": "dark" } },
    "spectrum_analysis": {
      "moving_average": { "points": 10 }
    }
  },
  "capture_parameters": {
    "number_of_averages": 10,
    "resolution_bandwidth_hz": 25000,
    "spectrum_retrieval_type": 1
  }
}
```

### SC-QAM Capture Parameters

| JSON path                                   | Type | Description                                                                  |
| ------------------------------------------- | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.number_of_averages`     | int  | Number of samples used to compute the per-bin average.                       |
| `capture_parameters.resolution_bandwidth_hz`| int  | Resolution bandwidth (Hz) used to derive segment span and bin count.         |
| `capture_parameters.spectrum_retrieval_type`| int  | Retrieval mode enum value (FILE = 1, SNMP = 2).                              |

> `resolution_bandwidth_hz` is used to auto-scale RBW settings (segment span and bins per segment).

To scope captures to specific SC-QAM channels, set `pnm_parameters.capture.channel_ids`. Omit or use an empty list to capture all downstream SC-QAM channels.

### SC-QAM Multi-Channel Return Structure

**Payload: `data.analyses[]` (SC-QAM)**

Same as OFDM: each list element represents a per-channel analysis view with
`device_details`, `capture_parameters`, and `signal_analysis`.

**Payload: `data.primative` (SC-QAM)**

| Field           | Type  | Description                                                             |
| --------------- | ----- | ----------------------------------------------------------------------- |
| `"0"`, `"1"`, … | array | Raw per-channel capture payloads for each SC-QAM channel position.     |

**Payload: `data.measurement_stats[]` (SC-QAM)**

Reuses the single-capture `measurement_stats` field definitions, with `channel_id`
and `channel_stats` included per SC-QAM channel.

## Archive Output

For all three endpoints, when `analysis.output.type = "archive"`:

* The response body is a ZIP file (no JSON `data` envelope).
* Contents typically include:
  * CSV exports of amplitude vs frequency.
  * Matplotlib PNG plots per channel and aggregate views.

Examples of generated plots:

| Standard Plot  | Moving Average Plot  | Description |
| -------------- | -------------------- | ----------- |
| [DS Full Bandwidth](../images/spectrum/spec-analysis-standard.png) | [DS Full Bandwidth](../images/spectrum/spec-analysis-moving-average.png)    | Single-capture standard vs moving-average spectrum views.       |
| [SCQAM](../images/spectrum/scqam-2-spec-analysis-standard.png)     | [SCQAM](../images/spectrum/scqam-2-spec-analysis-moving-average.png)        | Example SC-QAM channel standard and moving-average plots.       |
| [OFDM](../images/spectrum/ofdm-34-spec-analysis-standard.png)      | [OFDM](../images/spectrum/ofdm-34-spec-analysis-moving-average.png)         | Example OFDM channel standard and moving-average plots.         |

## Notes

* Always validate requested frequency ranges against the modem diplexer configuration.  
* Spectrum captures can be long-running operations depending on span and averaging.  

