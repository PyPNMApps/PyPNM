## Agent Review Bundle Summary
- Goal: Document spectrum analyzer JSON return updates and ensure per-channel JSON artifacts drop measurement_stats.channel_id via shared helper.
- Changes: Updated OFDM/SC-QAM report JSON writing to remove measurement_stats.channel_id with DictGenerate.pop_keys_recursive; updated spectrum analyzer docs to describe channel context fields and per-channel JSON behavior; retained channel_stats injection path from router into report builders.
- Files: src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/abstract/com_spec_chan_ana.py; src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/service.py; src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/router.py; src/pypnm/api/routes/basic/ofdm_spec_analyzer_rpt.py; src/pypnm/api/routes/basic/scqam_spec_analyzer_rpt.py; tests/test_spectrum_analyzer_measurement_stats_channel_stats.py; tests/test_spectrum_analyzer_report_measurement_stats_json.py; docs/api/fast-api/single/spectrum-analyzer/spectrum-analyzer.md
- Tests: python3 -m compileall src (pass); ruff check src (pass); ruff format --check . (fails: would reformat existing files); pytest -q (pass, 3 skipped).
- Notes: Ruff format check fails due to pre-existing formatting drift across repo.

# FILE: src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/abstract/com_spec_chan_ana.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import DocsPnmCmCtlTest
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.DocsIf31CmDsOfdmChanEntry import (
    DocsIf31CmDsOfdmChanChannelEntry,
)
from pypnm.docsis.data_type.DocsIfDownstreamChannel import DocsIfDownstreamChannelEntry
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
)
from pypnm.lib.types import ChannelId, FrequencyHz

StartFrequency      = FrequencyHz
PlcFrequency        = FrequencyHz
EndFrequency        = FrequencyHz
CenterFrequency     = FrequencyHz
OfdmSpectrumBw      = tuple[StartFrequency, PlcFrequency, EndFrequency]
OfdmSpectrumBwLut   = dict[ChannelId, OfdmSpectrumBw]
ScQamSpectrumBw     = tuple[StartFrequency, CenterFrequency, EndFrequency]
ScQamSpectrumBwLut  = dict[ChannelId, ScQamSpectrumBw]
CommonChannelSpectumBwLut  = dict[ChannelId, tuple[StartFrequency, CenterFrequency | PlcFrequency, EndFrequency]]
CommonSpectrumBw    = tuple[StartFrequency, CenterFrequency, EndFrequency]

class CommonSpectrumChannelAnalyzer(ABC):
    def __init__(self, cm: CableModem) -> None:
        self._cm = cm
        self._pnm_test_type = DocsPnmCmCtlTest.SPECTRUM_ANALYZER
        self.logger = logging.getLogger(self.__class__.__name__)
        self.log_prefix = f"[{self.__class__.__name__}]"
        self._pnm_test_type = DocsPnmCmCtlTest.SPECTRUM_ANALYZER
        self._measurement_stat: dict[ChannelId, list[DocsIf3CmSpectrumAnalysisEntry]] = {}

    @abstractmethod
    async def start(self, capture_per_channel: bool = False) -> list[tuple[ChannelId, MessageResponse]]:
        """
        Start the spectrum analyzer measurement on the cable modem.
        Parameters
        ----------
        capture_per_channel : bool, optional
            If True, perform individual captures per channel; otherwise,
            perform a single capture covering all channels. Default is False.

        Returns
        -------
        List[Tuple[ChannelId, MessageResponse]]
            A list of tuples containing channel identifiers and their corresponding
            message responses from the cable modem.

        Notes
        -----
        - Concrete implementations must configure capture parameters and trigger
          spectrum captures for each target channel.
        """
        pass

    async def getPnmMeasurementStatistics(self) -> dict[ChannelId, list[DocsIf3CmSpectrumAnalysisEntry]]:
        """
        Return the raw PNM measurement statistics keyed by channel.

        Returns
        -------
        Dict[ChannelId, List[DocsIf3CmSpectrumAnalysisEntry]]
            Mapping of channel identifiers to their corresponding measurement
            entry lists.
        """
        return self._measurement_stat

    async def getPnmMeasurementStatisticsFlat(self) -> list[DocsIf3CmSpectrumAnalysisEntry]:
        """
        Return a flattened list of all PNM measurement entries across channels.

        This helper is intended for API layers that only need a single list of
        entries (for example, when serializing measurement statistics into a
        JSON payload without preserving per-channel grouping).

        Returns
        -------
        List[DocsIf3CmSpectrumAnalysisEntry]
            Flattened list of measurement entries aggregated from all channels.
        """
        entries: list[DocsIf3CmSpectrumAnalysisEntry] = []
        for channel_entries in self._measurement_stat.values():
            entries.extend(channel_entries)
        return entries

    async def updatePnmMeasurementStatistics(self, channel_id: ChannelId) -> bool:
        """
        Retrieve and store PNM measurement entries for the current `pnm_test_type`.

        Parameters
        ----------
        channel_id : ChannelId
            Channel identifier associated with the measurement update.

        Returns
        -------
        bool
            True if the measurement statistics were updated or a warning was
            logged; False is never returned but reserved for future logic.

        Notes
        -----
        - For spectrum analyzer test types, this method fetches
          DocsIf3CmSpectrumAnalysisEntry models from the cable modem and stores
          them under the given channel identifier.
        """
        if self._pnm_test_type in (
            DocsPnmCmCtlTest.SPECTRUM_ANALYZER,
            DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA,
        ):
            self._measurement_stat[channel_id] = await self._cm.getDocsIf3CmSpectrumAnalysisEntry()
        else:
            self.logger.warning(
                "%s - Unknown PNM test type: %s",
                self.log_prefix,
                self._pnm_test_type,
            )

        return True

    async def is_snmp_ready(self) -> bool:
        """
        Asynchronously check if the cable modem is accessible via SNMP.

        Returns
        -------
        bool
            True if the modem responds to SNMP queries, False otherwise.
        """
        return await self._cm.is_snmp_reachable()

    @abstractmethod
    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        """
        Compute start/center/end frequencies for each downstream channel.

        Returns
        -------
        CommonSpectumBwLut
            Mapping of ChannelId -> (start_hz, center_or_plc_hz, end_hz).

        Notes
        -----
        - Concrete implementations must derive per-channel bandwidth tuples
          according to the modulation type (OFDM or SC-QAM).
        """
        pass

    @abstractmethod
    async def calculate_spectrum_bandwidth(self) -> CommonSpectrumBw:
        """
        Retrieve the precomputed spectrum bandwidth mapping.

        Returns
        -------
        CommonSpectumBwLut
            Mapping of ChannelId -> (start_hz, center_or_plc_hz, end_hz).
        """
        pass

    @abstractmethod
    async def getChannelEntry(self) -> list[DocsIf31CmDsOfdmChanChannelEntry | DocsIfDownstreamChannelEntry]:
        pass

# FILE: src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, cast

from pydantic import BaseModel, Field

from pypnm.api.routes.common.extended.common_measure_schema import SpecAnCapturePara
from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import DocsPnmCmCtlTest
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.abstract.com_spec_chan_ana import (
    CommonChannelSpectumBwLut,
    CommonSpectrumBw,
    CommonSpectrumChannelAnalyzer,
    OfdmSpectrumBwLut,
    ScQamSpectrumBwLut,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import (
    ResolutionBw,
    SpecAnCaptureParaFriendly,
    SpectrumAnalyzerFriendlyCaptureBuilder,
    SpectrumRetrievalType,
    WindowFunction,
)
from pypnm.config.pnm_config_manager import PnmConfigManager
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.DocsIf31CmDsOfdmChanEntry import (
    DocsIf31CmDsOfdmChanChannelEntry,
    DocsIf31CmDsOfdmChanEntry,
)
from pypnm.docsis.data_type.DocsIfDownstreamChannel import (
    DocsIfDownstreamChannelEntry,
)
from pypnm.lib.constants import INVALID_CHANNEL_ID
from pypnm.lib.inet import Inet
from pypnm.lib.types import ChannelId, FrequencyHz
from pypnm.lib.utils import Generate
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest as DocsPnmCmCtlTestPnm


class SpectrumAnalyzerFriendlyCaptureInput(BaseModel):
    """
    User-supplied parameters for friendly spectrum capture.

    This input accepts a resolution bandwidth (RBW) and a frequency range
    and uses the helper tool (spectrum-analysis-capture-set.py) to derive
    segment span and bin count.
    """
    inactivity_timeout: int           = Field(..., description="Seconds of inactivity before auto-disabling analyzer.")
    first_segment_center_freq: int    = Field(..., description="First segment center frequency in Hz.")
    last_segment_center_freq: int     = Field(..., description="Last segment center frequency in Hz.")
    resolution_bw_hz: int             = Field(..., description="Resolution bandwidth in Hz (RBW).")
    noise_bw: int                     = Field(default=150, description="Equivalent noise bandwidth in Hz.")
    window_function: int              = Field(default=1, description="Window function index.")
    num_averages: int                 = Field(default=1, description="Number of averages per bin.")
    spectrum_retrieval_type: int      = Field(default=1, description="Spectrum retrieval type (FILE/SNMP).")


class SpectrumAnalyzerFriendlyCaptureBuilder:
    @staticmethod
    def build(params: SpecAnCaptureParaFriendly) -> SpecAnCapturePara:
        """
        Convert friendly RBW input parameters into actual spectrum capture settings.

        This follows the same logic used by `spectrum-analysis-capture-set.py`.
        It calculates:
        - segment span
        - number of bins per segment
        - first/last segment center frequencies

        Returns
        -------
        SpecAnCapturePara
        """
        span, bins = SpectrumAnalyzerFriendlyCaptureBuilder._rbw_to_span_and_bins(params.resolution_bandwidth_hz)
        start_hz, end_hz = SpectrumAnalyzerFriendlyCaptureBuilder._shift_edges(
            params.first_segment_center_freq,
            params.last_segment_center_freq,
            span,
        )

        return SpecAnCapturePara(
            inactivity_timeout       = params.inactivity_timeout,
            first_segment_center_freq= FrequencyHz(start_hz),
            last_segment_center_freq = FrequencyHz(end_hz),
            segment_freq_span        = FrequencyHz(span),
            num_bins_per_segment     = bins,
            noise_bw                 = params.noise_bw,
            window_function          = params.window_function,
            num_averages             = params.num_averages,
            spectrum_retrieval_type  = params.spectrum_retrieval_type,
        )

    @staticmethod
    def _rbw_to_span_and_bins(rbw: ResolutionBw) -> tuple[int, int]:
        """
        Translate a requested RBW into the closest supported segment span and bin count.
        """
        if rbw <= 15_000:
            return (1_000_000, 100)
        if rbw <= 30_000:
            return (1_000_000, 40)
        if rbw <= 50_000:
            return (1_000_000, 20)
        if rbw <= 100_000:
            return (1_000_000, 10)
        if rbw <= 200_000:
            return (2_000_000, 10)
        if rbw <= 500_000:
            return (5_000_000, 10)
        return (10_000_000, 10)

    @staticmethod
    def _shift_edges(first_hz: int, last_hz: int, span_hz: int) -> tuple[int, int]:
        half_span = int(span_hz / 2)
        return (first_hz + half_span, last_hz - half_span)


class OfdmChanSpecAnalyzerService(CommonMeasureService):
    """
    Wrapper for a single OFDM spectrum analyzer capture.
    """

    def __init__(
        self,
        cable_modem: CableModem,
        tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
        tftp_path: str = PnmConfigManager.get_tftp_path(),
    ) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__(
            DocsPnmCmCtlTest.SPECTRUM_ANALYZER,
            cable_modem,
            tftp_servers,
            tftp_path,
            cable_modem.getWriteCommunity(),
        )


class DsOfdmChannelSpectrumAnalyzer(CommonSpectrumChannelAnalyzer):
    """
    Downstream OFDM Channel Spectrum Analyzer Orchestrator.
    """

    def __init__(
        self,
        cable_modem: CableModem,
        tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
        number_of_averages: int = 1,
        resolution_bandwidth_hz: ResolutionBw | None = None,
        channel_ids: list[ChannelId] | None = None,
        spectrum_retrieval_type: SpectrumRetrievalType = SpectrumRetrievalType.FILE,
        test_mode: bool = False,
    ) -> None:
        super().__init__(cable_modem)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._number_of_averages = number_of_averages
        self._resolution_bandwidth = resolution_bandwidth_hz if resolution_bandwidth_hz is not None else ResolutionBw(25_000)
        self._spectrum_retrieval_type = spectrum_retrieval_type
        self._tftp_servers = tftp_servers

        self._channel_ids = channel_ids if channel_ids else None

        self.log_prefix = f"DsOfdmChannelSpectrumAnalyzer - CM {self._cm.get_mac_address}"
        self._test_mode = False

    async def start(self, capture_per_channel: bool = False) -> list[tuple[ChannelId, MessageResponse]]:
        """
        Execute spectrum analyzer captures across OFDM channels.
        """
        channel_spec_capture: list[tuple[ChannelId, SpecAnCapturePara]] = []
        out: list[tuple[ChannelId, MessageResponse]] = []

        channel_bw_map: OfdmSpectrumBwLut = await self.calculate_channel_spectrum_bandwidth()
        number_of_averages = self._number_of_averages
        spectrum_retrieval_type = self._spectrum_retrieval_type
        inactivity_timeout = 60
        noise_bw = 150
        channel_filter = set(self._channel_ids) if self._channel_ids else None

        for count, (chan_id, (start_hz, _plc_hz, end_hz)) in enumerate(channel_bw_map.items()):

            if channel_filter and chan_id not in channel_filter:
                continue

            if self._test_mode and count > 1:
                self.logger.warning("Test mode active: processing only first 2 channels.")
                break

            friendly_capture_parameter = SpecAnCaptureParaFriendly(
                inactivity_timeout        = inactivity_timeout,
                first_segment_center_freq = FrequencyHz(start_hz),
                last_segment_center_freq  = FrequencyHz(end_hz),
                resolution_bandwidth_hz   = ResolutionBw(self._resolution_bandwidth),
                noise_bw                  = noise_bw,
                window_function           = WindowFunction.HANN,
                num_averages              = number_of_averages,
                spectrum_retrieval_type   = spectrum_retrieval_type,
            )
            capture_parameter = SpectrumAnalyzerFriendlyCaptureBuilder.build(
                friendly_capture_parameter,
            )

            channel_spec_capture.append((chan_id, capture_parameter))

        for chan_id, capture_parameter in channel_spec_capture:
            service = OfdmChanSpecAnalyzerService(self._cm, tftp_servers=self._tftp_servers)
            service.setSpectrumCaptureParameters(capture_parameter)
            out.append((chan_id, await service.set_and_go()))
            await self.updatePnmMeasurementStatistics(chan_id)

        return out

    async def calculate_channel_spectrum_bandwidth(self) -> OfdmSpectrumBwLut:
        """Compute OFDM channel-specific (start, plc, end) frequency tuples."""
        out: OfdmSpectrumBwLut = {}

        ofdm_channels: list[DocsIf31CmDsOfdmChanEntry] = await self._cm.getDocsIf31CmDsOfdmChanEntry()
        if not ofdm_channels:
            self.logger.warning("No downstream OFDM channels returned from cable modem.")
            return out

        for channel in ofdm_channels:
            zero_freq: FrequencyHz | None = channel.docsIf31CmDsOfdmChanSubcarrierZeroFreq
            first_active: int | None = channel.docsIf31CmDsOfdmChanFirstActiveSubcarrierNum
            last_active: int | None = channel.docsIf31CmDsOfdmChanLastActiveSubcarrierNum
            sub_spacing: FrequencyHz | None = channel.docsIf31CmDsOfdmChanSubcarrierSpacing
            plc_freq: FrequencyHz | None = channel.docsIf31CmDsOfdmChanPlcFreq
            chan_id: ChannelId          = cast(ChannelId, channel.docsIf31CmDsOfdmChanChannelId)

            if (chan_id is None or zero_freq is None or
                first_active is None or last_active is None or
                sub_spacing is None or plc_freq is None ):

                self.logger.debug(
                    "Skipping channel with missing data: "
                    f"id={chan_id}, zero_freq={zero_freq}, first_active={first_active}, "
                    f"last_active={last_active}, spacing={sub_spacing}, plc_freq={plc_freq}")

                continue

            start_freq  = zero_freq + (first_active * sub_spacing)
            end_freq    = zero_freq + ((last_active + 1) * sub_spacing)

            out[chan_id] = (FrequencyHz(start_freq), FrequencyHz(plc_freq), FrequencyHz(end_freq))

            self.logger.debug(
                "Computed OFDM channel frequencies: "
                f"ch_id={chan_id}, start={start_freq}, plc={plc_freq}, end={end_freq}, "
                f"first_active={first_active}, last_active={last_active}, spacing={sub_spacing}"
            )

        return out

    async def calculate_spectrum_bandwidth(self) -> CommonSpectrumBw:
        """
        Retrieve The Precomputed Spectrum Bandwidth Mapping (Placeholder)

        Returns
        -------
        CommonSpectrumBw
            Placeholder tuple ``(0, 0, 0)``. This method is intentionally a stub
            in this class; see the SC-QAM variant for a complete implementation.

        Notes
        -----
        - Intentional placeholder to keep interface symmetry with
          :class:`DsScQamChannelSpectrumAnalyzer`. The OFDM flow typically
          uses per-channel tuples directly.
        """
        return (FrequencyHz(0), FrequencyHz(0), FrequencyHz(0))  # Placeholder implementation

    async def getChannelEntry(self) -> list[DocsIf31CmDsOfdmChanChannelEntry]:
        """
        Retrieve the OFDM channel entry list from the cable modem.

        Returns
        -------
        list[DocsIf31CmDsOfdmChanChannelEntry | DocsIfDownstreamChannelEntry]
            OFDM channel entries returned by the modem. The list is empty
            when no channels are present.
        """
        entries = await self._cm.getDocsIf31CmDsOfdmChanEntry()
        if not entries:
            self.logger.warning("No downstream OFDM channel entries returned from cable modem.")
        return entries

class ScQamChanSpecAnalyzerService(CommonMeasureService):
    """
    Helper Service For SC-QAM Spectrum Analyzer Runs

    Purpose
    -------
    Thin wrapper around :class:`CommonMeasureService` that configures a
    single spectrum analyzer capture for a downstream SC-QAM channel set.

    Parameters
    ----------
    cable_modem : CableModem
        Target cable modem instance.
    tftp_servers : tuple[Inet, Inet], optional
        Primary/secondary TFTP servers for capture file transfer.
        Defaults to :func:`PnmConfigManager.get_tftp_servers`.
    tftp_path : str, optional
        Remote TFTP directory for capture output.
        Defaults to :func:`PnmConfigManager.get_tftp_path`.

    Usage
    -----
    1) Construct the service.
    2) Call :meth:`setSpectrumCaptureParameters` with :class:`SpecAnCapturePara`.
    3) Execute :meth:`set_and_go` to run the test.
    """

    def __init__(
        self,
        cable_modem: CableModem,
        tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
        tftp_path: str = PnmConfigManager.get_tftp_path(),
    ) -> None:
        """
        Initialize The SC-QAM Spectrum Analyzer Service

        Notes
        -----
        - This constructor does not validate parameter contents; they are passed
          unchanged to :class:`CommonMeasureService`.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__(
            DocsPnmCmCtlTest.SPECTRUM_ANALYZER,
            cable_modem,
            tftp_servers,
            tftp_path,
            cable_modem.getWriteCommunity(),)

class DsScQamChannelSpectrumAnalyzer(CommonSpectrumChannelAnalyzer):
    """
    Downstream SC-QAM Channel Spectrum Analyzer Orchestrator

    Responsibilities
    ----------------
    1) Fetch downstream SC-QAM channel list from the cable modem.
    2) Compute per-channel tuples (start_hz, center_hz, end_hz) using
       the reported center frequency and channel width.
    3) Build :class:`SpecAnCapturePara` and run captures per channel via
       :class:`ScQamChanSpecAnalyzerService`.

    Parameters
    ----------
    cable_modem : CableModem
        Cable modem to analyze.
    number_of_averages : int, default 1
        Number of averages per segment to request.
    resolution_bandwidth : ResolutionBw, optional
        Resolution bandwidth in Hz; defaults to 300 kHz if not provided.
    spectrum_retrieval_type : SpectrumRetrievalType, default SpectrumRetrievalType.FILE
        Data retrieval mechanism for captures.
    """

    def __init__(self, cable_modem: CableModem,
                 tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
                 number_of_averages: int = 1,
                 resolution_bandwidth_hz: ResolutionBw | None = None,
                 channel_ids: list[ChannelId] | None = None,
                 spectrum_retrieval_type: SpectrumRetrievalType = SpectrumRetrievalType.FILE,
                 test_mode: bool = False,) -> None:
        super().__init__(cable_modem)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._number_of_averages = number_of_averages
        self._resolution_bandwidth = resolution_bandwidth_hz if resolution_bandwidth_hz is not None else ResolutionBw(25_000)
        self._spectrum_retrieval_type = spectrum_retrieval_type
        self._tftp_servers = tftp_servers

        self._channel_ids = channel_ids if channel_ids else None

        self.log_prefix = f"DsScQamChannelSpectrumAnalyzer - CM {self._cm.get_mac_address}"
        self._test_mode = False

    async def start(self, capture_per_channel: bool = False) -> list[tuple[ChannelId, MessageResponse]]:
        """
        Run Spectrum Captures Across All SC-QAM Channels

        Behavior
        --------
        - Computes per-channel (start/center/end) tuples via
          :meth:`calculate_channel_spectrum_bandwidth`.
        - Configures :class:`SpecAnCapturePara` per channel using:
            * first_segment_center_freq = start_hz
            * last_segment_center_freq  = end_hz
            * segment_freq_span         = 1_000_000 Hz (default here)
            * num_bins_per_segment      = 256 (default here)
            * window_function           = HANN
            * num_averages              = instance default
            * spectrum_retrieval_type   = instance default
        - Executes :meth:`set_and_go` for each channel.

        Parameters
        ----------
        capture_per_channel : bool, optional
            Reserved for future modes; current implementation iterates all
            channels. Default False.

        Returns
        -------
        list[tuple[ChannelId, MessageResponse]]
            Per-channel results from the spectrum analyzer run.
        """
        channel_spec_capture: list[tuple[ChannelId, SpecAnCapturePara]] = []
        out: list[tuple[ChannelId, MessageResponse]] = []

        bw_by_channel: ScQamSpectrumBwLut = await self.calculate_channel_spectrum_bandwidth()
        number_of_averages = self._number_of_averages
        spectrum_retrieval_type = self._spectrum_retrieval_type
        inactivity_timeout = 60
        noise_bw = 150
        channel_filter = set(self._channel_ids) if self._channel_ids else None

        for count, (chan_id, (start_hz, _center_hz, end_hz)) in enumerate(bw_by_channel.items()):

            if channel_filter and chan_id not in channel_filter:
                continue

            if self._test_mode and count > 1:
                self.logger.warning("Test mode active: processing only first 2 channels.")
                break

            friendly_capture_parameter = SpecAnCaptureParaFriendly(
                inactivity_timeout        = inactivity_timeout,
                first_segment_center_freq = FrequencyHz(start_hz),
                last_segment_center_freq  = FrequencyHz(end_hz),
                resolution_bandwidth_hz   = ResolutionBw(self._resolution_bandwidth),
                noise_bw                  = noise_bw,
                window_function           = WindowFunction.HANN,
                num_averages              = number_of_averages,
                spectrum_retrieval_type   = spectrum_retrieval_type,
            )
            capture_parameter = SpectrumAnalyzerFriendlyCaptureBuilder.build(
                friendly_capture_parameter,
            )

            channel_spec_capture.append((chan_id, capture_parameter))

        for chan_id, capture_parameter in channel_spec_capture:
            service = ScQamChanSpecAnalyzerService(self._cm, tftp_servers=self._tftp_servers)
            service.setSpectrumCaptureParameters(capture_parameter)
            out.append((chan_id, await service.set_and_go()))
            await self.updatePnmMeasurementStatistics(chan_id)

        return out

    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        """
        Calculate Per-Channel SC-QAM Spectrum Tuples

        Method
        ------
        For each SC-QAM channel, computes:
            start = center - width/2
            end   = center + width/2

        Returns
        -------
        CommonChannelSpectumBwLut
            Mapping of ``ChannelId → (start_hz, center_hz, end_hz)``.

        Notes
        -----
        - Pulls channel center frequency and width from
          :class:`DocsIfDownstreamChannelEntry` via the modem.
        - Channels with missing data are skipped and logged.
        """
        out: CommonChannelSpectumBwLut = {}

        channels: list[DocsIfDownstreamChannelEntry] = await self._cm.getDocsIfDownstreamChannel()
        if not channels:
            self.logger.warning("No downstream SC-QAM channels returned from cable modem.")
            return out

        for channel in channels:
            cfreq: FrequencyHz = cast(FrequencyHz, channel.entry.docsIfDownChannelFrequency)
            cwidth: FrequencyHz = cast(FrequencyHz, channel.entry.docsIfDownChannelWidth)
            chan_id: ChannelId = cast(ChannelId, channel.entry.docsIfDownChannelId)

            if cfreq is None or cwidth is None or chan_id is None:
                self.logger.debug(
                    "Skipping channel with missing data: id=%s, freq=%s, width=%s",
                    chan_id,
                    cfreq,
                    cwidth,
                )
                continue

            half_width: FrequencyHz = cast(FrequencyHz, cwidth // 2)
            start: FrequencyHz = cast(FrequencyHz, cfreq - half_width)
            end: FrequencyHz = cast(FrequencyHz, cfreq + half_width)

            self.logger.debug(
                "Calculate SC-QAM Spectrum Settings: Mac: %s - Channel-Settings: Ch=%s, Start=%s, Center=%s, End=%s",
                self._cm.get_mac_address, chan_id, start, cfreq, end,
            )

            out[chan_id] = (start, cfreq, end)

        return out

    async def calculate_spectrum_bandwidth(self) -> CommonSpectrumBw:
        """
        Compute Overall SC-QAM Spectrum Bounds

        Purpose
        -------
        Folds all per-channel tuples into a single band by selecting the lowest
        start frequency and highest end frequency among channels, and computes a
        *nominal* midpoint as ``center = (start_global + end_global) // 2``.

        Returns
        -------
        CommonSpectrumBw
            Tuple ``(start_hz_global, center_hz_global, end_hz_global)``.

        Notes
        -----
        - The returned "center" is a nominal midpoint only. When configuring
          captures you typically prefer explicit first/last frequencies.
        - Logs incremental accumulation for traceability.
        """
        channels: CommonChannelSpectumBwLut = await self.calculate_channel_spectrum_bandwidth()
        if not channels:
            self.logger.warning("SC-QAM: no channels available to compute overall bandwidth.")
            return (FrequencyHz(0), FrequencyHz(0), FrequencyHz(0))

        iterator = iter(channels.items())
        first_key, (start_hz, _, end_hz) = next(iterator)
        start_hz_global: FrequencyHz = FrequencyHz(start_hz)
        end_hz_global: FrequencyHz = FrequencyHz(end_hz)

        for channel_id, (ch_start, _ch_center, ch_end) in iterator:
            s = FrequencyHz(ch_start)
            e = FrequencyHz(ch_end)
            if s < start_hz_global:
                start_hz_global = s
            if e > end_hz_global:
                end_hz_global = e

            self.logger.debug(
                "SC-QAM accumulate: ch=%s, start=%d, end=%d → global=(%d, %d)",
                channel_id, s, e, start_hz_global, end_hz_global
            )

        center_hz_global: FrequencyHz = FrequencyHz((start_hz_global + end_hz_global) // 2)

        self.logger.debug(
            "SC-QAM overall bandwidth: start=%d Hz, end=%d Hz (width=%d Hz); nominal center=%d Hz",
            start_hz_global, end_hz_global, end_hz_global - start_hz_global, center_hz_global
        )

        return (start_hz_global, center_hz_global, end_hz_global)

    async def getChannelEntry(self) -> list[DocsIfDownstreamChannelEntry]:
        """
        Retrieve the SC-QAM channel entry list from the cable modem.

        Returns
        -------
        list[DocsIfDownstreamChannelEntry]
            SC-QAM channel entries returned by the modem. The list is empty
            when no channels are present.
        """
        entries = await self._cm.getDocsIfDownstreamChannel()
        if not entries:
            self.logger.warning("No downstream SC-QAM channel entries returned from cable modem.")
        return entries

# FILE: src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisRptMatplotConfig
from pypnm.api.routes.basic.ofdm_spec_analyzer_rpt import OfdmSpecAnalyzerAnalysisReport
from pypnm.api.routes.basic.scqam_spec_analyzer_rpt import (
    ScQamSpecAnalyzerAnalysisReport,
)
from pypnm.api.routes.basic.spec_analyzer_analysis_rpt import SpectrumAnalyzerReport
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.analysis.model.process import (
    AnalysisProcessParameters,
)
from pypnm.api.routes.common.classes.analysis.multi_analysis import MultiAnalysis
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import (
    OfdmSpecAnaAnalysisRequest,
    OfdmSpecAnaAnalysisResponse,
    ScQamSpecAnaAnalysisRequest,
    ScQamSpecAnaAnalysisResponse,
    SingleCaptureSpectrumAnalyzerFriendlyRequest,
    SingleCaptureSpectrumAnalyzerRequest,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.service import (
    CmSpectrumAnalysisService,
    DsOfdmChannelSpectrumAnalyzer,
    DsScQamChannelSpectrumAnalyzer,
    SpectrumAnalyzerFriendlyCaptureBuilder,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.DocsIf31CmDsOfdmChanEntry import (
    DocsIf31CmDsOfdmChanChannelEntry,
)
from pypnm.docsis.data_type.DocsIfDownstreamChannel import DocsIfDownstreamChannelEntry
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
)
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, FrequencyHz, InetAddressStr, MacAddressStr, Path


class SpectrumAnalyzerRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/ds"
        self.base_endpoint = "/spectrumAnalyzer"
        self.router = APIRouter(prefix=prefix, tags=["PNM Operations - Spectrum Analyzer"])
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.__routes()

    @staticmethod
    def _build_channel_entry_lookup(
        entries: list[DocsIf31CmDsOfdmChanChannelEntry | DocsIfDownstreamChannelEntry],
    ) -> dict[ChannelId, DocsIf31CmDsOfdmChanChannelEntry | DocsIfDownstreamChannelEntry]:
        lookup: dict[ChannelId, DocsIf31CmDsOfdmChanChannelEntry | DocsIfDownstreamChannelEntry] = {}
        for entry in entries:
            if entry.channel_id <= 0:
                continue
            lookup[ChannelId(entry.channel_id)] = entry
        return lookup

    @classmethod
    def _build_measurement_stats_with_channel_stats(
        cls,
        measurement_stats: dict[ChannelId, list[DocsIf3CmSpectrumAnalysisEntry]],
        channel_entries: list[DocsIf31CmDsOfdmChanChannelEntry | DocsIfDownstreamChannelEntry],
    ) -> list[dict[str, Any]]:
        channel_lookup = cls._build_channel_entry_lookup(channel_entries)
        out: list[dict[str, Any]] = []

        for channel_id, entries in measurement_stats.items():
            channel_entry = channel_lookup.get(channel_id)
            channel_stats = channel_entry.model_dump() if channel_entry is not None else None

            for entry in entries:
                payload = entry.model_dump()
                payload["channel_id"] = channel_id
                if channel_stats is not None:
                    payload["channel_stats"] = channel_stats
                out.append(payload)

        return out

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get Spectrum Analyzer Capture",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_capture(request: SingleCaptureSpectrumAnalyzerRequest) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Perform Spectrum Analyzer Capture And Return Analysis Results.

            This endpoint triggers a spectrum capture on the requested cable modem using the
            provided capture parameters. The measurement response is then processed through
            the common analysis pipeline and returned as either:

            - A JSON analysis payload containing decoded amplitude data and summary metrics.
            - An archive file containing plots and related report artifacts (ZIP).

            The cable modem must be PNM-ready and the capture parameters must respect the
            diplexer configuration and platform constraints (DOCSIS 3.x and DOCSIS 4.0 FDD).

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/spectrum-analyzer.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            self.logger.info("Starting Spectrum Analyzer capture for MAC: %s, IP: %s, Output Type: %s",
                mac, ip, request.analysis.output.type,)

            cm = CableModem(mac_address=MacAddress(mac),
                            inet=Inet(ip),
                            write_community=community,)

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_pnm_ready_status=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service = CmSpectrumAnalysisService(
                cable_modem=cm,
                tftp_servers=tftp_servers,
                capture_parameters=request.capture_parameters,)

            msg_rsp: MessageResponse = await service.set_and_go()

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Spectrum Analyzer capture."
                self.logger.error("%s Status: %s", err, msg_rsp.status.name)
                return SnmpResponse(mac_address=mac, status=msg_rsp.status, message=err)

            channel_ids = None
            measurement_stats: list[DocsIf3CmSpectrumAnalysisEntry] = cast(
                list[DocsIf3CmSpectrumAnalysisEntry],
                await service.getPnmMeasurementStatistics(channel_ids=channel_ids),)

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp, skip_automatic_process=True)
            analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())
                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "mac_address", "channel_id"])

                primative = msg_rsp.payload_to_dict("primative")
                DictGenerate.pop_keys_recursive(
                    primative,
                    ["device_details", "channel_id", "amplitude_bin_segments_float"],
                )
                payload.update(cast(dict[str, Any], primative))
                payload.update(
                    DictGenerate.models_to_nested_dict(
                        measurement_stats,
                        "measurement_stats",
                    )
                )

                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.SUCCESS,
                    data=payload,
                )

            if request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme=theme)
                analysis_rpt = SpectrumAnalyzerReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            return PnmAnalysisResponse(
                mac_address=mac,
                status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                data={},
            )

        @self.router.post(
            f"{self.base_endpoint}/getCapture/friendly",
            summary="Get Spectrum Analyzer Capture (Friendly)",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_capture_friendly(
            request: SingleCaptureSpectrumAnalyzerFriendlyRequest,
        ) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Perform Spectrum Analyzer Capture Using Friendly RBW Inputs.

            This endpoint accepts a resolution bandwidth (RBW) and a requested window,
            then derives a segment span and bin count using the spectrum-analysis-capture-set
            rules. The segment center frequencies are adjusted inward by half a segment
            span on each edge to satisfy the analyzer's scaled window constraints.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/spectrum-analyzer/spectrum-analyzer.md)
            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            self.logger.info("Starting Spectrum Analyzer friendly capture for MAC: %s, IP: %s, Output Type: %s",
                mac, ip, request.analysis.output.type,)

            cm = CableModem(mac_address=MacAddress(mac),
                            inet=Inet(ip),
                            write_community=community,)

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_pnm_ready_status=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            try:
                capture_parameters = SpectrumAnalyzerFriendlyCaptureBuilder.build(
                    request.capture_parameters,
                )
            except ValueError as e:
                err = f"Invalid capture parameters: {e}"
                self.logger.error(err)
                return SnmpResponse(mac_address=mac, status=ServiceStatusCode.INVALID_CAPTURE_PARAMETERS, message=err)

            service = CmSpectrumAnalysisService(
                cable_modem=cm,
                tftp_servers=tftp_servers,
                capture_parameters=capture_parameters,)

            msg_rsp: MessageResponse = await service.set_and_go()

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Spectrum Analyzer capture."
                self.logger.error("%s Status: %s", err, msg_rsp.status.name)
                return SnmpResponse(mac_address=mac, status=msg_rsp.status, message=err)

            channel_ids = None
            measurement_stats: list[DocsIf3CmSpectrumAnalysisEntry] = cast(
                list[DocsIf3CmSpectrumAnalysisEntry],
                await service.getPnmMeasurementStatistics(channel_ids=channel_ids),)

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp, skip_automatic_process=True)
            analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())
                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "mac_address", "channel_id"])

                primative = msg_rsp.payload_to_dict("primative")
                DictGenerate.pop_keys_recursive(
                    primative,
                    ["device_details", "channel_id", "amplitude_bin_segments_float"],
                )
                payload.update(cast(dict[str, Any], primative))
                payload.update(
                    DictGenerate.models_to_nested_dict(
                        measurement_stats,
                        "measurement_stats",
                    )
                )

                return PnmAnalysisResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.SUCCESS,
                    data=payload,
                )

            if request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme=theme)
                analysis_rpt = SpectrumAnalyzerReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            return PnmAnalysisResponse(
                mac_address=mac,
                status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                data={},
            )

        @self.router.post(
            f"{self.base_endpoint}/getCapture/ofdm",
            summary="Get OFDM Channels Spectrum Analyzer Capture",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_ofdm_ds_channels_analysis(request: OfdmSpecAnaAnalysisRequest) -> OfdmSpecAnaAnalysisResponse | FileResponse:
            """
            Perform OFDM Downstream Spectrum Capture Across All DS OFDM Channels.

            This endpoint triggers spectrum capture operations on each DOCSIS 3.1 OFDM
            downstream channel of the requested cable modem. Each per-channel response is
            processed through the common analysis pipeline, aggregated into a multi-analysis
            structure, and then returned as either JSON or an archive.

            The cable modem must support OFDM downstream channels and be PNM-ready, and
            the spectrum capture parameters must be valid for the underlying platform and
            diplexer configuration.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/spectrum-analyzer.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            cm = CableModem(mac_address=MacAddress(mac),
                            inet=Inet(ip),
                            write_community=community)
            multi_analysis = MultiAnalysis()

            self.logger.info("DOCSIS 3.1 OFDM Downstream Spectrum Capture for MAC %s, IP %s", mac, ip,)

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_ofdm_exist=True,
                validate_pnm_ready_status=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return OfdmSpecAnaAnalysisResponse(
                    mac_address=mac, status=status, message=msg, data={},)

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids

            service = DsOfdmChannelSpectrumAnalyzer(
                cable_modem             =   cm,
                tftp_servers            =   tftp_servers,
                number_of_averages      =   request.capture_parameters.number_of_averages,
                resolution_bandwidth_hz =   request.capture_parameters.resolution_bandwidth_hz,
                channel_ids             =   channel_ids if channel_ids else None,
                spectrum_retrieval_type =   request.capture_parameters.spectrum_retrieval_type)

            msg_responses: list[tuple[ChannelId, MessageResponse]] = await service.start()

            measurement_stats = await service.getPnmMeasurementStatistics()
            channel_entries = await service.getChannelEntry()
            measurement_stats_with_channels = self._build_measurement_stats_with_channel_stats(
                measurement_stats,
                channel_entries,
            )
            measurement_stats_by_channel: dict[ChannelId, list[dict[str, Any]]] = {}
            for entry in measurement_stats_with_channels:
                channel_id = cast(ChannelId, entry["channel_id"])
                measurement_stats_by_channel.setdefault(channel_id, []).append(entry)

            primative: dict[str, dict[Any, Any]] = {"primative": {}}

            for idx, (chan_id, msg_rsp) in enumerate(msg_responses):
                cps_msg_rsp = CommonProcessService(msg_rsp).process()

                analysis = Analysis(AnalysisType.BASIC, cps_msg_rsp, skip_automatic_process=True,)
                analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))
                multi_analysis.add(chan_id, analysis)

                primative_entry = cps_msg_rsp.payload_to_dict(idx)
                primative["primative"].update(primative_entry)

            analyzer_rpt = OfdmSpecAnalyzerAnalysisReport(
                multi_analysis,
                measurement_stats_by_channel=measurement_stats_by_channel,
            )
            analyzer_rpt.build_report()

            if request.analysis.output.type == OutputType.JSON:
                analyzer_rpt_dict = analyzer_rpt.to_dict()
                analyzer_rpt_dict.update(primative)
                analyzer_rpt_dict.update({"measurement_stats": measurement_stats_with_channels})

                return OfdmSpecAnaAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   analyzer_rpt_dict,
                )

            if request.analysis.output.type == OutputType.ARCHIVE:
                return PnmFileService().get_file(
                    FileType.ARCHIVE, analyzer_rpt.get_archive(),
                )

            return OfdmSpecAnaAnalysisResponse(
                mac_address =   mac,
                status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message     =   f"Unsupported output type: {request.analysis.output.type}",
                data={},
            )

        @self.router.post(
            f"{self.base_endpoint}/getCapture/scqam",
            summary="Get SC-QAM Downstream Channels Spectrum Analysis",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )
        async def get_scqam_ds_channels_analysis(request: ScQamSpecAnaAnalysisRequest) -> ScQamSpecAnaAnalysisResponse | FileResponse:
            """
            Perform SC-QAM Downstream Spectrum Capture Across All DS SC-QAM Channels.

            This endpoint triggers spectrum capture operations on each DOCSIS 3.0 SC-QAM
            downstream channel of the requested cable modem. Each per-channel response is
            processed through the common analysis pipeline, aggregated into a multi-analysis
            structure, and then returned as either JSON or an archive.

            The cable modem must support SC-QAM downstream channels and be PNM-ready, and
            the spectrum capture parameters must be valid for the underlying platform and
            diplexer configuration.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/spectrum-analyzer.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            cm = CableModem(mac_address=MacAddress(mac), inet=Inet(ip), write_community=community)
            multi_analysis = MultiAnalysis()

            self.logger.info("DOCSIS 3.0 SC-QAM downstream spectrum capture for MAC %s, IP %s", mac, ip)

            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_scqam_exist=True,
                validate_pnm_ready_status=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return ScQamSpecAnaAnalysisResponse(
                    mac_address=mac,
                    status=status, message=msg, data={}, )

            number_of_averages: int = request.capture_parameters.number_of_averages
            spectrum_retrieval_type = request.capture_parameters.spectrum_retrieval_type
            resolution_bandwidth: FrequencyHz = request.capture_parameters.resolution_bandwidth_hz
            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids

            service = DsScQamChannelSpectrumAnalyzer(
                cable_modem             =   cm,
                tftp_servers            =   tftp_servers,
                number_of_averages      =   number_of_averages,
                resolution_bandwidth_hz =   resolution_bandwidth,
                channel_ids              =   channel_ids if channel_ids else None,
                spectrum_retrieval_type =   spectrum_retrieval_type,
            )

            msg_responses: list[tuple[ChannelId, MessageResponse]] = await service.start()

            measurement_stats = await service.getPnmMeasurementStatistics()
            channel_entries = await service.getChannelEntry()
            measurement_stats_with_channels = self._build_measurement_stats_with_channel_stats(
                measurement_stats,
                channel_entries,
            )
            measurement_stats_by_channel: dict[ChannelId, list[dict[str, Any]]] = {}
            for entry in measurement_stats_with_channels:
                channel_id = cast(ChannelId, entry["channel_id"])
                measurement_stats_by_channel.setdefault(channel_id, []).append(entry)

            primative: dict[str, dict[Any, Any]] = {"primative": {}}

            for idx, (chan_id, msg_rsp) in enumerate(msg_responses):
                cps_msg_rsp = CommonProcessService(msg_rsp).process()

                analysis = Analysis(AnalysisType.BASIC, cps_msg_rsp, skip_automatic_process=True,)
                analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))
                multi_analysis.add(chan_id, analysis)

                primative_entry = cps_msg_rsp.payload_to_dict(idx)
                primative["primative"].update(primative_entry)

            analyzer_rpt = ScQamSpecAnalyzerAnalysisReport(
                multi_analysis,
                measurement_stats_by_channel=measurement_stats_by_channel,
            )
            analyzer_rpt.build_report()

            if request.analysis.output.type == OutputType.JSON:
                analyzer_rpt_dict = analyzer_rpt.to_dict()
                analyzer_rpt_dict.update(primative)
                analyzer_rpt_dict.update({"measurement_stats": measurement_stats_with_channels})

                return ScQamSpecAnaAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   analyzer_rpt_dict,
                )

            if request.analysis.output.type == OutputType.ARCHIVE:
                return PnmFileService().get_file(FileType.ARCHIVE, analyzer_rpt.get_archive(),)

            return ScQamSpecAnaAnalysisResponse(
                mac_address=mac,
                status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message=f"Unsupported output type: {request.analysis.output.type}",
                data={},
            )


# Required for dynamic auto-registration
router = SpectrumAnalyzerRouter().router

# FILE: src/pypnm/api/routes/basic/ofdm_spec_analyzer_rpt.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, cast

from pydantic import BaseModel

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisReport
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.basic.spec_analyzer_analysis_rpt import (
    SpecAnaWindowAvgRptModel,
    SpectrumAnalyzerAnalysisRptModel,
    SpectrumAnalyzerSignalProcessRptModel,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.spectrum_analyzer_schema import (
    BaseAnalysisModel,
    SpectrumAnalyzerAnalysisModel,
)
from pypnm.api.routes.common.classes.analysis.multi_analysis import MultiAnalysis
from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.docsis.cable_modem import MacAddress
from pypnm.lib.archive.manager import ArchiveManager
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import ArrayLike, ChannelId, FloatSeries, FrequencySeriesHz, Path, PathLike
from pypnm.lib.utils import Generate


class OfdmSpecAnalysisRptModel(BaseModel):
    """Pydantic model for a compiled OFDM Spectrum Analyzer report.
    """
    models:list[BaseAnalysisModel]


class OfdmSpecAnalyzerAnalysisReport:
    """Coordinator that compiles per-channel Spectrum Analyzer artifacts into a single deliverable.

    The class iterates over a :class:`MultiAnalysis` container, invokes
    :class:`SingleOfdmSpecAnalyzerReport` for each constituent
    :class:`Analysis`, collects all generated files (CSV/plots), and can bundle
    them into a zip archive.

    Parameters
    ----------
    multi_analysis : MultiAnalysis
        A container of individual Spectrum Analyzer analyses to be reported.

    Examples
    --------
    >>> rpt = OfdmSpecAnalyzerReport(multi_analysis)
    >>> rpt.build_report()
    >>> archive_path = rpt._build_archive()
    >>> rpt_dict = rpt.to_dict()
    """

    def __init__(
        self,
        multi_analysis: MultiAnalysis,
        measurement_stats_by_channel: dict[ChannelId, list[dict[str, Any]]] | None = None,
    ) -> None:
        """Initialize the report coordinator.

        Parameters
        ----------
        multi_analysis : MultiAnalysis
            Source of per-channel :class:`Analysis` objects to process.
        """
        self._multi_analysis = multi_analysis
        self._archive_path:PathLike = SystemConfigSettings.archive_dir()
        self._analysis_files:list[PathLike] = []
        self._archive_file:PathLike
        self._measurement_stats_by_channel = measurement_stats_by_channel

    def build_report(self) -> PathLike:
        """
        Generate and collect all per-channel analysis artifacts into a final archive.

        This method iterates over each :class:`Analysis` object within a
        :class:`MultiAnalysis` instance, generating CSVs and plots using
        :class:`SingleOfdmSpecAnalyzerReport`. It then aggregates all
        generated files and produces a single ZIP archive.

        Returns:
            PathLike: The path to the created archive file.

        Workflow:
            1. For each `Analysis`, create and execute a
            `SingleOfdmSpecAnalyzerReport`.
            2. Collect all generated files using
            :meth:`SingleOfdmSpecAnalyzerReport.get_all_generated_files`.
            3. Combine them into a single archive using :meth:`_build_archive`.

        Notes:
            - The internal list of report files is updated via `_analysis_files`.
            - Only the archive file path is returned; individual CSVs and plots
            remain accessible through their respective report instances.
        """
        for _ in self._get_analyses():
            rpt = SingleOfdmSpecAnalyzerReport(_, measurement_stats_by_channel=self._measurement_stats_by_channel)
            rpt.build_report()
            rpt.get_all_generated_files()
            self._analysis_files.extend(rpt.get_all_generated_files())

        return self._build_archive()

    def _get_models(self) -> list[BaseAnalysisModel]:
        """Return the list of models sourced from the bound :class:`MultiAnalysis`."""
        return self._multi_analysis.to_model()

    def _get_analyses(self) -> list[Analysis]:
        """Return the list of analyses sourced from the bound :class:`MultiAnalysis`."""
        return self._multi_analysis.get_analyses()

    def _report_files(self) -> list[PathLike]:
        """Return the list of file paths collected during :meth:`build_report`."""
        return self._analysis_files

    def _build_archive(self) -> PathLike:
        """Create a zip archive containing all collected report files.

        Returns
        -------
        PathLike
            Absolute or relative filesystem path to the generated archive.

        Notes
        -----
        The archive location defaults to :data:`SystemConfigSettings.archive_dir`
        and is cached internally for retrieval via :meth:`get_archive`.
        """
        self._archive_file = ArchiveManager().zip_files(files=self._report_files(),
                                                        archive_path=self._create_archive_fname())
        return self._archive_file

    def _create_archive_fname(self) -> PathLike:
        """Create a unique archive name based on the current timestamp.

        Returns
        -------
        PathLike
            The generated archive name.
        """
        mac = self.get_mac_address().to_mac_format()

        return Path(self._archive_path) / f"scqam_report_{mac}_{Generate.time_stamp()}.zip"

    def get_mac_address(self) -> MacAddress:
        """Return the MAC address associated with the report.

        Notes
        -----
        Assumes all analyses in the bound :class:`MultiAnalysis` share the same MAC.
        """
        analyses = self._get_analyses()
        if not analyses:
            raise ValueError("No analyses available to extract MAC address.")

        first_analysis:Analysis = analyses[0]

        return MacAddress(cast(BaseAnalysisModel, first_analysis.get_model()[0].mac_address))

    def get_archive(self) -> PathLike:
        """Return the path to the previously created archive.

        Notes
        -----
        Call :meth:`_build_archive` before invoking this method.
        """
        return self._archive_file

    def to_model(self) -> OfdmSpecAnalysisRptModel:
        """Return a structured model of the aggregated report output.

        Notes
        -----
        The model schema is minimal today and will evolve as fields stabilize.
        """
        return OfdmSpecAnalysisRptModel(
            models=self._multi_analysis.to_model())

    def to_dict(self) -> dict[str,Any]:
        """Return the report as a serializable ``dict`` via Pydantic's ``model_dump``."""
        return self._multi_analysis.to_dict()


class SingleOfdmSpecAnalyzerReport(AnalysisReport):
    """Emitter for CSV and plots from a single OFDM Spectrum Analyzer analysis.

    This concrete :class:`AnalysisReport`:
      * builds a CSV (Frequency, Magnitude dBmV, Moving Average),
      * generates two line plots per channel (raw spectrum, windowed average),
      * materializes a :class:`SpectrumAnalyzerAnalysisRptModel` for downstream use.

    Attributes
    ----------
    FNAME_TAG : str
        Base tag used in output filenames to consistently label Spectrum Analyzer artifacts.
    """
    FNAME_TAG: str = "ofdm_spec_ana_rpt"

    def __init__(
        self,
        analysis: Analysis,
        measurement_stats_by_channel: dict[ChannelId, list[dict[str, Any]]] | None = None,
    ) -> None:
        """Create a report instance bound to a single :class:`Analysis`.

        Parameters
        ----------
        analysis : Analysis
            The source analysis whose models/results will be rendered to artifacts.
        """
        super().__init__(analysis)
        self.logger = logging.getLogger("SingleOfdmSpecAnalyzerReport")
        self._results: dict[int, SpectrumAnalyzerAnalysisRptModel] = {}
        self._measurement_stats_by_channel = measurement_stats_by_channel

    def _build_common_analysis_json(self, channel_id: ChannelId, common_analysis: CommonAnalysis) -> None:
        payload = common_analysis.model_dump()
        if self._measurement_stats_by_channel is not None:
            stats = self._measurement_stats_by_channel.get(channel_id, [])
            if stats:
                DictGenerate.pop_keys_recursive(stats, ["channel_id"])
                payload["measurement_stats"] = stats

        full_path_fname = self.create_json_fname(tags=[str(channel_id), "analysis", str(Generate.time_stamp())])
        self.json_files.append(full_path_fname)
        JsonTransactionDb().write_json(
            data=payload,
            fname=Path(full_path_fname).parts[-1],
        )

    def create_csv(self, **kwargs: dict[str, object]) -> list[CSVManager]:
        """Emit a CSV per channel with ``Frequency``, ``Magnitude(dBmV)``, and ``MovingAverage``.

        Returns
        -------
        List[CSVManager]
            One manager per generated CSV (already populated and path-bound).

        Notes
        -----
        - Rows are aligned by index across frequency, amplitude, and moving-average series.
        - Filenames include the channel id and :data:`FNAME_TAG`.
        - Exceptions are logged; partial outputs may still be returned.
        """
        csv_mgr_list: list[CSVManager] = []

        for common_model in self.get_common_analysis_model():
            model = cast(SpectrumAnalyzerAnalysisRptModel, common_model)
            channel_id: int = model.channel_id
            sig = model.signal

            try:
                csv_mgr: CSVManager = self.csv_manager_factory()
                csv_mgr.set_header(["Frequency", "Magnitude(dBmV)", "MovingAverage"])

                # Rows aligned by index
                for f_hz, mag_dbmv, ma in zip(sig.frequencies, sig.amplitude, sig.window.windows_average, strict=False):
                    csv_mgr.insert_row ([f_hz, mag_dbmv, ma])

                csv_fname = self.create_csv_fname(tags=[str(channel_id), self.FNAME_TAG])
                csv_mgr.set_path_fname(csv_fname)

                self.logger.debug("CSV created: %s (rows=%s)", csv_fname, csv_mgr.get_row_count())
                csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception("Failed to create CSV: %s", exc, exc_info=True)

        return csv_mgr_list

    def create_matplot(self, **kwargs: dict[str, object]) -> list[MatplotManager]:
        """Create two figures per channel: raw spectrum and moving average."""
        out: list[MatplotManager] = []

        for common_model in self.get_common_analysis_model():
            m = cast(SpectrumAnalyzerAnalysisRptModel, common_model)
            sig = m.signal

            try:
                fname = self.create_png_fname(tags=[self.FNAME_TAG, "standard"])
                self.logger.debug("Creating Standard Spectrum Plot: %s", fname)

                cfg = PlotConfig(
                    title           =   "Spectrum Analysis · Standard",
                    x               =   cast(ArrayLike, sig.frequencies),
                    y               =   cast(ArrayLike, sig.amplitude),
                    xlabel          =   None,
                    xlabel_base     =   "Frequency",
                    x_tick_mode     =   "unit",
                    x_unit_from     =   "hz",
                    x_unit_out      =   "mhz",
                    x_tick_decimals =   0,
                    ylabel          =   "dB",
                    grid            =   False,
                    legend          =   False,
                    transparent     =   False,
                    theme           =   self.getAnalysisRptMatplotConfig().theme,)

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=fname)
                out.append(mgr)

            except Exception as exc:
                self.logger.exception("Failed to create plot for (standard): %s", exc, exc_info=True)

            try:
                fname = self.create_png_fname(tags=[self.FNAME_TAG, "moving_average"])
                self.logger.debug("Creating Window Average Spectrum Plot: %s", fname)

                cfg = PlotConfig(
                    title           =   f"Spectrum Analysis · Moving Average n={sig.window.window_size}",
                    x               =   cast(ArrayLike, sig.frequencies),
                    y               =   cast(ArrayLike, sig.window.windows_average),
                    xlabel          =   None,
                    xlabel_base     =   "Frequency",
                    x_tick_mode     =   "unit",
                    x_unit_from     =   "hz",
                    x_unit_out      =   "mhz",
                    x_tick_decimals =   0,
                    ylabel          =   "dB",
                    grid            =   False,
                    legend          =   False,
                    transparent     =   False,
                    theme           =   self.getAnalysisRptMatplotConfig().theme,)

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=fname)
                out.append(mgr)

            except Exception as exc:
                self.logger.exception("Failed to create plot for (moving avg): %s", exc, exc_info=True)

        return out

    def _process(self) -> None:
        """Convert SpectrumAnalyzerAnalysisModel → SpectrumAnalyzerAnalysisRptModel per channel."""
        models: list[SpectrumAnalyzerAnalysisModel] = \
            cast(list[SpectrumAnalyzerAnalysisModel], self.get_analysis_model())

        for _idx, _model in enumerate(models):

            sig_analysis = _model.signal_analysis
            freq_hz: FrequencySeriesHz  = [int(f) for f in sig_analysis.frequencies]
            mag_dbmv: FloatSeries       = list(sig_analysis.magnitudes)
            ma_vals: FloatSeries        = list(sig_analysis.window_average.magnitudes)

            # Anti-log in linear ratio (suitable for amplitude-like values)
            anti_log: FloatSeries = [10.0 ** (v / 20.0) for v in mag_dbmv]

            window = SpecAnaWindowAvgRptModel(
                window_size     =   sig_analysis.window_average.points,
                windows_average =   ma_vals,
                length          =   len(ma_vals),
            )

            signal = SpectrumAnalyzerSignalProcessRptModel(
                frequencies     =   freq_hz,
                amplitude       =   mag_dbmv,
                anti_log        =   anti_log,
                window          =   window,
            )

            rpt = SpectrumAnalyzerAnalysisRptModel(
                channel_id      =   _model.channel_id,
                signal          =   signal,
            )

            self.register_common_analysis_model(_model.channel_id, rpt)

# FILE: src/pypnm/api/routes/basic/scqam_spec_analyzer_rpt.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, cast

from pydantic import BaseModel

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisReport
from pypnm.api.routes.basic.abstract.base_models.common_analysis import CommonAnalysis
from pypnm.api.routes.basic.spec_analyzer_analysis_rpt import (
    SpecAnaWindowAvgRptModel,
    SpectrumAnalyzerAnalysisRptModel,
    SpectrumAnalyzerSignalProcessRptModel,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis
from pypnm.api.routes.common.classes.analysis.model.spectrum_analyzer_schema import (
    BaseAnalysisModel,
    SpectrumAnalyzerAnalysisModel,
)
from pypnm.api.routes.common.classes.analysis.multi_analysis import MultiAnalysis
from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.archive.manager import ArchiveManager
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.matplot.manager import MatplotManager, PlotConfig
from pypnm.lib.types import ArrayLike, ChannelId, FloatSeries, FrequencySeriesHz, Path, PathLike
from pypnm.lib.utils import Generate


class ScQamSpecAnalysisRptModel(BaseModel):
    """Pydantic model for a compiled SC-QAM Spectrum Analyzer report.
    """
    models:list[BaseAnalysisModel]


class ScQamSpecAnalyzerAnalysisReport:
    """Coordinator that compiles per-channel Spectrum Analyzer artifacts into a single deliverable.

    The class iterates over a :class:`MultiAnalysis` container, invokes
    :class:`SingleScQamSpecAnalyzerReport` for each constituent
    :class:`Analysis`, collects all generated files (CSV/plots), and can bundle
    them into a zip archive.

    Parameters
    ----------
    multi_analysis : MultiAnalysis
        A container of individual Spectrum Analyzer analyses to be reported.

    Examples
    --------
    >>> rpt = ScQamSpecAnalyzerReport(multi_analysis)
    >>> rpt.build_report()
    >>> archive_path = rpt._build_archive()
    >>> rpt_dict = rpt.to_dict()
    """

    def __init__(
        self,
        multi_analysis: MultiAnalysis,
        measurement_stats_by_channel: dict[ChannelId, list[dict[str, Any]]] | None = None,
    ) -> None:
        """Initialize the report coordinator.

        Parameters
        ----------
        multi_analysis : MultiAnalysis
            Source of per-channel :class:`Analysis` objects to process.
        """
        self._multi_analysis = multi_analysis
        self._archive_path:PathLike = SystemConfigSettings.archive_dir()
        self._analysis_files:list[PathLike] = []
        self._archive_file:PathLike
        self._measurement_stats_by_channel = measurement_stats_by_channel

    def build_report(self) -> PathLike:
        """
        Generate and collect all per-channel analysis artifacts into a final archive.

        This method iterates over each :class:`Analysis` object within a
        :class:`MultiAnalysis` instance, generating CSVs and plots using
        :class:`SingleScQamSpecAnalyzerReport`. It then aggregates all
        generated files and produces a single ZIP archive.

        Returns:
            PathLike: The path to the created archive file.

        Workflow:
            1. For each `Analysis`, create and execute a
            `SingleScQamSpecAnalyzerReport`.
            2. Collect all generated files using
            :meth:`SingleScQamSpecAnalyzerReport.get_all_generated_files`.
            3. Combine them into a single archive using :meth:`_build_archive`.

        Notes:
            - The internal list of report files is updated via `_analysis_files`.
            - Only the archive file path is returned; individual CSVs and plots
            remain accessible through their respective report instances.
        """
        for a in self._get_analyses():
            rpt = SingleScQamSpecAnalyzerReport(a, measurement_stats_by_channel=self._measurement_stats_by_channel)
            rpt.build_report()
            rpt.get_all_generated_files()
            self._analysis_files.extend(rpt.get_all_generated_files())

        return self._build_archive()

    def _get_analyses(self) -> list[Analysis]:
        """Return the list of analyses sourced from the bound :class:`MultiAnalysis`."""
        return self._multi_analysis.get_analyses()

    def _report_files(self) -> list[PathLike]:
        """Return the list of file paths collected during :meth:`build_report`."""
        return self._analysis_files

    def _build_archive(self) -> PathLike:
        """Create a zip archive containing all collected report files.

        Returns
        -------
        PathLike
            Absolute or relative filesystem path to the generated archive.

        Notes
        -----
        The archive location defaults to :data:`SystemConfigSettings.archive_dir`
        and is cached internally for retrieval via :meth:`get_archive`.
        """
        self._archive_file = ArchiveManager().zip_files(files=self._report_files(),
                                                        archive_path=self._create_archive_fname())
        return self._archive_file

    def _create_archive_fname(self) -> PathLike:
        """Create a unique archive name based on the current timestamp.

        Returns
        -------
        PathLike
            The generated archive name.
        """
        mac = self.get_mac_address().to_mac_format()

        return Path(self._archive_path) / f"scqam_report_{mac}_{Generate.time_stamp()}.zip"

    def get_mac_address(self) -> MacAddress:
        """Return the MAC address associated with the report.

        Notes
        -----
        Assumes all analyses in the bound :class:`MultiAnalysis` share the same MAC.
        """
        analyses = self._get_analyses()
        if not analyses:
            raise ValueError("No analyses available to extract MAC address.")

        first_analysis = analyses[0]

        return MacAddress(cast(BaseAnalysisModel, first_analysis.get_model()[0].mac_address))

    def get_archive(self) -> PathLike:
        """Return the path to the previously created archive.

        Notes
        -----
        Call :meth:`_build_archive` before invoking this method.
        """
        return self._archive_file

    def to_model(self) -> ScQamSpecAnalysisRptModel:
        """Return a structured model of the aggregated report output.

        Notes
        -----
        The model schema is minimal today and will evolve as fields stabilize.
        """
        return ScQamSpecAnalysisRptModel(
            models=self._multi_analysis.to_model())

    def to_dict(self) -> dict[str,Any]:
        """Return the report as a serializable ``dict`` via Pydantic's ``model_dump``."""
        return self._multi_analysis.to_dict()


class SingleScQamSpecAnalyzerReport(AnalysisReport):
    """Emitter for CSV and plots from a single SC-QAM Spectrum Analyzer analysis.

    This concrete :class:`AnalysisReport`:
      * builds a CSV (Frequency, Magnitude dBmV, Moving Average),
      * generates two line plots per channel (raw spectrum, windowed average),
      * materializes a :class:`SpectrumAnalyzerAnalysisRptModel` for downstream use.

    Attributes
    ----------
    FNAME_TAG : str
        Base tag used in output filenames to consistently label Spectrum Analyzer artifacts.
    """
    FNAME_TAG: str = "scqam_spec_ana_rpt"

    def __init__(
        self,
        analysis: Analysis,
        measurement_stats_by_channel: dict[ChannelId, list[dict[str, Any]]] | None = None,
    ) -> None:
        """Create a report instance bound to a single :class:`Analysis`.

        Parameters
        ----------
        analysis : Analysis
            The source analysis whose models/results will be rendered to artifacts.
        """
        super().__init__(analysis)
        self.logger = logging.getLogger("SpectrumAnalyzerReport")
        self._results: dict[int, SpectrumAnalyzerAnalysisRptModel] = {}
        self._measurement_stats_by_channel = measurement_stats_by_channel

    def _build_common_analysis_json(self, channel_id: ChannelId, common_analysis: CommonAnalysis) -> None:
        payload = common_analysis.model_dump()
        if self._measurement_stats_by_channel is not None:
            stats = self._measurement_stats_by_channel.get(channel_id, [])
            if stats:
                DictGenerate.pop_keys_recursive(stats, ["channel_id"])
                payload["measurement_stats"] = stats

        full_path_fname = self.create_json_fname(tags=[str(channel_id), "analysis", str(Generate.time_stamp())])
        self.json_files.append(full_path_fname)
        JsonTransactionDb().write_json(
            data=payload,
            fname=Path(full_path_fname).parts[-1],
        )

    def create_csv(self) -> list[CSVManager]:
        """Emit a CSV per channel with ``Frequency``, ``Magnitude(dBmV)``, and ``MovingAverage``.

        Returns
        -------
        List[CSVManager]
            One manager per generated CSV (already populated and path-bound).

        Notes
        -----
        - Rows are aligned by index across frequency, amplitude, and moving-average series.
        - Filenames include the channel id and :data:`FNAME_TAG`.
        - Exceptions are logged; partial outputs may still be returned.
        """
        csv_mgr_list: list[CSVManager] = []

        for common_model in self.get_common_analysis_model():
            model = cast(SpectrumAnalyzerAnalysisRptModel, common_model)
            channel_id: int = model.channel_id
            sig = model.signal

            try:
                csv_mgr: CSVManager = self.csv_manager_factory()
                csv_mgr.set_header(["Frequency", "Magnitude(dBmV)", "MovingAverage"])

                # Rows aligned by index
                for f_hz, mag_dbmv, ma in zip(sig.frequencies, sig.amplitude, sig.window.windows_average, strict=False):
                    csv_mgr.insert_row ([f_hz, mag_dbmv, ma])

                csv_fname = self.create_csv_fname(tags=[str(channel_id), self.FNAME_TAG])
                csv_mgr.set_path_fname(csv_fname)

                self.logger.debug("CSV created: %s (rows=%s)", csv_fname, csv_mgr.get_row_count())
                csv_mgr_list.append(csv_mgr)

            except Exception as exc:
                self.logger.exception("Failed to create CSV: %s", exc, exc_info=True)

        return csv_mgr_list

    def create_matplot(self) -> list[MatplotManager]:
        """Create two figures per channel: raw spectrum and moving average."""
        out: list[MatplotManager] = []

        for common_model in self.get_common_analysis_model():
            m = cast(SpectrumAnalyzerAnalysisRptModel, common_model)
            sig = m.signal

            try:
                fname = self.create_png_fname(tags=[self.FNAME_TAG, "standard"])
                self.logger.debug("Creating Standard Spectrum Plot: %s", fname)

                cfg = PlotConfig(
                    title           =   "Spectrum Analysis · Standard",
                    x               =   cast(ArrayLike, sig.frequencies),
                    y               =   cast(ArrayLike, sig.amplitude),
                    xlabel          =   None,
                    xlabel_base     =   "Frequency",
                    x_tick_mode     =   "unit",
                    x_unit_from     =   "hz",
                    x_unit_out      =   "mhz",
                    x_tick_decimals =   0,
                    ylabel          =   "dB",
                    grid            =   False,
                    legend          =   False,
                    transparent     =   False,
                    theme           =   self.getAnalysisRptMatplotConfig().theme,)

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=fname)
                out.append(mgr)

            except Exception as exc:
                self.logger.exception("Failed to create plot for (standard): %s", exc, exc_info=True)

            try:
                fname = self.create_png_fname(tags=[self.FNAME_TAG, "moving_average"])
                self.logger.debug("Creating Window Average Spectrum Plot: %s", fname)

                cfg = PlotConfig(
                    title           =   f"Spectrum Analysis · Moving Average n={sig.window.window_size}",
                    x               =   cast(ArrayLike, sig.frequencies),
                    y               =   cast(ArrayLike, sig.window.windows_average),
                    xlabel          =   None,
                    xlabel_base     =   "Frequency",
                    x_tick_mode     =   "unit",
                    x_unit_from     =   "hz",
                    x_unit_out      =   "mhz",
                    x_tick_decimals =   0,
                    ylabel          =   "dB",
                    grid            =   False,
                    legend          =   False,
                    transparent     =   False,
                    theme           =   self.getAnalysisRptMatplotConfig().theme,)

                mgr = MatplotManager(default_cfg=cfg)
                mgr.plot_line(filename=fname)
                out.append(mgr)

            except Exception as exc:
                self.logger.exception("Failed to create plot for (moving avg): %s", exc, exc_info=True)

        return out

    def _process(self) -> None:
        """Convert SpectrumAnalyzerAnalysisModel → SpectrumAnalyzerAnalysisRptModel per channel."""
        models: list[SpectrumAnalyzerAnalysisModel] = \
            cast(list[SpectrumAnalyzerAnalysisModel], self.get_analysis_model())

        for _idx, _model in enumerate(models):

            sig_analysis = _model.signal_analysis
            freq_hz: FrequencySeriesHz  = [int(f) for f in sig_analysis.frequencies]
            mag_dbmv: FloatSeries       = list(sig_analysis.magnitudes)
            ma_vals: FloatSeries        = list(sig_analysis.window_average.magnitudes)

            # Anti-log in linear ratio (suitable for amplitude-like values)
            anti_log: FloatSeries = [10.0 ** (v / 20.0) for v in mag_dbmv]

            window = SpecAnaWindowAvgRptModel(
                window_size     =   sig_analysis.window_average.points,
                windows_average =   ma_vals,
                length          =   len(ma_vals),
            )

            signal = SpectrumAnalyzerSignalProcessRptModel(
                frequencies     =   freq_hz,
                amplitude       =   mag_dbmv,
                anti_log        =   anti_log,
                window          =   window,
            )

            rpt = SpectrumAnalyzerAnalysisRptModel(
                channel_id      =   _model.channel_id,
                signal          =   signal,
            )

            self.register_common_analysis_model(_model.channel_id, rpt)

# FILE: tests/test_spectrum_analyzer_measurement_stats_channel_stats.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.docs.pnm.spectrumAnalyzer.router import SpectrumAnalyzerRouter
from pypnm.docsis.data_type.DocsIf31CmDsOfdmChanEntry import (
    DocsIf31CmDsOfdmChanChannelEntry,
    DocsIf31CmDsOfdmChanEntry,
)
from pypnm.docsis.data_type.DocsIfDownstreamChannel import (
    DocsIfDownstreamChannelEntry,
    DocsIfDownstreamEntry,
)
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
    DocsIf3CmSpectrumAnalysisEntryFields,
)
from pypnm.lib.types import ChannelId


def _measurement_entry(index: int) -> DocsIf3CmSpectrumAnalysisEntry:
    return DocsIf3CmSpectrumAnalysisEntry(
        index=index,
        entry=DocsIf3CmSpectrumAnalysisEntryFields(
            docsIf3CmSpectrumAnalysisCtrlCmdEnable=True,
            docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout=60,
            docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency=100,
            docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency=200,
            docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan=100,
            docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment=10,
            docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth=150,
            docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction=1,
            docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages=1,
            docsIf3CmSpectrumAnalysisCtrlCmdFileEnable=True,
            docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus="inactive",
            docsIf3CmSpectrumAnalysisCtrlCmdFileName="file",
        ),
    )


def test_measurement_stats_include_ofdm_channel_stats() -> None:
    measurement_stats = {ChannelId(3): [_measurement_entry(0)]}
    channel_entry = DocsIf31CmDsOfdmChanChannelEntry(
        index=1,
        channel_id=3,
        entry=DocsIf31CmDsOfdmChanEntry(
            docsIf31CmDsOfdmChanChannelId=ChannelId(3),
        ),
    )

    out = SpectrumAnalyzerRouter._build_measurement_stats_with_channel_stats(
        measurement_stats,
        [channel_entry],
    )

    assert len(out) == 1
    assert out[0]["channel_id"] == ChannelId(3)
    assert out[0]["channel_stats"]["channel_id"] == 3


def test_measurement_stats_include_scqam_channel_stats() -> None:
    measurement_stats = {ChannelId(4): [_measurement_entry(1)]}
    channel_entry = DocsIfDownstreamChannelEntry(
        index=2,
        channel_id=4,
        entry=DocsIfDownstreamEntry(
            docsIfDownChannelId=ChannelId(4),
        ),
    )

    out = SpectrumAnalyzerRouter._build_measurement_stats_with_channel_stats(
        measurement_stats,
        [channel_entry],
    )

    assert len(out) == 1
    assert out[0]["channel_id"] == ChannelId(4)
    assert out[0]["channel_stats"]["channel_id"] == 4


def test_measurement_stats_without_channel_stats() -> None:
    measurement_stats = {ChannelId(5): [_measurement_entry(2)]}

    out = SpectrumAnalyzerRouter._build_measurement_stats_with_channel_stats(
        measurement_stats,
        [],
    )

    assert len(out) == 1
    assert out[0]["channel_id"] == ChannelId(5)
    assert "channel_stats" not in out[0]

# FILE: tests/test_spectrum_analyzer_report_measurement_stats_json.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from typing import cast

from pypnm.api.routes.basic.ofdm_spec_analyzer_rpt import SingleOfdmSpecAnalyzerReport
from pypnm.api.routes.basic.spec_analyzer_analysis_rpt import (
    SpecAnaWindowAvgRptModel,
    SpectrumAnalyzerAnalysisRptModel,
    SpectrumAnalyzerSignalProcessRptModel,
)
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.types import ChannelId, FrequencySeriesHz, FloatSeries


class _FakeAnalysis:
    def __init__(self) -> None:
        self._results = {
            "analysis": [
                {
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                    "device_details": {
                        "system_description": {
                            "HW_REV": "1.0",
                            "VENDOR": "LANCity",
                            "BOOTR": "NONE",
                            "SW_REV": "1.0.0",
                            "MODEL": "LCPET-3",
                        }
                    },
                }
            ]
        }

    def get_results(self, full_dict: bool = True) -> dict[str, object]:
        return self._results

    def get_model(self) -> list[object]:
        return []


def _build_report_model(channel_id: ChannelId) -> SpectrumAnalyzerAnalysisRptModel:
    frequencies: FrequencySeriesHz = [100]
    magnitudes: FloatSeries = [1.0]
    windows: FloatSeries = [1.0]

    window = SpecAnaWindowAvgRptModel(
        window_size=1,
        windows_average=windows,
        length=1,
    )

    signal = SpectrumAnalyzerSignalProcessRptModel(
        frequencies=frequencies,
        amplitude=magnitudes,
        anti_log=[1.0],
        window=window,
    )

    return SpectrumAnalyzerAnalysisRptModel(
        channel_id=channel_id,
        signal=signal,
    )


def test_ofdm_report_json_includes_measurement_stats(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_write_json(self, data: dict[str, object], fname: str, extension: str = "json") -> None:
        captured["data"] = data
        captured["fname"] = fname
        captured["extension"] = extension

    monkeypatch.setattr(JsonTransactionDb, "write_json", _fake_write_json)

    channel_id = ChannelId(3)
    measurement_stats_by_channel = {
        channel_id: [
            {
                "channel_id": channel_id,
                "entry": {"docsIf3CmSpectrumAnalysisCtrlCmdEnable": True},
            }
        ]
    }

    report = SingleOfdmSpecAnalyzerReport(
        _FakeAnalysis(),
        measurement_stats_by_channel=measurement_stats_by_channel,
    )
    report.register_common_analysis_model(channel_id, _build_report_model(channel_id))

    payload = cast(dict[str, object], captured.get("data", {}))
    assert payload.get("channel_id") == channel_id
    measurement_stats = cast(list[dict[str, object]], payload["measurement_stats"])
    assert "channel_id" not in measurement_stats[0]

# FILE: docs/api/fast-api/single/spectrum-analyzer/spectrum-analyzer.md
# Spectrum Analyzer Capture

The spectrum analyzer API provides:

* A standard single-capture endpoint (`/getCapture`).
* A friendly input mode that lets clients specify RBW (`/getCapture/friendly`).
* An OFDM-focused endpoint (`/getCapture/ofdm`) that walks all downstream OFDM channels.
* An SC-QAM-focused endpoint (`/getCapture/scqam`) that walks all downstream SC-QAM channels.

Reference implementation:
[`SpectrumAnalyzerRouter`](http://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/router.py)

## Endpoints

| Operation                     | Method | Path                                             |
| ----------------------------- | ------ | ------------------------------------------------ |
| Single spectrum capture        | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture`       |
| Single spectrum capture (RBW)  | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture/friendly` |
| All OFDM downstream channels   | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture/ofdm`  |
| All SC-QAM downstream channels | POST   | `/docs/pnm/ds/spectrumAnalyzer/getCapture/scqam` |

## Single Capture - `/spectrumAnalyzer/getCapture`

This endpoint performs a single downstream spectrum capture using the CM's
spectrum analyzer controls. A full PNM capture and analysis are executed, and
results are returned in JSON or archive format depending on `analysis.output.type`.

Supported retrieval modes:

* `1` = FILE
* `2` = SNMP

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
    "num_bins_per_segment": 100,
    "noise_bw": 150,
    "window_function": 1,
    "num_averages": 1,
    "spectrum_retrieval_type": 1
  }
}
```

### Single Capture Parameters

| JSON path                                        | Type | Description                                                |
| ------------------------------------------------ | ---- | ---------------------------------------------------------- |
| `capture_parameters.inactivity_timeout`          | int  | Inactivity timeout before disabling analyzer (seconds).    |
| `capture_parameters.first_segment_center_freq`   | int  | First segment center frequency in Hz.                      |
| `capture_parameters.last_segment_center_freq`    | int  | Last segment center frequency in Hz.                       |
| `capture_parameters.segment_freq_span`           | int  | Frequency span (Hz) per segment.                           |
| `capture_parameters.num_bins_per_segment`        | int  | Number of FFT bins per segment.                            |
| `capture_parameters.noise_bw`                    | int  | Equivalent noise bandwidth (Hz).                           |
| `capture_parameters.window_function`             | int  | Window function index.                                     |
| `capture_parameters.num_averages`                | int  | Number of averages to perform per measurement.             |
| `capture_parameters.spectrum_retrieval_type`     | int  | Retrieval method (1 = FILE, 2 = SNMP).                     |

### Single Capture JSON Response (Abbreviated)

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
          "noise_bw": 150,
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
    "primative": [
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
        "first_segment_center_frequency": 300000000,
        "last_segment_center_frequency": 900000000,
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
    "measurement_stats": [
      {
        "index": 0,
        "entry": {
          "docsIf3CmSpectrumAnalysisCtrlCmdEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout": 30,
          "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency": 300000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency": 900000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan": 1000000,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment": 100,
          "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth": 110,
          "docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction": 1,
          "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages": 2,
          "docsIf3CmSpectrumAnalysisCtrlCmdFileEnable": true,
          "docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus": "sample_ready",
          "docsIf3CmSpectrumAnalysisCtrlCmdFileName": "spectrum_analyzer_aabbccddeeff_0_1762840189.bin"
        }
      }
    ]
  }
}
```

### Single Capture Return Structure

**Payload: `data.analysis[]`**

| Field                          | Type   | Description                                     |
| ------------------------------ | ------ | ----------------------------------------------- |
| `[index]`.device_details.*     | object | System description at capture time.             |
| `[index]`.capture_parameters.* | object | Spectrum analyzer control parameters.           |
| `[index]`.signal_analysis.*    | object | Frequency and magnitude results with smoothing. |

**Payload: `data.primative[]`**

| Field                      | Type   | Description                                       |
| -------------------------- | ------ | ------------------------------------------------- |
| `[index]`.pnm_header.*     | object | Standard PNM capture header.                      |
| `[index]`.channel_id       | int    | Channel ID; typically 0 for single capture.       |
| `[index]`.mac_address      | string | Cable modem MAC address.                          |
| `[index]`.*                | object | Spectrum analyzer capture metadata and data.      |

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

## Single Capture (Friendly) - `/spectrumAnalyzer/getCapture/friendly`

This endpoint accepts a resolution bandwidth (RBW) and a frequency window
(first/last center frequency), and automatically derives segment span
and bin count using the `spectrum-analysis-capture-set.py` logic.

The returned capture parameters follow the same schema as `/getCapture`.

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

| JSON path                                  | Type | Description                                                                  |
| ------------------------------------------ | ---- | ---------------------------------------------------------------------------- |
| `capture_parameters.inactivity_timeout`    | int  | Inactivity timeout before disabling analyzer (seconds).                      |
| `capture_parameters.first_segment_center_freq` | int | First segment center frequency in Hz.                                    |
| `capture_parameters.last_segment_center_freq`  | int | Last segment center frequency in Hz.                                     |
| `capture_parameters.resolution_bw`         | int  | Requested resolution bandwidth in Hz (RBW).                                 |
| `capture_parameters.noise_bw`              | int  | Equivalent noise bandwidth in Hz.                                           |
| `capture_parameters.window_function`       | int  | Window function index.                                                      |
| `capture_parameters.num_averages`          | int  | Number of averages to perform per measurement.                              |
| `capture_parameters.spectrum_retrieval_type`| int | Retrieval method (1 = FILE, 2 = SNMP).                                      |

### Friendly Capture Return Notes

* `resolution_bw` is used to compute `segment_freq_span` and `num_bins_per_segment`.
* Returned capture parameters match the regular `/getCapture` schema.

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
| "0", "1", … | array | Raw per-channel capture payloads for each OFDM channel position.       |

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
| "0", "1", … | array | Raw per-channel capture payloads for each SC-QAM channel position.     |

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
