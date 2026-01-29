# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import cast

from pypnm.api.routes.common.classes.analysis.analysis import (
    WindowFunction,  # type: ignore[import-untyped]
)
from pypnm.api.routes.common.extended.common_measure_service import (
    CommonMeasureService,  # type: ignore[import-untyped]
)
from pypnm.api.routes.common.extended.common_process_service import (
    MessageResponse,  # type: ignore[import-untyped]
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.abstract.com_spec_chan_ana import (  # type: ignore[import-untyped]
    CommonChannelSpectumBwLut,
    CommonSpectrumBw,
    CommonSpectrumChannelAnalyzer,
    OfdmSpectrumBwLut,
    ScQamSpectrumBwLut,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.schemas import (
    SpecAnCapturePara,  # type: ignore[import-untyped]
    SpecAnCaptureParaFriendly,  # type: ignore[import-untyped]
)
from pypnm.config.pnm_config_manager import (
    PnmConfigManager,  # type: ignore[import-untyped]
)
from pypnm.docsis.cable_modem import CableModem  # type: ignore[import-untyped]
from pypnm.docsis.cm_snmp_operation import (  # type: ignore[import-untyped]
    DocsIf31CmDsOfdmChanChannelEntry,
    DocsIfDownstreamChannelEntry,
    SpectrumRetrievalType,
)
from pypnm.lib.conversions.rbw import RBWConversion
from pypnm.lib.inet import Inet  # type: ignore[import-untyped]
from pypnm.lib.types import (  # type: ignore[import-untyped]
    ChannelId,
    FrequencyHz,
    ResolutionBw,
    SubcarrierIdx,
)
from pypnm.pnm.data_type.pnm_test_types import (
    DocsPnmCmCtlTest,  # type: ignore[import-untyped]
)


class CmSpectrumAnalysisService(CommonMeasureService):
    """
    Service For Cable Modem Spectrum Analysis (Single Run)

    Purpose
    -------
    Orchestrates a single spectrum analyzer measurement on a target cable modem,
    applying the provided capture parameters and the PNM TFTP/SNMP configuration.
    Selects the correct `DocsPnmCmCtlTest` based on the retrieval type (FILE vs SNMP).

    Parameters
    ----------
    cable_modem : CableModem
        Target cable modem on which to run the measurement.
    tftp_servers : tuple[Inet, Inet], optional
        Primary/secondary TFTP server addresses used for result file storage.
        Defaults to values from :func:`PnmConfigManager.get_tftp_servers`.
    tftp_path : str, optional
        Remote TFTP directory where result files are written.
        Defaults to :func:`PnmConfigManager.get_tftp_path`.
    capture_parameters : SpecAnCapturePara
        Fully specified capture configuration (timeouts, segment layout,
        binning, ENBW, windowing, averaging, retrieval type).

    Notes
    -----
    - If ``capture_parameters.spectrum_retrieval_type == SpectrumRetrievalType.SNMP``,
      the service switches to ``DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA``.
    - After construction, call :meth:`set_and_go` (via ``CommonMeasureService``) to execute.
    """

    def __init__(self,
        cable_modem: CableModem,
        tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
        tftp_path: str = PnmConfigManager.get_tftp_path(),*,
        capture_parameters: SpecAnCapturePara,) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

        pnmCmCtlTest = DocsPnmCmCtlTest.SPECTRUM_ANALYZER

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

        if capture_parameters.spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.debug('Selecting: SPECTRUM_ANALYZER_SNMP_AMP_DATA')
            pnmCmCtlTest = DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA

        super().__init__(
            pnmCmCtlTest,
            cable_modem,
            tftp_servers,
            tftp_path,
            cable_modem.getWriteCommunity(),)

        self.setSpectrumCaptureParameters(capture_parameters)

class SpectrumAnalyzerFriendlyCaptureBuilder:
    """
    Build Spectrum Analyzer capture parameters from the friendly request shape.

    Uses the spectrum-analysis-capture-set algorithm to derive segment span,
    bins per segment, and adjusted first/last segment center frequencies
    based on the requested window and resolution bandwidth.
    """

    MIN_SEGMENT_SPAN_HZ: int = 1_000_000
    MAX_BINS: int = 2048
    MAX_TRIES: int = 64

    @staticmethod
    def _floor_to_multiple(value: int, base: int) -> int:
        if base <= 0:
            return value
        return (value // base) * base

    @staticmethod
    def _pick_seg_span_and_bins(freq_span: int, rbw_hz: int) -> tuple[int, int]:
        if rbw_hz <= 0:
            raise ValueError("resolution_bw must be > 0")
        if freq_span < (2 * SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ):
            raise ValueError("Frequency span too small to support scaled window rules with minimum segment span")

        best_seg_span = 0
        best_bins = 0
        best_err = float("inf")

        max_seg_span = freq_span // 2
        if max_seg_span < SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ:
            max_seg_span = SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ

        seg_span = SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ
        while seg_span <= max_seg_span:
            k = freq_span // seg_span
            if k < 2:
                seg_span += SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ
                continue

            bins = int(round(float(seg_span) / float(rbw_hz)))
            if bins < 1:
                bins = 1
            if bins > SpectrumAnalyzerFriendlyCaptureBuilder.MAX_BINS:
                seg_span += SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ
                continue

            rbw_actual = float(seg_span) / float(bins)
            err = abs(rbw_actual - float(rbw_hz)) / float(rbw_hz)

            if (err < best_err) or ((err == best_err) and (seg_span < best_seg_span)):
                best_err = err
                best_seg_span = seg_span
                best_bins = bins

            seg_span += SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ

        if best_seg_span <= 0 or best_bins <= 0:
            raise ValueError("No valid segment span/bins combination found for the requested resolution bandwidth")

        return best_seg_span, best_bins

    @staticmethod
    def build(capture_parameters: SpecAnCaptureParaFriendly) -> SpecAnCapturePara:
        """
        Convert friendly capture settings into a concrete spectrum analyzer command.

        The returned parameters are aligned such that the raw window is divisible
        by the derived segment span and the configured segment centers are
        offset inward by half a segment span on each side.
        """
        req_first = int(capture_parameters.first_segment_center_freq)
        req_last = int(capture_parameters.last_segment_center_freq)
        rbw_hz = int(capture_parameters.resolution_bw)

        if req_first <= 0 or req_last <= 0:
            raise ValueError("Requested frequencies must be > 0")
        if req_last <= req_first:
            raise ValueError("Invalid range: last_segment_center_freq must be greater than first_segment_center_freq")

        first = req_first
        last = req_last
        tries = 0
        first_scaled = 0
        last_scaled = 0
        seg_span = SpectrumAnalyzerFriendlyCaptureBuilder.MIN_SEGMENT_SPAN_HZ
        bins = 0

        while tries < SpectrumAnalyzerFriendlyCaptureBuilder.MAX_TRIES:
            tries += 1

            freq_span = int(last - first)
            seg_span, bins = SpectrumAnalyzerFriendlyCaptureBuilder._pick_seg_span_and_bins(
                freq_span=freq_span,
                rbw_hz=rbw_hz,
            )

            if (freq_span % seg_span) != 0:
                usable = SpectrumAnalyzerFriendlyCaptureBuilder._floor_to_multiple(freq_span, seg_span)
                if usable <= 0:
                    usable = seg_span

                candidate_last = first + usable
                if candidate_last > last:
                    candidate_last = last
                if candidate_last > req_last:
                    candidate_last = req_last

                if candidate_last <= first:
                    candidate_first = last - usable
                    if candidate_first < req_first:
                        candidate_first = req_first
                    first = candidate_first
                    continue

                last = candidate_last
                continue

            half = seg_span // 2
            first_scaled = first + half
            last_scaled = last - half

            if last_scaled <= first_scaled:
                last = max(first + seg_span, first + 1)
                continue

            break

        if tries >= SpectrumAnalyzerFriendlyCaptureBuilder.MAX_TRIES:
            raise ValueError("Unable to find settings within bounds that satisfy rules")

        return SpecAnCapturePara(
            inactivity_timeout          = capture_parameters.inactivity_timeout,
            first_segment_center_freq   = FrequencyHz(first_scaled),
            last_segment_center_freq    = FrequencyHz(last_scaled),
            segment_freq_span           = FrequencyHz(seg_span),
            num_bins_per_segment        = bins,
            noise_bw                    = capture_parameters.noise_bw,
            window_function             = capture_parameters.window_function,
            num_averages                = capture_parameters.num_averages,
            spectrum_retrieval_type     = capture_parameters.spectrum_retrieval_type,
        )

class OfdmChanSpecAnalyzerService(CommonMeasureService):
    """
    Helper Service For OFDM Spectrum Analyzer Runs

    Purpose
    -------
    Thin wrapper over :class:`CommonMeasureService` that preconfigures the PNM
    Spectrum Analyzer test for a downstream OFDM capture on a single modem.

    Parameters
    ----------
    cable_modem : CableModem
        Target cable modem instance.
    tftp_servers : tuple[Inet, Inet], optional
        Primary/secondary TFTP servers used for capture file transfer.
        Defaults to :func:`PnmConfigManager.get_tftp_servers`.
    tftp_path : str, optional
        Remote TFTP directory where capture files are written.
        Defaults to :func:`PnmConfigManager.get_tftp_path`.

    Usage
    -----
    1) Construct the service.
    2) Call :meth:`setSpectrumCaptureParameters` with a :class:`SpecAnCapturePara`.
    3) Execute :meth:`set_and_go` to run the test.
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
    Downstream OFDM Channel Spectrum Analyzer Orchestrator

    Responsibilities
    ----------------
    1) Query the cable modem for DS OFDM channel configuration.
    2) Compute per-channel spectrum bandwidth tuples: (start_hz, plc_hz, end_hz).
    3) Build :class:`SpecAnCapturePara` for each channel and invoke
       :class:`OfdmChanSpecAnalyzerService` to capture.

    Parameters
    ----------
    cable_modem : CableModem
        Cable modem whose downstream OFDM channels will be analyzed.
    number_of_averages : int, default 2
        Number of averages to request per segment in the capture.
    resolution_bandwidth : ResolutionBw, optional
        Resolution bandwidth in Hz; defaults to 300 kHz if not provided.
    spectrum_retrieval_type : SpectrumRetrievalType, default SpectrumRetrievalType.FILE
        Data retrieval mechanism (file-based or SNMP amplitude data).
    """

    def __init__(self, cable_modem: CableModem,
                 tftp_servers: tuple[Inet, Inet] = PnmConfigManager.get_tftp_servers(),
                 number_of_averages: int = 2,
                 resolution_bandwidth_hz: ResolutionBw | None = None,
                 channel_ids: list[ChannelId] | None = None,
                 spectrum_retrieval_type:SpectrumRetrievalType = SpectrumRetrievalType.FILE,) -> None:
        super().__init__(cable_modem)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._number_of_averages = number_of_averages
        self._resolution_bandwidth = (
            resolution_bandwidth_hz
            if resolution_bandwidth_hz is not None
            else RBWConversion.DEFAULT_RBW_HZ
        )
        self._spectrum_retrieval_type = spectrum_retrieval_type
        self._pnm_test_type = DocsPnmCmCtlTest.SPECTRUM_ANALYZER
        self.log_prefix = f"DsOfdmChannelSpectrumAnalyzer - CM {self._cm.get_mac_address}"
        self._tftp_servers = tftp_servers

        self._channel_ids = channel_ids if channel_ids else None

    async def start(self, capture_per_channel: bool = False) -> list[tuple[ChannelId, MessageResponse]]:
        """
        Run Spectrum Captures Across All OFDM Channels

        Behavior
        --------
        - Retrieves per-channel (start/plc/end) frequency tuples via
          :meth:`calculate_channel_spectrum_bandwidth`.
        - Builds a :class:`SpecAnCapturePara` for each channel using:
            * first_segment_center_freq = start_hz
            * last_segment_center_freq  = end_hz
            * segment_freq_span         = 1_000_000 Hz (default here)
            * num_bins_per_segment      = 256 (default here)
            * window_function           = HANN
            * num_averages              = instance default
            * spectrum_retrieval_type   = instance default
        - Executes :meth:`set_and_go` for each channel via
          :class:`OfdmChanSpecAnalyzerService`.

        Parameters
        ----------
        capture_per_channel : bool, optional
            Reserved flag for future modes; current implementation always
            iterates all channels. Default False.

        Returns
        -------
        list[tuple[ChannelId, MessageResponse]]
            Per-channel results from the spectrum analyzer run.

        Notes
        -----
        - The notion of "center" from this analyzer is not used to configure the
          capture here; the capture aligns to the *first* and *last* frequencies
          (start/end) as provided by the OFDM channel range.
        """
        channel_specCapture:list[tuple[ChannelId, SpecAnCapturePara]] = []
        out:list[tuple[ChannelId, MessageResponse]] = []

        # Compute the bandwidth mapping for all OFDM channels
        bw_by_channel: OfdmSpectrumBwLut = await self.calculate_channel_spectrum_bandwidth()

        number_of_averages      = self._number_of_averages
        spectrum_retrieval_type = self._spectrum_retrieval_type
        inactivity_timeout      = 30
        noise_bw                = 150
        channel_filter = set(self._channel_ids) if self._channel_ids else None

        for chan_id, (start_hz, plc_hz, end_hz) in bw_by_channel.items():
            if channel_filter and chan_id not in channel_filter:
                continue
            self.logger.debug(
                f"OFDM - Mac: {self._cm.get_mac_address} - "
                f"Channel Settings: {chan_id}, {start_hz}, {plc_hz}, {end_hz}"
            )

            friendly_capture_parameter = SpecAnCaptureParaFriendly(
                inactivity_timeout          = inactivity_timeout,
                first_segment_center_freq   = FrequencyHz(start_hz),
                last_segment_center_freq    = FrequencyHz(end_hz),
                resolution_bandwidth_hz     = ResolutionBw(self._resolution_bandwidth),
                noise_bw                    = noise_bw,
                window_function             = WindowFunction.HANN,
                num_averages                = number_of_averages,
                spectrum_retrieval_type     = spectrum_retrieval_type,
            )
            capture_parameter = SpectrumAnalyzerFriendlyCaptureBuilder.build(
                friendly_capture_parameter,
            )

            self.logger.debug(
                f"OFDM - Mac: {self._cm.get_mac_address} - "
                f"Capture Parameters: {capture_parameter.model_dump()}"
            )

            channel_specCapture.append((chan_id, capture_parameter))

        for chan_id, capture_parameter in channel_specCapture:
            service = OfdmChanSpecAnalyzerService(self._cm, tftp_servers=self._tftp_servers)
            service.setSpectrumCaptureParameters(capture_parameter)
            out.append((chan_id, await service.set_and_go()))
            await self.updatePnmMeasurementStatistics(chan_id)

        return out

    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        """
        Calculate Per-Channel OFDM Spectrum Tuples

        Returns
        -------
        CommonChannelSpectumBwLut
            Mapping of ``ChannelId → (start_hz, plc_hz, end_hz)`` where:
            - ``start_hz = zero_freq + first_active * subcarrier_spacing``
            - ``end_hz   = zero_freq + (last_active + 1) * subcarrier_spacing``
            - ``plc_hz`` is the PLC frequency reported by the modem.

        Notes
        -----
        - Uses DOCSIS 3.1 fields from ``DocsIf31CmDsOfdmChanEntry``:
          SubcarrierZeroFreq, FirstActiveSubcarrierNum, LastActiveSubcarrierNum,
          SubcarrierSpacing, PlcFreq.
        - Start/End reflect the occupied OFDM spectrum range for each channel.
        """
        out: CommonChannelSpectumBwLut = {}

        channels: list[DocsIf31CmDsOfdmChanChannelEntry] = await self._cm.getDocsIf31CmDsOfdmChanEntry()
        if not channels:
            self.logger.warning("No downstream OFDM channels returned from cable modem.")
            return out

        for channel in channels:
            entry = channel.entry

            zero_freq: FrequencyHz      = cast(FrequencyHz, entry.docsIf31CmDsOfdmChanSubcarrierZeroFreq)
            first_active: SubcarrierIdx = cast(SubcarrierIdx, entry.docsIf31CmDsOfdmChanFirstActiveSubcarrierNum)
            last_active: SubcarrierIdx  = cast(SubcarrierIdx, entry.docsIf31CmDsOfdmChanLastActiveSubcarrierNum)
            sub_spacing: FrequencyHz    = cast(FrequencyHz, entry.docsIf31CmDsOfdmChanSubcarrierSpacing)
            plc_freq: FrequencyHz       = cast(FrequencyHz, entry.docsIf31CmDsOfdmChanPlcFreq)
            chan_id: ChannelId          = cast(ChannelId, entry.docsIf31CmDsOfdmChanChannelId)

            if (chan_id is None or zero_freq is None or
                first_active is None or last_active is None or
                sub_spacing is None or plc_freq is None ):

                self.logger.debug(
                    "Skipping channel with missing data: "
                    f"id={chan_id}, zero_freq={zero_freq}, first_active={first_active}, "
                    f"last_active={last_active}, spacing={sub_spacing}, plc_freq={plc_freq}")

                continue

            # For now, starting at zero_freq as per current implementation
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

        # Initialize using the first entry
        iterator = iter(channels.items())
        first_key, (start_hz, _, end_hz) = next(iterator)
        start_hz_global: FrequencyHz = FrequencyHz(start_hz)
        end_hz_global: FrequencyHz = FrequencyHz(end_hz)

        # Fold the rest
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
