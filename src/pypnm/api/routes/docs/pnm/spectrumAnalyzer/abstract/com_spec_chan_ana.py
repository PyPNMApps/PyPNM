
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
