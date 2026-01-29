## Agent Review Bundle Summary
- Goal: Cap spectrum analyzer averages at 1, warn on caps, and honor channel_id filters for OFDM/SC-QAM.
- Changes: Capped spectrum analyzer averages with warning log; added channel_id filtering in OFDM/SC-QAM analyzers and router; added tests for averages cap and channel filter.
- Files: src/pypnm/api/routes/common/extended/common_measure_service.py, src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/router.py, src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/service.py, tools/agent-review/2026-01-29-spectrum-analyzer-friendly-capture.review.md, tests/test_spectrum_analyzer_averages_cap.py, tests/test_spectrum_analyzer_channel_filter.py
- Tests: ruff check src; pytest -q
- Notes: pytest skips hardware integration tests.

# FILE: src/pypnm/api/routes/common/extended/common_measure_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
import math
import os
import shutil
import time
from enum import Enum, auto
from pathlib import Path
from typing import TypeAlias, cast

from pypnm.api.routes.common.classes.analysis.analysis import SpecAnCapturePara
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
    UpstreamOfdmaParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    CommonMessagingService,
    MessageResponse,
)
from pypnm.api.routes.common.extended.types import CommonMessagingServiceExtension as CMSE
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_config_manager import PnmConfigManager
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import (
    DocsPnmBulkFileUploadStatus,
    DocsPnmCmCtlStatus,
    FecSummaryType,
)
from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsConstDispMeasEntry import (
    DocsPnmCmDsConstDispMeasEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsHistEntry import DocsPnmCmDsHistEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmFecEntry import DocsPnmCmDsOfdmFecEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmModProfEntry import (
    DocsPnmCmDsOfdmModProfEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmRxMerEntry import (
    DocsPnmCmDsOfdmRxMerEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmOfdmChanEstCoefEntry import (
    DocsPnmCmOfdmChanEstCoefEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmUsPreEqEntry import DocsPnmCmUsPreEqEntry
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.ftp.ftp_connector import FTPConnector
from pypnm.lib.host_endpoint import HostEndpoint
from pypnm.lib.inet import Inet
from pypnm.lib.ping import Ping
from pypnm.lib.ssh.ssh_connector import SSHConnector
from pypnm.lib.tftp.tftp_connector import TFTPConnector
from pypnm.lib.types import ChannelId, FileNameStr, InterfaceIndex, TransactionId, HostNameStr
from pypnm.lib.utils import Generate
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import (
    DocsIf3CmSpectrumAnalysisCtrlCmd,
    SpectrumRetrievalType,
    WindowFunction,
)
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.snmp.modules import DocsisIfType
from pypnm.snmp.snmp_v2c import Snmp_v2c
from pypnm.api.routes.common.extended.types import CommonMessagingServiceExtension as CMSE


class MeasureServiceReturnTypes(Enum):
    BASE_MODEL = auto()
    DICT = auto()

MeasurementEntry: TypeAlias =   DocsPnmCmOfdmChanEstCoefEntry   | \
                                DocsPnmCmDsConstDispMeasEntry   | \
                                DocsPnmCmDsOfdmRxMerEntry       | \
                                DocsPnmCmUsPreEqEntry           | \
                                DocsPnmCmDsHistEntry            | \
                                DocsPnmCmDsOfdmFecEntry         | \
                                DocsPnmCmDsOfdmModProfEntry     | \
                                DocsIf3CmSpectrumAnalysisEntry

class CommonMeasureService(CommonMessagingService):
    SPECTRUM_ANALYZER_AVERAGES_CAP: int = 1
    """
    Base service class for executing common Proactive Network Maintenance (PNM) measurement tests.

    Parameters:
        pnm_test_type (DocsPnmCmCtlTest): The type of PNM test to execute.
        cable_modem (CableModem): The cable modem instance used for the test.
        tftp_servers (Inet,Inet): (IPv4,IPv6)
        tftp_path (str, optional): The path on the TFTP server where test result files are stored. Default is an empty string.
        snmp_write_community (str, optional): The SNMP community string for write access. Default is "private".
        **extra_options (dict, optional): Additional keyword arguments specific to the test type, such as:
            - fec_summary_type (FecSummaryType): Required for tests involving FEC summary metrics.
            - Other parameters based on the test type.

    Notes:
        This class serves as a base for test-specific measurement operations. Subclasses should implement
        specific tests such as:
        - Downstream OFDM codeword error rate
        - RXMER per subcarrier
        - FEC statistics, etc.

        It is expected that subclasses will extend this service and provide the necessary implementations for
        executing and processing PNM measurements based on the test type and parameters.
    """
    def __init__(self, pnm_test_type:DocsPnmCmCtlTest,
                 cable_modem: CableModem,
                 tftp_servers: tuple[Inet,Inet],
                 tftp_path: str = "",
                 snmp_write_community: str = "private",
                 **extra_options) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.propagate = True

        self.pnm_filename:list[str]

        self._transactionId_pnmFile: dict[str, str] = {}
        self.pnm_test_type:DocsPnmCmCtlTest         = pnm_test_type
        self.cm:CableModem                          = cable_modem
        self.tftp_servers:tuple[Inet,Inet]          = tftp_servers
        self.tftp_path:str                          = tftp_path
        self.snmp_write_community:str               = snmp_write_community
        self.extra_options                          = extra_options
        self.config_mgr:ConfigManager               = ConfigManager()
        self.log_prefix:str                         = f"MAC: {self.cm.get_mac_address} - INET: {self.cm.get_inet_address}"
        self.pnm_dir                                = PnmConfigManager.get_save_dir()
        self.pnm_local_dir                          = SystemConfigSettings.pnm_dir
        self._capture_parameter:SpecAnCapturePara   = SpecAnCapturePara()

        # Initialize default spectrum capture parameters
        self._capture_parameter.spectrum_retrieval_type = SpectrumRetrievalType.UNKNOWN

        if self.extra_options:
            self.logger.debug(f"{self.log_prefix} - OPTIONS: {self.extra_options}")
            self._preload_interface_parameters()

        self._precheck()

    def _precheck(self) -> None:
        """
        Perform pre-check and ensure the save directory exists.
        """
        self.logger.debug(f'PreCheck: SaveDir: {self.pnm_dir}')
        save_path = Path(self.pnm_dir)
        save_path.mkdir(parents=True, exist_ok=True)

    def _preload_interface_parameters(self) -> None:
        """
        Load optional interface parameters from extra_options dictionary.
        If not present, sets interface_parameters to None.
        """
        self.interface_parameters = self.extra_options.get("interface_parameters", None)

    def setSpectrumCaptureParameters(self, capture_parameter:SpecAnCapturePara) -> None:
        """
        Set the spectrum capture parameters for the measurement.

        TODO: This method may be deprecated in favor of passing parameters directly during initialization.

        Args:
            capture_parameter (SpecAnCapturePara): The spectrum capture parameters.
        """
        self._capture_parameter = capture_parameter

    def getSpectrumCaptureParameters(self) -> SpecAnCapturePara:
        """
        Get the current spectrum capture parameters.

        Returns:
            SpecAnCapturePara: The current spectrum capture parameters.
        """
        return self._capture_parameter

    async def set_and_go(self, interface_parameters: DownstreamOfdmParameters | UpstreamOfdmaParameters | None = None ,
                         max_wait_count: int = 5,) -> MessageResponse:
        """
        Trigger PNM file capture and retrieval based on direction-specific parameters.

        Args:
            interface_parameters (InterfaceParameters, optional):
                The configuration specifying the direction of capture:
                - `DownstreamOfdmParameters`: For OFDM downstream channels.
                - `UpstreamOfdmaParameters`: For OFDMA upstream channels.
                If `None` (default), all channels will be captured.

            max_wait_count (int, optional):
                Maximum seconds to wait for measurement readiness. Default is 5.

        Returns:
            MessageResponse: Result indicating success or failure of the operation.
        """

        ##########################################################
        # Verify that we can connect to the CM via Ping and SNMP
        ##########################################################

        if not self.is_ping_reachable():
            self.logger.error(f"{self.log_prefix} - Unreachable via PING")
            return self.build_send_msg(ServiceStatusCode.UNREACHABLE_PING)

        if not await self.is_snmp_ready():
            self.logger.error(f"{self.log_prefix} - Unreachable via SNMP")
            return self.build_send_msg(ServiceStatusCode.UNREACHABLE_SNMP)

        #########################################################################
        #                   Spectrum Analysis SNMP Return                       #
        #########################################################################

        if self.getSpectrumCaptureParameters().spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.debug(f"{self.log_prefix} - Performing Spectrum Analysis SNMP Amplitude Data")

            #Set Spectrum Analyzer
            __status = await self._generic_spectrum_analyzer_operation()

            if __status[0] != ServiceStatusCode.SUCCESS:
               self.logger.error(f"{self.log_prefix} - Unable to set Spectrum Analyzer Settings")
               return self.build_send_msg(ServiceStatusCode.SPEC_ANALYZER_SET_CONFIG_ERROR)

            # This is a blocking method, it will return SUCCESS or wait till timeout to return an ERROR
            status = await self._check_spectrum_amplitude_data_status()

            if status == ServiceStatusCode.SUCCESS:
                self.logger.info(f"{self.log_prefix} - Spectrum Amplitude Data is READY, collecting amplitude data, may take a while...")
                amp_data: bytes = await self.cm.getSpectrumAmplitudeData()
                self.logger.info(f"{self.log_prefix} - Spectrum Amplitude Data collection COMPLETE, total bytes: {len(amp_data)}.")
                #################################################################################################
                # Build binary filename and save file - START
                #################################################################################################
                filename = await self._pnm_file_generator(DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA)
                tx_id = self._get_transaction_id_by_filename(filename)
                if not tx_id:
                    self.logger.error(f"{self.log_prefix} - Unable to find Transaction ID for PNM filename: {filename}")
                    return self.build_send_msg(ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND)

                pnm_dir = SystemConfigSettings.pnm_dir()
                fpath = f"{pnm_dir}/{filename}"
                self.logger.debug(f'SpectrumAmplitudeData: - FNAME: {filename} - Length:{len(amp_data)} - TransactionID: {tx_id}')

                FileProcessor(fpath).write_file(amp_data)
                
                #################################################################################################
                # Build binary filename and save file - END
                #################################################################################################
                capture_para:SpecAnCapturePara = self.getSpectrumCaptureParameters()
                self.build_transaction_msg_extension(tx_id, 
                                                     filename, 
                                                     extension={f'{CMSE.SPECTRUM_ANALYSIS_SNMP_CAPTURE_PARAMETER}': capture_para.model_dump()})

            return self.build_send_msg(status)

        #########################################################################
        # Ensure CM Inet and TFTP server address use the same IP version
        #
        # The TFTP server address must match the IP version (IPv4 or IPv6) used
        # by the Cable Modem (CM). By default, we assume IPv4.
        #
        # If the CM's IP address is IPv6 and matches the version of the
        # secondary TFTP server entry, we switch to using the IPv6 TFTP server.
        #
        # TODO: Enhance this logic to support dual-stack (dual-home) cable modems,
        # where both IPv4 and IPv6 may be valid simultaneously.
        #########################################################################

        self.logger.info(f'{self.log_prefix} - TFTP-SERVERS: ({self.tftp_servers[0]} | {self.tftp_servers[1].inet})')

        # Default to using the IPv4 TFTP server
        tftp_server: Inet = self.tftp_servers[0]

        # Switch to IPv6 TFTP server if CM uses IPv6
        if self.cm.same_inet_version(self.tftp_servers[1]):
            tftp_server = self.tftp_servers[1]

        # Attempt to configure the CM with the selected TFTP server and path
        if not await self.cm.setDocsPnmBulk(tftp_server.inet, self.tftp_path):
            self.logger.error(
                f"{self.log_prefix} - Unable to set TFTP server {tftp_server.inet} "
                f"or TFTP path: {self.tftp_path}")
            return self.build_send_msg(ServiceStatusCode.TFTP_SERVER_PATH_SET_FAIL)

        ##############################################################################################
        # This section is determine by the direction due to which interface and type we are accessing
        ##############################################################################################

        status_index_channelId = await self._get_indexes_via_pnm_test_type(interface_parameters)
        self.logger.info(f'{self.log_prefix} - Index/ChannelID List: {status_index_channelId[1]}')
        if status_index_channelId[0] != ServiceStatusCode.SUCCESS or status_index_channelId[1] is None:
            self.logger.error(f'{self.log_prefix} - Unable to aquire index from ChannelID, reason: {status_index_channelId[0]}')
            return self.build_send_msg(status_index_channelId[0])

        ##############################################################################################
        # This section runs through all the indexes, build PNM file, run measurement and check status
        ##############################################################################################
        index_channelId: list[tuple[InterfaceIndex, ChannelId]] = status_index_channelId[1]
        return self.build_send_msg(await self._pnm_measure_status_and_pnm_file_transfer(index_channelId, max_wait_count))

    def getInterfaceParameters(self,
        interface_type: DocsisIfType) -> DownstreamOfdmParameters | UpstreamOfdmaParameters:
        """
        Instantiate and return the PNM test parameters for the specified DOCSIS interface.

        Args:
            interface_type (DocsisIfType):
                The DOCSIS interface type:
                - `DocsisIfType.docsOfdmDownstream` → returns DownstreamOfdmParameters
                - `DocsisIfType.docsOfdmaUpstream`  → returns UpstreamOfdmaParameters

        Returns:
            Union[DownstreamOfdmParameters, UpstreamOfdmaParameters]:
                A parameters object tailored to the requested interface.

        Raises:
            ValueError: If `interface_type` is not OFDM downstream or OFDMA upstream.
        """
        if interface_type == DocsisIfType.docsOfdmDownstream:
            return DownstreamOfdmParameters()
        if interface_type == DocsisIfType.docsOfdmaUpstream:
            return UpstreamOfdmaParameters()

        raise ValueError(
            f"Unsupported interface type: {interface_type!r}. "
            "Expected docsOfdmDownstream or docsOfdmaUpstream."
        )

    def is_ping_reachable(self) -> bool:
        """
        Check if the cable modem is reachable via ICMP ping.

        Returns:
            bool: True if the modem responds to ping, False otherwise.
        """
        return self.cm.is_ping_reachable()

    async def is_snmp_ready(self) -> bool:
        """
        Asynchronously check if the cable modem is accessible via SNMP.

        Returns:
            bool: True if the modem responds to SNMP queries, False otherwise.
        """
        return await self.cm.is_snmp_reachable()

    async def _filter_measurement_entries(
        self,
        entries: list[MeasurementEntry],
        channel_ids: list[ChannelId] | None,
    ) -> list[MeasurementEntry]:
        if not channel_ids:
            return entries

        channel_id_set = {int(channel_id) for channel_id in channel_ids}
        index_set: set[int] = set()

        if self.pnm_test_type in (
            DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
            DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF,
            DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
            DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
            DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        ):
            idx_channel_id = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()
            index_set = {int(idx) for idx, channel_id in idx_channel_id if int(channel_id) in channel_id_set}

        elif self.pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:
            idx_channel_id = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
            index_set = {int(idx) for idx, channel_id in idx_channel_id if int(channel_id) in channel_id_set}

        filtered: list[MeasurementEntry] = []
        for entry in entries:
            if isinstance(entry, (DocsPnmCmDsHistEntry, DocsIf3CmSpectrumAnalysisEntry)):
                continue
            if index_set:
                if int(entry.index) in index_set:
                    filtered.append(entry)
                continue
            if not hasattr(entry, "channel_id"):
                continue
            if int(entry.channel_id) in channel_id_set:
                filtered.append(entry)
        return filtered

    async def getPnmMeasurementStatistics(
        self,
        channel_ids: list[ChannelId] | None = None,
    ) -> list[MeasurementEntry]:
        """
        Retrieve PNM measurement entries for the currently configured `pnm_test_type`.

        Returns
        -------
        List[MeasurementEntry]
            A (possibly empty) list of model instances corresponding to the active
            test type:

            - DS_OFDM_CHAN_EST_COEF             → List[DocsPnmCmOfdmChanEstCoefEntry]
            - DS_CONSTELLATION_DISP             → List[DocsPnmCmDsConstDispMeasEntry]
            - DS_OFDM_RXMER_PER_SUBCAR          → List[DocsPnmCmDsOfdmRxMerEntry]
            - US_PRE_EQUALIZER_COEF             → List[DocsPnmCmUsPreEqEntry]
            - DS_HISTOGRAM                      → List[DocsPnmCmDsHistEntry]
            - DS_OFDM_FEC_SUMMARY               → List[DocsPnmCmDsOfdmFecEntry]
            - DS_OFDM_MODULATION_PROFILE        → List[DocsPnmCmDsOfdmModProfEntry]
            - SPECTRUM_ANALYZER                 → List[DocsIf3CmSpectrumAnalysisEntry]
            - SPECTRUM_ANALYZER_SNMP_AMP_DATA   → List[DocsIf3CmSpectrumAnalysisEntry]

            For other (stub/unsupported) test types, an empty list is returned.

        Notes
        -----
        - This method performs no aggregation; it returns the raw per-entry models
          fetched from the cable modem for the selected measurement type.
        - For strict typing, concrete lists are cast to `List[MeasurementEntry]`
          at return points (because `List` is invariant in the type system).
        - If `channel_ids` is provided and not empty, results are filtered to only
          include entries whose `channel_id` is in the list.
        """
        entries: list[MeasurementEntry] = []

        if self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            self.logger.debug(f"{self.log_prefix} - Running SPECTRUM_ANALYZER")
            concrete = await self.cm.getDocsIf3CmSpectrumAnalysisEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF:
            self.logger.debug(f"{self.log_prefix} - Running OFDM Channel Estimation Coefficient collection")
            concrete = await self.cm.getDocsPnmCmOfdmChanEstCoefEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP:
            self.logger.debug(f"{self.log_prefix} - Running OFDM Constellation Display collection")
            concrete = await self.cm.getDocsPnmCmDsConstDispMeasEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR:
            self.logger.debug(f"{self.log_prefix} - Running RXMER entry collection")
            concrete = await self.cm.getDocsPnmCmDsOfdmRxMerEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE:
            self.logger.debug(f"{self.log_prefix} - Running DS_OFDM_CODEWORD_ERROR_RATE")
            concrete = await self.cm.getDocsPnmCmDsOfdmFecEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM:
            self.logger.debug(f"{self.log_prefix} - Running DS_HISTOGRAM")
            concrete = await self.cm.getDocsPnmCmDsHistEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:
            self.logger.debug(f"{self.log_prefix} - Running Upstream Pre-Equalization entry collection")
            concrete = await self.cm.getDocsPnmCmUsPreEqEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE:
            self.logger.debug(f"{self.log_prefix} - Running DS_OFDM_MODULATION_PROFILE")
            concrete = await self.cm.getDocsPnmCmDsOfdmModProfEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA:
            self.logger.debug(f"{self.log_prefix} - Running SPECTRUM_ANALYZER_SNMP_AMP_DATA")
            concrete = await self.cm.getDocsIf3CmSpectrumAnalysisEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_SYMBOL_CAPTURE:
            self.logger.warning(f"{self.log_prefix} - Stub handler: DS_OFDM_SYMBOL_CAPTURE")

        elif self.pnm_test_type == DocsPnmCmCtlTest.LATENCY_REPORT:
            self.logger.warning(f"{self.log_prefix} - Stub handler: LATENCY_REPORT")

        else:
            self.logger.warning(f"{self.log_prefix} - Unknown PNM test type: {self.pnm_test_type}")

        return entries

    ###################
    # Private Methods #
    ###################

    async def _get_and_move_pnm_file(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Retrieves and moves the specified PNM file based on the configured retrieval method.

        This method delegates the file retrieval operation to a protocol-specific handler method
        depending on the configuration defined under `PnmFileRetrieval.method`. 
        Supported methods include: "local", "tftp", "sftp"
        # TODO: Need to implement, not sure if we need to: "ftp", "http", and "https".

        Configuration keys used:
            - PnmFileRetrieval.method: The file retrieval method to use (e.g., "local", "tftp", etc.).
            - PnmFileRetrieval.retries: Optional number of retries for retrieval attempts (currently unused here).

        Args:
            pnm_file_name (str): The name of the file to retrieve and move.

        Returns:
            bool: True if the file was successfully retrieved and moved; False otherwise.
        """
        method = SystemConfigSettings.retrieval_method()
        self.logger.info(f"{self.log_prefix} - Retrieval method: {method}")

        try:
            if method == "local":
                return await self._handle_local_fetch(pnm_file_name)
            elif method == "tftp":
                return self._handle_tftp_fetch(pnm_file_name)
            elif method == "ftp":
                return self._handle_ftp_fetch(pnm_file_name)
            elif method == "sftp":
                return self._handle_sftp_fetch(pnm_file_name)
            elif method == "http":
                return self._handle_http_fetch(pnm_file_name)
            elif method == "https":
                return self._handle_https_fetch(pnm_file_name)
            else:
                self.logger.error(f"{self.log_prefix} - Unsupported retrieval method: {method}")
                return ServiceStatusCode.FILE_RETRIEVAL_TYPE_INVALID

        except Exception as e:
            self.logger.exception(f"{self.log_prefix} - File retrieval failed: {e}")
            return ServiceStatusCode.PNM_FILE_RETRIEVAL_ERROR

    async def _get_indexes_via_pnm_test_type(self, ifParameters: DownstreamOfdmParameters | UpstreamOfdmaParameters | None = None
                                             ) -> tuple[ServiceStatusCode, list[tuple[InterfaceIndex, ChannelId]] | None]:
        """
        Determines the appropriate interface indexes and channel IDs to target for a given PNM test type.

        Depending on the configured PNM test type, this method selects the relevant interface and filters the index/ChannelID
        tuples based on user-specified parameters.

        Args:
            interface_parameters (Optional[InterfaceParameters]): Parameters specifying interface type ("ofdm" or "ofdma")
                and optionally a list of channel IDs to filter. If not provided, default parameters are selected based on test type.

        Returns:
            Tuple[ServiceStatusCode, Optional[List[Tuple[int, int]]]]:
                A status code indicating success or reason for failure, and a list of (index, channelId) tuples.
        """

        if ifParameters is None:
            ifParameters = DownstreamOfdmParameters()

        if not ifParameters:
            ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmDownstream)

        if self.pnm_test_type in (DocsPnmCmCtlTest.DS_HISTOGRAM, DocsPnmCmCtlTest.LATENCY_REPORT):
            idx:list[InterfaceIndex] = await self.cm.getIfTypeIndex(DocsisIfType.docsCableMaclayer)
            return ServiceStatusCode.SUCCESS, [(idx[0], ChannelId(0))]

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            return ServiceStatusCode.SUCCESS, [(InterfaceIndex(0), ChannelId(0))]

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA:
            return ServiceStatusCode.SUCCESS, [(InterfaceIndex(0), ChannelId(0))]

        elif self.pnm_test_type in (DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
                                    DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF,
                                    DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
                                    DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
                                    DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR):

            if not ifParameters:
                ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmDownstream)

        elif self.pnm_test_type in (DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF,):
            ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmaUpstream)
            self.logger.debug(f'{DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF} Measurement - IfParameters: {ifParameters.model_dump()}')

        '''
        There is redundant code, but incase I may need to change due to
        change of requiments depending on Downstream vs. Upstream

        TODO: lol, I am sure I will not revisit, but OK for now.
        '''
        if ifParameters.type == "ofdm":
            channel_id_list = ifParameters.channel_id
            idx_channelId = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()

            if not idx_channelId:
                self.logger.warning("No OFDM channel data found.")
                return ServiceStatusCode.NO_OFDMA_CHAN_ID_INDEX_FOUND, []

            if channel_id_list:
                filtered = [tpl for tpl in idx_channelId if tpl[1] in channel_id_list]
                self.logger.debug(f'Downstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
                return ServiceStatusCode.SUCCESS, filtered

            self.logger.info(f'Downstream: {ifParameters.type} -> IDX,CHAN_ID: {idx_channelId}')

            return ServiceStatusCode.SUCCESS, idx_channelId

        elif ifParameters.type == "ofdma":
            channel_id_list = ifParameters.channel_id
            idx_channelId = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
            if not idx_channelId:
                self.logger.warning("No OFDMA channel found.")
                return ServiceStatusCode.NO_OFDMA_CHAN_ID_INDEX_FOUND, []

            if channel_id_list:
                filtered = [tpl for tpl in idx_channelId if tpl[1] in channel_id_list]
                self.logger.info(f'Upstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
                return ServiceStatusCode.SUCCESS, filtered

            self.logger.info(f'Upstream: {ifParameters.type} -> IDX,CHAN_ID: {idx_channelId}')

        return ServiceStatusCode.SUCCESS, idx_channelId

    async def _pnm_measure_status_and_pnm_file_transfer(self, idx_channelId:list[tuple[InterfaceIndex, ChannelId]], max_wait_count:int) -> ServiceStatusCode:
        """
        Set and monitor the OFDM measurement test for specified (index, PLC) tuples.

        For each (index, PLC) pair:
            - Initiates the PNM test using SNMP.
            - Waits for the test status to reach READY.
            - Monitors for the measurement status to become SAMPLE_READY.
            - Retrieves the resulting PNM file and stores it locally.

        Args:
            idx_channelId (Tuple[int, int]): A list of tuples where each tuple consists of
                the SNMP interface index and the corresponding PLC (center frequency).
            max_wait_count (int): Maximum number of seconds to wait for SAMPLE_READY status.

        Returns:
            ServiceStatusCode: SUCCESS if all steps completed successfully,
                otherwise a specific error status (e.g., if the file couldn't be retrieved
                or the measurement status did not become SAMPLE_READY).
        """
        for interface_index, channel_id in idx_channelId:

            #######################################################################
            # This sets the Measurement Table/Row for the specific PNM Measurement
            #######################################################################
            ctl_measure_status:tuple[ServiceStatusCode, list[FileNameStr]] = \
                await self._setDocsPnmCmMeasureTest(self.pnm_test_type, interface_index, channel_id)
            
            if ctl_measure_status[0] != ServiceStatusCode.SUCCESS:
                return ctl_measure_status[0]

            pnm_filenames = ctl_measure_status[1]
            self.logger.info(f'{self.log_prefix} - PNM File(s) -> {pnm_filenames}')

            count=1
            while True:
                cm_ctl_status:DocsPnmCmCtlStatus = await self.cm.getDocsPnmCmCtlStatus()
                self.logger.info(f"{self.log_prefix} - PNM status: {str(cm_ctl_status).upper()} - count: {count}")
                if cm_ctl_status == DocsPnmCmCtlStatus.TEST_IN_PROGRESS:
                    count += 1
                    await asyncio.sleep(1)
                    continue

                if cm_ctl_status == DocsPnmCmCtlStatus.READY:
                    break

                if cm_ctl_status == DocsPnmCmCtlStatus.TEMP_REJECT:
                    break

                if cm_ctl_status == DocsPnmCmCtlStatus.SNMP_ERROR:
                    break

            self.logger.debug(f"{self.log_prefix} - Checking Measurement Status for {self.pnm_test_type} @ IDX: {interface_index}")

            wait_count = 0
            def extract_idx(idx):
                return idx[0] if isinstance(idx, list) and idx else idx

            while wait_count < max_wait_count:
                meas_status = await self.cm.getPnmMeasurementStatus(self.pnm_test_type, extract_idx(interface_index))
                self.logger.info(f"{self.log_prefix} - MeasureStatus: {meas_status.name}")
                if meas_status == MeasStatusType.SAMPLE_READY:
                    break
                await asyncio.sleep(1)
                wait_count += 1

            else:
                self.logger.error(f"{self.log_prefix} - SAMPLE_READY not reached for ChannelID {channel_id}")
                return ServiceStatusCode.NOT_READY_AFTER_FILE_CAPTURE

            #Multiple PNM files for special cases
            for pnm_fname in pnm_filenames:

                status:ServiceStatusCode = await self._check_and_wait_for_tftp_upload(FileNameStr(pnm_fname))

                if status != ServiceStatusCode.SUCCESS:
                    self.logger.error(f"{self.log_prefix} - Unable to Upload PNM File to TFTP({status})")
                    return status

                # Get and copy PNM file to local data directory
                retrieval_status = await self._get_and_move_pnm_file(FileNameStr(pnm_fname))
                if retrieval_status != ServiceStatusCode.SUCCESS:
                    self.logger.error(
                        f"{self.log_prefix} - Unable to copy PNM file to local {self.pnm_dir} dir "
                        f"(status={retrieval_status})")
                    return retrieval_status

                # Find Transaction ID via filename
                trans_id = self._get_transaction_id_by_filename(pnm_fname)
                if not trans_id:
                    self.logger.error(f"{self.log_prefix} - Unable to find Transaction ID for PNM filename: {pnm_fname}")
                    return ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND
                
                self.logger.debug(f'{self.log_prefix} - TransID: {trans_id} -> Filename: {pnm_fname}')
                self.build_transaction_msg(trans_id, pnm_fname)

        return ServiceStatusCode.SUCCESS

    async def _check_and_wait_for_tftp_upload(self, filename: str, max_wait_count: int = 5) -> ServiceStatusCode:
        """
        Waits for a PNM file to be uploaded via TFTP by polling the upload status.

        Args:
            filename (str): The name of the file being uploaded.
            max_wait_count (int): Maximum number of seconds to wait before timing out.

        Returns:
            ServiceStatusCode: SUCCESS if upload completed, failure code otherwise.
        """
        wait_count = 0

        while wait_count < max_wait_count:
            try:
                status = await self.cm.getBulkFileUploadStatus(filename)
            except Exception as e:
                self.logger.error(f"{self.log_prefix} - Error checking upload status for '{filename}': {e}")
                return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

            if status == DocsPnmBulkFileUploadStatus.UPLOAD_COMPLETED:
                self.logger.info(f"{self.log_prefix} - File '{filename}' uploaded successfully.")
                return ServiceStatusCode.SUCCESS

            if status == DocsPnmBulkFileUploadStatus.ERROR:
                self.logger.error(f"{self.log_prefix} - Device reported ERROR for file upload '{filename}'.")
                return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

            self.logger.debug(
                f"{self.log_prefix} - Waiting for file '{filename}' to upload "
                f"(status={status.name}, wait_count={wait_count})"
            )

            await asyncio.sleep(1)
            wait_count += 1

        self.logger.error(f"{self.log_prefix} - TFTP file '{filename}' upload timed out after {max_wait_count} seconds.")
        return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

    async def _setDocsPnmCmMeasureTest(self, pnm_test_type:DocsPnmCmCtlTest,
                                       interface_index:int, channel_id:ChannelId) -> tuple[ServiceStatusCode, list[FileNameStr]]:
        """
        Configure and trigger a specific PNM (Proactive Network Maintenance) measurement
        test on a cable modem based on the test type.

        Depending on the `pnm_test_type`, this method:
        - Generates appropriate output file names.
        - Uses SNMP to set the modem to collect specific diagnostic data.
        - Handles various DOCSIS downstream and upstream tests, including:
            - US Pre-Equalizer Coefficients (requires two files per interface: pre-eq and last pre-eq)
            - DS OFDM RxMER per Subcarrier
            - DS OFDM Codeword Error Rate
            - DS OFDM Channel Estimation Coefficients
            - DS Constellation Display
            - DS Histogram
            - DS OFDM Modulation Profile
            - Spectrum Analyzer Scan

        Parameters:
            pnm_test_type (DocsPnmCmCtlTest): Enum value indicating the PNM test to perform.
            interface_index (int): The SNMP index for the OFDM channel (usually the interface index).
            channel_id (int): The channel ID associated with the modem interface.

        Returns:
            Tuple[ServiceStatusCode, List[str]]: Status of the operation and list of generated file names.
        """
        pnm_files: list[FileNameStr] = []

        if pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:

            # Pre-Eq and Last Pre-EQ (2 files)
            pre_eq_filename         = await self._pnm_file_generator(self.pnm_test_type, str(channel_id))
            last_pre_eq_filename    = await self._pnm_file_generator(self.pnm_test_type, f'last_pre-eq_{str(channel_id)}')

            self.logger.info(f'{self.log_prefix} - Setting {self.pnm_test_type} for ChannelID: {channel_id} "'
                             f'@ IDX: {interface_index} -> FN(): {pre_eq_filename}, FN(last): {last_pre_eq_filename}')

            self.logger.info(f'{self.log_prefix} - Performing US_PRE_EQUALIZER_COEF measurement on IDX: ({interface_index})')
            if not await self.cm.setDocsPnmCmUsPreEq(ofdma_idx              =   interface_index,
                                                     filename               =   pre_eq_filename,
                                                     last_pre_eq_filename   =   last_pre_eq_filename):
                self.logger.error(f"{self.log_prefix} - Upstream OFDMA Pre-Equalization is Not Avalaible")
                return ServiceStatusCode.FILE_SET_FAIL, []

            #Append files for later fetching
            pnm_files.extend([pre_eq_filename, last_pre_eq_filename])

        else:
            #The remaining PNM Measuresurement are single PNM file
            pnm_filename = await self._pnm_file_generator(self.pnm_test_type, str(channel_id))
            self.logger.debug(f'{self.log_prefix} - Setting {self.pnm_test_type} for ChannelID: {channel_id} @ IDX: {interface_index} -> FN: {pnm_filename}')
            pnm_files.append(pnm_filename)

            if pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR:

                if not await self.cm.setDocsPnmCmDsOfdmRxMer(ofdm_idx=interface_index, rxmer_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE:

                fst = self.extra_options.get("fec_summary_type", FecSummaryType.TEN_MIN)

                if not await self.cm.setDocsPnmCmDsOfdmFecSum(ofdm_idx=interface_index, fec_sum_file_name=pnm_filename, fec_sum_type=fst):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF:

                if not await self.cm.setDocsPnmCmOfdmChEstCoef(ofdm_idx=interface_index, chan_est_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP:
                # OFDM Downstream Constellation Display setup
                # Extra SNMP options may include:
                #   - modulation_offset: Optional[int]
                #   - num_sample_symb: Optional[int]
                if not await self.cm.setDocsPnmCmDsConstDisp(
                    ofdm_idx                =   interface_index,
                    const_disp_name         =   pnm_filename,
                    modulation_order_offset =   self.extra_options.get('modulation_order_offset', 0),
                    number_sample_symbol    =   self.extra_options.get('number_sample_symbol', 0)
                ):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM:
                sample_duration = self.extra_options.get("histogram_sample_duration", 10)
                if not await self.cm.setDocsPnmCmDsHist(ds_histogram_file_name=pnm_filename, timeout=sample_duration):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE:

                if not await self.cm.setDocsPnmCmDsOfdmModProf(ofdm_idx=interface_index, mod_prof_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
                #Created generic to be used for PNM File and SNMP Return data
                 __status = await self._generic_spectrum_analyzer_operation(filename=pnm_filename)
                 if __status[0] != ServiceStatusCode.SUCCESS:
                    return __status

        return ServiceStatusCode.SUCCESS, pnm_files

    async def _check_spectrum_amplitude_data_status(self, timeout_seconds: int = 300) -> ServiceStatusCode:
        """
        Polls the cable modem for spectrum amplitude data availability within a timeout period.

        This method repeatedly checks if `docsIf3CmSpectrumAnalysisMeasAmplitudeData` is present
        on the modem, and returns a success or timeout status accordingly.

        Args:
            timeout_seconds (int): Maximum number of seconds to wait before timing out. Default is 300.

        Returns:
            ServiceStatusCode:
                - SUCCESS if data becomes available within the timeout period.
                - SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT if the timeout is exceeded.
        """
        t_start = time.time()

        while True:
            if await self.cm.isAmplitudeDataPresent():
                return ServiceStatusCode.SUCCESS
            now:int = math.floor(time.time() - t_start)

            if now >= timeout_seconds:
                self.logger.warning(f'{self.log_prefix} - Timeout for Amplitude Data ({now} of {timeout_seconds} seconds)')
                return ServiceStatusCode.SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT

            self.logger.info(f'{self.log_prefix} - Waiting for Amplitude Data ({now} of {timeout_seconds})')

            await asyncio.sleep(1)

    async def _handle_local_fetch(self, pnm_file_name: str) -> ServiceStatusCode:
        """
        Handles copying a specified PNM file from a local source directory to a configured save directory.

        This method looks up the source and destination paths from the application's system configuration
        (under the "PnmFileRetrieval" section) and attempts to copy the file named `pnm_file_name`
        from the source directory to the save directory.

        Configuration keys used:
            - PnmFileRetrieval.local.src_dir: Source directory where the PNM file resides.
            - PnmFileRetrieval.save_dir: Destination directory where the file should be saved.

        Args:
            pnm_file_name (str): The name of the file to copy.

        Returns:
            bool: True if the file was successfully copied; False otherwise.
        """

        src_dir = SystemConfigSettings.local_src_dir()

        self.logger.info(
            f'{self.log_prefix} - Local Copy - SRC: {src_dir} - SAVE: {self.pnm_dir} - FN: {pnm_file_name}'
        )

        if not os.path.isdir(src_dir) or not os.path.isdir(self.pnm_dir):
            self.logger.error(f"{self.log_prefix} - Invalid source or destination directory")
            return ServiceStatusCode.LOCAL_FETCH_FAILURE

        while True:
            await asyncio.sleep(1)
            file_found = False
            for filename in os.listdir(src_dir):
                if filename == pnm_file_name:
                    file_found = True
                    src_path = os.path.join(src_dir, filename)
                    dest_path = os.path.join(self.pnm_dir, filename)
                    try:
                        shutil.copy2(src_path, dest_path)
                        self.logger.debug(f"{self.log_prefix} - Copied {filename} to {self.pnm_dir}")
                        return ServiceStatusCode.SUCCESS
                    except Exception as e:
                        self.logger.error(f"{self.log_prefix} - Copy failed for {filename}: {e}")
                        return ServiceStatusCode.LOCAL_FETCH_FAILURE

            if not file_found:
                self.logger.warning(f"{self.log_prefix} - File not found in source directory: {pnm_file_name}")

            return ServiceStatusCode.LOCAL_FETCH_FAILURE

    def _handle_sftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch a file from remote SFTP server.

        Args:
            pnm_file_name: Name of the file to fetch from remote server

        Returns:
            bool: True if file transfer successful, False otherwise
        """
        sys_config = SystemConfigSettings()

        self.logger.debug(f"{self.log_prefix} - SFTP: Connecting to: {sys_config.sftp_host()}")

        if self._ping_pnm_file_server(HostNameStr(sys_config.sftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for SFTP host: {sys_config.sftp_host()}")
            return ServiceStatusCode.SFTP_HOST_UNREACHABLE

        sftp = SSHConnector(
            hostname        =   sys_config.sftp_host(),
            username        =   sys_config.sftp_user(),
            port            =   sys_config.sftp_port())

        password_enc     = sys_config.sftp_password()
        private_key_path = sys_config.sftp_private_key_path()

        try:
            if not sftp.connect(password_enc     =   password_enc,
                                private_key_path =   private_key_path):
                self.logger.error(f'{self.log_prefix} - SFTP Connect Failure: Host: {sys_config.sftp_host()}')
                return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

            remote_file_path = f'{sys_config.sftp_remote_dir()}/{pnm_file_name}'
            if not sftp.receive_file(remote_path =   remote_file_path,
                                     local_path  =   sys_config.pnm_dir()):
                self.logger.error(
                    f'{self.log_prefix} - SFTP Receive File Error '
                    f'(SRC:{remote_file_path} DST: {sys_config.pnm_dir()})'
                )
                return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

            self.logger.info(f'{self.log_prefix} - Successfully fetched file: {pnm_file_name}')
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f'{self.log_prefix} - SFTP Fetch Exception: {e}')
            return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

        finally:
            sftp.disconnect()

    def _handle_tftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch the specified PNM file via TFTP.

        Assumes the following attributes on self:
        - self.pnm_local_dir (str)    # local directory to save the downloaded file
        - self.log_prefix (str)       # used for consistent logging

        TFTP settings are read from SystemConfigCommonSettings:
        - tftp_host (str)
        - tftp_port (int)
        - tftp_timeout (int)
        - tftp_remote_dir (str)   # remote directory where PNM files live (if applicable)
        """

        if self._ping_pnm_file_server(HostNameStr(SystemConfigSettings.tftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for TFTP host: {SystemConfigSettings.tftp_host()}")
            return ServiceStatusCode.TFTP_HOST_UNREACHABLE  

        try:
            connector = TFTPConnector(
                host    =   Inet(SystemConfigSettings.tftp_host()),
                port    =   int(str(SystemConfigSettings.tftp_port())))

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during TFTP connecting: {e}")
            return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

        try:

            self.logger.info(
                f"{self.log_prefix} - Starting TFTP download from "
                f"{SystemConfigSettings.tftp_host()}:{SystemConfigSettings.tftp_port()}"
            )

            # Build remote filename (some tftp servers require just the basename)
            remote_name = (
                f"{SystemConfigSettings.tftp_remote_dir().rstrip('/')}/{pnm_file_name}"
                if SystemConfigSettings.tftp_remote_dir() else
                pnm_file_name
            )
            local_path = os.path.join(SystemConfigSettings.pnm_dir(), pnm_file_name)

            success = connector.download_file(remote_name, local_path)

            if not success:
                self.logger.error(
                    f"{self.log_prefix} - TFTP download failed for '{remote_name}'"
                )
                return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

            self.logger.info(
                f"{self.log_prefix} - Successfully fetched '{pnm_file_name}' via TFTP"
            )
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during TFTP downloading: {e}")
            return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

    def _handle_ftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch the specified PNM file via FTP.

        Assumes the following attributes exist on self:
        - self.pnm_local_dir (str)    # local directory to save the downloaded file
        - self.log_prefix (str)       # used for consistent logging

        All FTP-specific settings are read from SystemConfigCommonSettings:
        - ftp_host (str)
        - ftp_port (int)
        - ftp_user (str)
        - ftp_password (str)
        - ftp_use_tls (bool)
        - ftp_timeout (int)
        - ftp_remote_dir (str)   # remote directory where PNM files live
        """
        sys_config = SystemConfigSettings()

        if self._ping_pnm_file_server(HostNameStr(SystemConfigSettings.ftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for FTP host: {SystemConfigSettings.ftp_host()}")
            return ServiceStatusCode.FTP_HOST_UNREACHABLE  

        try:
            connector = FTPConnector(
                host        =   str(sys_config.ftp_host()),
                port        =   int(str(sys_config.ftp_port())),
                username    =   str(sys_config.ftp_user()),
                password    =   str(sys_config.ftp_password()),
                use_tls     =   bool(sys_config.ftp_use_tls()),
                timeout     =   int(str(sys_config.ftp_timeout()))
            )

            self.logger.debug(
                f"{self.log_prefix} - Connecting to FTP server "
                f"{sys_config.ftp_host}:{sys_config.ftp_port}"
            )
            if not connector.connect():
                self.logger.error(f"{self.log_prefix} - FTP connection failed")
                return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

            # Build remote and local paths
            remote_base = sys_config.ftp_remote_dir.rstrip("/") if sys_config.ftp_remote_dir else ""
            remote_path = f"{remote_base}/{pnm_file_name}" if remote_base else pnm_file_name

            local_path = os.path.join(self.pnm_local_dir, pnm_file_name)

            self.logger.debug(
                f"{self.log_prefix} - Downloading '{remote_path}' to '{local_path}'"
            )
            success = connector.download_file(remote_path, local_path)
            connector.disconnect()

            if not success:
                self.logger.error(
                    f"{self.log_prefix} - FTP download failed for '{remote_path}'"
                )
                return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

            self.logger.info(
                f"{self.log_prefix} - Successfully fetched '{pnm_file_name}' via FTP"
            )
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during FTP fetch: {e}")
            return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

    def _handle_http_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        # TODO: implement HTTP file fetch logic
        self.logger.debug(f"{self.log_prefix} - HTTP fetch not yet implemented")
        return ServiceStatusCode.HTTP_PNM_FILE_FETCH_ERROR

    def _handle_https_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        # TODO: implement HTTPS file fetch logic
        self.logger.debug(f"{self.log_prefix} - HTTPS fetch not yet implemented")
        return ServiceStatusCode.SHTTP_PNM_FILE_FETCH_ERROR
    
    async def _pnm_file_generator(self, test_type: DocsPnmCmCtlTest, suffix: str = "", ext: str = ".bin") -> FileNameStr:
        """
        Generates the PNM file name based on the provided DocsPnmCmCtlTest, with optional suffix and extension.

        Args:
            test_type (DocsPnmCmCtlTest): The type of the test to generate the prefix.
            suffix (str, optional): A suffix added to the file name. Defaults to an empty string.
            ext (str, optional): The file extension. Defaults to ".bin".

        Returns:
            str: The generated PNM file name.
        """
        test_prefix = test_type.name.lower()

        if suffix:
            suffix = f'_{suffix}'

        file_name:FileNameStr = FileNameStr(f"{test_prefix}_{self.cm.get_mac_address.to_mac_format()}{suffix}_{Generate.time_stamp()}{ext}")

        transaction_id = await PnmFileTransaction().insert(self.cm, test_type, file_name)

        self.logger.debug(f"Generated PNM file name: {file_name} -> TransID: {transaction_id}")

        self._transactionId_pnmFile[transaction_id] = file_name

        return file_name

    def _get_transaction_id_by_filename(self, file_name: str) -> TransactionId | None:
        """
        Return the transaction ID associated with the given file name.
        Assumes file names are unique. Returns None if not found.
        """
        for transaction_id, name in self._transactionId_pnmFile.items():
            if name == file_name:
                return TransactionId(transaction_id)
        return None

    async def _generic_spectrum_analyzer_operation(self, filename:str="") -> tuple[ServiceStatusCode, list[str]]:
        """
        Perform a generic spectrum-analyzer operation on the cable modem, supporting two retrieval modes:
        1. SNMP-based amplitude data return (AmplitudeData textual convention)
        2. PNM file return (download via TFTP once the CM writes the file)

        The same set of control parameters (frequency range, bin count, windowing, etc.) is used
        in both cases—avoiding duplicate “control-command” logic (DRY). Downstream, a separate helper
        method is called based on `spectrum_retrieval_type`.

        Extra options (from self.extra_options):
            • inactivity_timeout             (int, default=100)
                - Maximum seconds to wait for the CM to complete the measurement
            • first_segment_center_freq      (int, default=300_000_000)
                - Starting center frequency in Hz
            • last_segment_center_freq       (int, default=900_000_000)
                - Ending center frequency in Hz
            • segment_freq_span              (int, default=7_500_000)
                - Frequency span per segment in Hz
            • num_bins_per_segment           (int, default=256)
                - Number of bins (samples) per segment
            • noise_bw                       (int, default=110)
                - Equivalent noise bandwidth in Hz
            • window_function                (WindowFunction, default=WindowFunction.HANN)
                - Window function to apply to each segment
            • num_averages                   (int, default=1)
                - Number of averages to take
            • spectrum_retrieval_type        (SpectrumRetrievalType, default=SpectrumRetrievalType.FILE)
                - FILE: write to PNM file via TFTP (requires pnm_filename)
                - SNMP: return amplitude data directly via SNMP (no file write)

        Returns:
            Tuple[ServiceStatusCode, List[str]]:
                • On success: (ServiceStatusCode.SUCCESS, [<PNM filename>]) for FILE mode,
                  or (ServiceStatusCode.SUCCESS, []) for SNMP mode.
                • On failure: (ServiceStatusCode.SPEC_ANALYZER_NOT_AVAILABLE, []).

        Raises:
            None directly—errors are mapped to a failure status code.
        """
        self.logger.info(f"{self.log_prefix} - Entering into SPECTRUM-ANALYZER Mode (filename: {filename})")

        # Default: only SNMP control-command, no file write
        ctl_cmd_filename = Snmp_v2c.TRUE

        if (self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER or \
            self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA) and \
            (not self.getSpectrumCaptureParameters()):

            self.logger.error('No Spectrum Parameters Found, did you set: setSpectrumCaptureParameters()')

            return  ServiceStatusCode.NO_SPECTRUM_CAPTURE_PARAMETERS, []

        capture_parameter = self.getSpectrumCaptureParameters()

        if not capture_parameter:

            capture_parameter = SpecAnCapturePara (
                inactivity_timeout          = self.extra_options.get("inactivity_timeout", 100),
                first_segment_center_freq   = self.extra_options.get("first_segment_center_freq", 300_000_000),
                last_segment_center_freq    = self.extra_options.get("last_segment_center_freq", 993_000_000),
                segment_freq_span           = self.extra_options.get("segment_freq_span", 1_000_000),
                num_bins_per_segment        = self.extra_options.get("num_bins_per_segment", 256),
                noise_bw                    = self.extra_options.get("noise_bw", 110),
                window_function             = self.extra_options.get("window_function", WindowFunction.HANN),
                num_averages                = self.extra_options.get("num_averages", 1),
                spectrum_retrieval_type     = self.extra_options.get("spectrum_retrieval_type",SpectrumRetrievalType.FILE),
            )

        if capture_parameter.num_averages != self.SPECTRUM_ANALYZER_AVERAGES_CAP:
            self.logger.warning(
                "%s - Capping spectrum analyzer averages from %s to %s",
                self.log_prefix,
                capture_parameter.num_averages,
                self.SPECTRUM_ANALYZER_AVERAGES_CAP,
            )
            capture_parameter.num_averages = self.SPECTRUM_ANALYZER_AVERAGES_CAP

        if capture_parameter.spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.info(f"{self.log_prefix} - SPECTRUM-ANALYZER - SNMP-AMPLITUDE-DATA-RETURN")
            ctl_cmd_filename = Snmp_v2c.FALSE

        else:
            if not filename:
                self.logger.error(f"{self.log_prefix} - Missing 'filename' for FILE retrieval mode")
                return ServiceStatusCode.MISSING_PNM_FILENAME, []

        spectrum_cmd = DocsIf3CmSpectrumAnalysisCtrlCmd(
            docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout           =   capture_parameter.inactivity_timeout,
            docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency =   capture_parameter.first_segment_center_freq,
            docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency  =   capture_parameter.last_segment_center_freq,
            docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan        =   capture_parameter.segment_freq_span,
            docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment           =   capture_parameter.num_bins_per_segment,
            docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth    =   capture_parameter.noise_bw,
            docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction              =   capture_parameter.window_function,
            docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages            =   capture_parameter.num_averages,
            docsIf3CmSpectrumAnalysisCtrlCmdEnable                      =   Snmp_v2c.TRUE,
            docsIf3CmSpectrumAnalysisCtrlCmdFileName                    =   filename,
            docsIf3CmSpectrumAnalysisCtrlCmdFileEnable                  =   ctl_cmd_filename,)

        # Issue the SNMP SET for the control-command. The downstream logic
        # (not shown here) will branch to either:
        #   • SNMP:  set FileEnable = FALSE → wait for measurement → walk AmplitudeData
        #   • FILE:  set FileEnable = TRUE  → wait for measurement status → TFTP download
        if not await self.cm.setDocsIf3CmSpectrumAnalysisCtrlCmd(spectrum_cmd,
                                                                 capture_parameter.spectrum_retrieval_type):
            self.logger.error(f"{self.log_prefix} - Spectrum Analyzer is Not Available")
            return ServiceStatusCode.SPEC_ANALYZER_NOT_AVAILABLE, []

        # On success, return the filename (if FILE mode) or an empty list (SNMP mode)
        if capture_parameter.spectrum_retrieval_type == SpectrumRetrievalType.FILE:
            return ServiceStatusCode.SUCCESS, [filename]
        else:
            return ServiceStatusCode.SUCCESS, []

    def _ping_pnm_file_server(self, host: HostNameStr) -> ServiceStatusCode:
        """
        Ping The PNM File Server To Check Its Availability.

        This helper first attempts DNS resolution of the host. If the host
        resolves only to loopback addresses (for example "127.0.0.1" or "::1"),
        ICMP ping is bypassed and the host is treated as reachable so that
        local SCP/SFTP/TFTP retrieval is not blocked by loopback
        misconfiguration.

        If DNS resolution fails entirely, the ping pre-check is skipped and the
        method returns SUCCESS while logging the condition at debug level,
        allowing the subsequent transfer step to provide a more precise error.

        For non-loopback addresses that resolve successfully, a standard ICMP
        ping is issued via HostEndpoint. If the ping fails, PING_FAILED is
        returned.
        """
        endpoint  = HostEndpoint(host)
        addresses = endpoint.resolve()

        if not addresses:
            self.logger.debug(
                f"{self.log_prefix} - DNS lookup failed for host: {host}; "
                "skipping ping pre-check"
            )
            return ServiceStatusCode.SUCCESS

        for addr in addresses:
            if addr.startswith("127.") or addr == "::1":
                self.logger.debug(
                    f"{self.log_prefix} - Host {host} resolved to loopback ({addr}); "
                    "skipping ping pre-check"
                )
                return ServiceStatusCode.SUCCESS

        if endpoint.ping():
            return ServiceStatusCode.SUCCESS

        self.logger.debug(f"{self.log_prefix} - Ping failed for host: {host}")
        return ServiceStatusCode.PING_FAILED

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
                channel_ids              =   channel_ids if channel_ids else None,
                spectrum_retrieval_type =   request.capture_parameters.spectrum_retrieval_type)

            msg_responses: list[tuple[ChannelId, MessageResponse]] = await service.start()

            measurement_stats: list[DocsIf3CmSpectrumAnalysisEntry] = cast(
                list[DocsIf3CmSpectrumAnalysisEntry],
                await service.getPnmMeasurementStatisticsFlat(),
            )

            primative: dict[str, dict[Any, Any]] = {"primative": {}}

            for idx, (chan_id, msg_rsp) in enumerate(msg_responses):
                cps_msg_rsp = CommonProcessService(msg_rsp).process()

                analysis = Analysis(AnalysisType.BASIC, cps_msg_rsp, skip_automatic_process=True,)
                analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))
                multi_analysis.add(chan_id, analysis)

                primative_entry = cps_msg_rsp.payload_to_dict(idx)
                primative["primative"].update(primative_entry)

            analyzer_rpt = OfdmSpecAnalyzerAnalysisReport(multi_analysis)
            analyzer_rpt.build_report()

            if request.analysis.output.type == OutputType.JSON:
                analyzer_rpt_dict = analyzer_rpt.to_dict()
                analyzer_rpt_dict.update(primative)
                analyzer_rpt_dict.update(
                    DictGenerate.models_to_nested_dict(measurement_stats, "measurement_stats",))

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

            measurement_stats: list[DocsIf3CmSpectrumAnalysisEntry] = cast(
                list[DocsIf3CmSpectrumAnalysisEntry],
                await service.getPnmMeasurementStatisticsFlat(),
            )

            primative: dict[str, dict[Any, Any]] = {"primative": {}}

            for idx, (chan_id, msg_rsp) in enumerate(msg_responses):
                cps_msg_rsp = CommonProcessService(msg_rsp).process()

                analysis = Analysis(AnalysisType.BASIC, cps_msg_rsp, skip_automatic_process=True,)
                analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))
                multi_analysis.add(chan_id, analysis)

                primative_entry = cps_msg_rsp.payload_to_dict(idx)
                primative["primative"].update(primative_entry)

            analyzer_rpt = ScQamSpecAnalyzerAnalysisReport(multi_analysis)
            analyzer_rpt.build_report()

            if request.analysis.output.type == OutputType.JSON:
                analyzer_rpt_dict = analyzer_rpt.to_dict()
                analyzer_rpt_dict.update(primative)
                analyzer_rpt_dict.update(
                    DictGenerate.models_to_nested_dict(measurement_stats, "measurement_stats",))

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

# FILE: src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/service.py
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
    ResolutionBwSettings,
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

        rbw_settings: ResolutionBwSettings = RBWConversion.getSpectrumRbwSetttings(
            self._resolution_bandwidth,
        )

        num_bins_per_segment    = rbw_settings[1]
        number_of_averages      = self._number_of_averages
        spectrum_retrieval_type = self._spectrum_retrieval_type
        inactivity_timeout      = 30
        noise_bw                = 150
        channel_filter = set(self._channel_ids) if self._channel_ids else None
        segment_freq_span       = rbw_settings[2]

        for chan_id, (start_hz, plc_hz, end_hz) in bw_by_channel.items():
            if channel_filter and chan_id not in channel_filter:
                continue
            self.logger.debug(
                f"OFDM - Mac: {self._cm.get_mac_address} - "
                f"Channel Settings: {chan_id}, {start_hz}, {plc_hz}, {end_hz}"
            )

            capture_parameter = SpecAnCapturePara(
                inactivity_timeout          = inactivity_timeout,
                first_segment_center_freq   = FrequencyHz(start_hz),
                last_segment_center_freq    = FrequencyHz(end_hz),
                segment_freq_span           = FrequencyHz(segment_freq_span),
                num_bins_per_segment        = num_bins_per_segment,
                noise_bw                    = noise_bw,
                window_function             = WindowFunction.HANN,
                num_averages                = number_of_averages,
                spectrum_retrieval_type     = spectrum_retrieval_type,
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
        rbw_settings:ResolutionBwSettings = RBWConversion.getSpectrumRbwSetttings(self._resolution_bandwidth)

        num_bins_per_segment = rbw_settings[1]
        number_of_averages = self._number_of_averages
        spectrum_retrieval_type = self._spectrum_retrieval_type
        inactivity_timeout = 60
        noise_bw = 150
        channel_filter = set(self._channel_ids) if self._channel_ids else None
        segment_freq_span = rbw_settings[2]

        for count, (chan_id, (start_hz, _center_hz, end_hz)) in enumerate(bw_by_channel.items()):

            if channel_filter and chan_id not in channel_filter:
                continue

            if self._test_mode and count > 1:
                self.logger.warning("Test mode active: processing only first 2 channels.")
                break

            capture_parameter = SpecAnCapturePara(
                inactivity_timeout        = inactivity_timeout,
                first_segment_center_freq = FrequencyHz(start_hz),
                last_segment_center_freq  = FrequencyHz(end_hz),
                segment_freq_span         = FrequencyHz(segment_freq_span),
                num_bins_per_segment      = num_bins_per_segment,
                noise_bw                  = noise_bw,
                window_function           = WindowFunction.HANN,
                num_averages              = number_of_averages,
                spectrum_retrieval_type   = spectrum_retrieval_type,
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

# FILE: tools/agent-review/2026-01-29-spectrum-analyzer-friendly-capture.review.md
## Agent Review Bundle Summary
- Goal: Cap spectrum analyzer averages at 1 and honor channel_id filters for OFDM/SC-QAM spectrum capture.
- Changes: Capped spectrum analyzer averages; added channel_id filtering in OFDM/SC-QAM analyzers and router; added tests for averages cap and channel filter.
- Files: src/pypnm/api/routes/common/extended/common_measure_service.py, src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/router.py, src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/service.py, tools/agent-review/2026-01-29-spectrum-analyzer-friendly-capture.review.md, tests/test_spectrum_analyzer_averages_cap.py, tests/test_spectrum_analyzer_channel_filter.py
- Tests: ruff check src; pytest -q
- Notes: pytest skips hardware integration tests.

# FILE: src/pypnm/api/routes/common/extended/common_measure_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
import math
import os
import shutil
import time
from enum import Enum, auto
from pathlib import Path
from typing import TypeAlias, cast

from pypnm.api.routes.common.classes.analysis.analysis import SpecAnCapturePara
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
    UpstreamOfdmaParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    CommonMessagingService,
    MessageResponse,
)
from pypnm.api.routes.common.extended.types import CommonMessagingServiceExtension as CMSE
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_config_manager import PnmConfigManager
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import (
    DocsPnmBulkFileUploadStatus,
    DocsPnmCmCtlStatus,
    FecSummaryType,
)
from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsConstDispMeasEntry import (
    DocsPnmCmDsConstDispMeasEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsHistEntry import DocsPnmCmDsHistEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmFecEntry import DocsPnmCmDsOfdmFecEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmModProfEntry import (
    DocsPnmCmDsOfdmModProfEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmRxMerEntry import (
    DocsPnmCmDsOfdmRxMerEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmOfdmChanEstCoefEntry import (
    DocsPnmCmOfdmChanEstCoefEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmUsPreEqEntry import DocsPnmCmUsPreEqEntry
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.ftp.ftp_connector import FTPConnector
from pypnm.lib.host_endpoint import HostEndpoint
from pypnm.lib.inet import Inet
from pypnm.lib.ping import Ping
from pypnm.lib.ssh.ssh_connector import SSHConnector
from pypnm.lib.tftp.tftp_connector import TFTPConnector
from pypnm.lib.types import ChannelId, FileNameStr, InterfaceIndex, TransactionId, HostNameStr
from pypnm.lib.utils import Generate
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import (
    DocsIf3CmSpectrumAnalysisCtrlCmd,
    SpectrumRetrievalType,
    WindowFunction,
)
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.snmp.modules import DocsisIfType
from pypnm.snmp.snmp_v2c import Snmp_v2c
from pypnm.api.routes.common.extended.types import CommonMessagingServiceExtension as CMSE


class MeasureServiceReturnTypes(Enum):
    BASE_MODEL = auto()
    DICT = auto()

MeasurementEntry: TypeAlias =   DocsPnmCmOfdmChanEstCoefEntry   | \
                                DocsPnmCmDsConstDispMeasEntry   | \
                                DocsPnmCmDsOfdmRxMerEntry       | \
                                DocsPnmCmUsPreEqEntry           | \
                                DocsPnmCmDsHistEntry            | \
                                DocsPnmCmDsOfdmFecEntry         | \
                                DocsPnmCmDsOfdmModProfEntry     | \
                                DocsIf3CmSpectrumAnalysisEntry

class CommonMeasureService(CommonMessagingService):
    SPECTRUM_ANALYZER_AVERAGES_CAP: int = 1
    """
    Base service class for executing common Proactive Network Maintenance (PNM) measurement tests.

    Parameters:
        pnm_test_type (DocsPnmCmCtlTest): The type of PNM test to execute.
        cable_modem (CableModem): The cable modem instance used for the test.
        tftp_servers (Inet,Inet): (IPv4,IPv6)
        tftp_path (str, optional): The path on the TFTP server where test result files are stored. Default is an empty string.
        snmp_write_community (str, optional): The SNMP community string for write access. Default is "private".
        **extra_options (dict, optional): Additional keyword arguments specific to the test type, such as:
            - fec_summary_type (FecSummaryType): Required for tests involving FEC summary metrics.
            - Other parameters based on the test type.

    Notes:
        This class serves as a base for test-specific measurement operations. Subclasses should implement
        specific tests such as:
        - Downstream OFDM codeword error rate
        - RXMER per subcarrier
        - FEC statistics, etc.

        It is expected that subclasses will extend this service and provide the necessary implementations for
        executing and processing PNM measurements based on the test type and parameters.
    """
    def __init__(self, pnm_test_type:DocsPnmCmCtlTest,
                 cable_modem: CableModem,
                 tftp_servers: tuple[Inet,Inet],
                 tftp_path: str = "",
                 snmp_write_community: str = "private",
                 **extra_options) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.propagate = True

        self.pnm_filename:list[str]

        self._transactionId_pnmFile: dict[str, str] = {}
        self.pnm_test_type:DocsPnmCmCtlTest         = pnm_test_type
        self.cm:CableModem                          = cable_modem
        self.tftp_servers:tuple[Inet,Inet]          = tftp_servers
        self.tftp_path:str                          = tftp_path
        self.snmp_write_community:str               = snmp_write_community
        self.extra_options                          = extra_options
        self.config_mgr:ConfigManager               = ConfigManager()
        self.log_prefix:str                         = f"MAC: {self.cm.get_mac_address} - INET: {self.cm.get_inet_address}"
        self.pnm_dir                                = PnmConfigManager.get_save_dir()
        self.pnm_local_dir                          = SystemConfigSettings.pnm_dir
        self._capture_parameter:SpecAnCapturePara   = SpecAnCapturePara()

        # Initialize default spectrum capture parameters
        self._capture_parameter.spectrum_retrieval_type = SpectrumRetrievalType.UNKNOWN

        if self.extra_options:
            self.logger.info(f"{self.log_prefix} - OPTIONS: {self.extra_options}")
            self._preload_interface_parameters()

        self._precheck()

    def _precheck(self) -> None:
        """
        Perform pre-check and ensure the save directory exists.
        """
        self.logger.debug(f'PreCheck: SaveDir: {self.pnm_dir}')
        save_path = Path(self.pnm_dir)
        save_path.mkdir(parents=True, exist_ok=True)

    def _preload_interface_parameters(self) -> None:
        """
        Load optional interface parameters from extra_options dictionary.
        If not present, sets interface_parameters to None.
        """
        self.interface_parameters = self.extra_options.get("interface_parameters", None)

    def setSpectrumCaptureParameters(self, capture_parameter:SpecAnCapturePara) -> None:
        """
        Set the spectrum capture parameters for the measurement.

        TODO: This method may be deprecated in favor of passing parameters directly during initialization.

        Args:
            capture_parameter (SpecAnCapturePara): The spectrum capture parameters.
        """
        self._capture_parameter = capture_parameter

    def getSpectrumCaptureParameters(self) -> SpecAnCapturePara:
        """
        Get the current spectrum capture parameters.

        Returns:
            SpecAnCapturePara: The current spectrum capture parameters.
        """
        return self._capture_parameter

    async def set_and_go(self, interface_parameters: DownstreamOfdmParameters | UpstreamOfdmaParameters | None = None ,
                         max_wait_count: int = 5,) -> MessageResponse:
        """
        Trigger PNM file capture and retrieval based on direction-specific parameters.

        Args:
            interface_parameters (InterfaceParameters, optional):
                The configuration specifying the direction of capture:
                - `DownstreamOfdmParameters`: For OFDM downstream channels.
                - `UpstreamOfdmaParameters`: For OFDMA upstream channels.
                If `None` (default), all channels will be captured.

            max_wait_count (int, optional):
                Maximum seconds to wait for measurement readiness. Default is 5.

        Returns:
            MessageResponse: Result indicating success or failure of the operation.
        """

        ##########################################################
        # Verify that we can connect to the CM via Ping and SNMP
        ##########################################################

        if not self.is_ping_reachable():
            self.logger.error(f"{self.log_prefix} - Unreachable via PING")
            return self.build_send_msg(ServiceStatusCode.UNREACHABLE_PING)

        if not await self.is_snmp_ready():
            self.logger.error(f"{self.log_prefix} - Unreachable via SNMP")
            return self.build_send_msg(ServiceStatusCode.UNREACHABLE_SNMP)

        #########################################################################
        #                   Spectrum Analysis SNMP Return                       #
        #########################################################################

        if self.getSpectrumCaptureParameters().spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.debug(f"{self.log_prefix} - Performing Spectrum Analysis SNMP Amplitude Data")

            #Set Spectrum Analyzer
            __status = await self._generic_spectrum_analyzer_operation()

            if __status[0] != ServiceStatusCode.SUCCESS:
               self.logger.error(f"{self.log_prefix} - Unable to set Spectrum Analyzer Settings")
               return self.build_send_msg(ServiceStatusCode.SPEC_ANALYZER_SET_CONFIG_ERROR)

            # This is a blocking method, it will return SUCCESS or wait till timeout to return an ERROR
            status = await self._check_spectrum_amplitude_data_status()

            if status == ServiceStatusCode.SUCCESS:
                self.logger.info(f"{self.log_prefix} - Spectrum Amplitude Data is READY, collecting amplitude data, may take a while...")
                amp_data: bytes = await self.cm.getSpectrumAmplitudeData()
                self.logger.info(f"{self.log_prefix} - Spectrum Amplitude Data collection COMPLETE, total bytes: {len(amp_data)}.")
                #################################################################################################
                # Build binary filename and save file - START
                #################################################################################################
                filename = await self._pnm_file_generator(DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA)
                tx_id = self._get_transaction_id_by_filename(filename)
                if not tx_id:
                    self.logger.error(f"{self.log_prefix} - Unable to find Transaction ID for PNM filename: {filename}")
                    return self.build_send_msg(ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND)

                pnm_dir = SystemConfigSettings.pnm_dir()
                fpath = f"{pnm_dir}/{filename}"
                self.logger.debug(f'SpectrumAmplitudeData: - FNAME: {filename} - Length:{len(amp_data)} - TransactionID: {tx_id}')

                FileProcessor(fpath).write_file(amp_data)
                
                #################################################################################################
                # Build binary filename and save file - END
                #################################################################################################
                capture_para:SpecAnCapturePara = self.getSpectrumCaptureParameters()
                self.build_transaction_msg_extension(tx_id, 
                                                     filename, 
                                                     extension={f'{CMSE.SPECTRUM_ANALYSIS_SNMP_CAPTURE_PARAMETER}': capture_para.model_dump()})

            return self.build_send_msg(status)

        #########################################################################
        # Ensure CM Inet and TFTP server address use the same IP version
        #
        # The TFTP server address must match the IP version (IPv4 or IPv6) used
        # by the Cable Modem (CM). By default, we assume IPv4.
        #
        # If the CM's IP address is IPv6 and matches the version of the
        # secondary TFTP server entry, we switch to using the IPv6 TFTP server.
        #
        # TODO: Enhance this logic to support dual-stack (dual-home) cable modems,
        # where both IPv4 and IPv6 may be valid simultaneously.
        #########################################################################

        self.logger.info(f'{self.log_prefix} - TFTP-SERVERS: ({self.tftp_servers[0]} | {self.tftp_servers[1].inet})')

        # Default to using the IPv4 TFTP server
        tftp_server: Inet = self.tftp_servers[0]

        # Switch to IPv6 TFTP server if CM uses IPv6
        if self.cm.same_inet_version(self.tftp_servers[1]):
            tftp_server = self.tftp_servers[1]

        # Attempt to configure the CM with the selected TFTP server and path
        if not await self.cm.setDocsPnmBulk(tftp_server.inet, self.tftp_path):
            self.logger.error(
                f"{self.log_prefix} - Unable to set TFTP server {tftp_server.inet} "
                f"or TFTP path: {self.tftp_path}")
            return self.build_send_msg(ServiceStatusCode.TFTP_SERVER_PATH_SET_FAIL)

        ##############################################################################################
        # This section is determine by the direction due to which interface and type we are accessing
        ##############################################################################################

        status_index_channelId = await self._get_indexes_via_pnm_test_type(interface_parameters)
        self.logger.info(f'{self.log_prefix} - Index/ChannelID List: {status_index_channelId[1]}')
        if status_index_channelId[0] != ServiceStatusCode.SUCCESS or status_index_channelId[1] is None:
            self.logger.error(f'{self.log_prefix} - Unable to aquire index from ChannelID, reason: {status_index_channelId[0]}')
            return self.build_send_msg(status_index_channelId[0])

        ##############################################################################################
        # This section runs through all the indexes, build PNM file, run measurement and check status
        ##############################################################################################
        index_channelId: list[tuple[InterfaceIndex, ChannelId]] = status_index_channelId[1]
        return self.build_send_msg(await self._pnm_measure_status_and_pnm_file_transfer(index_channelId, max_wait_count))

    def getInterfaceParameters(self,
        interface_type: DocsisIfType) -> DownstreamOfdmParameters | UpstreamOfdmaParameters:
        """
        Instantiate and return the PNM test parameters for the specified DOCSIS interface.

        Args:
            interface_type (DocsisIfType):
                The DOCSIS interface type:
                - `DocsisIfType.docsOfdmDownstream` → returns DownstreamOfdmParameters
                - `DocsisIfType.docsOfdmaUpstream`  → returns UpstreamOfdmaParameters

        Returns:
            Union[DownstreamOfdmParameters, UpstreamOfdmaParameters]:
                A parameters object tailored to the requested interface.

        Raises:
            ValueError: If `interface_type` is not OFDM downstream or OFDMA upstream.
        """
        if interface_type == DocsisIfType.docsOfdmDownstream:
            return DownstreamOfdmParameters()
        if interface_type == DocsisIfType.docsOfdmaUpstream:
            return UpstreamOfdmaParameters()

        raise ValueError(
            f"Unsupported interface type: {interface_type!r}. "
            "Expected docsOfdmDownstream or docsOfdmaUpstream."
        )

    def is_ping_reachable(self) -> bool:
        """
        Check if the cable modem is reachable via ICMP ping.

        Returns:
            bool: True if the modem responds to ping, False otherwise.
        """
        return self.cm.is_ping_reachable()

    async def is_snmp_ready(self) -> bool:
        """
        Asynchronously check if the cable modem is accessible via SNMP.

        Returns:
            bool: True if the modem responds to SNMP queries, False otherwise.
        """
        return await self.cm.is_snmp_reachable()

    async def _filter_measurement_entries(
        self,
        entries: list[MeasurementEntry],
        channel_ids: list[ChannelId] | None,
    ) -> list[MeasurementEntry]:
        if not channel_ids:
            return entries

        channel_id_set = {int(channel_id) for channel_id in channel_ids}
        index_set: set[int] = set()

        if self.pnm_test_type in (
            DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
            DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF,
            DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
            DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
            DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        ):
            idx_channel_id = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()
            index_set = {int(idx) for idx, channel_id in idx_channel_id if int(channel_id) in channel_id_set}

        elif self.pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:
            idx_channel_id = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
            index_set = {int(idx) for idx, channel_id in idx_channel_id if int(channel_id) in channel_id_set}

        filtered: list[MeasurementEntry] = []
        for entry in entries:
            if isinstance(entry, (DocsPnmCmDsHistEntry, DocsIf3CmSpectrumAnalysisEntry)):
                continue
            if index_set:
                if int(entry.index) in index_set:
                    filtered.append(entry)
                continue
            if not hasattr(entry, "channel_id"):
                continue
            if int(entry.channel_id) in channel_id_set:
                filtered.append(entry)
        return filtered

    async def getPnmMeasurementStatistics(
        self,
        channel_ids: list[ChannelId] | None = None,
    ) -> list[MeasurementEntry]:
        """
        Retrieve PNM measurement entries for the currently configured `pnm_test_type`.

        Returns
        -------
        List[MeasurementEntry]
            A (possibly empty) list of model instances corresponding to the active
            test type:

            - DS_OFDM_CHAN_EST_COEF             → List[DocsPnmCmOfdmChanEstCoefEntry]
            - DS_CONSTELLATION_DISP             → List[DocsPnmCmDsConstDispMeasEntry]
            - DS_OFDM_RXMER_PER_SUBCAR          → List[DocsPnmCmDsOfdmRxMerEntry]
            - US_PRE_EQUALIZER_COEF             → List[DocsPnmCmUsPreEqEntry]
            - DS_HISTOGRAM                      → List[DocsPnmCmDsHistEntry]
            - DS_OFDM_FEC_SUMMARY               → List[DocsPnmCmDsOfdmFecEntry]
            - DS_OFDM_MODULATION_PROFILE        → List[DocsPnmCmDsOfdmModProfEntry]
            - SPECTRUM_ANALYZER                 → List[DocsIf3CmSpectrumAnalysisEntry]
            - SPECTRUM_ANALYZER_SNMP_AMP_DATA   → List[DocsIf3CmSpectrumAnalysisEntry]

            For other (stub/unsupported) test types, an empty list is returned.

        Notes
        -----
        - This method performs no aggregation; it returns the raw per-entry models
          fetched from the cable modem for the selected measurement type.
        - For strict typing, concrete lists are cast to `List[MeasurementEntry]`
          at return points (because `List` is invariant in the type system).
        - If `channel_ids` is provided and not empty, results are filtered to only
          include entries whose `channel_id` is in the list.
        """
        entries: list[MeasurementEntry] = []

        if self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            self.logger.debug(f"{self.log_prefix} - Running SPECTRUM_ANALYZER")
            concrete = await self.cm.getDocsIf3CmSpectrumAnalysisEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF:
            self.logger.debug(f"{self.log_prefix} - Running OFDM Channel Estimation Coefficient collection")
            concrete = await self.cm.getDocsPnmCmOfdmChanEstCoefEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP:
            self.logger.debug(f"{self.log_prefix} - Running OFDM Constellation Display collection")
            concrete = await self.cm.getDocsPnmCmDsConstDispMeasEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR:
            self.logger.debug(f"{self.log_prefix} - Running RXMER entry collection")
            concrete = await self.cm.getDocsPnmCmDsOfdmRxMerEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE:
            self.logger.debug(f"{self.log_prefix} - Running DS_OFDM_CODEWORD_ERROR_RATE")
            concrete = await self.cm.getDocsPnmCmDsOfdmFecEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM:
            self.logger.debug(f"{self.log_prefix} - Running DS_HISTOGRAM")
            concrete = await self.cm.getDocsPnmCmDsHistEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:
            self.logger.debug(f"{self.log_prefix} - Running Upstream Pre-Equalization entry collection")
            concrete = await self.cm.getDocsPnmCmUsPreEqEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE:
            self.logger.debug(f"{self.log_prefix} - Running DS_OFDM_MODULATION_PROFILE")
            concrete = await self.cm.getDocsPnmCmDsOfdmModProfEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA:
            self.logger.debug(f"{self.log_prefix} - Running SPECTRUM_ANALYZER_SNMP_AMP_DATA")
            concrete = await self.cm.getDocsIf3CmSpectrumAnalysisEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_SYMBOL_CAPTURE:
            self.logger.warning(f"{self.log_prefix} - Stub handler: DS_OFDM_SYMBOL_CAPTURE")

        elif self.pnm_test_type == DocsPnmCmCtlTest.LATENCY_REPORT:
            self.logger.warning(f"{self.log_prefix} - Stub handler: LATENCY_REPORT")

        else:
            self.logger.warning(f"{self.log_prefix} - Unknown PNM test type: {self.pnm_test_type}")

        return entries

    ###################
    # Private Methods #
    ###################

    async def _get_and_move_pnm_file(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Retrieves and moves the specified PNM file based on the configured retrieval method.

        This method delegates the file retrieval operation to a protocol-specific handler method
        depending on the configuration defined under `PnmFileRetrieval.method`. 
        Supported methods include: "local", "tftp", "sftp"
        # TODO: Need to implement, not sure if we need to: "ftp", "http", and "https".

        Configuration keys used:
            - PnmFileRetrieval.method: The file retrieval method to use (e.g., "local", "tftp", etc.).
            - PnmFileRetrieval.retries: Optional number of retries for retrieval attempts (currently unused here).

        Args:
            pnm_file_name (str): The name of the file to retrieve and move.

        Returns:
            bool: True if the file was successfully retrieved and moved; False otherwise.
        """
        method = SystemConfigSettings.retrieval_method()
        self.logger.info(f"{self.log_prefix} - Retrieval method: {method}")

        try:
            if method == "local":
                return await self._handle_local_fetch(pnm_file_name)
            elif method == "tftp":
                return self._handle_tftp_fetch(pnm_file_name)
            elif method == "ftp":
                return self._handle_ftp_fetch(pnm_file_name)
            elif method == "sftp":
                return self._handle_sftp_fetch(pnm_file_name)
            elif method == "http":
                return self._handle_http_fetch(pnm_file_name)
            elif method == "https":
                return self._handle_https_fetch(pnm_file_name)
            else:
                self.logger.error(f"{self.log_prefix} - Unsupported retrieval method: {method}")
                return ServiceStatusCode.FILE_RETRIEVAL_TYPE_INVALID

        except Exception as e:
            self.logger.exception(f"{self.log_prefix} - File retrieval failed: {e}")
            return ServiceStatusCode.PNM_FILE_RETRIEVAL_ERROR

    async def _get_indexes_via_pnm_test_type(self, ifParameters: DownstreamOfdmParameters | UpstreamOfdmaParameters | None = None
                                             ) -> tuple[ServiceStatusCode, list[tuple[InterfaceIndex, ChannelId]] | None]:
        """
        Determines the appropriate interface indexes and channel IDs to target for a given PNM test type.

        Depending on the configured PNM test type, this method selects the relevant interface and filters the index/ChannelID
        tuples based on user-specified parameters.

        Args:
            interface_parameters (Optional[InterfaceParameters]): Parameters specifying interface type ("ofdm" or "ofdma")
                and optionally a list of channel IDs to filter. If not provided, default parameters are selected based on test type.

        Returns:
            Tuple[ServiceStatusCode, Optional[List[Tuple[int, int]]]]:
                A status code indicating success or reason for failure, and a list of (index, channelId) tuples.
        """

        if ifParameters is None:
            ifParameters = DownstreamOfdmParameters()

        if not ifParameters:
            ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmDownstream)

        if self.pnm_test_type in (DocsPnmCmCtlTest.DS_HISTOGRAM, DocsPnmCmCtlTest.LATENCY_REPORT):
            idx:list[InterfaceIndex] = await self.cm.getIfTypeIndex(DocsisIfType.docsCableMaclayer)
            return ServiceStatusCode.SUCCESS, [(idx[0], ChannelId(0))]

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            return ServiceStatusCode.SUCCESS, [(InterfaceIndex(0), ChannelId(0))]

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA:
            return ServiceStatusCode.SUCCESS, [(InterfaceIndex(0), ChannelId(0))]

        elif self.pnm_test_type in (DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
                                    DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF,
                                    DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
                                    DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
                                    DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR):

            if not ifParameters:
                ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmDownstream)

        elif self.pnm_test_type in (DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF,):
            ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmaUpstream)
            self.logger.debug(f'{DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF} Measurement - IfParameters: {ifParameters.model_dump()}')

        '''
        There is redundant code, but incase I may need to change due to
        change of requiments depending on Downstream vs. Upstream

        TODO: lol, I am sure I will not revisit, but OK for now.
        '''
        if ifParameters.type == "ofdm":
            channel_id_list = ifParameters.channel_id
            idx_channelId = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()

            if not idx_channelId:
                self.logger.warning("No OFDM channel data found.")
                return ServiceStatusCode.NO_OFDMA_CHAN_ID_INDEX_FOUND, []

            if channel_id_list:
                filtered = [tpl for tpl in idx_channelId if tpl[1] in channel_id_list]
                self.logger.debug(f'Downstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
                return ServiceStatusCode.SUCCESS, filtered

            self.logger.info(f'Downstream: {ifParameters.type} -> IDX,CHAN_ID: {idx_channelId}')

            return ServiceStatusCode.SUCCESS, idx_channelId

        elif ifParameters.type == "ofdma":
            channel_id_list = ifParameters.channel_id
            idx_channelId = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
            if not idx_channelId:
                self.logger.warning("No OFDMA channel found.")
                return ServiceStatusCode.NO_OFDMA_CHAN_ID_INDEX_FOUND, []

            if channel_id_list:
                filtered = [tpl for tpl in idx_channelId if tpl[1] in channel_id_list]
                self.logger.info(f'Upstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
                return ServiceStatusCode.SUCCESS, filtered

            self.logger.info(f'Upstream: {ifParameters.type} -> IDX,CHAN_ID: {idx_channelId}')

        return ServiceStatusCode.SUCCESS, idx_channelId

    async def _pnm_measure_status_and_pnm_file_transfer(self, idx_channelId:list[tuple[InterfaceIndex, ChannelId]], max_wait_count:int) -> ServiceStatusCode:
        """
        Set and monitor the OFDM measurement test for specified (index, PLC) tuples.

        For each (index, PLC) pair:
            - Initiates the PNM test using SNMP.
            - Waits for the test status to reach READY.
            - Monitors for the measurement status to become SAMPLE_READY.
            - Retrieves the resulting PNM file and stores it locally.

        Args:
            idx_channelId (Tuple[int, int]): A list of tuples where each tuple consists of
                the SNMP interface index and the corresponding PLC (center frequency).
            max_wait_count (int): Maximum number of seconds to wait for SAMPLE_READY status.

        Returns:
            ServiceStatusCode: SUCCESS if all steps completed successfully,
                otherwise a specific error status (e.g., if the file couldn't be retrieved
                or the measurement status did not become SAMPLE_READY).
        """
        for interface_index, channel_id in idx_channelId:

            #######################################################################
            # This sets the Measurement Table/Row for the specific PNM Measurement
            #######################################################################
            ctl_measure_status:tuple[ServiceStatusCode, list[FileNameStr]] = \
                await self._setDocsPnmCmMeasureTest(self.pnm_test_type, interface_index, channel_id)
            
            if ctl_measure_status[0] != ServiceStatusCode.SUCCESS:
                return ctl_measure_status[0]

            pnm_filenames = ctl_measure_status[1]
            self.logger.info(f'{self.log_prefix} - PNM File(s) -> {pnm_filenames}')

            count=1
            while True:
                cm_ctl_status:DocsPnmCmCtlStatus = await self.cm.getDocsPnmCmCtlStatus()
                self.logger.info(f"{self.log_prefix} - PNM status: {str(cm_ctl_status).upper()} - count: {count}")
                if cm_ctl_status == DocsPnmCmCtlStatus.TEST_IN_PROGRESS:
                    count += 1
                    await asyncio.sleep(1)
                    continue

                if cm_ctl_status == DocsPnmCmCtlStatus.READY:
                    break

                if cm_ctl_status == DocsPnmCmCtlStatus.TEMP_REJECT:
                    break

                if cm_ctl_status == DocsPnmCmCtlStatus.SNMP_ERROR:
                    break

            self.logger.debug(f"{self.log_prefix} - Checking Measurement Status for {self.pnm_test_type} @ IDX: {interface_index}")

            wait_count = 0
            def extract_idx(idx):
                return idx[0] if isinstance(idx, list) and idx else idx

            while wait_count < max_wait_count:
                meas_status = await self.cm.getPnmMeasurementStatus(self.pnm_test_type, extract_idx(interface_index))
                self.logger.info(f"{self.log_prefix} - MeasureStatus: {meas_status.name}")
                if meas_status == MeasStatusType.SAMPLE_READY:
                    break
                await asyncio.sleep(1)
                wait_count += 1

            else:
                self.logger.error(f"{self.log_prefix} - SAMPLE_READY not reached for ChannelID {channel_id}")
                return ServiceStatusCode.NOT_READY_AFTER_FILE_CAPTURE

            #Multiple PNM files for special cases
            for pnm_fname in pnm_filenames:

                status:ServiceStatusCode = await self._check_and_wait_for_tftp_upload(FileNameStr(pnm_fname))

                if status != ServiceStatusCode.SUCCESS:
                    self.logger.error(f"{self.log_prefix} - Unable to Upload PNM File to TFTP({status})")
                    return status

                # Get and copy PNM file to local data directory
                retrieval_status = await self._get_and_move_pnm_file(FileNameStr(pnm_fname))
                if retrieval_status != ServiceStatusCode.SUCCESS:
                    self.logger.error(
                        f"{self.log_prefix} - Unable to copy PNM file to local {self.pnm_dir} dir "
                        f"(status={retrieval_status})")
                    return retrieval_status

                # Find Transaction ID via filename
                trans_id = self._get_transaction_id_by_filename(pnm_fname)
                if not trans_id:
                    self.logger.error(f"{self.log_prefix} - Unable to find Transaction ID for PNM filename: {pnm_fname}")
                    return ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND
                
                self.logger.debug(f'{self.log_prefix} - TransID: {trans_id} -> Filename: {pnm_fname}')
                self.build_transaction_msg(trans_id, pnm_fname)

        return ServiceStatusCode.SUCCESS

    async def _check_and_wait_for_tftp_upload(self, filename: str, max_wait_count: int = 5) -> ServiceStatusCode:
        """
        Waits for a PNM file to be uploaded via TFTP by polling the upload status.

        Args:
            filename (str): The name of the file being uploaded.
            max_wait_count (int): Maximum number of seconds to wait before timing out.

        Returns:
            ServiceStatusCode: SUCCESS if upload completed, failure code otherwise.
        """
        wait_count = 0

        while wait_count < max_wait_count:
            try:
                status = await self.cm.getBulkFileUploadStatus(filename)
            except Exception as e:
                self.logger.error(f"{self.log_prefix} - Error checking upload status for '{filename}': {e}")
                return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

            if status == DocsPnmBulkFileUploadStatus.UPLOAD_COMPLETED:
                self.logger.info(f"{self.log_prefix} - File '{filename}' uploaded successfully.")
                return ServiceStatusCode.SUCCESS

            if status == DocsPnmBulkFileUploadStatus.ERROR:
                self.logger.error(f"{self.log_prefix} - Device reported ERROR for file upload '{filename}'.")
                return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

            self.logger.debug(
                f"{self.log_prefix} - Waiting for file '{filename}' to upload "
                f"(status={status.name}, wait_count={wait_count})"
            )

            await asyncio.sleep(1)
            wait_count += 1

        self.logger.error(f"{self.log_prefix} - TFTP file '{filename}' upload timed out after {max_wait_count} seconds.")
        return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

    async def _setDocsPnmCmMeasureTest(self, pnm_test_type:DocsPnmCmCtlTest,
                                       interface_index:int, channel_id:ChannelId) -> tuple[ServiceStatusCode, list[FileNameStr]]:
        """
        Configure and trigger a specific PNM (Proactive Network Maintenance) measurement
        test on a cable modem based on the test type.

        Depending on the `pnm_test_type`, this method:
        - Generates appropriate output file names.
        - Uses SNMP to set the modem to collect specific diagnostic data.
        - Handles various DOCSIS downstream and upstream tests, including:
            - US Pre-Equalizer Coefficients (requires two files per interface: pre-eq and last pre-eq)
            - DS OFDM RxMER per Subcarrier
            - DS OFDM Codeword Error Rate
            - DS OFDM Channel Estimation Coefficients
            - DS Constellation Display
            - DS Histogram
            - DS OFDM Modulation Profile
            - Spectrum Analyzer Scan

        Parameters:
            pnm_test_type (DocsPnmCmCtlTest): Enum value indicating the PNM test to perform.
            interface_index (int): The SNMP index for the OFDM channel (usually the interface index).
            channel_id (int): The channel ID associated with the modem interface.

        Returns:
            Tuple[ServiceStatusCode, List[str]]: Status of the operation and list of generated file names.
        """
        pnm_files: list[FileNameStr] = []

        if pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:

            # Pre-Eq and Last Pre-EQ (2 files)
            pre_eq_filename         = await self._pnm_file_generator(self.pnm_test_type, str(channel_id))
            last_pre_eq_filename    = await self._pnm_file_generator(self.pnm_test_type, f'last_pre-eq_{str(channel_id)}')

            self.logger.info(f'{self.log_prefix} - Setting {self.pnm_test_type} for ChannelID: {channel_id} "'
                             f'@ IDX: {interface_index} -> FN(): {pre_eq_filename}, FN(last): {last_pre_eq_filename}')

            self.logger.info(f'{self.log_prefix} - Performing US_PRE_EQUALIZER_COEF measurement on IDX: ({interface_index})')
            if not await self.cm.setDocsPnmCmUsPreEq(ofdma_idx              =   interface_index,
                                                     filename               =   pre_eq_filename,
                                                     last_pre_eq_filename   =   last_pre_eq_filename):
                self.logger.error(f"{self.log_prefix} - Upstream OFDMA Pre-Equalization is Not Avalaible")
                return ServiceStatusCode.FILE_SET_FAIL, []

            #Append files for later fetching
            pnm_files.extend([pre_eq_filename, last_pre_eq_filename])

        else:
            #The remaining PNM Measuresurement are single PNM file
            pnm_filename = await self._pnm_file_generator(self.pnm_test_type, str(channel_id))
            self.logger.debug(f'{self.log_prefix} - Setting {self.pnm_test_type} for ChannelID: {channel_id} @ IDX: {interface_index} -> FN: {pnm_filename}')
            pnm_files.append(pnm_filename)

            if pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR:

                if not await self.cm.setDocsPnmCmDsOfdmRxMer(ofdm_idx=interface_index, rxmer_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE:

                fst = self.extra_options.get("fec_summary_type", FecSummaryType.TEN_MIN)

                if not await self.cm.setDocsPnmCmDsOfdmFecSum(ofdm_idx=interface_index, fec_sum_file_name=pnm_filename, fec_sum_type=fst):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF:

                if not await self.cm.setDocsPnmCmOfdmChEstCoef(ofdm_idx=interface_index, chan_est_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP:
                # OFDM Downstream Constellation Display setup
                # Extra SNMP options may include:
                #   - modulation_offset: Optional[int]
                #   - num_sample_symb: Optional[int]
                if not await self.cm.setDocsPnmCmDsConstDisp(
                    ofdm_idx                =   interface_index,
                    const_disp_name         =   pnm_filename,
                    modulation_order_offset =   self.extra_options.get('modulation_order_offset', 0),
                    number_sample_symbol    =   self.extra_options.get('number_sample_symbol', 0)
                ):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM:
                sample_duration = self.extra_options.get("histogram_sample_duration", 10)
                if not await self.cm.setDocsPnmCmDsHist(ds_histogram_file_name=pnm_filename, timeout=sample_duration):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE:

                if not await self.cm.setDocsPnmCmDsOfdmModProf(ofdm_idx=interface_index, mod_prof_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
                #Created generic to be used for PNM File and SNMP Return data
                 __status = await self._generic_spectrum_analyzer_operation(filename=pnm_filename)
                 if __status[0] != ServiceStatusCode.SUCCESS:
                    return __status

        return ServiceStatusCode.SUCCESS, pnm_files

    async def _check_spectrum_amplitude_data_status(self, timeout_seconds: int = 300) -> ServiceStatusCode:
        """
        Polls the cable modem for spectrum amplitude data availability within a timeout period.

        This method repeatedly checks if `docsIf3CmSpectrumAnalysisMeasAmplitudeData` is present
        on the modem, and returns a success or timeout status accordingly.

        Args:
            timeout_seconds (int): Maximum number of seconds to wait before timing out. Default is 300.

        Returns:
            ServiceStatusCode:
                - SUCCESS if data becomes available within the timeout period.
                - SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT if the timeout is exceeded.
        """
        t_start = time.time()

        while True:
            if await self.cm.isAmplitudeDataPresent():
                return ServiceStatusCode.SUCCESS
            now:int = math.floor(time.time() - t_start)

            if now >= timeout_seconds:
                self.logger.warning(f'{self.log_prefix} - Timeout for Amplitude Data ({now} of {timeout_seconds} seconds)')
                return ServiceStatusCode.SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT

            self.logger.info(f'{self.log_prefix} - Waiting for Amplitude Data ({now} of {timeout_seconds})')

            await asyncio.sleep(1)

    async def _handle_local_fetch(self, pnm_file_name: str) -> ServiceStatusCode:
        """
        Handles copying a specified PNM file from a local source directory to a configured save directory.

        This method looks up the source and destination paths from the application's system configuration
        (under the "PnmFileRetrieval" section) and attempts to copy the file named `pnm_file_name`
        from the source directory to the save directory.

        Configuration keys used:
            - PnmFileRetrieval.local.src_dir: Source directory where the PNM file resides.
            - PnmFileRetrieval.save_dir: Destination directory where the file should be saved.

        Args:
            pnm_file_name (str): The name of the file to copy.

        Returns:
            bool: True if the file was successfully copied; False otherwise.
        """

        src_dir = SystemConfigSettings.local_src_dir()

        self.logger.info(
            f'{self.log_prefix} - Local Copy - SRC: {src_dir} - SAVE: {self.pnm_dir} - FN: {pnm_file_name}'
        )

        if not os.path.isdir(src_dir) or not os.path.isdir(self.pnm_dir):
            self.logger.error(f"{self.log_prefix} - Invalid source or destination directory")
            return ServiceStatusCode.LOCAL_FETCH_FAILURE

        while True:
            await asyncio.sleep(1)
            file_found = False
            for filename in os.listdir(src_dir):
                if filename == pnm_file_name:
                    file_found = True
                    src_path = os.path.join(src_dir, filename)
                    dest_path = os.path.join(self.pnm_dir, filename)
                    try:
                        shutil.copy2(src_path, dest_path)
                        self.logger.debug(f"{self.log_prefix} - Copied {filename} to {self.pnm_dir}")
                        return ServiceStatusCode.SUCCESS
                    except Exception as e:
                        self.logger.error(f"{self.log_prefix} - Copy failed for {filename}: {e}")
                        return ServiceStatusCode.LOCAL_FETCH_FAILURE

            if not file_found:
                self.logger.warning(f"{self.log_prefix} - File not found in source directory: {pnm_file_name}")

            return ServiceStatusCode.LOCAL_FETCH_FAILURE

    def _handle_sftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch a file from remote SFTP server.

        Args:
            pnm_file_name: Name of the file to fetch from remote server

        Returns:
            bool: True if file transfer successful, False otherwise
        """
        sys_config = SystemConfigSettings()

        self.logger.debug(f"{self.log_prefix} - SFTP: Connecting to: {sys_config.sftp_host()}")

        if self._ping_pnm_file_server(HostNameStr(sys_config.sftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for SFTP host: {sys_config.sftp_host()}")
            return ServiceStatusCode.SFTP_HOST_UNREACHABLE

        sftp = SSHConnector(
            hostname        =   sys_config.sftp_host(),
            username        =   sys_config.sftp_user(),
            port            =   sys_config.sftp_port())

        password_enc     = sys_config.sftp_password()
        private_key_path = sys_config.sftp_private_key_path()

        try:
            if not sftp.connect(password_enc     =   password_enc,
                                private_key_path =   private_key_path):
                self.logger.error(f'{self.log_prefix} - SFTP Connect Failure: Host: {sys_config.sftp_host()}')
                return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

            remote_file_path = f'{sys_config.sftp_remote_dir()}/{pnm_file_name}'
            if not sftp.receive_file(remote_path =   remote_file_path,
                                     local_path  =   sys_config.pnm_dir()):
                self.logger.error(
                    f'{self.log_prefix} - SFTP Receive File Error '
                    f'(SRC:{remote_file_path} DST: {sys_config.pnm_dir()})'
                )
                return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

            self.logger.info(f'{self.log_prefix} - Successfully fetched file: {pnm_file_name}')
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f'{self.log_prefix} - SFTP Fetch Exception: {e}')
            return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

        finally:
            sftp.disconnect()

    def _handle_tftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch the specified PNM file via TFTP.

        Assumes the following attributes on self:
        - self.pnm_local_dir (str)    # local directory to save the downloaded file
        - self.log_prefix (str)       # used for consistent logging

        TFTP settings are read from SystemConfigCommonSettings:
        - tftp_host (str)
        - tftp_port (int)
        - tftp_timeout (int)
        - tftp_remote_dir (str)   # remote directory where PNM files live (if applicable)
        """

        if self._ping_pnm_file_server(HostNameStr(SystemConfigSettings.tftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for TFTP host: {SystemConfigSettings.tftp_host()}")
            return ServiceStatusCode.TFTP_HOST_UNREACHABLE  

        try:
            connector = TFTPConnector(
                host    =   Inet(SystemConfigSettings.tftp_host()),
                port    =   int(str(SystemConfigSettings.tftp_port())))

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during TFTP connecting: {e}")
            return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

        try:

            self.logger.info(
                f"{self.log_prefix} - Starting TFTP download from "
                f"{SystemConfigSettings.tftp_host()}:{SystemConfigSettings.tftp_port()}"
            )

            # Build remote filename (some tftp servers require just the basename)
            remote_name = (
                f"{SystemConfigSettings.tftp_remote_dir().rstrip('/')}/{pnm_file_name}"
                if SystemConfigSettings.tftp_remote_dir() else
                pnm_file_name
            )
            local_path = os.path.join(SystemConfigSettings.pnm_dir(), pnm_file_name)

            success = connector.download_file(remote_name, local_path)

            if not success:
                self.logger.error(
                    f"{self.log_prefix} - TFTP download failed for '{remote_name}'"
                )
                return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

            self.logger.info(
                f"{self.log_prefix} - Successfully fetched '{pnm_file_name}' via TFTP"
            )
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during TFTP downloading: {e}")
            return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

    def _handle_ftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch the specified PNM file via FTP.

        Assumes the following attributes exist on self:
        - self.pnm_local_dir (str)    # local directory to save the downloaded file
        - self.log_prefix (str)       # used for consistent logging

        All FTP-specific settings are read from SystemConfigCommonSettings:
        - ftp_host (str)
        - ftp_port (int)
        - ftp_user (str)
        - ftp_password (str)
        - ftp_use_tls (bool)
        - ftp_timeout (int)
        - ftp_remote_dir (str)   # remote directory where PNM files live
        """
        sys_config = SystemConfigSettings()

        if self._ping_pnm_file_server(HostNameStr(SystemConfigSettings.ftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for FTP host: {SystemConfigSettings.ftp_host()}")
            return ServiceStatusCode.FTP_HOST_UNREACHABLE  

        try:
            connector = FTPConnector(
                host        =   str(sys_config.ftp_host()),
                port        =   int(str(sys_config.ftp_port())),
                username    =   str(sys_config.ftp_user()),
                password    =   str(sys_config.ftp_password()),
                use_tls     =   bool(sys_config.ftp_use_tls()),
                timeout     =   int(str(sys_config.ftp_timeout()))
            )

            self.logger.debug(
                f"{self.log_prefix} - Connecting to FTP server "
                f"{sys_config.ftp_host}:{sys_config.ftp_port}"
            )
            if not connector.connect():
                self.logger.error(f"{self.log_prefix} - FTP connection failed")
                return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

            # Build remote and local paths
            remote_base = sys_config.ftp_remote_dir.rstrip("/") if sys_config.ftp_remote_dir else ""
            remote_path = f"{remote_base}/{pnm_file_name}" if remote_base else pnm_file_name

            local_path = os.path.join(self.pnm_local_dir, pnm_file_name)

            self.logger.debug(
                f"{self.log_prefix} - Downloading '{remote_path}' to '{local_path}'"
            )
            success = connector.download_file(remote_path, local_path)
            connector.disconnect()

            if not success:
                self.logger.error(
                    f"{self.log_prefix} - FTP download failed for '{remote_path}'"
                )
                return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

            self.logger.info(
                f"{self.log_prefix} - Successfully fetched '{pnm_file_name}' via FTP"
            )
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during FTP fetch: {e}")
            return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

    def _handle_http_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        # TODO: implement HTTP file fetch logic
        self.logger.debug(f"{self.log_prefix} - HTTP fetch not yet implemented")
        return ServiceStatusCode.HTTP_PNM_FILE_FETCH_ERROR

    def _handle_https_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        # TODO: implement HTTPS file fetch logic
        self.logger.debug(f"{self.log_prefix} - HTTPS fetch not yet implemented")
        return ServiceStatusCode.SHTTP_PNM_FILE_FETCH_ERROR
    
    async def _pnm_file_generator(self, test_type: DocsPnmCmCtlTest, suffix: str = "", ext: str = ".bin") -> FileNameStr:
        """
        Generates the PNM file name based on the provided DocsPnmCmCtlTest, with optional suffix and extension.

        Args:
            test_type (DocsPnmCmCtlTest): The type of the test to generate the prefix.
            suffix (str, optional): A suffix added to the file name. Defaults to an empty string.
            ext (str, optional): The file extension. Defaults to ".bin".

        Returns:
            str: The generated PNM file name.
        """
        test_prefix = test_type.name.lower()

        if suffix:
            suffix = f'_{suffix}'

        file_name:FileNameStr = FileNameStr(f"{test_prefix}_{self.cm.get_mac_address.to_mac_format()}{suffix}_{Generate.time_stamp()}{ext}")

        transaction_id = await PnmFileTransaction().insert(self.cm, test_type, file_name)

        self.logger.debug(f"Generated PNM file name: {file_name} -> TransID: {transaction_id}")

        self._transactionId_pnmFile[transaction_id] = file_name

        return file_name

    def _get_transaction_id_by_filename(self, file_name: str) -> TransactionId | None:
        """
        Return the transaction ID associated with the given file name.
        Assumes file names are unique. Returns None if not found.
        """
        for transaction_id, name in self._transactionId_pnmFile.items():
            if name == file_name:
                return TransactionId(transaction_id)
        return None

    async def _generic_spectrum_analyzer_operation(self, filename:str="") -> tuple[ServiceStatusCode, list[str]]:
        """
        Perform a generic spectrum-analyzer operation on the cable modem, supporting two retrieval modes:
        1. SNMP-based amplitude data return (AmplitudeData textual convention)
        2. PNM file return (download via TFTP once the CM writes the file)

        The same set of control parameters (frequency range, bin count, windowing, etc.) is used
        in both cases—avoiding duplicate “control-command” logic (DRY). Downstream, a separate helper
        method is called based on `spectrum_retrieval_type`.

        Extra options (from self.extra_options):
            • inactivity_timeout             (int, default=100)
                - Maximum seconds to wait for the CM to complete the measurement
            • first_segment_center_freq      (int, default=300_000_000)
                - Starting center frequency in Hz
            • last_segment_center_freq       (int, default=900_000_000)
                - Ending center frequency in Hz
            • segment_freq_span              (int, default=7_500_000)
                - Frequency span per segment in Hz
            • num_bins_per_segment           (int, default=256)
                - Number of bins (samples) per segment
            • noise_bw                       (int, default=110)
                - Equivalent noise bandwidth in Hz
            • window_function                (WindowFunction, default=WindowFunction.HANN)
                - Window function to apply to each segment
            • num_averages                   (int, default=1)
                - Number of averages to take
            • spectrum_retrieval_type        (SpectrumRetrievalType, default=SpectrumRetrievalType.FILE)
                - FILE: write to PNM file via TFTP (requires pnm_filename)
                - SNMP: return amplitude data directly via SNMP (no file write)

        Returns:
            Tuple[ServiceStatusCode, List[str]]:
                • On success: (ServiceStatusCode.SUCCESS, [<PNM filename>]) for FILE mode,
                  or (ServiceStatusCode.SUCCESS, []) for SNMP mode.
                • On failure: (ServiceStatusCode.SPEC_ANALYZER_NOT_AVAILABLE, []).

        Raises:
            None directly—errors are mapped to a failure status code.
        """
        self.logger.info(f"{self.log_prefix} - Entering into SPECTRUM-ANALYZER Mode (filename: {filename})")

        # Default: only SNMP control-command, no file write
        ctl_cmd_filename = Snmp_v2c.TRUE

        if (self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER or \
            self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA) and \
            (not self.getSpectrumCaptureParameters()):

            self.logger.error('No Spectrum Parameters Found, did you set: setSpectrumCaptureParameters()')

            return  ServiceStatusCode.NO_SPECTRUM_CAPTURE_PARAMETERS, []

        capture_parameter = self.getSpectrumCaptureParameters()

        if not capture_parameter:

            capture_parameter = SpecAnCapturePara (
                inactivity_timeout          = self.extra_options.get("inactivity_timeout", 100),
                first_segment_center_freq   = self.extra_options.get("first_segment_center_freq", 300_000_000),
                last_segment_center_freq    = self.extra_options.get("last_segment_center_freq", 993_000_000),
                segment_freq_span           = self.extra_options.get("segment_freq_span", 1_000_000),
                num_bins_per_segment        = self.extra_options.get("num_bins_per_segment", 256),
                noise_bw                    = self.extra_options.get("noise_bw", 110),
                window_function             = self.extra_options.get("window_function", WindowFunction.HANN),
                num_averages                = self.extra_options.get("num_averages", 1),
                spectrum_retrieval_type     = self.extra_options.get("spectrum_retrieval_type",SpectrumRetrievalType.FILE),
            )

        if capture_parameter.num_averages != self.SPECTRUM_ANALYZER_AVERAGES_CAP:
            self.logger.info(
                "%s - Capping spectrum analyzer averages from %s to %s",
                self.log_prefix,
                capture_parameter.num_averages,
                self.SPECTRUM_ANALYZER_AVERAGES_CAP,
            )
            capture_parameter.num_averages = self.SPECTRUM_ANALYZER_AVERAGES_CAP

        if capture_parameter.spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.info(f"{self.log_prefix} - SPECTRUM-ANALYZER - SNMP-AMPLITUDE-DATA-RETURN")
            ctl_cmd_filename = Snmp_v2c.FALSE

        else:
            if not filename:
                self.logger.error(f"{self.log_prefix} - Missing 'filename' for FILE retrieval mode")
                return ServiceStatusCode.MISSING_PNM_FILENAME, []

        spectrum_cmd = DocsIf3CmSpectrumAnalysisCtrlCmd(
            docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout           =   capture_parameter.inactivity_timeout,
            docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency =   capture_parameter.first_segment_center_freq,
            docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency  =   capture_parameter.last_segment_center_freq,
            docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan        =   capture_parameter.segment_freq_span,
            docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment           =   capture_parameter.num_bins_per_segment,
            docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth    =   capture_parameter.noise_bw,
            docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction              =   capture_parameter.window_function,
            docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages            =   capture_parameter.num_averages,
            docsIf3CmSpectrumAnalysisCtrlCmdEnable                      =   Snmp_v2c.TRUE,
            docsIf3CmSpectrumAnalysisCtrlCmdFileName                    =   filename,
            docsIf3CmSpectrumAnalysisCtrlCmdFileEnable                  =   ctl_cmd_filename,)

        # Issue the SNMP SET for the control-command. The downstream logic
        # (not shown here) will branch to either:
        #   • SNMP:  set FileEnable = FALSE → wait for measurement → walk AmplitudeData
        #   • FILE:  set FileEnable = TRUE  → wait for measurement status → TFTP download
        if not await self.cm.setDocsIf3CmSpectrumAnalysisCtrlCmd(spectrum_cmd,
                                                                 capture_parameter.spectrum_retrieval_type):
            self.logger.error(f"{self.log_prefix} - Spectrum Analyzer is Not Available")
            return ServiceStatusCode.SPEC_ANALYZER_NOT_AVAILABLE, []

        # On success, return the filename (if FILE mode) or an empty list (SNMP mode)
        if capture_parameter.spectrum_retrieval_type == SpectrumRetrievalType.FILE:
            return ServiceStatusCode.SUCCESS, [filename]
        else:
            return ServiceStatusCode.SUCCESS, []

    def _ping_pnm_file_server(self, host: HostNameStr) -> ServiceStatusCode:
        """
        Ping The PNM File Server To Check Its Availability.

        This helper first attempts DNS resolution of the host. If the host
        resolves only to loopback addresses (for example "127.0.0.1" or "::1"),
        ICMP ping is bypassed and the host is treated as reachable so that
        local SCP/SFTP/TFTP retrieval is not blocked by loopback
        misconfiguration.

        If DNS resolution fails entirely, the ping pre-check is skipped and the
        method returns SUCCESS while logging the condition at debug level,
        allowing the subsequent transfer step to provide a more precise error.

        For non-loopback addresses that resolve successfully, a standard ICMP
        ping is issued via HostEndpoint. If the ping fails, PING_FAILED is
        returned.
        """
        endpoint  = HostEndpoint(host)
        addresses = endpoint.resolve()

        if not addresses:
            self.logger.debug(
                f"{self.log_prefix} - DNS lookup failed for host: {host}; "
                "skipping ping pre-check"
            )
            return ServiceStatusCode.SUCCESS

        for addr in addresses:
            if addr.startswith("127.") or addr == "::1":
                self.logger.debug(
                    f"{self.log_prefix} - Host {host} resolved to loopback ({addr}); "
                    "skipping ping pre-check"
                )
                return ServiceStatusCode.SUCCESS

        if endpoint.ping():
            return ServiceStatusCode.SUCCESS

        self.logger.debug(f"{self.log_prefix} - Ping failed for host: {host}")
        return ServiceStatusCode.PING_FAILED

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
                channel_ids              =   channel_ids if channel_ids else None,
                spectrum_retrieval_type =   request.capture_parameters.spectrum_retrieval_type)

            msg_responses: list[tuple[ChannelId, MessageResponse]] = await service.start()

            measurement_stats: list[DocsIf3CmSpectrumAnalysisEntry] = cast(
                list[DocsIf3CmSpectrumAnalysisEntry],
                await service.getPnmMeasurementStatisticsFlat(),
            )

            primative: dict[str, dict[Any, Any]] = {"primative": {}}

            for idx, (chan_id, msg_rsp) in enumerate(msg_responses):
                cps_msg_rsp = CommonProcessService(msg_rsp).process()

                analysis = Analysis(AnalysisType.BASIC, cps_msg_rsp, skip_automatic_process=True,)
                analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))
                multi_analysis.add(chan_id, analysis)

                primative_entry = cps_msg_rsp.payload_to_dict(idx)
                primative["primative"].update(primative_entry)

            analyzer_rpt = OfdmSpecAnalyzerAnalysisReport(multi_analysis)
            analyzer_rpt.build_report()

            if request.analysis.output.type == OutputType.JSON:
                analyzer_rpt_dict = analyzer_rpt.to_dict()
                analyzer_rpt_dict.update(primative)
                analyzer_rpt_dict.update(
                    DictGenerate.models_to_nested_dict(measurement_stats, "measurement_stats",))

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

            measurement_stats: list[DocsIf3CmSpectrumAnalysisEntry] = cast(
                list[DocsIf3CmSpectrumAnalysisEntry],
                await service.getPnmMeasurementStatisticsFlat(),
            )

            primative: dict[str, dict[Any, Any]] = {"primative": {}}

            for idx, (chan_id, msg_rsp) in enumerate(msg_responses):
                cps_msg_rsp = CommonProcessService(msg_rsp).process()

                analysis = Analysis(AnalysisType.BASIC, cps_msg_rsp, skip_automatic_process=True,)
                analysis.process(cast(AnalysisProcessParameters, request.analysis.spectrum_analysis))
                multi_analysis.add(chan_id, analysis)

                primative_entry = cps_msg_rsp.payload_to_dict(idx)
                primative["primative"].update(primative_entry)

            analyzer_rpt = ScQamSpecAnalyzerAnalysisReport(multi_analysis)
            analyzer_rpt.build_report()

            if request.analysis.output.type == OutputType.JSON:
                analyzer_rpt_dict = analyzer_rpt.to_dict()
                analyzer_rpt_dict.update(primative)
                analyzer_rpt_dict.update(
                    DictGenerate.models_to_nested_dict(measurement_stats, "measurement_stats",))

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

# FILE: src/pypnm/api/routes/docs/pnm/spectrumAnalyzer/service.py
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
    ResolutionBwSettings,
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

        rbw_settings: ResolutionBwSettings = RBWConversion.getSpectrumRbwSetttings(
            self._resolution_bandwidth,
        )

        num_bins_per_segment    = rbw_settings[1]
        number_of_averages      = self._number_of_averages
        spectrum_retrieval_type = self._spectrum_retrieval_type
        inactivity_timeout      = 30
        noise_bw                = 150
        channel_filter = set(self._channel_ids) if self._channel_ids else None
        segment_freq_span       = rbw_settings[2]

        for chan_id, (start_hz, plc_hz, end_hz) in bw_by_channel.items():
            if channel_filter and chan_id not in channel_filter:
                continue
            self.logger.debug(
                f"OFDM - Mac: {self._cm.get_mac_address} - "
                f"Channel Settings: {chan_id}, {start_hz}, {plc_hz}, {end_hz}"
            )

            capture_parameter = SpecAnCapturePara(
                inactivity_timeout          = inactivity_timeout,
                first_segment_center_freq   = FrequencyHz(start_hz),
                last_segment_center_freq    = FrequencyHz(end_hz),
                segment_freq_span           = FrequencyHz(segment_freq_span),
                num_bins_per_segment        = num_bins_per_segment,
                noise_bw                    = noise_bw,
                window_function             = WindowFunction.HANN,
                num_averages                = number_of_averages,
                spectrum_retrieval_type     = spectrum_retrieval_type,
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
        rbw_settings:ResolutionBwSettings = RBWConversion.getSpectrumRbwSetttings(self._resolution_bandwidth)

        num_bins_per_segment = rbw_settings[1]
        number_of_averages = self._number_of_averages
        spectrum_retrieval_type = self._spectrum_retrieval_type
        inactivity_timeout = 60
        noise_bw = 150
        channel_filter = set(self._channel_ids) if self._channel_ids else None
        segment_freq_span = rbw_settings[2]

        for count, (chan_id, (start_hz, _center_hz, end_hz)) in enumerate(bw_by_channel.items()):

            if channel_filter and chan_id not in channel_filter:
                continue

            if self._test_mode and count > 1:
                self.logger.warning("Test mode active: processing only first 2 channels.")
                break

            capture_parameter = SpecAnCapturePara(
                inactivity_timeout        = inactivity_timeout,
                first_segment_center_freq = FrequencyHz(start_hz),
                last_segment_center_freq  = FrequencyHz(end_hz),
                segment_freq_span         = FrequencyHz(segment_freq_span),
                num_bins_per_segment      = num_bins_per_segment,
                noise_bw                  = noise_bw,
                window_function           = WindowFunction.HANN,
                num_averages              = number_of_averages,
                spectrum_retrieval_type   = spectrum_retrieval_type,
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

# FILE: tools/agent-review/2026-01-29-spectrum-analyzer-friendly-capture.review.md
## Agent Review Bundle Summary
- Goal: Cap spectrum analyzer number of averages to 1 for SNMP control commands.
- Changes: Added average cap in spectrum analyzer operation; added unit test covering cap behavior.
- Files: src/pypnm/api/routes/common/extended/common_measure_service.py, tests/test_spectrum_analyzer_averages_cap.py
- Tests: ruff check src; pytest -q
- Notes: pytest skips hardware integration tests.

# FILE: src/pypnm/api/routes/common/extended/common_measure_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
import math
import os
import shutil
import time
from enum import Enum, auto
from pathlib import Path
from typing import TypeAlias, cast

from pypnm.api.routes.common.classes.analysis.analysis import SpecAnCapturePara
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
    UpstreamOfdmaParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    CommonMessagingService,
    MessageResponse,
)
from pypnm.api.routes.common.extended.types import CommonMessagingServiceExtension as CMSE
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_config_manager import PnmConfigManager
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import (
    DocsPnmBulkFileUploadStatus,
    DocsPnmCmCtlStatus,
    FecSummaryType,
)
from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsConstDispMeasEntry import (
    DocsPnmCmDsConstDispMeasEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsHistEntry import DocsPnmCmDsHistEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmFecEntry import DocsPnmCmDsOfdmFecEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmModProfEntry import (
    DocsPnmCmDsOfdmModProfEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmRxMerEntry import (
    DocsPnmCmDsOfdmRxMerEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmOfdmChanEstCoefEntry import (
    DocsPnmCmOfdmChanEstCoefEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmUsPreEqEntry import DocsPnmCmUsPreEqEntry
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.ftp.ftp_connector import FTPConnector
from pypnm.lib.host_endpoint import HostEndpoint
from pypnm.lib.inet import Inet
from pypnm.lib.ping import Ping
from pypnm.lib.ssh.ssh_connector import SSHConnector
from pypnm.lib.tftp.tftp_connector import TFTPConnector
from pypnm.lib.types import ChannelId, FileNameStr, InterfaceIndex, TransactionId, HostNameStr
from pypnm.lib.utils import Generate
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import (
    DocsIf3CmSpectrumAnalysisCtrlCmd,
    SpectrumRetrievalType,
    WindowFunction,
)
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.snmp.modules import DocsisIfType
from pypnm.snmp.snmp_v2c import Snmp_v2c
from pypnm.api.routes.common.extended.types import CommonMessagingServiceExtension as CMSE


class MeasureServiceReturnTypes(Enum):
    BASE_MODEL = auto()
    DICT = auto()

MeasurementEntry: TypeAlias =   DocsPnmCmOfdmChanEstCoefEntry   | \
                                DocsPnmCmDsConstDispMeasEntry   | \
                                DocsPnmCmDsOfdmRxMerEntry       | \
                                DocsPnmCmUsPreEqEntry           | \
                                DocsPnmCmDsHistEntry            | \
                                DocsPnmCmDsOfdmFecEntry         | \
                                DocsPnmCmDsOfdmModProfEntry     | \
                                DocsIf3CmSpectrumAnalysisEntry

class CommonMeasureService(CommonMessagingService):
    SPECTRUM_ANALYZER_AVERAGES_CAP: int = 1
    """
    Base service class for executing common Proactive Network Maintenance (PNM) measurement tests.

    Parameters:
        pnm_test_type (DocsPnmCmCtlTest): The type of PNM test to execute.
        cable_modem (CableModem): The cable modem instance used for the test.
        tftp_servers (Inet,Inet): (IPv4,IPv6)
        tftp_path (str, optional): The path on the TFTP server where test result files are stored. Default is an empty string.
        snmp_write_community (str, optional): The SNMP community string for write access. Default is "private".
        **extra_options (dict, optional): Additional keyword arguments specific to the test type, such as:
            - fec_summary_type (FecSummaryType): Required for tests involving FEC summary metrics.
            - Other parameters based on the test type.

    Notes:
        This class serves as a base for test-specific measurement operations. Subclasses should implement
        specific tests such as:
        - Downstream OFDM codeword error rate
        - RXMER per subcarrier
        - FEC statistics, etc.

        It is expected that subclasses will extend this service and provide the necessary implementations for
        executing and processing PNM measurements based on the test type and parameters.
    """
    def __init__(self, pnm_test_type:DocsPnmCmCtlTest,
                 cable_modem: CableModem,
                 tftp_servers: tuple[Inet,Inet],
                 tftp_path: str = "",
                 snmp_write_community: str = "private",
                 **extra_options) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.propagate = True

        self.pnm_filename:list[str]

        self._transactionId_pnmFile: dict[str, str] = {}
        self.pnm_test_type:DocsPnmCmCtlTest         = pnm_test_type
        self.cm:CableModem                          = cable_modem
        self.tftp_servers:tuple[Inet,Inet]          = tftp_servers
        self.tftp_path:str                          = tftp_path
        self.snmp_write_community:str               = snmp_write_community
        self.extra_options                          = extra_options
        self.config_mgr:ConfigManager               = ConfigManager()
        self.log_prefix:str                         = f"MAC: {self.cm.get_mac_address} - INET: {self.cm.get_inet_address}"
        self.pnm_dir                                = PnmConfigManager.get_save_dir()
        self.pnm_local_dir                          = SystemConfigSettings.pnm_dir
        self._capture_parameter:SpecAnCapturePara   = SpecAnCapturePara()

        # Initialize default spectrum capture parameters
        self._capture_parameter.spectrum_retrieval_type = SpectrumRetrievalType.UNKNOWN

        if self.extra_options:
            self.logger.info(f"{self.log_prefix} - OPTIONS: {self.extra_options}")
            self._preload_interface_parameters()

        self._precheck()

    def _precheck(self) -> None:
        """
        Perform pre-check and ensure the save directory exists.
        """
        self.logger.debug(f'PreCheck: SaveDir: {self.pnm_dir}')
        save_path = Path(self.pnm_dir)
        save_path.mkdir(parents=True, exist_ok=True)

    def _preload_interface_parameters(self) -> None:
        """
        Load optional interface parameters from extra_options dictionary.
        If not present, sets interface_parameters to None.
        """
        self.interface_parameters = self.extra_options.get("interface_parameters", None)

    def setSpectrumCaptureParameters(self, capture_parameter:SpecAnCapturePara) -> None:
        """
        Set the spectrum capture parameters for the measurement.

        TODO: This method may be deprecated in favor of passing parameters directly during initialization.

        Args:
            capture_parameter (SpecAnCapturePara): The spectrum capture parameters.
        """
        self._capture_parameter = capture_parameter

    def getSpectrumCaptureParameters(self) -> SpecAnCapturePara:
        """
        Get the current spectrum capture parameters.

        Returns:
            SpecAnCapturePara: The current spectrum capture parameters.
        """
        return self._capture_parameter

    async def set_and_go(self, interface_parameters: DownstreamOfdmParameters | UpstreamOfdmaParameters | None = None ,
                         max_wait_count: int = 5,) -> MessageResponse:
        """
        Trigger PNM file capture and retrieval based on direction-specific parameters.

        Args:
            interface_parameters (InterfaceParameters, optional):
                The configuration specifying the direction of capture:
                - `DownstreamOfdmParameters`: For OFDM downstream channels.
                - `UpstreamOfdmaParameters`: For OFDMA upstream channels.
                If `None` (default), all channels will be captured.

            max_wait_count (int, optional):
                Maximum seconds to wait for measurement readiness. Default is 5.

        Returns:
            MessageResponse: Result indicating success or failure of the operation.
        """

        ##########################################################
        # Verify that we can connect to the CM via Ping and SNMP
        ##########################################################

        if not self.is_ping_reachable():
            self.logger.error(f"{self.log_prefix} - Unreachable via PING")
            return self.build_send_msg(ServiceStatusCode.UNREACHABLE_PING)

        if not await self.is_snmp_ready():
            self.logger.error(f"{self.log_prefix} - Unreachable via SNMP")
            return self.build_send_msg(ServiceStatusCode.UNREACHABLE_SNMP)

        #########################################################################
        #                   Spectrum Analysis SNMP Return                       #
        #########################################################################

        if self.getSpectrumCaptureParameters().spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.debug(f"{self.log_prefix} - Performing Spectrum Analysis SNMP Amplitude Data")

            #Set Spectrum Analyzer
            __status = await self._generic_spectrum_analyzer_operation()

            if __status[0] != ServiceStatusCode.SUCCESS:
               self.logger.error(f"{self.log_prefix} - Unable to set Spectrum Analyzer Settings")
               return self.build_send_msg(ServiceStatusCode.SPEC_ANALYZER_SET_CONFIG_ERROR)

            # This is a blocking method, it will return SUCCESS or wait till timeout to return an ERROR
            status = await self._check_spectrum_amplitude_data_status()

            if status == ServiceStatusCode.SUCCESS:
                self.logger.info(f"{self.log_prefix} - Spectrum Amplitude Data is READY, collecting amplitude data, may take a while...")
                amp_data: bytes = await self.cm.getSpectrumAmplitudeData()
                self.logger.info(f"{self.log_prefix} - Spectrum Amplitude Data collection COMPLETE, total bytes: {len(amp_data)}.")
                #################################################################################################
                # Build binary filename and save file - START
                #################################################################################################
                filename = await self._pnm_file_generator(DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA)
                tx_id = self._get_transaction_id_by_filename(filename)
                if not tx_id:
                    self.logger.error(f"{self.log_prefix} - Unable to find Transaction ID for PNM filename: {filename}")
                    return self.build_send_msg(ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND)

                pnm_dir = SystemConfigSettings.pnm_dir()
                fpath = f"{pnm_dir}/{filename}"
                self.logger.debug(f'SpectrumAmplitudeData: - FNAME: {filename} - Length:{len(amp_data)} - TransactionID: {tx_id}')

                FileProcessor(fpath).write_file(amp_data)
                
                #################################################################################################
                # Build binary filename and save file - END
                #################################################################################################
                capture_para:SpecAnCapturePara = self.getSpectrumCaptureParameters()
                self.build_transaction_msg_extension(tx_id, 
                                                     filename, 
                                                     extension={f'{CMSE.SPECTRUM_ANALYSIS_SNMP_CAPTURE_PARAMETER}': capture_para.model_dump()})

            return self.build_send_msg(status)

        #########################################################################
        # Ensure CM Inet and TFTP server address use the same IP version
        #
        # The TFTP server address must match the IP version (IPv4 or IPv6) used
        # by the Cable Modem (CM). By default, we assume IPv4.
        #
        # If the CM's IP address is IPv6 and matches the version of the
        # secondary TFTP server entry, we switch to using the IPv6 TFTP server.
        #
        # TODO: Enhance this logic to support dual-stack (dual-home) cable modems,
        # where both IPv4 and IPv6 may be valid simultaneously.
        #########################################################################

        self.logger.info(f'{self.log_prefix} - TFTP-SERVERS: ({self.tftp_servers[0]} | {self.tftp_servers[1].inet})')

        # Default to using the IPv4 TFTP server
        tftp_server: Inet = self.tftp_servers[0]

        # Switch to IPv6 TFTP server if CM uses IPv6
        if self.cm.same_inet_version(self.tftp_servers[1]):
            tftp_server = self.tftp_servers[1]

        # Attempt to configure the CM with the selected TFTP server and path
        if not await self.cm.setDocsPnmBulk(tftp_server.inet, self.tftp_path):
            self.logger.error(
                f"{self.log_prefix} - Unable to set TFTP server {tftp_server.inet} "
                f"or TFTP path: {self.tftp_path}")
            return self.build_send_msg(ServiceStatusCode.TFTP_SERVER_PATH_SET_FAIL)

        ##############################################################################################
        # This section is determine by the direction due to which interface and type we are accessing
        ##############################################################################################

        status_index_channelId = await self._get_indexes_via_pnm_test_type(interface_parameters)
        self.logger.info(f'{self.log_prefix} - Index/ChannelID List: {status_index_channelId[1]}')
        if status_index_channelId[0] != ServiceStatusCode.SUCCESS or status_index_channelId[1] is None:
            self.logger.error(f'{self.log_prefix} - Unable to aquire index from ChannelID, reason: {status_index_channelId[0]}')
            return self.build_send_msg(status_index_channelId[0])

        ##############################################################################################
        # This section runs through all the indexes, build PNM file, run measurement and check status
        ##############################################################################################
        index_channelId: list[tuple[InterfaceIndex, ChannelId]] = status_index_channelId[1]
        return self.build_send_msg(await self._pnm_measure_status_and_pnm_file_transfer(index_channelId, max_wait_count))

    def getInterfaceParameters(self,
        interface_type: DocsisIfType) -> DownstreamOfdmParameters | UpstreamOfdmaParameters:
        """
        Instantiate and return the PNM test parameters for the specified DOCSIS interface.

        Args:
            interface_type (DocsisIfType):
                The DOCSIS interface type:
                - `DocsisIfType.docsOfdmDownstream` → returns DownstreamOfdmParameters
                - `DocsisIfType.docsOfdmaUpstream`  → returns UpstreamOfdmaParameters

        Returns:
            Union[DownstreamOfdmParameters, UpstreamOfdmaParameters]:
                A parameters object tailored to the requested interface.

        Raises:
            ValueError: If `interface_type` is not OFDM downstream or OFDMA upstream.
        """
        if interface_type == DocsisIfType.docsOfdmDownstream:
            return DownstreamOfdmParameters()
        if interface_type == DocsisIfType.docsOfdmaUpstream:
            return UpstreamOfdmaParameters()

        raise ValueError(
            f"Unsupported interface type: {interface_type!r}. "
            "Expected docsOfdmDownstream or docsOfdmaUpstream."
        )

    def is_ping_reachable(self) -> bool:
        """
        Check if the cable modem is reachable via ICMP ping.

        Returns:
            bool: True if the modem responds to ping, False otherwise.
        """
        return self.cm.is_ping_reachable()

    async def is_snmp_ready(self) -> bool:
        """
        Asynchronously check if the cable modem is accessible via SNMP.

        Returns:
            bool: True if the modem responds to SNMP queries, False otherwise.
        """
        return await self.cm.is_snmp_reachable()

    async def _filter_measurement_entries(
        self,
        entries: list[MeasurementEntry],
        channel_ids: list[ChannelId] | None,
    ) -> list[MeasurementEntry]:
        if not channel_ids:
            return entries

        channel_id_set = {int(channel_id) for channel_id in channel_ids}
        index_set: set[int] = set()

        if self.pnm_test_type in (
            DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
            DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF,
            DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
            DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
            DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        ):
            idx_channel_id = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()
            index_set = {int(idx) for idx, channel_id in idx_channel_id if int(channel_id) in channel_id_set}

        elif self.pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:
            idx_channel_id = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
            index_set = {int(idx) for idx, channel_id in idx_channel_id if int(channel_id) in channel_id_set}

        filtered: list[MeasurementEntry] = []
        for entry in entries:
            if isinstance(entry, (DocsPnmCmDsHistEntry, DocsIf3CmSpectrumAnalysisEntry)):
                continue
            if index_set:
                if int(entry.index) in index_set:
                    filtered.append(entry)
                continue
            if not hasattr(entry, "channel_id"):
                continue
            if int(entry.channel_id) in channel_id_set:
                filtered.append(entry)
        return filtered

    async def getPnmMeasurementStatistics(
        self,
        channel_ids: list[ChannelId] | None = None,
    ) -> list[MeasurementEntry]:
        """
        Retrieve PNM measurement entries for the currently configured `pnm_test_type`.

        Returns
        -------
        List[MeasurementEntry]
            A (possibly empty) list of model instances corresponding to the active
            test type:

            - DS_OFDM_CHAN_EST_COEF             → List[DocsPnmCmOfdmChanEstCoefEntry]
            - DS_CONSTELLATION_DISP             → List[DocsPnmCmDsConstDispMeasEntry]
            - DS_OFDM_RXMER_PER_SUBCAR          → List[DocsPnmCmDsOfdmRxMerEntry]
            - US_PRE_EQUALIZER_COEF             → List[DocsPnmCmUsPreEqEntry]
            - DS_HISTOGRAM                      → List[DocsPnmCmDsHistEntry]
            - DS_OFDM_FEC_SUMMARY               → List[DocsPnmCmDsOfdmFecEntry]
            - DS_OFDM_MODULATION_PROFILE        → List[DocsPnmCmDsOfdmModProfEntry]
            - SPECTRUM_ANALYZER                 → List[DocsIf3CmSpectrumAnalysisEntry]
            - SPECTRUM_ANALYZER_SNMP_AMP_DATA   → List[DocsIf3CmSpectrumAnalysisEntry]

            For other (stub/unsupported) test types, an empty list is returned.

        Notes
        -----
        - This method performs no aggregation; it returns the raw per-entry models
          fetched from the cable modem for the selected measurement type.
        - For strict typing, concrete lists are cast to `List[MeasurementEntry]`
          at return points (because `List` is invariant in the type system).
        - If `channel_ids` is provided and not empty, results are filtered to only
          include entries whose `channel_id` is in the list.
        """
        entries: list[MeasurementEntry] = []

        if self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            self.logger.debug(f"{self.log_prefix} - Running SPECTRUM_ANALYZER")
            concrete = await self.cm.getDocsIf3CmSpectrumAnalysisEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF:
            self.logger.debug(f"{self.log_prefix} - Running OFDM Channel Estimation Coefficient collection")
            concrete = await self.cm.getDocsPnmCmOfdmChanEstCoefEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP:
            self.logger.debug(f"{self.log_prefix} - Running OFDM Constellation Display collection")
            concrete = await self.cm.getDocsPnmCmDsConstDispMeasEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR:
            self.logger.debug(f"{self.log_prefix} - Running RXMER entry collection")
            concrete = await self.cm.getDocsPnmCmDsOfdmRxMerEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE:
            self.logger.debug(f"{self.log_prefix} - Running DS_OFDM_CODEWORD_ERROR_RATE")
            concrete = await self.cm.getDocsPnmCmDsOfdmFecEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM:
            self.logger.debug(f"{self.log_prefix} - Running DS_HISTOGRAM")
            concrete = await self.cm.getDocsPnmCmDsHistEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:
            self.logger.debug(f"{self.log_prefix} - Running Upstream Pre-Equalization entry collection")
            concrete = await self.cm.getDocsPnmCmUsPreEqEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE:
            self.logger.debug(f"{self.log_prefix} - Running DS_OFDM_MODULATION_PROFILE")
            concrete = await self.cm.getDocsPnmCmDsOfdmModProfEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA:
            self.logger.debug(f"{self.log_prefix} - Running SPECTRUM_ANALYZER_SNMP_AMP_DATA")
            concrete = await self.cm.getDocsIf3CmSpectrumAnalysisEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_SYMBOL_CAPTURE:
            self.logger.warning(f"{self.log_prefix} - Stub handler: DS_OFDM_SYMBOL_CAPTURE")

        elif self.pnm_test_type == DocsPnmCmCtlTest.LATENCY_REPORT:
            self.logger.warning(f"{self.log_prefix} - Stub handler: LATENCY_REPORT")

        else:
            self.logger.warning(f"{self.log_prefix} - Unknown PNM test type: {self.pnm_test_type}")

        return entries

    ###################
    # Private Methods #
    ###################

    async def _get_and_move_pnm_file(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Retrieves and moves the specified PNM file based on the configured retrieval method.

        This method delegates the file retrieval operation to a protocol-specific handler method
        depending on the configuration defined under `PnmFileRetrieval.method`. 
        Supported methods include: "local", "tftp", "sftp"
        # TODO: Need to implement, not sure if we need to: "ftp", "http", and "https".

        Configuration keys used:
            - PnmFileRetrieval.method: The file retrieval method to use (e.g., "local", "tftp", etc.).
            - PnmFileRetrieval.retries: Optional number of retries for retrieval attempts (currently unused here).

        Args:
            pnm_file_name (str): The name of the file to retrieve and move.

        Returns:
            bool: True if the file was successfully retrieved and moved; False otherwise.
        """
        method = SystemConfigSettings.retrieval_method()
        self.logger.info(f"{self.log_prefix} - Retrieval method: {method}")

        try:
            if method == "local":
                return await self._handle_local_fetch(pnm_file_name)
            elif method == "tftp":
                return self._handle_tftp_fetch(pnm_file_name)
            elif method == "ftp":
                return self._handle_ftp_fetch(pnm_file_name)
            elif method == "sftp":
                return self._handle_sftp_fetch(pnm_file_name)
            elif method == "http":
                return self._handle_http_fetch(pnm_file_name)
            elif method == "https":
                return self._handle_https_fetch(pnm_file_name)
            else:
                self.logger.error(f"{self.log_prefix} - Unsupported retrieval method: {method}")
                return ServiceStatusCode.FILE_RETRIEVAL_TYPE_INVALID

        except Exception as e:
            self.logger.exception(f"{self.log_prefix} - File retrieval failed: {e}")
            return ServiceStatusCode.PNM_FILE_RETRIEVAL_ERROR

    async def _get_indexes_via_pnm_test_type(self, ifParameters: DownstreamOfdmParameters | UpstreamOfdmaParameters | None = None
                                             ) -> tuple[ServiceStatusCode, list[tuple[InterfaceIndex, ChannelId]] | None]:
        """
        Determines the appropriate interface indexes and channel IDs to target for a given PNM test type.

        Depending on the configured PNM test type, this method selects the relevant interface and filters the index/ChannelID
        tuples based on user-specified parameters.

        Args:
            interface_parameters (Optional[InterfaceParameters]): Parameters specifying interface type ("ofdm" or "ofdma")
                and optionally a list of channel IDs to filter. If not provided, default parameters are selected based on test type.

        Returns:
            Tuple[ServiceStatusCode, Optional[List[Tuple[int, int]]]]:
                A status code indicating success or reason for failure, and a list of (index, channelId) tuples.
        """

        if ifParameters is None:
            ifParameters = DownstreamOfdmParameters()

        if not ifParameters:
            ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmDownstream)

        if self.pnm_test_type in (DocsPnmCmCtlTest.DS_HISTOGRAM, DocsPnmCmCtlTest.LATENCY_REPORT):
            idx:list[InterfaceIndex] = await self.cm.getIfTypeIndex(DocsisIfType.docsCableMaclayer)
            return ServiceStatusCode.SUCCESS, [(idx[0], ChannelId(0))]

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            return ServiceStatusCode.SUCCESS, [(InterfaceIndex(0), ChannelId(0))]

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA:
            return ServiceStatusCode.SUCCESS, [(InterfaceIndex(0), ChannelId(0))]

        elif self.pnm_test_type in (DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
                                    DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF,
                                    DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
                                    DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
                                    DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR):

            if not ifParameters:
                ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmDownstream)

        elif self.pnm_test_type in (DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF,):
            ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmaUpstream)
            self.logger.debug(f'{DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF} Measurement - IfParameters: {ifParameters.model_dump()}')

        '''
        There is redundant code, but incase I may need to change due to
        change of requiments depending on Downstream vs. Upstream

        TODO: lol, I am sure I will not revisit, but OK for now.
        '''
        if ifParameters.type == "ofdm":
            channel_id_list = ifParameters.channel_id
            idx_channelId = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()

            if not idx_channelId:
                self.logger.warning("No OFDM channel data found.")
                return ServiceStatusCode.NO_OFDMA_CHAN_ID_INDEX_FOUND, []

            if channel_id_list:
                filtered = [tpl for tpl in idx_channelId if tpl[1] in channel_id_list]
                self.logger.debug(f'Downstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
                return ServiceStatusCode.SUCCESS, filtered

            self.logger.info(f'Downstream: {ifParameters.type} -> IDX,CHAN_ID: {idx_channelId}')

            return ServiceStatusCode.SUCCESS, idx_channelId

        elif ifParameters.type == "ofdma":
            channel_id_list = ifParameters.channel_id
            idx_channelId = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
            if not idx_channelId:
                self.logger.warning("No OFDMA channel found.")
                return ServiceStatusCode.NO_OFDMA_CHAN_ID_INDEX_FOUND, []

            if channel_id_list:
                filtered = [tpl for tpl in idx_channelId if tpl[1] in channel_id_list]
                self.logger.info(f'Upstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
                return ServiceStatusCode.SUCCESS, filtered

            self.logger.info(f'Upstream: {ifParameters.type} -> IDX,CHAN_ID: {idx_channelId}')

        return ServiceStatusCode.SUCCESS, idx_channelId

    async def _pnm_measure_status_and_pnm_file_transfer(self, idx_channelId:list[tuple[InterfaceIndex, ChannelId]], max_wait_count:int) -> ServiceStatusCode:
        """
        Set and monitor the OFDM measurement test for specified (index, PLC) tuples.

        For each (index, PLC) pair:
            - Initiates the PNM test using SNMP.
            - Waits for the test status to reach READY.
            - Monitors for the measurement status to become SAMPLE_READY.
            - Retrieves the resulting PNM file and stores it locally.

        Args:
            idx_channelId (Tuple[int, int]): A list of tuples where each tuple consists of
                the SNMP interface index and the corresponding PLC (center frequency).
            max_wait_count (int): Maximum number of seconds to wait for SAMPLE_READY status.

        Returns:
            ServiceStatusCode: SUCCESS if all steps completed successfully,
                otherwise a specific error status (e.g., if the file couldn't be retrieved
                or the measurement status did not become SAMPLE_READY).
        """
        for interface_index, channel_id in idx_channelId:

            #######################################################################
            # This sets the Measurement Table/Row for the specific PNM Measurement
            #######################################################################
            ctl_measure_status:tuple[ServiceStatusCode, list[FileNameStr]] = \
                await self._setDocsPnmCmMeasureTest(self.pnm_test_type, interface_index, channel_id)
            
            if ctl_measure_status[0] != ServiceStatusCode.SUCCESS:
                return ctl_measure_status[0]

            pnm_filenames = ctl_measure_status[1]
            self.logger.info(f'{self.log_prefix} - PNM File(s) -> {pnm_filenames}')

            count=1
            while True:
                cm_ctl_status:DocsPnmCmCtlStatus = await self.cm.getDocsPnmCmCtlStatus()
                self.logger.info(f"{self.log_prefix} - PNM status: {str(cm_ctl_status).upper()} - count: {count}")
                if cm_ctl_status == DocsPnmCmCtlStatus.TEST_IN_PROGRESS:
                    count += 1
                    await asyncio.sleep(1)
                    continue

                if cm_ctl_status == DocsPnmCmCtlStatus.READY:
                    break

                if cm_ctl_status == DocsPnmCmCtlStatus.TEMP_REJECT:
                    break

                if cm_ctl_status == DocsPnmCmCtlStatus.SNMP_ERROR:
                    break

            self.logger.debug(f"{self.log_prefix} - Checking Measurement Status for {self.pnm_test_type} @ IDX: {interface_index}")

            wait_count = 0
            def extract_idx(idx):
                return idx[0] if isinstance(idx, list) and idx else idx

            while wait_count < max_wait_count:
                meas_status = await self.cm.getPnmMeasurementStatus(self.pnm_test_type, extract_idx(interface_index))
                self.logger.info(f"{self.log_prefix} - MeasureStatus: {meas_status.name}")
                if meas_status == MeasStatusType.SAMPLE_READY:
                    break
                await asyncio.sleep(1)
                wait_count += 1

            else:
                self.logger.error(f"{self.log_prefix} - SAMPLE_READY not reached for ChannelID {channel_id}")
                return ServiceStatusCode.NOT_READY_AFTER_FILE_CAPTURE

            #Multiple PNM files for special cases
            for pnm_fname in pnm_filenames:

                status:ServiceStatusCode = await self._check_and_wait_for_tftp_upload(FileNameStr(pnm_fname))

                if status != ServiceStatusCode.SUCCESS:
                    self.logger.error(f"{self.log_prefix} - Unable to Upload PNM File to TFTP({status})")
                    return status

                # Get and copy PNM file to local data directory
                retrieval_status = await self._get_and_move_pnm_file(FileNameStr(pnm_fname))
                if retrieval_status != ServiceStatusCode.SUCCESS:
                    self.logger.error(
                        f"{self.log_prefix} - Unable to copy PNM file to local {self.pnm_dir} dir "
                        f"(status={retrieval_status})")
                    return retrieval_status

                # Find Transaction ID via filename
                trans_id = self._get_transaction_id_by_filename(pnm_fname)
                if not trans_id:
                    self.logger.error(f"{self.log_prefix} - Unable to find Transaction ID for PNM filename: {pnm_fname}")
                    return ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND
                
                self.logger.debug(f'{self.log_prefix} - TransID: {trans_id} -> Filename: {pnm_fname}')
                self.build_transaction_msg(trans_id, pnm_fname)

        return ServiceStatusCode.SUCCESS

    async def _check_and_wait_for_tftp_upload(self, filename: str, max_wait_count: int = 5) -> ServiceStatusCode:
        """
        Waits for a PNM file to be uploaded via TFTP by polling the upload status.

        Args:
            filename (str): The name of the file being uploaded.
            max_wait_count (int): Maximum number of seconds to wait before timing out.

        Returns:
            ServiceStatusCode: SUCCESS if upload completed, failure code otherwise.
        """
        wait_count = 0

        while wait_count < max_wait_count:
            try:
                status = await self.cm.getBulkFileUploadStatus(filename)
            except Exception as e:
                self.logger.error(f"{self.log_prefix} - Error checking upload status for '{filename}': {e}")
                return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

            if status == DocsPnmBulkFileUploadStatus.UPLOAD_COMPLETED:
                self.logger.info(f"{self.log_prefix} - File '{filename}' uploaded successfully.")
                return ServiceStatusCode.SUCCESS

            if status == DocsPnmBulkFileUploadStatus.ERROR:
                self.logger.error(f"{self.log_prefix} - Device reported ERROR for file upload '{filename}'.")
                return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

            self.logger.debug(
                f"{self.log_prefix} - Waiting for file '{filename}' to upload "
                f"(status={status.name}, wait_count={wait_count})"
            )

            await asyncio.sleep(1)
            wait_count += 1

        self.logger.error(f"{self.log_prefix} - TFTP file '{filename}' upload timed out after {max_wait_count} seconds.")
        return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

    async def _setDocsPnmCmMeasureTest(self, pnm_test_type:DocsPnmCmCtlTest,
                                       interface_index:int, channel_id:ChannelId) -> tuple[ServiceStatusCode, list[FileNameStr]]:
        """
        Configure and trigger a specific PNM (Proactive Network Maintenance) measurement
        test on a cable modem based on the test type.

        Depending on the `pnm_test_type`, this method:
        - Generates appropriate output file names.
        - Uses SNMP to set the modem to collect specific diagnostic data.
        - Handles various DOCSIS downstream and upstream tests, including:
            - US Pre-Equalizer Coefficients (requires two files per interface: pre-eq and last pre-eq)
            - DS OFDM RxMER per Subcarrier
            - DS OFDM Codeword Error Rate
            - DS OFDM Channel Estimation Coefficients
            - DS Constellation Display
            - DS Histogram
            - DS OFDM Modulation Profile
            - Spectrum Analyzer Scan

        Parameters:
            pnm_test_type (DocsPnmCmCtlTest): Enum value indicating the PNM test to perform.
            interface_index (int): The SNMP index for the OFDM channel (usually the interface index).
            channel_id (int): The channel ID associated with the modem interface.

        Returns:
            Tuple[ServiceStatusCode, List[str]]: Status of the operation and list of generated file names.
        """
        pnm_files: list[FileNameStr] = []

        if pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:

            # Pre-Eq and Last Pre-EQ (2 files)
            pre_eq_filename         = await self._pnm_file_generator(self.pnm_test_type, str(channel_id))
            last_pre_eq_filename    = await self._pnm_file_generator(self.pnm_test_type, f'last_pre-eq_{str(channel_id)}')

            self.logger.info(f'{self.log_prefix} - Setting {self.pnm_test_type} for ChannelID: {channel_id} "'
                             f'@ IDX: {interface_index} -> FN(): {pre_eq_filename}, FN(last): {last_pre_eq_filename}')

            self.logger.info(f'{self.log_prefix} - Performing US_PRE_EQUALIZER_COEF measurement on IDX: ({interface_index})')
            if not await self.cm.setDocsPnmCmUsPreEq(ofdma_idx              =   interface_index,
                                                     filename               =   pre_eq_filename,
                                                     last_pre_eq_filename   =   last_pre_eq_filename):
                self.logger.error(f"{self.log_prefix} - Upstream OFDMA Pre-Equalization is Not Avalaible")
                return ServiceStatusCode.FILE_SET_FAIL, []

            #Append files for later fetching
            pnm_files.extend([pre_eq_filename, last_pre_eq_filename])

        else:
            #The remaining PNM Measuresurement are single PNM file
            pnm_filename = await self._pnm_file_generator(self.pnm_test_type, str(channel_id))
            self.logger.debug(f'{self.log_prefix} - Setting {self.pnm_test_type} for ChannelID: {channel_id} @ IDX: {interface_index} -> FN: {pnm_filename}')
            pnm_files.append(pnm_filename)

            if pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR:

                if not await self.cm.setDocsPnmCmDsOfdmRxMer(ofdm_idx=interface_index, rxmer_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE:

                fst = self.extra_options.get("fec_summary_type", FecSummaryType.TEN_MIN)

                if not await self.cm.setDocsPnmCmDsOfdmFecSum(ofdm_idx=interface_index, fec_sum_file_name=pnm_filename, fec_sum_type=fst):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF:

                if not await self.cm.setDocsPnmCmOfdmChEstCoef(ofdm_idx=interface_index, chan_est_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP:
                # OFDM Downstream Constellation Display setup
                # Extra SNMP options may include:
                #   - modulation_offset: Optional[int]
                #   - num_sample_symb: Optional[int]
                if not await self.cm.setDocsPnmCmDsConstDisp(
                    ofdm_idx                =   interface_index,
                    const_disp_name         =   pnm_filename,
                    modulation_order_offset =   self.extra_options.get('modulation_order_offset', 0),
                    number_sample_symbol    =   self.extra_options.get('number_sample_symbol', 0)
                ):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM:
                sample_duration = self.extra_options.get("histogram_sample_duration", 10)
                if not await self.cm.setDocsPnmCmDsHist(ds_histogram_file_name=pnm_filename, timeout=sample_duration):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE:

                if not await self.cm.setDocsPnmCmDsOfdmModProf(ofdm_idx=interface_index, mod_prof_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
                #Created generic to be used for PNM File and SNMP Return data
                 __status = await self._generic_spectrum_analyzer_operation(filename=pnm_filename)
                 if __status[0] != ServiceStatusCode.SUCCESS:
                    return __status

        return ServiceStatusCode.SUCCESS, pnm_files

    async def _check_spectrum_amplitude_data_status(self, timeout_seconds: int = 300) -> ServiceStatusCode:
        """
        Polls the cable modem for spectrum amplitude data availability within a timeout period.

        This method repeatedly checks if `docsIf3CmSpectrumAnalysisMeasAmplitudeData` is present
        on the modem, and returns a success or timeout status accordingly.

        Args:
            timeout_seconds (int): Maximum number of seconds to wait before timing out. Default is 300.

        Returns:
            ServiceStatusCode:
                - SUCCESS if data becomes available within the timeout period.
                - SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT if the timeout is exceeded.
        """
        t_start = time.time()

        while True:
            if await self.cm.isAmplitudeDataPresent():
                return ServiceStatusCode.SUCCESS
            now:int = math.floor(time.time() - t_start)

            if now >= timeout_seconds:
                self.logger.warning(f'{self.log_prefix} - Timeout for Amplitude Data ({now} of {timeout_seconds} seconds)')
                return ServiceStatusCode.SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT

            self.logger.info(f'{self.log_prefix} - Waiting for Amplitude Data ({now} of {timeout_seconds})')

            await asyncio.sleep(1)

    async def _handle_local_fetch(self, pnm_file_name: str) -> ServiceStatusCode:
        """
        Handles copying a specified PNM file from a local source directory to a configured save directory.

        This method looks up the source and destination paths from the application's system configuration
        (under the "PnmFileRetrieval" section) and attempts to copy the file named `pnm_file_name`
        from the source directory to the save directory.

        Configuration keys used:
            - PnmFileRetrieval.local.src_dir: Source directory where the PNM file resides.
            - PnmFileRetrieval.save_dir: Destination directory where the file should be saved.

        Args:
            pnm_file_name (str): The name of the file to copy.

        Returns:
            bool: True if the file was successfully copied; False otherwise.
        """

        src_dir = SystemConfigSettings.local_src_dir()

        self.logger.info(
            f'{self.log_prefix} - Local Copy - SRC: {src_dir} - SAVE: {self.pnm_dir} - FN: {pnm_file_name}'
        )

        if not os.path.isdir(src_dir) or not os.path.isdir(self.pnm_dir):
            self.logger.error(f"{self.log_prefix} - Invalid source or destination directory")
            return ServiceStatusCode.LOCAL_FETCH_FAILURE

        while True:
            await asyncio.sleep(1)
            file_found = False
            for filename in os.listdir(src_dir):
                if filename == pnm_file_name:
                    file_found = True
                    src_path = os.path.join(src_dir, filename)
                    dest_path = os.path.join(self.pnm_dir, filename)
                    try:
                        shutil.copy2(src_path, dest_path)
                        self.logger.debug(f"{self.log_prefix} - Copied {filename} to {self.pnm_dir}")
                        return ServiceStatusCode.SUCCESS
                    except Exception as e:
                        self.logger.error(f"{self.log_prefix} - Copy failed for {filename}: {e}")
                        return ServiceStatusCode.LOCAL_FETCH_FAILURE

            if not file_found:
                self.logger.warning(f"{self.log_prefix} - File not found in source directory: {pnm_file_name}")

            return ServiceStatusCode.LOCAL_FETCH_FAILURE

    def _handle_sftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch a file from remote SFTP server.

        Args:
            pnm_file_name: Name of the file to fetch from remote server

        Returns:
            bool: True if file transfer successful, False otherwise
        """
        sys_config = SystemConfigSettings()

        self.logger.debug(f"{self.log_prefix} - SFTP: Connecting to: {sys_config.sftp_host()}")

        if self._ping_pnm_file_server(HostNameStr(sys_config.sftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for SFTP host: {sys_config.sftp_host()}")
            return ServiceStatusCode.SFTP_HOST_UNREACHABLE

        sftp = SSHConnector(
            hostname        =   sys_config.sftp_host(),
            username        =   sys_config.sftp_user(),
            port            =   sys_config.sftp_port())

        password_enc     = sys_config.sftp_password()
        private_key_path = sys_config.sftp_private_key_path()

        try:
            if not sftp.connect(password_enc     =   password_enc,
                                private_key_path =   private_key_path):
                self.logger.error(f'{self.log_prefix} - SFTP Connect Failure: Host: {sys_config.sftp_host()}')
                return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

            remote_file_path = f'{sys_config.sftp_remote_dir()}/{pnm_file_name}'
            if not sftp.receive_file(remote_path =   remote_file_path,
                                     local_path  =   sys_config.pnm_dir()):
                self.logger.error(
                    f'{self.log_prefix} - SFTP Receive File Error '
                    f'(SRC:{remote_file_path} DST: {sys_config.pnm_dir()})'
                )
                return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

            self.logger.info(f'{self.log_prefix} - Successfully fetched file: {pnm_file_name}')
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f'{self.log_prefix} - SFTP Fetch Exception: {e}')
            return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

        finally:
            sftp.disconnect()

    def _handle_tftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch the specified PNM file via TFTP.

        Assumes the following attributes on self:
        - self.pnm_local_dir (str)    # local directory to save the downloaded file
        - self.log_prefix (str)       # used for consistent logging

        TFTP settings are read from SystemConfigCommonSettings:
        - tftp_host (str)
        - tftp_port (int)
        - tftp_timeout (int)
        - tftp_remote_dir (str)   # remote directory where PNM files live (if applicable)
        """

        if self._ping_pnm_file_server(HostNameStr(SystemConfigSettings.tftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for TFTP host: {SystemConfigSettings.tftp_host()}")
            return ServiceStatusCode.TFTP_HOST_UNREACHABLE  

        try:
            connector = TFTPConnector(
                host    =   Inet(SystemConfigSettings.tftp_host()),
                port    =   int(str(SystemConfigSettings.tftp_port())))

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during TFTP connecting: {e}")
            return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

        try:

            self.logger.info(
                f"{self.log_prefix} - Starting TFTP download from "
                f"{SystemConfigSettings.tftp_host()}:{SystemConfigSettings.tftp_port()}"
            )

            # Build remote filename (some tftp servers require just the basename)
            remote_name = (
                f"{SystemConfigSettings.tftp_remote_dir().rstrip('/')}/{pnm_file_name}"
                if SystemConfigSettings.tftp_remote_dir() else
                pnm_file_name
            )
            local_path = os.path.join(SystemConfigSettings.pnm_dir(), pnm_file_name)

            success = connector.download_file(remote_name, local_path)

            if not success:
                self.logger.error(
                    f"{self.log_prefix} - TFTP download failed for '{remote_name}'"
                )
                return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

            self.logger.info(
                f"{self.log_prefix} - Successfully fetched '{pnm_file_name}' via TFTP"
            )
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during TFTP downloading: {e}")
            return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

    def _handle_ftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch the specified PNM file via FTP.

        Assumes the following attributes exist on self:
        - self.pnm_local_dir (str)    # local directory to save the downloaded file
        - self.log_prefix (str)       # used for consistent logging

        All FTP-specific settings are read from SystemConfigCommonSettings:
        - ftp_host (str)
        - ftp_port (int)
        - ftp_user (str)
        - ftp_password (str)
        - ftp_use_tls (bool)
        - ftp_timeout (int)
        - ftp_remote_dir (str)   # remote directory where PNM files live
        """
        sys_config = SystemConfigSettings()

        if self._ping_pnm_file_server(HostNameStr(SystemConfigSettings.ftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for FTP host: {SystemConfigSettings.ftp_host()}")
            return ServiceStatusCode.FTP_HOST_UNREACHABLE  

        try:
            connector = FTPConnector(
                host        =   str(sys_config.ftp_host()),
                port        =   int(str(sys_config.ftp_port())),
                username    =   str(sys_config.ftp_user()),
                password    =   str(sys_config.ftp_password()),
                use_tls     =   bool(sys_config.ftp_use_tls()),
                timeout     =   int(str(sys_config.ftp_timeout()))
            )

            self.logger.debug(
                f"{self.log_prefix} - Connecting to FTP server "
                f"{sys_config.ftp_host}:{sys_config.ftp_port}"
            )
            if not connector.connect():
                self.logger.error(f"{self.log_prefix} - FTP connection failed")
                return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

            # Build remote and local paths
            remote_base = sys_config.ftp_remote_dir.rstrip("/") if sys_config.ftp_remote_dir else ""
            remote_path = f"{remote_base}/{pnm_file_name}" if remote_base else pnm_file_name

            local_path = os.path.join(self.pnm_local_dir, pnm_file_name)

            self.logger.debug(
                f"{self.log_prefix} - Downloading '{remote_path}' to '{local_path}'"
            )
            success = connector.download_file(remote_path, local_path)
            connector.disconnect()

            if not success:
                self.logger.error(
                    f"{self.log_prefix} - FTP download failed for '{remote_path}'"
                )
                return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

            self.logger.info(
                f"{self.log_prefix} - Successfully fetched '{pnm_file_name}' via FTP"
            )
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during FTP fetch: {e}")
            return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

    def _handle_http_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        # TODO: implement HTTP file fetch logic
        self.logger.debug(f"{self.log_prefix} - HTTP fetch not yet implemented")
        return ServiceStatusCode.HTTP_PNM_FILE_FETCH_ERROR

    def _handle_https_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        # TODO: implement HTTPS file fetch logic
        self.logger.debug(f"{self.log_prefix} - HTTPS fetch not yet implemented")
        return ServiceStatusCode.SHTTP_PNM_FILE_FETCH_ERROR
    
    async def _pnm_file_generator(self, test_type: DocsPnmCmCtlTest, suffix: str = "", ext: str = ".bin") -> FileNameStr:
        """
        Generates the PNM file name based on the provided DocsPnmCmCtlTest, with optional suffix and extension.

        Args:
            test_type (DocsPnmCmCtlTest): The type of the test to generate the prefix.
            suffix (str, optional): A suffix added to the file name. Defaults to an empty string.
            ext (str, optional): The file extension. Defaults to ".bin".

        Returns:
            str: The generated PNM file name.
        """
        test_prefix = test_type.name.lower()

        if suffix:
            suffix = f'_{suffix}'

        file_name:FileNameStr = FileNameStr(f"{test_prefix}_{self.cm.get_mac_address.to_mac_format()}{suffix}_{Generate.time_stamp()}{ext}")

        transaction_id = await PnmFileTransaction().insert(self.cm, test_type, file_name)

        self.logger.debug(f"Generated PNM file name: {file_name} -> TransID: {transaction_id}")

        self._transactionId_pnmFile[transaction_id] = file_name

        return file_name

    def _get_transaction_id_by_filename(self, file_name: str) -> TransactionId | None:
        """
        Return the transaction ID associated with the given file name.
        Assumes file names are unique. Returns None if not found.
        """
        for transaction_id, name in self._transactionId_pnmFile.items():
            if name == file_name:
                return TransactionId(transaction_id)
        return None

    async def _generic_spectrum_analyzer_operation(self, filename:str="") -> tuple[ServiceStatusCode, list[str]]:
        """
        Perform a generic spectrum-analyzer operation on the cable modem, supporting two retrieval modes:
        1. SNMP-based amplitude data return (AmplitudeData textual convention)
        2. PNM file return (download via TFTP once the CM writes the file)

        The same set of control parameters (frequency range, bin count, windowing, etc.) is used
        in both cases—avoiding duplicate “control-command” logic (DRY). Downstream, a separate helper
        method is called based on `spectrum_retrieval_type`.

        Extra options (from self.extra_options):
            • inactivity_timeout             (int, default=100)
                - Maximum seconds to wait for the CM to complete the measurement
            • first_segment_center_freq      (int, default=300_000_000)
                - Starting center frequency in Hz
            • last_segment_center_freq       (int, default=900_000_000)
                - Ending center frequency in Hz
            • segment_freq_span              (int, default=7_500_000)
                - Frequency span per segment in Hz
            • num_bins_per_segment           (int, default=256)
                - Number of bins (samples) per segment
            • noise_bw                       (int, default=110)
                - Equivalent noise bandwidth in Hz
            • window_function                (WindowFunction, default=WindowFunction.HANN)
                - Window function to apply to each segment
            • num_averages                   (int, default=1)
                - Number of averages to take
            • spectrum_retrieval_type        (SpectrumRetrievalType, default=SpectrumRetrievalType.FILE)
                - FILE: write to PNM file via TFTP (requires pnm_filename)
                - SNMP: return amplitude data directly via SNMP (no file write)

        Returns:
            Tuple[ServiceStatusCode, List[str]]:
                • On success: (ServiceStatusCode.SUCCESS, [<PNM filename>]) for FILE mode,
                  or (ServiceStatusCode.SUCCESS, []) for SNMP mode.
                • On failure: (ServiceStatusCode.SPEC_ANALYZER_NOT_AVAILABLE, []).

        Raises:
            None directly—errors are mapped to a failure status code.
        """
        self.logger.info(f"{self.log_prefix} - Entering into SPECTRUM-ANALYZER Mode (filename: {filename})")

        # Default: only SNMP control-command, no file write
        ctl_cmd_filename = Snmp_v2c.TRUE

        if (self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER or \
            self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA) and \
            (not self.getSpectrumCaptureParameters()):

            self.logger.error('No Spectrum Parameters Found, did you set: setSpectrumCaptureParameters()')

            return  ServiceStatusCode.NO_SPECTRUM_CAPTURE_PARAMETERS, []

        capture_parameter = self.getSpectrumCaptureParameters()

        if not capture_parameter:

            capture_parameter = SpecAnCapturePara (
                inactivity_timeout          = self.extra_options.get("inactivity_timeout", 100),
                first_segment_center_freq   = self.extra_options.get("first_segment_center_freq", 300_000_000),
                last_segment_center_freq    = self.extra_options.get("last_segment_center_freq", 993_000_000),
                segment_freq_span           = self.extra_options.get("segment_freq_span", 1_000_000),
                num_bins_per_segment        = self.extra_options.get("num_bins_per_segment", 256),
                noise_bw                    = self.extra_options.get("noise_bw", 110),
                window_function             = self.extra_options.get("window_function", WindowFunction.HANN),
                num_averages                = self.extra_options.get("num_averages", 1),
                spectrum_retrieval_type     = self.extra_options.get("spectrum_retrieval_type",SpectrumRetrievalType.FILE),
            )

        if capture_parameter.num_averages != self.SPECTRUM_ANALYZER_AVERAGES_CAP:
            self.logger.info(
                "%s - Capping spectrum analyzer averages from %s to %s",
                self.log_prefix,
                capture_parameter.num_averages,
                self.SPECTRUM_ANALYZER_AVERAGES_CAP,
            )
            capture_parameter.num_averages = self.SPECTRUM_ANALYZER_AVERAGES_CAP

        if capture_parameter.spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.info(f"{self.log_prefix} - SPECTRUM-ANALYZER - SNMP-AMPLITUDE-DATA-RETURN")
            ctl_cmd_filename = Snmp_v2c.FALSE

        else:
            if not filename:
                self.logger.error(f"{self.log_prefix} - Missing 'filename' for FILE retrieval mode")
                return ServiceStatusCode.MISSING_PNM_FILENAME, []

        spectrum_cmd = DocsIf3CmSpectrumAnalysisCtrlCmd(
            docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout           =   capture_parameter.inactivity_timeout,
            docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency =   capture_parameter.first_segment_center_freq,
            docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency  =   capture_parameter.last_segment_center_freq,
            docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan        =   capture_parameter.segment_freq_span,
            docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment           =   capture_parameter.num_bins_per_segment,
            docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth    =   capture_parameter.noise_bw,
            docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction              =   capture_parameter.window_function,
            docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages            =   capture_parameter.num_averages,
            docsIf3CmSpectrumAnalysisCtrlCmdEnable                      =   Snmp_v2c.TRUE,
            docsIf3CmSpectrumAnalysisCtrlCmdFileName                    =   filename,
            docsIf3CmSpectrumAnalysisCtrlCmdFileEnable                  =   ctl_cmd_filename,)

        # Issue the SNMP SET for the control-command. The downstream logic
        # (not shown here) will branch to either:
        #   • SNMP:  set FileEnable = FALSE → wait for measurement → walk AmplitudeData
        #   • FILE:  set FileEnable = TRUE  → wait for measurement status → TFTP download
        if not await self.cm.setDocsIf3CmSpectrumAnalysisCtrlCmd(spectrum_cmd,
                                                                 capture_parameter.spectrum_retrieval_type):
            self.logger.error(f"{self.log_prefix} - Spectrum Analyzer is Not Available")
            return ServiceStatusCode.SPEC_ANALYZER_NOT_AVAILABLE, []

        # On success, return the filename (if FILE mode) or an empty list (SNMP mode)
        if capture_parameter.spectrum_retrieval_type == SpectrumRetrievalType.FILE:
            return ServiceStatusCode.SUCCESS, [filename]
        else:
            return ServiceStatusCode.SUCCESS, []

    def _ping_pnm_file_server(self, host: HostNameStr) -> ServiceStatusCode:
        """
        Ping The PNM File Server To Check Its Availability.

        This helper first attempts DNS resolution of the host. If the host
        resolves only to loopback addresses (for example "127.0.0.1" or "::1"),
        ICMP ping is bypassed and the host is treated as reachable so that
        local SCP/SFTP/TFTP retrieval is not blocked by loopback
        misconfiguration.

        If DNS resolution fails entirely, the ping pre-check is skipped and the
        method returns SUCCESS while logging the condition at debug level,
        allowing the subsequent transfer step to provide a more precise error.

        For non-loopback addresses that resolve successfully, a standard ICMP
        ping is issued via HostEndpoint. If the ping fails, PING_FAILED is
        returned.
        """
        endpoint  = HostEndpoint(host)
        addresses = endpoint.resolve()

        if not addresses:
            self.logger.debug(
                f"{self.log_prefix} - DNS lookup failed for host: {host}; "
                "skipping ping pre-check"
            )
            return ServiceStatusCode.SUCCESS

        for addr in addresses:
            if addr.startswith("127.") or addr == "::1":
                self.logger.debug(
                    f"{self.log_prefix} - Host {host} resolved to loopback ({addr}); "
                    "skipping ping pre-check"
                )
                return ServiceStatusCode.SUCCESS

        if endpoint.ping():
            return ServiceStatusCode.SUCCESS

        self.logger.debug(f"{self.log_prefix} - Ping failed for host: {host}")
        return ServiceStatusCode.PING_FAILED

# FILE: tests/test_spectrum_analyzer_averages_cap.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.common.classes.analysis.analysis import SpecAnCapturePara
from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.docsis.cm_snmp_operation import DocsPnmCmCtlTest
from pypnm.lib.inet import Inet
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import SpectrumRetrievalType


class _FakeCableModem:
    def __init__(self) -> None:
        self._mac = "aa:bb:cc:dd:ee:ff"
        self._inet = "192.168.0.100"
        self.last_cmd = None

    @property
    def get_mac_address(self) -> str:
        return self._mac

    @property
    def get_inet_address(self) -> str:
        return self._inet

    async def setDocsIf3CmSpectrumAnalysisCtrlCmd(self, cmd: object, _retrieval_type: object) -> bool:
        self.last_cmd = cmd
        return True


@pytest.mark.asyncio
async def test_spectrum_analyzer_averages_capped_to_one() -> None:
    cm = _FakeCableModem()
    service = CommonMeasureService(
        pnm_test_type=DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA,
        cable_modem=cm,
        tftp_servers=(Inet("192.168.0.100"), Inet("192.168.0.101")),
    )
    capture = SpecAnCapturePara(
        inactivity_timeout=60,
        first_segment_center_freq=300_000_000,
        last_segment_center_freq=900_000_000,
        segment_freq_span=1_000_000,
        num_bins_per_segment=256,
        noise_bw=150,
        window_function=1,
        num_averages=10,
        spectrum_retrieval_type=SpectrumRetrievalType.SNMP,
    )
    service.setSpectrumCaptureParameters(capture)

    status, _ = await service._generic_spectrum_analyzer_operation()

    assert status == ServiceStatusCode.SUCCESS
    assert cm.last_cmd is not None
    assert getattr(cm.last_cmd, "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages") == 1

# FILE: tests/test_spectrum_analyzer_averages_cap.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.common.classes.analysis.analysis import SpecAnCapturePara
from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.docsis.cm_snmp_operation import DocsPnmCmCtlTest
from pypnm.lib.inet import Inet
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import SpectrumRetrievalType


class _FakeCableModem:
    def __init__(self) -> None:
        self._mac = "aa:bb:cc:dd:ee:ff"
        self._inet = "192.168.0.100"
        self.last_cmd = None

    @property
    def get_mac_address(self) -> str:
        return self._mac

    @property
    def get_inet_address(self) -> str:
        return self._inet

    async def setDocsIf3CmSpectrumAnalysisCtrlCmd(self, cmd: object, _retrieval_type: object) -> bool:
        self.last_cmd = cmd
        return True


@pytest.mark.asyncio
async def test_spectrum_analyzer_averages_capped_to_one() -> None:
    cm = _FakeCableModem()
    service = CommonMeasureService(
        pnm_test_type=DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA,
        cable_modem=cm,
        tftp_servers=(Inet("192.168.0.100"), Inet("192.168.0.101")),
    )
    capture = SpecAnCapturePara(
        inactivity_timeout=60,
        first_segment_center_freq=300_000_000,
        last_segment_center_freq=900_000_000,
        segment_freq_span=1_000_000,
        num_bins_per_segment=256,
        noise_bw=150,
        window_function=1,
        num_averages=10,
        spectrum_retrieval_type=SpectrumRetrievalType.SNMP,
    )
    service.setSpectrumCaptureParameters(capture)

    status, _ = await service._generic_spectrum_analyzer_operation()

    assert status == ServiceStatusCode.SUCCESS
    assert cm.last_cmd is not None
    assert getattr(cm.last_cmd, "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages") == 1

# FILE: tests/test_spectrum_analyzer_channel_filter.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.common.extended.common_messaging_service import (
    MessageResponse,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.spectrumAnalyzer import service as spectrum_service
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.abstract.com_spec_chan_ana import (
    CommonChannelSpectumBwLut,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.service import (
    DsOfdmChannelSpectrumAnalyzer,
    DsScQamChannelSpectrumAnalyzer,
)
from pypnm.lib.types import ChannelId, FrequencyHz, ResolutionBw


class _FakeCableModem:
    def __init__(self) -> None:
        self._mac = "aa:bb:cc:dd:ee:ff"

    @property
    def get_mac_address(self) -> str:
        return self._mac


class _TestScqamAnalyzer(DsScQamChannelSpectrumAnalyzer):
    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        return {
            ChannelId(4): (
                FrequencyHz(400_000_000),
                FrequencyHz(405_000_000),
                FrequencyHz(410_000_000),
            ),
            ChannelId(5): (
                FrequencyHz(500_000_000),
                FrequencyHz(505_000_000),
                FrequencyHz(510_000_000),
            ),
        }

    async def updatePnmMeasurementStatistics(self, channel_id: ChannelId) -> bool:
        return True


class _TestOfdmAnalyzer(DsOfdmChannelSpectrumAnalyzer):
    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        return {
            ChannelId(4): (
                FrequencyHz(600_000_000),
                FrequencyHz(610_000_000),
                FrequencyHz(620_000_000),
            ),
            ChannelId(5): (
                FrequencyHz(700_000_000),
                FrequencyHz(710_000_000),
                FrequencyHz(720_000_000),
            ),
        }

    async def updatePnmMeasurementStatistics(self, channel_id: ChannelId) -> bool:
        return True


@pytest.mark.asyncio
async def test_scqam_channel_filtering(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[object] = []

    class _FakeScQamChanSpecAnalyzerService:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self._params = None

        def setSpectrumCaptureParameters(self, capture_parameters: object) -> None:
            self._params = capture_parameters
            captured.append(capture_parameters)

        async def set_and_go(self) -> MessageResponse:
            return MessageResponse(ServiceStatusCode.SUCCESS)

    monkeypatch.setattr(
        spectrum_service,
        "ScQamChanSpecAnalyzerService",
        _FakeScQamChanSpecAnalyzerService,
    )

    analyzer = _TestScqamAnalyzer(
        cable_modem=_FakeCableModem(),
        number_of_averages=1,
        resolution_bandwidth_hz=ResolutionBw(25_000),
        channel_ids=[ChannelId(4)],
    )

    await analyzer.start()

    assert len(captured) == 1


@pytest.mark.asyncio
async def test_ofdm_channel_filtering(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[object] = []

    class _FakeOfdmChanSpecAnalyzerService:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self._params = None

        def setSpectrumCaptureParameters(self, capture_parameters: object) -> None:
            self._params = capture_parameters
            captured.append(capture_parameters)

        async def set_and_go(self) -> MessageResponse:
            return MessageResponse(ServiceStatusCode.SUCCESS)

    monkeypatch.setattr(
        spectrum_service,
        "OfdmChanSpecAnalyzerService",
        _FakeOfdmChanSpecAnalyzerService,
    )

    analyzer = _TestOfdmAnalyzer(
        cable_modem=_FakeCableModem(),
        number_of_averages=1,
        resolution_bandwidth_hz=ResolutionBw(25_000),
        channel_ids=[ChannelId(4)],
    )

    await analyzer.start()

    assert len(captured) == 1

# FILE: tests/test_spectrum_analyzer_averages_cap.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.common.classes.analysis.analysis import SpecAnCapturePara
from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.docsis.cm_snmp_operation import DocsPnmCmCtlTest
from pypnm.lib.inet import Inet
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import SpectrumRetrievalType


class _FakeCableModem:
    def __init__(self) -> None:
        self._mac = "aa:bb:cc:dd:ee:ff"
        self._inet = "192.168.0.100"
        self.last_cmd = None

    @property
    def get_mac_address(self) -> str:
        return self._mac

    @property
    def get_inet_address(self) -> str:
        return self._inet

    async def setDocsIf3CmSpectrumAnalysisCtrlCmd(self, cmd: object, _retrieval_type: object) -> bool:
        self.last_cmd = cmd
        return True


@pytest.mark.asyncio
async def test_spectrum_analyzer_averages_capped_to_one() -> None:
    cm = _FakeCableModem()
    service = CommonMeasureService(
        pnm_test_type=DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA,
        cable_modem=cm,
        tftp_servers=(Inet("192.168.0.100"), Inet("192.168.0.101")),
    )
    capture = SpecAnCapturePara(
        inactivity_timeout=60,
        first_segment_center_freq=300_000_000,
        last_segment_center_freq=900_000_000,
        segment_freq_span=1_000_000,
        num_bins_per_segment=256,
        noise_bw=150,
        window_function=1,
        num_averages=10,
        spectrum_retrieval_type=SpectrumRetrievalType.SNMP,
    )
    service.setSpectrumCaptureParameters(capture)

    status, _ = await service._generic_spectrum_analyzer_operation()

    assert status == ServiceStatusCode.SUCCESS
    assert cm.last_cmd is not None
    assert getattr(cm.last_cmd, "docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages") == 1

# FILE: tests/test_spectrum_analyzer_channel_filter.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.common.extended.common_messaging_service import (
    MessageResponse,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.spectrumAnalyzer import service as spectrum_service
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.abstract.com_spec_chan_ana import (
    CommonChannelSpectumBwLut,
)
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.service import (
    DsOfdmChannelSpectrumAnalyzer,
    DsScQamChannelSpectrumAnalyzer,
)
from pypnm.lib.types import ChannelId, FrequencyHz, ResolutionBw


class _FakeCableModem:
    def __init__(self) -> None:
        self._mac = "aa:bb:cc:dd:ee:ff"

    @property
    def get_mac_address(self) -> str:
        return self._mac


class _TestScqamAnalyzer(DsScQamChannelSpectrumAnalyzer):
    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        return {
            ChannelId(4): (
                FrequencyHz(400_000_000),
                FrequencyHz(405_000_000),
                FrequencyHz(410_000_000),
            ),
            ChannelId(5): (
                FrequencyHz(500_000_000),
                FrequencyHz(505_000_000),
                FrequencyHz(510_000_000),
            ),
        }

    async def updatePnmMeasurementStatistics(self, channel_id: ChannelId) -> bool:
        return True


class _TestOfdmAnalyzer(DsOfdmChannelSpectrumAnalyzer):
    async def calculate_channel_spectrum_bandwidth(self) -> CommonChannelSpectumBwLut:
        return {
            ChannelId(4): (
                FrequencyHz(600_000_000),
                FrequencyHz(610_000_000),
                FrequencyHz(620_000_000),
            ),
            ChannelId(5): (
                FrequencyHz(700_000_000),
                FrequencyHz(710_000_000),
                FrequencyHz(720_000_000),
            ),
        }

    async def updatePnmMeasurementStatistics(self, channel_id: ChannelId) -> bool:
        return True


@pytest.mark.asyncio
async def test_scqam_channel_filtering(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[object] = []

    class _FakeScQamChanSpecAnalyzerService:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self._params = None

        def setSpectrumCaptureParameters(self, capture_parameters: object) -> None:
            self._params = capture_parameters
            captured.append(capture_parameters)

        async def set_and_go(self) -> MessageResponse:
            return MessageResponse(ServiceStatusCode.SUCCESS)

    monkeypatch.setattr(
        spectrum_service,
        "ScQamChanSpecAnalyzerService",
        _FakeScQamChanSpecAnalyzerService,
    )

    analyzer = _TestScqamAnalyzer(
        cable_modem=_FakeCableModem(),
        number_of_averages=1,
        resolution_bandwidth_hz=ResolutionBw(25_000),
        channel_ids=[ChannelId(4)],
    )

    await analyzer.start()

    assert len(captured) == 1


@pytest.mark.asyncio
async def test_ofdm_channel_filtering(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[object] = []

    class _FakeOfdmChanSpecAnalyzerService:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self._params = None

        def setSpectrumCaptureParameters(self, capture_parameters: object) -> None:
            self._params = capture_parameters
            captured.append(capture_parameters)

        async def set_and_go(self) -> MessageResponse:
            return MessageResponse(ServiceStatusCode.SUCCESS)

    monkeypatch.setattr(
        spectrum_service,
        "OfdmChanSpecAnalyzerService",
        _FakeOfdmChanSpecAnalyzerService,
    )

    analyzer = _TestOfdmAnalyzer(
        cable_modem=_FakeCableModem(),
        number_of_averages=1,
        resolution_bandwidth_hz=ResolutionBw(25_000),
        channel_ids=[ChannelId(4)],
    )

    await analyzer.start()

    assert len(captured) == 1
