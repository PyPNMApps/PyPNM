## Agent Review Bundle Summary
- Goal: M3 cutover to DB-backed transactions + artifact resolution, remove runtime dependency on transactions.json, and update docs/tests.
- Changes: Added artifact repository and resolver, wired capture/upload paths to register artifacts, migrated file-manager resolution to DB artifacts, added DB-backed tests and ledger guards, updated docs to reflect DB authority.
- Files: src/pypnm/api/routes/common/extended/common_measure_service.py; docs/api/fast-api/multi/capture-operation.md; docs/api/fast-api/pypnm/db/data-base.md; docs/issues/support-bundle.md; docs/design/db/addemdum.md.
- Tests: python3 -m compileall src; ruff check src; ruff format --check .; pytest -q (603 passed, 9 skipped).
- Notes: Skips: PNM_CM_IT hardware integration and PYPNM_DB_POSTGRES_DSN-gated tests.

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
from pypnm.lib.db.artifact_repository import ROLE_PNM_RAW
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
    UpstreamOfdmaParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    CommonMessagingService,
    MessageResponse,
)
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
                try:
                    PnmFileTransaction().register_pnm_artifact(
                        tx_id,
                        filename,
                        ROLE_PNM_RAW,
                    )
                except (FileNotFoundError, RuntimeError) as exc:
                    self.logger.error(
                        "%s - Failed to register PNM artifact for transaction %s: %s",
                        self.log_prefix,
                        tx_id,
                        exc,
                    )
                    return self.build_send_msg(ServiceStatusCode.PNM_FILE_RETRIEVAL_ERROR)
                #################################################################################################
                # Build binary filename and save file - END
                #################################################################################################

                self.build_transaction_msg(tx_id, filename)

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
            self.logger.info(f'{DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF} Measurement - IfParameters: {ifParameters.model_dump()}')

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
                self.logger.info(f'Downstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
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
                try:
                    PnmFileTransaction().register_pnm_artifact(
                        trans_id,
                        pnm_fname,
                        ROLE_PNM_RAW,
                    )
                except (FileNotFoundError, RuntimeError) as exc:
                    self.logger.error(
                        "%s - Failed to register PNM artifact for transaction %s: %s",
                        self.log_prefix,
                        trans_id,
                        exc,
                    )
                    return ServiceStatusCode.PNM_FILE_RETRIEVAL_ERROR
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

        tx_id = str(transaction_id)
        if not tx_id.strip():
            self.logger.warning(
                "%s - Skipping transaction mapping for empty transaction_id (filename=%s)",
                self.log_prefix,
                file_name,
            )
            return file_name

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

# FILE: docs/api/fast-api/multi/capture-operation.md
# Multi‑Capture Operation Overview

When you initiate a **multi-capture** session (e.g., Multi‑RxMER or Multi‑DS‑Channel‑Estimation), PyPNM maintains a DB-backed tracking system and stages resulting PNM binaries for downstream workflows.

**Directory Layout**:

```text
.data/
├── db/
│   ├── pypnm.sqlite3               # SQLite DB (when backend=sqlite)
│   └── json_transactions.json      # JSON artifact ledger (JSON exports only)
├── operations/
│   └── <operation_id>.json         # Status + progress for async operations
└── pnm/
    └── <.bin files>                # Raw PNM captures retrieved via TFTP
```

Capture metadata is stored in the DB (`transaction_records`, `capture_groups`, `capture_group_transactions`, `operation_captures`). Postgres deployments use the configured external DSN instead of a local SQLite file.

## 1. Operation Status Registry (`operations/<operation_id>.json`)

Each operation has its own status file to support `status`, `result`, and `cancel` endpoints.

**Example**:

```json
{
  "operation_id": "f6afb2d7df2c4a5c",
  "state": "running",
  "created_ts": 1730000000,
  "updated_ts": 1730000010,
  "progress_current": 1,
  "progress_total": 6,
  "message": "Operation running",
  "error": null,
  "artifact_paths": [
    "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_160_1730000000.bin"
  ]
}
```

## 2. Operation Mapping (DB: `operation_captures`)

Operation-to-capture-group links are stored in the `operation_captures` table.

Fields:

* **operation_id**: Operation identifier (primary key).
* **capture_group_id**: Associated capture group (foreign key).
* **created_epoch**: Unix timestamp when the operation started.

Legacy JSON key `capture_group` is accepted only during offline migration; runtime resolution uses the DB.

## 3. Capture Group Registry (DB: `capture_groups` + `capture_group_transactions`)

Capture groups live in `capture_groups`, with ordered membership in `capture_group_transactions`.

Fields:

* **capture_group_id**: Capture group identifier (primary key).
* **created_epoch**: Unix timestamp when the group was created.
* **transaction_id**: Linked transaction identifier (foreign key).
* **position**: Ordering index for deterministic listing.

## 4. Transaction Records (DB: `transaction_records` + `transaction_artifacts`)

Transaction metadata is stored in `transaction_records`, while on-disk files are resolved via `transaction_artifacts` and `file_artifacts`.

**Example (logical record shape)**:

```json
{
  "2ee6138bbc1b3c3d": {
      "timestamp": 1748280294,
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
      "filename": "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_34_1748280294.bin",
      "device_details": {
          "system_description": {
              "HW_REV": "1.0",
              "VENDOR": "LANCity",
              "BOOTR": "NONE",
              "SW_REV": "1.0.0",
              "MODEL": "LCPET-3"
          }
      }
  }
}
```

* **Key**: `transaction_id` (e.g., `2ee6138bbc1b3c3d`).
* **timestamp**: Unix epoch when the file was staged.
* **mac\_address**: Sanitized MAC of the target modem.
* **pnm\_test\_type**: Identifier of the PNM capture type.
* **filename**: Name of the `.bin` file in `.data/pnm/` (recorded for reference).
* **device\_details.system\_description**: Snapshot of modem metadata at capture time.

Transaction IDs must be non-empty. Blank or whitespace-only IDs are dropped with a warning and are never persisted.
The `mac_address` field is intentionally stored in `transaction_records` (it is not treated as redundant in the SQL-backed schema direction).

## 5. Operation Workflow Endpoints (POST)

Generic workflow endpoints provide a consistent interface for operation status, result, and cancellation.
These endpoints rely on an in-memory OperationRegistry for live stop/status hooks and a filesystem-backed
OperationStore for authoritative state. Cancel requests are best-effort in-process; the OperationStore
status remains authoritative across restarts.

**Request** `POST /advance/operation/start`

```json
{
  "progress_total": 6,
  "message": "Operation created"
}
```

**Response** (start includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "running",
    "created_ts": 1730000000,
    "updated_ts": 1730000000,
    "progress_current": 0,
    "progress_total": 6,
    "message": "Operation created",
    "error": null,
    "artifact_paths": []
  },
  "time_remaining": 0
}
```

**Request** `POST /advance/operation/status`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Response** (registry status includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "running",
    "created_ts": 1730000000,
    "updated_ts": 1730000010,
    "progress_current": 1,
    "progress_total": 6,
    "message": "Operation running",
    "error": null,
    "artifact_paths": []
  },
  "time_remaining": 0
}
```

**Request** `POST /advance/operation/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Response** (registry result includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "completed",
    "created_ts": 1730000000,
    "updated_ts": 1730000030,
    "progress_current": 6,
    "progress_total": 6,
    "message": "Operation completed",
    "error": null,
    "artifact_paths": []
  }
}
```

**Request** `POST /advance/operation/cancel`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Response** (registry cancel includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "canceled",
    "created_ts": 1730000000,
    "updated_ts": 1730000020,
    "progress_current": 2,
    "progress_total": 6,
    "message": "Operation canceled",
    "error": null,
    "artifact_paths": []
  }
}
```

## 6. Multi-RxMER Workflow Endpoints (POST)

**Request** `POST /advance/ds/ofdm/rxmer/multi/start`

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.0.100",
  "duration": 60,
  "interval": 5
}
```

**Request** `POST /advance/ds/ofdm/rxmer/multi/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

## 7. Multi-ChannelEstimation Workflow Endpoints (POST)

**Request** `POST /advance/multiChannelEstimation/start`

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100"
  },
  "capture": {
    "parameters": {
      "measurement_duration": 60,
      "sample_interval": 5
    }
  }
}
```

Note: The legacy `measure` payload is currently ignored and will be removed in a future release.

**Request** `POST /advance/multiChannelEstimation/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

Result behavior:
- Missing transaction records are skipped with warnings.
- If no transaction records resolve, the endpoint returns HTTP 404.

Start response fields:
- capture_group_id is canonical.
- group_id is legacy and will be deprecated.
- status is ServiceStatusCode.SUCCESS when the operation starts; operation_state indicates RUNNING.
Status semantics:
- Top-level status is always a ServiceStatusCode value.
- operation.state carries running/stopped/completed semantics.
- Registry endpoints return legacy status string plus service_status as the canonical ServiceStatusCode.

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and inserts DB metadata (transaction record + artifact linkage).
4. **Database Updates**: `operation_captures`, `capture_groups`, and `capture_group_transactions` reflect the capture state.
5. **Completion**: After the capture ends, the DB tables fully describe what was captured, when, and for which operation/group.

> Downstream tools should query the DB-backed APIs (for example, `searchFiles` or `getMacAddresses`) to discover new PNM files. The legacy `transactions.json` manifest is no longer a runtime source of truth.

# FILE: docs/api/fast-api/pypnm/db/data-base.md
# PyPNM Database

Overview of how PyPNM stores, organizes, and links measurement data for traceability and REST access.

## Table Of Contents

- [Data Repository Layout](#data-repository-layout)
- [Directory Reference](#directory-reference)
- [Operation Capture Linking](#operation-capture-linking)
- [Capture Group Registry](#capture-group-registry)
- [Transaction Records](#transaction-records)
- [JSON Capture Ledger](#json-capture-ledger)
- [Summary Of Relationships](#summary-of-relationships)

## Data Repository Layout

The `.data` tree is the on-disk workspace for all PyPNM captures, intermediate artifacts, plots, and ledgers.

```text
.data
├── archive
│   └── aabbccddeeff_lcpet3_1760940313.zip
├── csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch33_pid0.csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch33_pid1.csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch33_pid3.csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch34_pid0.csv
│   ├── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch34_pid1.csv
│   └── aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch34_pid3.csv
├── db
│   ├── pypnm.sqlite3
│   └── json_transactions.json
├── json
│   ├── aabbccddeeff_example_run_1760940313_33_cmdsofdmrxmer_1760940313000000000.json
│   └── aabbccddeeff_example_run_1760940313_34_cmdsofdmrxmer_1760940313999999999.json
├── msg_rsp
├── png
│   ├── aabbccddeeff_lcpet3_1760940313_33_profile_0_ofdm_profile_perf_1.png
│   ├── aabbccddeeff_lcpet3_1760940313_33_profile_1_ofdm_profile_perf_1.png
│   ├── aabbccddeeff_lcpet3_1760940313_33_profile_3_ofdm_profile_perf_1.png
│   ├── aabbccddeeff_lcpet3_1760940313_34_profile_0_ofdm_profile_perf_1.png
│   ├── aabbccddeeff_lcpet3_1760940313_34_profile_1_ofdm_profile_perf_1.png
│   └── aabbccddeeff_lcpet3_1760940313_34_profile_3_ofdm_profile_perf_1.png
├── pnm
│   ├── ds_ofdm_codeword_error_rate_aabbccddeeff_33_1760940254.bin
│   ├── ds_ofdm_codeword_error_rate_aabbccddeeff_33_1760940285.bin
│   ├── ds_ofdm_codeword_error_rate_aabbccddeeff_34_1760940287.bin
│   ├── ds_ofdm_modulation_profile_aabbccddeeff_33_1760940269.bin
│   ├── ds_ofdm_modulation_profile_aabbccddeeff_34_1760940270.bin
│   ├── ds_ofdm_rxmer_per_subcar_aabbccddeeff_33_1760940252.bin
│   └── ds_ofdm_rxmer_per_subcar_aabbccddeeff_33_1760940260.bin
└── xlsx
```

## Directory Reference

Each subdirectory has a well-defined role. The table below summarizes typical contents and how they are used by PyPNM.

| Directory  | Typical Contents                                                | Example Filenames                                                     | Purpose                                                                                           |
| ---------- | --------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `archive/` | ZIP archives combining multi-file outputs (CSV, PNG, summaries) | `aabbccddeeff_lcpet3_1760940313.zip`                                  | One-stop bundle for download/sharing and offline review.                                          |
| `csv/`     | Per-measurement CSV exports                                     | `aabbccddeeff_lcpet3_1760940313_ofdm_profile_perf_1_ch34_pid1.csv`    | Tabular data for analysis, BI tools, and spreadsheets.                                            |
| `db/`      | SQLite DB (or external Postgres via DSN)                        | `pypnm.sqlite3`                                                       | DB-backed metadata: transactions, capture groups, operation mappings, and artifacts.             |
| `db/`      | JSON capture ledger                                             | `json_transactions.json`                                              | Index of processed JSON capture files (under `.data/json/`), including size and SHA-256 hashes.  |
| `json/`    | Raw/processed JSON outputs (when enabled)                       | `aabbccddeeff_example_run_1760940313_33_cmdsofdmrxmer_*.json`         | Structured artifacts for programmatic consumption; filenames are recorded in `json_transactions`. |
| `msg_rsp/` | Request/response message snapshots (optional)                   | —                                                                     | Diagnostics and audit of REST or SNMP exchanges.                                                  |
| `png/`     | Visualization images per capture/profile/channel                | `aabbccddeeff_lcpet3_1760940313_34_profile_1_ofdm_profile_perf_1.png` | Quick-look plots for reports and UIs.                                                             |
| `pnm/`     | Binary PNM files pulled from devices or uploads                 | `ds_ofdm_rxmer_per_subcar_aabbccddeeff_33_1760940252.bin`             | Source files used by analyses; include the embedded `pnm_header`.                                |
| `xlsx/`    | Excel workbooks                                                 | —                                                                     | Multi-sheet summaries and cross-linked reports.                                                   |

## Operation Capture Linking

Operation-to-capture-group mapping is stored in the `operation_captures` DB table.
An operation represents a higher-level request that may include different PNM test types (RxMER, FEC Summary, Modulation Profile).

### Field Overview

| Field              | Type    | Description                                   |
| ------------------ | ------- | --------------------------------------------- |
| `operation_id`     | string  | Operation identifier (primary key).           |
| `capture_group_id` | string  | Unique ID of the broader capture session.     |
| `created_epoch`    | integer | Operation creation timestamp (epoch seconds). |

Common uses:

- Retrieve a complete session by operation ID via REST.
- Persist session context for deferred or repeat analysis.

## Capture Group Registry

Capture groups are stored in `capture_groups`, with ordered membership in `capture_group_transactions`.
Capture groups can span multiple test types or measurements and underpin multi-file workflows (Excel generation, correlation, etc.).

### Field Overview

| Field              | Type    | Description                                                               |
| ------------------ | ------- | ------------------------------------------------------------------------- |
| `capture_group_id` | string  | Group identifier (primary key).                                           |
| `created_epoch`    | integer | Group creation timestamp (epoch seconds; often the first operation time). |
| `transaction_id`   | string  | Transaction ID linked to the group.                                       |
| `position`         | integer | Ordering index for deterministic listing.                                 |

## Transaction Records

Transactions are stored in the `transaction_records` table, with file resolution via `transaction_artifacts`.
Each entry represents a single file **transaction**, whether:

- Pulled automatically from a cable modem (for example, via TFTP), or
- Manually uploaded by a user via the UI or API.

### Structure

Each transaction is indexed by a unique ID (16-char digest) and stored in the DB:

```json
"1e171e1f8ef5377a": {
  "timestamp": 1751950064,
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
  "filename": "ds_ofdm_rxmer_per_subcar_aabbccddeeff_197_1751950064.bin",
  "device_details": {
    "sys_descr": {
      "HW_REV": "1.0",
      "VENDOR": "LANCity",
      "BOOTR": "NONE",
      "SW_REV": "1.0.0",
      "MODEL": "LCPET-3"
    }
  }
}
```

### Field Overview

| Field            | Type    | Description                                                                 |
| ---------------- | ------- | --------------------------------------------------------------------------- |
| `timestamp`      | integer | Unix epoch seconds when the file was received or uploaded.                  |
| `mac_address`    | string  | Cable modem MAC address.                                                    |
| `pnm_test_type`  | string  | Test type that produced the file (for example, `DS_OFDM_RXMER_PER_SUBCAR`). |
| `filename`       | string  | Saved binary filename in `.data/pnm/`.                                      |
| `device_details` | object  | Parsed device metadata from SNMP when available (`sys_descr` fields shown). |

On-disk file resolution uses `transaction_artifacts` with role preference (`pnm_raw`, then `pnm_uploaded_raw`) and joins through `file_artifacts` and `artifact_stores`.

## JSON Capture Ledger

The `.data/db/json_transactions.json` file is the ledger for JSON capture artifacts saved under `.data/json/`.
It lets PyPNM track processed JSON outputs separately from raw PNM files.

Each entry is keyed by a transaction ID and points to a JSON file created from a particular capture session.

```json
"df448ebff10d2dd203011b53": {
  "timestamp": 1760940313,
  "filename": "aabbccddeeff_example_run_1760940313_34_cmdsofdmrxmer_1760940313999999999.json",
  "byte_size": 585286,
  "sha256": "98509bf7b8dcbb01638953207e6e6691520daee16212f5ddf96bee41b7511779"
},
"94bab9dc131f173f6bdc4fe5": {
  "timestamp": 1760940313,
  "filename": "aabbccddeeff_example_run_1760940313_33_cmdsofdmrxmer_1760940313000000000.json",
  "byte_size": 586564,
  "sha256": "ed1fdc3f816e6037c1e10f4f66c4489a4ad6bc5421d93c970d7812fa456a7315"
}
```

### Field Overview

| Field       | Type    | Description                                                              |
| ---------- | ------- | ------------------------------------------------------------------------ |
| `timestamp` | integer | Unix epoch seconds when the JSON capture file was written.              |
| `filename`  | string  | JSON filename stored under `.data/json/`.                               |
| `byte_size` | integer | Size of the JSON file in bytes, used for quick sanity checks.           |
| `sha256`    | string  | SHA-256 hash of the JSON file contents for integrity and dedup checks.  |

The filename pattern generally encodes:

- Cable modem MAC address (for example, `aa:bb:cc:dd:ee:ff` as `aabbccddeeff`)
- A run label or hostname (for example, `example_run`)
- A base capture timestamp
- Channel or profile identifier (for example, `33` or `34`)
- The test name (for example, `cmdsofdmrxmer`)
- A high-resolution timestamp or unique suffix

This allows you to map JSON artifacts back to their originating modem, run, and test context.

## Summary Of Relationships

- **Operation Capture → Capture Group → Transaction (PNM binary)**  
  An **operation** references a single **capture group**, which aggregates many **transactions** in `transaction_records`. Each transaction resolves to a PNM file via `transaction_artifacts`.

- **Transactions (PNM) → JSON Captures**  
  JSON exports derived from those PNM files are written to `.data/json/` and tracked in `json_transactions.json` with size and checksum metadata.

- **Reporting And REST Access**  
  Use the **operation ID** for API recall, the **capture group** for report generation and correlation across tests, and the **transaction IDs** (PNM and JSON) for raw file or artifact lookup.

# FILE: docs/issues/support-bundle.md
# PyPNM - Support Bundle Builder

Create Sanitized Support Bundles For PNM File And Capture Issues.

## Table Of Contents

- [Overview](#overview)
- [What Gets Collected](#what-gets-collected)
- [Sanitization Rules](#sanitization-rules)
- [Command-Line Usage](#command-line-usage)
- [Examples](#examples)
  - [1. Build Bundle From A Single Transaction ID](#1-build-bundle-from-a-single-transaction-id)
  - [2. Build Bundle From An Operation ID (Multi-Capture)](#2-build-bundle-from-an-operation-id-multi-capture)
  - [3. Build Bundle From A MAC Address](#3-build-bundle-from-a-mac-address)
  - [4. Build Bundle With No Sanitization](#4-build-bundle-with-no-sanitization)
- [Bundle Layout](#bundle-layout)
- [Submitting A Bundle](#submitting-a-bundle)

## Overview

The **Support Bundle Builder** is an offline helper script that creates a
sanitized archive (.zip) containing only the PNM files and metadata required to
debug a specific PyPNM issue.

Instead of sharing your full `.data/` tree, you can run this tool locally and
send a compact bundle that contains:

- Only the captures relevant to your issue (by Transaction ID, Operation ID, or MAC).
- Sanitized MAC addresses (rewritten to `aa:bb:cc:dd:ee:ff` by default).
- Sanitized `system_description` fields using the canonical demo descriptor:

```json
{
  "HW_REV":  "1.0",
  "VENDOR":  "LANCity",
  "BOOTR":   "NONE",
  "SW_REV":  "1.0.0",
  "MODEL":   "LCPET-3"
}
```

The original data stays on your system. The bundle is safe to attach to a
support ticket or email when requesting help.

## What Gets Collected

Given a set of input selectors (Transaction ID, Operation ID, or MAC address),
the tool:

1. Uses the configured DB backend (SQLite or Postgres) to discover the relevant transactions
   via `transaction_records`, `capture_groups`, and `operation_captures`.

2. Resolves each transaction into:

   - The capture file under `.data/pnm`
   - The corresponding transaction record from the transaction DB

3. Builds a temporary **support dataset** under a working directory using the
   same structure as `.data`:

```text
.data/
  pnm/
    <capture files>
  db/
    pypnm.sqlite3
    json_transactions.json
```

4. Sanitizes the dataset (MAC address, filename MAC fragments, and
   `system_description`) so it can be safely shared.

5. Packs the dataset into a ZIP file using the `ArchiveManager.zip_files`
   helper. Unless you pass an absolute `--output-zip` path, the ZIP is created
   under an `issues/` directory in the current working tree.

## Sanitization Rules

By default, the support bundle is sanitized to remove customer-specific identity
details while preserving structure and relative relationships.

### MAC Address

- All MAC addresses in:
  - Transaction JSON records (`mac_address` field)
  - Filenames that include MAC fragments
  - Any capture files passed through `pnm-mac-updater.py`
- Are rewritten to the generic MAC address:

```text
aa:bb:cc:dd:ee:ff
```

This preserves per-modem grouping while removing the original hardware identity.

### System Descriptor

For each transaction record that includes `device_details.system_description`,
the script overwrites the contents with the canonical demo descriptor:

```json
{
  "HW_REV":  "1.0",
  "VENDOR":  "LANCity",
  "BOOTR":   "NONE",
  "SW_REV":  "1.0.0",
  "MODEL":   "LCPET-3"
}
```

This keeps the field present (so parsing and models behave normally) but removes
real vendor and model information.

### Opt-Out

Optional flags allow you to keep real MAC addresses and/or system descriptions
when absolutely necessary for debugging. See the [Examples](#examples) section
for usage notes.

## Command-Line Usage

The support bundle script is intended to live under `tools/`:

```text
tools/build/support_bundle_builder.py
```

Basic invocation:

```bash
./tools/build/support_bundle_builder.py [OPTIONS]
```

Core selectors (you must provide at least one):

- `--transaction-id TRANSACTION_ID`  
  Build a bundle for a single transaction.

- `--operation-id OPERATION_ID`  
  Build a bundle containing all transactions associated with a multi-capture
  operation.

- `--mac-address MAC_ADDRESS`  
  Build a bundle containing all transactions and captures for a cable modem
  MAC address.

Sanitization and behavior flags:

- `--keep-original-mac`  
  Keep the original MAC address in JSON and filenames, and skip binary MAC
  rewriting. By default, all MAC addresses are sanitized to `aa:bb:cc:dd:ee:ff`.

- `--keep-original-sysdescr`  
  Keep the original `device_details.system_description` instead of the demo
  descriptor.

- `--output-zip PATH`  
  Name or path of the output ZIP file. When PATH is relative (the default is
  `pypnm_support_bundle.zip`), the file is written under the `issues/`
  directory (for example, `issues/pypnm_support_bundle.zip`). When PATH is
  absolute, it is used as-is.

- `--support-root PATH`  
  Temporary working directory used to construct the `.data` tree before zipping
  (default: `.support_bundle`). This directory can be safely deleted after the
  bundle is created.

- `--clean-output`  
  Remove any existing `--support-root` directory before building the bundle.

- `--verbose`  
  Enable per-file logging during bundle creation.

The script prints the final ZIP file path at the end, for example:

```text
Support bundle created at: issues/pypnm_support_bundle.zip
```

## Examples

### 1. Build Bundle From A Single Transaction ID

You have a failing analysis for a single capture and want to share that file and
its metadata only.

```bash
./tools/build/support_bundle_builder.py   --transaction-id ea18519a572e2487
```

Results:

- All files and JSON records related to `ea18519a572e2487` are copied into a
  temporary `.data` tree.
- MAC address and system_description are sanitized.
- A ZIP file is created under `issues/` and the full path is printed.

### 2. Build Bundle From An Operation ID (Multi-Capture)

You ran a multi-capture test (for example, multi-RxMER or multi-constellation)
and want to share the entire capture group.

```bash
./tools/build/support_bundle_builder.py   --operation-id ed2fcba02bba42f6
```

The tool:

1. Looks up the capture group for `ed2fcba02bba42f6` via the operation DB.
2. Retrieves all transaction IDs listed for that group.
3. Collects all related capture files and transaction records.
4. Sanitizes and archives them into a single support bundle ZIP under `issues/`.

### 3. Build Bundle From A MAC Address

You suspect a specific modem is mis-behaving and want to share all captures
PyPNM has stored for that MAC address.

```bash
./tools/build/support_bundle_builder.py   --mac-address aa:bb:cc:dd:ee:ff
```

All transactions whose `mac_address` matches the provided value are included in
the bundle, and the sanitized ZIP is written to `issues/pypnm_support_bundle.zip`
by default.

### 4. Build Bundle With No Sanitization

If you are working in a lab environment and want to keep the real MAC and
system_description values, you can disable sanitization:

```bash
./tools/build/support_bundle_builder.py   --transaction-id ea18519a572e2487   \
                                    --keep-original-mac                 \
                                    --keep-original-sysdescr
```

Use this only when you are comfortable with sharing identifying details.

## Bundle Layout

Inside the ZIP file, the support bundle uses a **minimal** `.data` layout that
mirrors the PyPNM runtime structure but contains only the files needed to
reproduce the issue:

```text
.data/
  pnm/
    ds_ofdm_rxmer_per_subcar_aa_bb_cc_dd_ee_ff_194_1764820674.bin
    ds_ofdm_constellation_aa_bb_cc_dd_ee_ff_194_1764820678.bin
    ...
  db/
    json_transactions.json
    pypnm.sqlite3
```

Key points:

- Only PNM files and JSON metadata for the selected transactions are included.
- Paths are relative to `.data/` so the bundle can be dropped into another
  PyPNM instance for reproduction.
- If sanitization is enabled, the contents are safe to share outside your
  environment.

## Submitting A Bundle

When you open a support request for PyPNM, include:

1. The generated ZIP file (for example:  
   `issues/pypnm_support_bundle.zip`)

2. A short description of the problem:
   - Which endpoint or CLI command you used.
   - What you expected to happen.
   - The actual error message or behavior.

3. Any relevant screenshots or logs (for example, `logs/pypnm.log`).

With a sanitized support bundle attached, PyPNM maintainers can reproduce and
investigate issues without requiring full access to your production data.

# FILE: docs/design/db/addemdum.md
# PyPNM DB Backend · Locked Decisions (Selection Summary)

This file captures the decision set you selected:

`1A, 2B+2.1B, 3B, 4A(SQLite)+4C(Postgres when PyPNM-CMTS/multi-worker), 5C+5.1A, 6B+6.1A, 7B, 8A`

## Insert Into Design Doc

Add this as a new section (recommended placement: after **4. Design Requirements** or after **7. Backend Selection And Installation Contract**).

### Design Decision Register

1) **Persistence Ownership (1A)**  
   PyPNM owns persistence, schema initialization, and DB access APIs. PyPNM-CMTS must use PyPNM DB APIs only and must not implement a separate backend selector or schema manager.

2) **Installer Behavior (2B)**  
   `install.sh` supports explicit flags and a safe default:
   - `--db-install-sqlite` (default when no flag provided)
   - `--db-install-postgres`
   - If no flag is provided: interactive prompt with default `sqlite`.

3) **Secrets / Credential Handling (2.1B)**  
   Postgres credentials are not required to be stored in tracked JSON.  
   Required behavior:
   - Support env var overrides (and/or `.env`) for DSN/password
   - CI/dev may use `pypnm/pypnm` defaults, but docs must label them “development only”.

4) **Schema Application Model (3B)**  
   Schema init is performed via an idempotent SQL apply step using the shipped DDL assets:
   - `docs/design/db/schema_sqlite.sql`
   - `docs/design/db/schema_postgres.sql`  
   The apply step must:
   - Create tables/indexes idempotently
   - Seed canonical `UNKNOWN` sysDescr row idempotently
   - Seed default `artifact_stores` row idempotently (prod and demo, as applicable)
   - Enable SQLite FK enforcement (`PRAGMA foreign_keys = ON`).

5) **Concurrency And Backend Guidance (4A + 4C)**  
   - **SQLite (4A)** is supported for single-process, single-writer deployments (typical PyPNM standalone use).  
   - **Postgres (4C)** is the recommended backend when running **PyPNM-CMTS** and/or any **multi-worker / multi-process** deployment mode.  
   Installer and docs must communicate this clearly (no ambiguity).

6) **Artifact Store + Path Portability (5C + 5.1A)**  
   The DB stores only portable, app-root relative paths:
   - `artifact_stores.root_path` is app-root relative (prod: `.data/pnm`; demo: `demo/.data/pnm`)
   - `file_artifacts.relative_path` is relative to the store root  
   Runtime resolution:
   `absolute_path = Path(app_root) / artifact_stores.root_path / file_artifacts.relative_path`

7) **CI Policy And Postgres Validation (6B + 6.1A)**  
   - SQLite tests are mandatory in CI.  
   - Postgres tests are validated in CI using a service container (recommended: required, not “allowed failure”), with DSN provided via env vars.  
   CI credential defaults are acceptable for the service container only.

8) **Cutover / Legacy Ledger Strategy (8A)**  
   Treat JSON ledger persistence as deprecated and removed from the design and code paths.  
   Optional: a one-time offline migrator may be added later, but it must not be required for normal installs and must not ship populated DBs.

## Burndown Deltas

If these items are not already explicit in the burndown, add them so Codex cannot miss them.

### Phase 1 (M1) · Installer

- [ ] Add install-time warning text:
  - [ ] SQLite is recommended for standalone PyPNM/single-writer.
  - [ ] Postgres is recommended for PyPNM-CMTS and/or multi-worker.
- [ ] Postgres prompt path:
  - [ ] Allow DSN entry OR discrete fields that render into a DSN.
  - [ ] Ensure password can be provided via env var override (no plaintext requirement in JSON).

### Phase 2 (M2) · Schema Apply

- [ ] Seed `artifact_stores` idempotently:
  - [ ] prod store: `.data/pnm`
  - [ ] demo store: `demo/.data/pnm` (only if demo enabled/used)

### Phase 6 (M6) · Docs + Mermaid

- [ ] Remove/replace any remaining doc references to legacy JSON ledgers now that the DB is authoritative.
- [ ] Add Mermaid support for docs builds:
  - [ ] Add Mermaid plugin dependency to docs extras in `pyproject.toml` (example: `mkdocs-mermaid2-plugin`)
  - [ ] Update MkDocs config to render Mermaid fences (`pymdownx.superfences` mermaid custom fence)

### Phase 7 (M7) · Pytest + GitHub Actions

- [ ] Replace legacy ledger fixtures/tests with DB fixtures:
  - [ ] temporary SQLite DB under `tmp_path` + schema init helper
  - [ ] default artifact store seed helper
  - [ ] UNKNOWN sysDescr seed helper
- [ ] Add CI job for Postgres:
  - [ ] `postgres` service container
  - [ ] env var DSN provided to tests
  - [ ] schema init executed during test setup (idempotent)

## Optional Text For Docs

Use this wording (or equivalent) in the design doc and install docs:

- SQLite is intended for single-writer deployments and local/lab usage.
- For PyPNM-CMTS and/or multi-worker deployments, Postgres is recommended to avoid SQLite write contention and locked-database failure modes.
