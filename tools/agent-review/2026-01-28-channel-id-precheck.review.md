## Agent Review Bundle Summary
- Goal: Validate DS/US channel IDs in precheck and fail fast on invalid input across channel-based endpoints.
- Changes: Added channel-id validation to CableModemServicePreCheck; added INVALID_CHANNEL_ID status code; wired validation into multi-capture and single PNM endpoints that accept channel_ids; added tests for DS/US channel validation.
- Files: src/pypnm/api/routes/common/classes/operation/cable_modem_precheck.py; src/pypnm/api/routes/common/service/status_codes.py; src/pypnm/api/routes/advance/multi_rxmer/router.py; src/pypnm/api/routes/advance/multi_ds_chan_est/router.py; src/pypnm/api/routes/advance/multi_us_ofdma_pre_eq/router.py; src/pypnm/api/routes/docs/pnm/ds/ofdm/rxmer/router.py; src/pypnm/api/routes/docs/pnm/ds/ofdm/chan_est_coeff/router.py; src/pypnm/api/routes/docs/pnm/ds/ofdm/const_display/router.py; src/pypnm/api/routes/docs/pnm/ds/ofdm/fec_summary/router.py; src/pypnm/api/routes/docs/pnm/ds/ofdm/modulation_profile/router.py; src/pypnm/api/routes/docs/pnm/us/ofdma/pre_equalization/router.py; tests/test_cable_modem_precheck_channel_ids.py.
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails: repo drift); pytest -q.
- Notes: pytest skips due to PNM_CM_IT not set; ruff format check failed because of pre-existing formatting drift.

# FILE: src/pypnm/api/routes/common/classes/operation/cable_modem_precheck.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Iterable

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPConfig,
    SNMPv2c,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import DocsPnmCmCtlStatus
from pypnm.docsis.data_type.ClabsDocsisVersion import ClabsDocsisVersion
from pypnm.docsis.data_type.InterfaceStats import DocsisIfType
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, InetAddressStr, MacAddressStr

PreCheckStatus = tuple[ServiceStatusCode, str]

class CableModemServicePreCheck:
    """
    Performs preliminary connectivity and validation checks against a DOCSIS Cable Modem.

    This service supports:
    - ICMP ping reachability check
    - SNMP reachability check
    - MAC address verification
    - Optional DOCSIS version compatibility validation
    - Optional validation that OFDM (DS) and/or OFDMA (US) channels exist

    Initialization methods:
    - Provide a pre-constructed `CableModem` object
    - Or specify a `mac_address` and `ip_address` pair

    Parameters allow flexible diagnostics for network readiness prior to performing
    PNM measurements or control operations.
    """

    def __init__(
        self,
        cable_modem: CableModem | None = None,
        mac_address: MacAddressStr | None = None,
        ip_address: InetAddressStr | None = None,
        snmp_config: SNMPConfig | None = None,
        check_docsis_version: list[ClabsDocsisVersion] = None,
        validate_ofdm_exist: bool       = False,
        validate_ofdma_exist: bool      = False,
        validate_scqam_exist: bool      = False,
        validate_atdma_exist: bool      = False,
        validate_ds_channel_ids_exist: list[ChannelId] | None = None,
        validate_us_channel_ids_exist: list[ChannelId] | None = None,
        validate_pnm_ready_status: bool = True,
        ignore_mac_address_check: bool  = False,
    ) -> None:
        """
        Initialize the pre-check service.

        Args:
            cable_modem: An existing CableModem instance to use for queries (optional).
            mac_address: MAC address of the target cable modem (optional).
            ip_address: IP address of the target cable modem (optional).
            check_docsis_version: Optional list of acceptable DOCSIS versions to validate.
            validate_ofdm_exist: If True, verifies that one or more downstream OFDM channels exist.
            validate_ofdma_exist: If True, verifies that one or more upstream OFDMA channels exist.
            validate_ds_channel_ids_exist: Optional list of downstream OFDM channel IDs to validate.
            validate_us_channel_ids_exist: Optional list of upstream OFDMA channel IDs to validate.

        Raises:
            ValueError: If neither a `CableModem` object nor both `mac_address` and `ip_address` are provided.
        """
        if check_docsis_version is None:
            check_docsis_version = []
        self.logger = logging.getLogger(self.__class__.__name__)

        if cable_modem:
            self.cm = cable_modem
        elif mac_address and ip_address:

            if snmp_config is None:
                self.logger.debug("No SNMPConfig provided, using default settings")
                snmp_config = SNMPConfig(snmp_v2c=SNMPv2c(community=None))

            self.cm = CableModem(
                mac_address     =   MacAddress(mac_address),
                inet            =   Inet(ip_address),
                write_community =   snmp_config.snmp_v2c.community,
            )
        else:
            raise ValueError("Must provide either `cable_modem` or both `mac_address` and `ip_address`.")

        if check_docsis_version:
            if isinstance(check_docsis_version, ClabsDocsisVersion):
                self.check_docsis_version = [check_docsis_version]
            elif isinstance(check_docsis_version, Iterable):
                self.check_docsis_version = list(check_docsis_version)
            else:
                self.check_docsis_version = [check_docsis_version]
        else:
            self.check_docsis_version = []

        self._validate_ofdma_exist      = validate_ofdma_exist
        self._validate_ofdm_exist       = validate_ofdm_exist
        self._validate_scqam_exist      = validate_scqam_exist
        self._validate_atdma_exist      = validate_atdma_exist
        self._validate_ds_channel_ids  = validate_ds_channel_ids_exist
        self._validate_us_channel_ids  = validate_us_channel_ids_exist
        self._validate_pnm_ready_stat   = validate_pnm_ready_status
        self._ignore_mac_address_check  = ignore_mac_address_check

    async def run_precheck(self) -> tuple[ServiceStatusCode, str]:
        """
        Run full pre-check routine:
          1. Ping modem
          2. Perform SNMP check
          3. Does Mac Match CableModem Mac
          4. Validate DOCSIS version (optional)

        Returns:
            Tuple[ServiceStatusCode, str]: Status and message.
        """
        self.logger.debug(f"Starting pre-check for CableModem: {self.cm}")

        status = self.ping_reachable()
        if status != ServiceStatusCode.SUCCESS:
            msg = f"Ping check failed: {status}"
            self.logger.error(msg)
            return status, msg

        status = await self.snmp_reachable()
        if status != ServiceStatusCode.SUCCESS:
            msg = f"SNMP check failed: {status}"
            self.logger.error(msg)
            return status, msg

        if not self._ignore_mac_address_check:
            status = await self.isMacCorrect()
            if status != ServiceStatusCode.SUCCESS:

                try:
                    mac = await self.getRealMacAddress()
                except Exception as e:
                    self.logger.error(f"Error retrieving real MAC address: {e}", exc_info=True)
                    mac = "Unknown"

                msg = f"Found: {mac} MAC address CableModem Mac check failed: {status}"
                self.logger.error(msg)
                return status, msg

        if self.check_docsis_version:
            status, msg = await self.validate_docsis_version()
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        if self._validate_ofdm_exist:
            status, msg = await self.validate_ofdm_channel_exist()
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        if self._validate_ofdma_exist:
            status, msg = await self.validate_ofdma_channel_exist()
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        if self._validate_scqam_exist:
            status, msg = await self.validate_scqam_channel_exist()
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        if self._validate_atdma_exist:
            status, msg = await self.validate_atdma_channel_exist()
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        if self._validate_ds_channel_ids is not None:
            status, msg = await self.validate_ds_channel_ids_exist(self._validate_ds_channel_ids)
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        if self._validate_us_channel_ids is not None:
            status, msg = await self.validate_us_channel_ids_exist(self._validate_us_channel_ids)
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        if self._validate_pnm_ready_stat:
            status, msg = await self.validate_pnm_ready_status()
            if status != ServiceStatusCode.SUCCESS:
                return status, msg

        msg = "Pre-check successful: CableModem reachable via ping and SNMP"
        self.logger.debug(msg)
        return ServiceStatusCode.SUCCESS, msg

    def ping_reachable(self) -> ServiceStatusCode:
        """
        Perform an ICMP ping test.

        Returns:
            SUCCESS if reachable, else PING_FAILED.
        """
        try:
            if self.cm.is_ping_reachable():
                self.logger.debug("Ping check passed")
                return ServiceStatusCode.SUCCESS
            self.logger.debug("Ping check failed")
            return ServiceStatusCode.PING_FAILED
        except Exception as e:
            self.logger.error(f"Ping check exception: {e}", exc_info=True)
            return ServiceStatusCode.PING_FAILED

    async def snmp_reachable(self) -> ServiceStatusCode:
        """
        Perform SNMP reachability check.

        Returns:
            SUCCESS if SNMP response received, else UNREACHABLE_SNMP.
        """
        try:
            if await self.cm.is_snmp_reachable():
                self.logger.debug("SNMP check passed")
                return ServiceStatusCode.SUCCESS
            self.logger.debug("SNMP check failed")
            return ServiceStatusCode.UNREACHABLE_SNMP

        except Exception as e:
            self.logger.error(f"SNMP check exception: {e}", exc_info=True)
            return ServiceStatusCode.UNREACHABLE_SNMP

    async def isMacCorrect(self) -> ServiceStatusCode:
        """
        Check if the cable modem's MAC address is correct.
        """
        try:
            if await self.cm.isCableModemMacCorrect():
                self.logger.debug("MAC address check passed")
                return ServiceStatusCode.SUCCESS
            self.logger.debug("MAC address check failed")
            return ServiceStatusCode.CM_MAC_DOES_MATCH_MATCH
        except Exception as e:
            self.logger.error(f"MAC address check exception: {e}", exc_info=True)
            return ServiceStatusCode.UNREACHABLE_SNMP

    async def getRealMacAddress(self) -> MacAddress:
        """
        Retrieve the real MAC address from the cable modem via SNMP.

        Returns:
            MacAddress: The MAC address retrieved from the cable modem.
        """
        try:
            mac = await self.cm.getIfPhysAddress()
            self.logger.debug(f"Retrieved MAC address: {mac}")
            return mac
        except Exception as e:
            self.logger.error(f"Error retrieving MAC address: {e}", exc_info=True)
            raise

    async def validate_docsis_version(self) -> tuple[ServiceStatusCode, str]:
        """
        Check if the modem's DOCSIS version is in the accepted list.

        Returns:
            SUCCESS if version is allowed, else INVALID_DOCSIS_VERSION.
        """
        try:
            base_cap:ClabsDocsisVersion = await self.cm.getDocsisBaseCapability()
            if base_cap not in self.check_docsis_version:
                msg = f"Invalid DOCSIS Version: {base_cap.name}"
                self.logger.error(msg)
                return ServiceStatusCode.INVALID_DOCSIS_VERSION, msg

            self.logger.debug(f"DOCSIS version check passed: {base_cap.name}")
            return ServiceStatusCode.SUCCESS, "Valid DOCSIS version"

        except Exception as e:
            msg = f"Error checking DOCSIS version: {e}"
            self.logger.error(msg, exc_info=True)
            return ServiceStatusCode.INVALID_DOCSIS_VERSION, msg

    async def validate_ofdm_channel_exist(self) -> tuple[ServiceStatusCode, str]:
        """
        Checks whether any OFDM downstream channels are present on the cable modem.

        This method queries the cable modem for the DOCSIS 3.1 upstream OFDMA channel
        index stack. If no indices are found, it returns a failure status.

        Returns:
            Tuple[ServiceStatusCode, str]: A tuple containing the status code and an explanatory message.
                - ServiceStatusCode.SUCCESS if channels are found
                - ServiceStatusCode.NO_OFDMA_CHANNELS_EXIST if no channels are detected
        """
        idx_chan_stack = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()

        if not idx_chan_stack:
            msg = "No OFDM channels found on the cable modem."
            return ServiceStatusCode.NO_OFDMA_CHANNELS_EXIST, msg

        return ServiceStatusCode.SUCCESS, "OFDMA upstream channels detected."

    async def validate_ofdma_channel_exist(self) -> tuple[ServiceStatusCode, str]:
        """
        Checks whether any OFDMA upstream channels are present on the cable modem.

        This method queries the cable modem for the DOCSIS 3.1 upstream OFDMA channel
        index stack. If no indices are found, it returns a failure status.

        Returns:
            Tuple[ServiceStatusCode, str]: A tuple containing the status code and an explanatory message.
                - ServiceStatusCode.SUCCESS if channels are found
                - ServiceStatusCode.NO_OFDMA_CHANNELS_EXIST if no channels are detected
        """
        idx_chan_stack = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()

        if not idx_chan_stack:
            msg = "No OFDMA channels found on the cable modem."
            return ServiceStatusCode.NO_OFDMA_CHANNELS_EXIST, msg

        return ServiceStatusCode.SUCCESS, "OFDMA upstream channels detected."

    async def validate_scqam_channel_exist(self) -> tuple[ServiceStatusCode, str]:
        """
        Checks whether any SC-QAM downstream channels are present on the cable modem.

        This method queries the cable modem for the DOCSIS 3.0 SC-QAM downstream channel
        index stack. If no indices are found, it returns a failure status.

        Returns:
            Tuple[ServiceStatusCode, str]: A tuple containing the status code and an explanatory message.
                - ServiceStatusCode.SUCCESS if channels are found
                - ServiceStatusCode.NO_SCQAM_CHAN_ID_INDEX_FOUND if no channels are detected
        """
        scqam_idx_list = await self.cm.getIfTypeIndex(DocsisIfType.docsCableDownstream)

        if not scqam_idx_list:
            msg = "No SC-QAM channels found on the cable modem."
            return ServiceStatusCode.NO_SCQAM_CHAN_ID_INDEX_FOUND, msg

        return ServiceStatusCode.SUCCESS, "SC-QAM downstream channels detected."

    async def validate_atdma_channel_exist(self) -> tuple[ServiceStatusCode, str]:
        """
        Checks whether any ATDMA upstream channels are present on the cable modem.

        This method queries the cable modem for the DOCSIS 3.0 ATDMA upstream channel
        index stack. If no indices are found, it returns a failure status.

        Returns:
            Tuple[ServiceStatusCode, str]: A tuple containing the status code and an explanatory message.
                - ServiceStatusCode.SUCCESS if channels are found
                - ServiceStatusCode.NO_ATDMA_CHAN_ID_INDEX_FOUND if no channels are detected
        """
        atdma_idx_list = await self.cm.getIfTypeIndex(DocsisIfType.docsCableUpstream)

        if not atdma_idx_list:
            msg = "No ATDMA channels found on the cable modem."
            return ServiceStatusCode.NO_ATDMA_CHAN_ID_INDEX_FOUND, msg

        return ServiceStatusCode.SUCCESS, "ATDMA upstream channels detected."

    async def validate_ds_channel_ids_exist(self, channel_ids: list[ChannelId]) -> PreCheckStatus:
        """
        Validate that provided downstream OFDM channel IDs exist on the cable modem.
        """
        if len(channel_ids) == 0:
            return ServiceStatusCode.SUCCESS, "No DS channel IDs provided for validation."

        idx_chan_stack = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()
        available_ids = {int(chan_id) for _, chan_id in idx_chan_stack}
        missing = [int(channel_id) for channel_id in channel_ids if int(channel_id) not in available_ids]

        if missing:
            msg = f"Invalid DS channel ID(s): {missing}"
            return ServiceStatusCode.INVALID_CHANNEL_ID, msg

        return ServiceStatusCode.SUCCESS, "DS channel IDs validated."

    async def validate_us_channel_ids_exist(self, channel_ids: list[ChannelId]) -> PreCheckStatus:
        """
        Validate that provided upstream OFDMA channel IDs exist on the cable modem.
        """
        if len(channel_ids) == 0:
            return ServiceStatusCode.SUCCESS, "No US channel IDs provided for validation."

        idx_chan_stack = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
        available_ids = {int(chan_id) for _, chan_id in idx_chan_stack}
        missing = [int(channel_id) for channel_id in channel_ids if int(channel_id) not in available_ids]

        if missing:
            msg = f"Invalid US channel ID(s): {missing}"
            return ServiceStatusCode.INVALID_CHANNEL_ID, msg

        return ServiceStatusCode.SUCCESS, "US channel IDs validated."

    async def validate_pnm_ready_status(self) -> PreCheckStatus:

        out:PreCheckStatus = (ServiceStatusCode.SUCCESS, DocsPnmCmCtlStatus.READY.name)

        rst: DocsPnmCmCtlStatus = await self.cm.getDocsPnmCmCtlStatus()

        if rst != DocsPnmCmCtlStatus.READY:
            return ServiceStatusCode.SUCCESS, rst.name

        return out


# FILE: src/pypnm/api/routes/common/service/status_codes.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from enum import IntEnum


class ServiceStatusCode(IntEnum):
    '''
    SKIP_MESSAGE is to indicat not process the MessageResponse
    '''
    SKIP_MESSAGE_RESPONSE                   = -2
    UNKNOWN                                 = -1
    SUCCESS                                 =  0
    UNREACHABLE_PING                        =  1
    UNREACHABLE_SNMP                        =  2
    NO_PLC_FOUND                            =  3
    INVALID_PLC                             =  4
    TFTP_INET_MISMATCH                      =  5
    FILE_SET_FAIL                           =  6
    TEST_ERROR                              =  7
    MEASUREMENT_TIMEOUT                     =  8
    TFTP_SERVER_PATH_SET_FAIL               =  9
    NOT_READY_AFTER_FILE_CAPTURE            = 10
    COPY_PNM_FILE_TO_LOCAL_SAVE_DIR_FAILED  = 11
    TRANSACTION_RECORD_SET_FAILED           = 12
    UNSUPPORTED_IF_TYPE                     = 13
    NO_OFDM_CHAN_ID_INDEX_FOUND             = 14
    NO_OFDMA_CHAN_ID_INDEX_FOUND            = 15
    INVALID_INTERFACE_PARAMETERS            = 16
    FAILURE                                 = 17
    RESET_NOW_FAILED                        = 18
    PING_FAILED                             = 19
    MISSING_PNM_FILENAME                    = 20
    TFTP_PNM_FILE_UPLOAD_FAILURE            = 21
    NO_SCQAM_CHAN_ID_INDEX_FOUND            = 22
    NO_ATDMA_CHAN_ID_INDEX_FOUND            = 23
    MISSING_PNM_TEST_TYPE                   = 24
    CM_MAC_DOES_MATCH_MATCH                 = 25

    INVALID_CAPTURE_PARAMETERS              = 90

    PNM_FILE_RETRIEVAL_ERROR                = 98
    FILE_RETRIEVAL_TYPE_INVALID             = 99

    SCP_PNM_FILE_FETCH_ERROR                = 100
    SFTP_PNM_FILE_FETCH_ERROR               = 101
    TFTP_PNM_FILE_FETCH_ERROR               = 102
    FTP_PNM_FILE_FETCH_ERROR                = 103
    HTTP_PNM_FILE_FETCH_ERROR               = 104
    SHTTP_PNM_FILE_FETCH_ERROR              = 105
    LOCAL_FETCH_FAILURE                     = 106

    SCP_HOST_UNREACHABLE                    = 110
    SFTP_HOST_UNREACHABLE                   = 111
    TFTP_HOST_UNREACHABLE                   = 112
    FTP_HOST_UNREACHABLE                    = 113
    HTTP_HOST_UNREACHABLE                   = 114
    SHTTP_HOST_UNREACHABLE                  = 115
    LOCAL_HOST_UNREACHABLE                  = 116

    INVALID_DOCSIS_VERSION                  = 120
    NO_OFDMA_CHANNELS_EXIST                 = 121
    NO_OFDM_CHANNELS_EXIST                  = 122
    INVALID_CHANNEL_ID                      = 123

    TRANSACTION_RECORD_GET_FAILED           = 200
    UNSUPPORTED_TEST_TYPE                   = 201
    CAPTURE_GROUP_NOT_FOUND                 = 202
    PNM_FILE_TRANSACTION_ID_NOT_FOUND       = 203

    INVALID_OUTPUT_TYPE                     = 220

    DS_OFDM_RXMER_NOT_AVAILABLE             = 300

    SPEC_ANALYZER_NOT_AVAILABLE             = 400
    SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT    = 401
    SPEC_ANALYZER_AMPLITUDE_DATA_NOT_FOUND  = 402
    SPEC_ANALYZER_DATA_RETRIVAL_ERROR       = 403
    SPEC_ANALYZER_SET_CONFIG_ERROR          = 404

    DS_OFDM_MULIT_RXMER_FAILED              = 500
    MEASURE_MODE_INVALID                    = 501
    DS_OFDM_MULIT_RXMER_ANALYSIS_TYPE       = 502

    DS_OFDM_CHAN_EST_NOT_AVAILABLE          = 550
    DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE  = 551

    US_OFDMA_PRE_EQ_NOT_AVAILABLE           = 600
    US_OFDMA_PRE_EQ_INVALID_ANALYSIS_TYPE   = 601

    DS_OFDM_FEC_SUMMARY_NOT_AVALIABLE       = 700

    DS_OFDM_MOD_PROFILE_NOT_AVALAIBLE       = 800

    NO_SPECTRUM_CAPTURE_PARAMETERS          = 1000


# FILE: src/pypnm/api/routes/advance/multi_rxmer/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import io
import logging
import os
import zipfile
from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from pypnm.api.routes.advance.analysis.signal_analysis.multi_rxmer_signal_analysis import (
    MultiRxMerAnalysisResult,
    MultiRxMerAnalysisType,
    MultiRxMerSignalAnalysis,
)
from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.multi_rxmer.schemas import (
    MultiRxMerAnalysisRequest,
    MultiRxMerAnalysisResponse,
    MultiRxMerMeasureModes,
    MultiRxMerRequest,
    MultiRxMerResponseStatus,
    MultiRxMerStartResponse,
    MultiRxMerStatusResponse,
)
from pypnm.api.routes.advance.multi_rxmer.service import (
    MultiRxMer_Ofdm_Performance_1_Service,
    MultiRxMerService,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import FileType, PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, GroupId, MacAddressStr, OperationId


class MultiRxMerRouter(AbstractService):
    """
    Router For Multi-RxMER Capture And Analysis

    Overview
    --------
    Exposes endpoints to:
      • Start a background, periodic RxMER capture on a DOCSIS cable modem
      • Poll capture status (state, collected sample count, time remaining)
      • Download all collected raw RxMER files as a ZIP archive
      • Stop an active capture early
      • Run post-capture analysis on the collected dataset

    Execution Model
    ---------------
    Each capture runs asynchronously under a managed operation. The returned `operation_id`
    is used to query status, fetch results, or trigger analysis. Pre-checks verify PNM-ready
    state and the presence of downstream OFDM.

    Inherits
    --------
    AbstractService
        Provides `loadService(...)` and `getService(...)` for service lifecycle and operation lookup.
    """
    def __init__(self) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/advance/multi/rxMer",
            tags=["PNM Operations - Multi-Downstream OFDM RxMER"],)
        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post("/start",
            response_model=MultiRxMerStartResponse | SnmpResponse,
            summary="Start a Multi-RxMER capture",
            responses=FAST_API_RESPONSE,)
        async def start_multi_rxmer(request: MultiRxMerRequest) -> SnmpResponse | MultiRxMerStartResponse:
            """
            Start Multi-RxMER Capture

            Description
            -----------
            Starts an asynchronous RxMER capture on the target cable modem. Sampling cadence is
            controlled by `capture.parameters.measurement_duration` and `capture.parameters.sample_interval`.

            Modes
            -----
            • `MeasureModes.CONTINUOUS` - Continuous sampling for min/avg/max and heat-map workflows
            • `MeasureModes.OFDM_PERFORMANCE_1` - Performance study pairing RxMER with modulation-profile
              and FEC summary collection

            Returns
            -------
            • `MultiRxMerStartResponse` with `group_id` and `operation_id` on success
            • `SnmpResponse` when modem pre-checks fail (e.g., not PNM-ready or OFDM missing)

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """

            mac_address: MacAddressStr = request.cable_modem.mac_address
            ip_address: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)
            duration = request.capture.parameters.measurement_duration
            interval = request.capture.parameters.sample_interval
            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            interface_parameters = self._resolve_interface_parameters(channel_ids)

            measure_modes = request.measure.mode
            msg:str = ""

            self.logger.info(
                f"Starting Multi-RxMER capture for MAC={mac_address} "
                f"(duration={duration}s, interval={interval}s)")

            cable_modem = CableModem(mac_address=MacAddress(mac_address),
                                     inet=Inet(ip_address),
                                     write_community=community)

            status, msg = await CableModemServicePreCheck(cable_modem=cable_modem,
                                                          validate_ofdm_exist=True,
                                                          validate_ds_channel_ids_exist=channel_ids,
                                                          validate_pnm_ready_status=True).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)

            if measure_modes == MultiRxMerMeasureModes.CONTINUOUS:
                msg=f'Starting Multi-RxMER capture for MAC={mac_address}'
                self.logger.info(f'{msg}')
                group_id, operation_id = await self.loadService(
                    MultiRxMerService,
                    cable_modem,
                    tftp_servers,
                    duration=duration,
                    interval=interval,
                    interface_parameters=interface_parameters,)

            elif measure_modes == MultiRxMerMeasureModes.OFDM_PERFORMANCE_1:
                msg=f'Starting Multi-RxMER-OFDM-Performance-1 capture for MAC={mac_address}'
                self.logger.info(f'{msg}')
                group_id, operation_id = await self.loadService(
                    MultiRxMer_Ofdm_Performance_1_Service,
                    cable_modem,
                    tftp_servers,
                    duration=duration,
                    interval=interval,
                    interface_parameters=interface_parameters,)

            else:
                self.logger.error(f'Invalid Measure Mode Selected: ({measure_modes})')
                return MultiRxMerStartResponse(
                    mac_address =   mac_address,
                    status      =   ServiceStatusCode.MEASURE_MODE_INVALID,
                    message =f"{ServiceStatusCode.MEASURE_MODE_INVALID.name}",
                    group_id="", operation_id="",)

            return MultiRxMerStartResponse(
                mac_address =   mac_address,
                status      =   OperationState.RUNNING,
                message     =   msg,
                group_id    =   group_id,
                operation_id=   operation_id,
            )

        @self.router.get("/status/{operation_id}",
            response_model=MultiRxMerStatusResponse,
            summary="Get status of a Multi-RxMER capture",
            responses=FAST_API_RESPONSE,)
        def get_status(operation_id: OperationId) -> MultiRxMerStatusResponse:
            """
            Check Multi-RxMER Capture Status

            Description
            -----------
            Returns the current state of the capture, number of samples collected, and estimated
            time remaining for the given `operation_id`.

            Path Parameters
            ---------------
            operation_id : OperationId
                Identifier returned by `/start`.

            Returns
            -------
            `MultiRxMerStatusResponse` populated with `operation.state`, `operation.collected`,
            and `operation.time_remaining`.

            Errors
            ------
            404 — Operation not found.

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """
            try:
                service:MultiRxMerService = cast(MultiRxMerService, self.getService(operation_id))

            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            status = service.status(operation_id)

            self.logger.debug(f'OpId: {operation_id} - Status: {status}')

            return MultiRxMerStatusResponse(
                mac_address =   service.cm.get_mac_address.mac_address,
                status      =   "success",
                message     =   None,
                operation   =   MultiRxMerResponseStatus(
                                    operation_id    =   operation_id,
                                    state           =   status["state"],
                                    collected       =   status["collected"],
                                    time_remaining  =   status["time_remaining"],
                                    message         =   None,
                ),
            )

        @self.router.get("/results/{operation_id}",
            summary="Download a ZIP archive of all RxMER capture files",
            responses=FAST_API_RESPONSE,)
        def download_measurements_zip(operation_id: OperationId) -> StreamingResponse:
            """
            Download Captured RxMER Measurements (ZIP)

            Description
            -----------
            Streams a ZIP archive containing all RxMER `.bin` files associated with the specified
            `operation_id`. Useful for offline analysis or archival.

            Content
            -------
            • Media Type: `application/zip`
            • Disposition: `attachment; filename=multiRxMer_<mac>_<operation_id>.zip`

            Path Parameters
            ---------------
            operation_id : OperationId
                Identifier returned by `/start`.

            Returns
            -------
            `StreamingResponse` — Streamed ZIP of all capture files found. Missing files are logged and skipped.

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """
            svc:MultiRxMerService = cast(MultiRxMerService, self.getService(operation_id))
            samples = svc.results(operation_id)

            pnm_dir = str(SystemConfigSettings.pnm_dir())
            mac = svc.cm.get_mac_address.mac_address

            buf = io.BytesIO()
            with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zipf:
                for sample in samples:
                    file_path = os.path.join(pnm_dir, sample.filename)
                    arcname = os.path.basename(sample.filename)
                    try:
                        zipf.write(file_path, arcname=arcname)
                    except FileNotFoundError:
                        self.logger.warning(f"File not found, skipping: {file_path}")
                    except Exception as e:
                        self.logger.warning(f"Skipping {file_path}: {e}")

            buf.seek(0)

            headers = {"Content-Disposition": f"attachment; filename=multiRxMer_{mac}_{operation_id}.zip"}
            return StreamingResponse(buf, media_type="application/zip", headers=headers)

        @self.router.delete("/stop/{operation_id}",
            response_model=MultiRxMerStatusResponse,
            summary="Stop a running Multi-RxMER capture early",
            responses=FAST_API_RESPONSE,)
        def stop_capture(operation_id: OperationId) -> MultiRxMerStatusResponse:
            """
            Stop Multi-RxMER Capture

            Description
            -----------
            Signals the background worker to stop sampling after the current iteration for the
            specified `operation_id`.

            Path Parameters
            ---------------
            operation_id : OperationId
                Identifier returned by `/start`.

            Returns
            -------
            `MultiRxMerStatusResponse` — Finalized state and counters at stop time.

            Errors
            ------
            404 — Operation not found.

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """
            try:
                service:MultiRxMerService = cast(MultiRxMerService, self.getService(operation_id))
            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            service.stop(operation_id)
            status = service.status(operation_id)

            return MultiRxMerStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                status=OperationState.STOPPED,
                message=None,
                operation=MultiRxMerResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None,
                ),
            )

        @self.router.post("/analysis",
            response_model=MultiRxMerAnalysisResponse,
            summary="Perform signal analysis on a previously executed Multi-RxMER captures",
            responses=FAST_API_RESPONSE,)
        def analysis(request: MultiRxMerAnalysisRequest) -> MultiRxMerAnalysisResponse | FileResponse:
            """
            Multi-RxMER Analysis

            Description
            -----------
            Runs post-capture analysis for the dataset associated with `request.operation_id`.
            The capture group is derived internally from the operation.

            Analysis Types
            --------------
            • `MIN_AVG_MAX` — Per-subcarrier min/avg/max over the series
            • `RXMER_HEAT_MAP` — Heat-map oriented dataset for visualization
            • `OFDM_PROFILE_PERFORMANCE_1` — Averages RxMER, compares to modulation profiles,
              and aggregates FEC statistics over time

            Output
            ------
            Controlled by `request.analysis.output.type`:
            • `OutputType.JSON` — Typed JSON payload for UI consumption
            • `OutputType.ARCHIVE` — Generated ZIP report via `PnmFileService`

            Returns
            -------
            • `MultiRxMerAnalysisResponse` (JSON output)
            • `FileResponse` (archive report)

            Errors
            ------
            • Capture group not found for the supplied operation
            • Invalid analysis type or invalid output type

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """
            try:
                capture_group_id:GroupId = OperationManager.get_capture_group(request.operation_id)
                self.logger.info(f'[analysis] - OperationID: {request.operation_id} -> CaptureGroup: {capture_group_id}')

            except KeyError:
                return MultiRxMerAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message     =   f"No capture group found for operation {request.operation_id}",
                    data        =   {})

            cda = CaptureDataAggregator(capture_group_id)

            try:
                atype = MultiRxMerAnalysisType(request.analysis.type)
            except ValueError:
                msg = f'Invalid Analysis Type, reason: {request.analysis.type}'
                return MultiRxMerAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.DS_OFDM_MULIT_RXMER_ANALYSIS_TYPE,
                    message     =   msg,
                    data        =   {})
            self.logger.info(f'Performing Multi-RxMER Min/Avg/Max Analysis for group: {capture_group_id}')

            if atype == MultiRxMerAnalysisType.MIN_AVG_MAX:
                engine = MultiRxMerSignalAnalysis(cda, atype)
                multi_analysis:MultiRxMerAnalysisResult = engine.to_model()

            elif atype == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
                engine = MultiRxMerSignalAnalysis(cda, MultiRxMerAnalysisType.RXMER_HEAT_MAP)
                multi_analysis = engine.to_model()

            elif atype == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
                '''
                    Operation of this test:
                    -----------------------
                    * Collect a seriers of RxMER
                    * Collect at least 1 Modualtion Profile=
                    * Collect a Fec Summary at:
                        - 1 FecSummary every 10 Min
                        - At end of the test

                    OFDM_PROFILE_MEASUREMENT_1
                    --------------------------
                    * Calculate the Avg RxMER of the series
                    * Calculate Shannon for each subcarrier
                    * Compare each modualtion profile against the RxMER Average
                    * Calculate the percentage of subcarries that are outside a given profile
                    * Provide total FEC Stats for each profile over the time of the capture.
                '''
                engine = MultiRxMerSignalAnalysis(cda, MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1)
                multi_analysis = engine.to_model()

            else:
                msg = f'Invalid Analysis Type {atype}'
                return MultiRxMerAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.DS_OFDM_MULIT_RXMER_ANALYSIS_TYPE,
                    message     =   msg,
                    data        =   {})

            # 4) Map analysis output to response fields
            analysis_name = MultiRxMerAnalysisType(atype).name
            message = f"Analysis {analysis_name} completed for group {capture_group_id}"

            try:
                output_type = request.analysis.output.type
            except ValueError:
                msg = f'Invalid Output Type Selected: ({request.analysis.output.type})'
                return MultiRxMerAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    message     =   msg,
                    data        =   {})

            mac_address = multi_analysis.mac_address

            if output_type == OutputType.JSON:
                data = multi_analysis.model_dump().get("data", {})
                return MultiRxMerAnalysisResponse(
                    mac_address =   mac_address,
                    status      =   ServiceStatusCode.SUCCESS,
                    message     =   message,
                    data        =   data,)

            elif output_type == OutputType.ARCHIVE:
                rpt = engine.build_report()
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:

                # Fallback for unsupported output types
                return MultiRxMerAnalysisResponse(
                    mac_address =   mac_address,
                    status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    message     =   f"Unsupported output type: {output_type}",
                    data        =   {},)

    @staticmethod
    def _resolve_interface_parameters(
        channel_ids: list[ChannelId] | None,
    ) -> DownstreamOfdmParameters | None:
        if not channel_ids:
            return None
        return DownstreamOfdmParameters(channel_id=list(channel_ids))

# For dynamic auto-registration
router = MultiRxMerRouter().router


# FILE: src/pypnm/api/routes/advance/multi_ds_chan_est/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import io
import logging
import os
import zipfile
from collections.abc import Callable
from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from pypnm.api.routes.advance.analysis.signal_analysis.multi_chan_est_singnal_analysis import (
    MultiChanEstAnalysisType,
    MultiChanEstimationSignalAnalysis,
)
from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.multi_ds_chan_est.schemas import (
    AnalysisDataModel,
    MultiChanEstAnalysisRequest,
    MultiChanEstimationAnalysisResponse,
    MultiChanEstimationResponseStatus,
    MultiChanEstimationStartResponse,
    MultiChanEstRequest,
    MultiChanEstStatusResponse,
)
from pypnm.api.routes.advance.multi_ds_chan_est.service import (
    MultiChannelEstimationService,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, GroupId, MacAddressStr, OperationId


class MultiDsChanEstRouter(AbstractService):
    """Router for handling Multi-DS-Channel-Estimation operations."""

    def __init__(self) -> None:
        super().__init__()
        self.router = APIRouter(prefix="/advance/multi/channelEstimation",
                                tags=["PNM Operations - Multi-DS-Channel-Estimation"])
        self.logger = logging.getLogger(self.__class__.__name__)
        self._add_routes()

    # ──────────────────────────────────────────────────────────
    # Routes
    # ──────────────────────────────────────────────────────────
    def _add_routes(self) -> None:

        @self.router.post("/start",
            response_model=MultiChanEstimationStartResponse | SnmpResponse,
            summary="Start a multi-sample ChannelEstimation capture")
        async def start_multi_chan_estimation(request: MultiChanEstRequest) -> MultiChanEstimationStartResponse | SnmpResponse:

            duration, interval = request.capture.parameters.measurement_duration, request.capture.parameters.sample_interval
            mac_address: MacAddressStr = request.cable_modem.mac_address
            ip_address: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)
            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            interface_parameters = self._resolve_interface_parameters(channel_ids)


            self.logger.info(f"[start] Multi-ChanEst for MAC={mac_address}, duration={duration}s interval={interval}s")

            cm = CableModem(mac_address=MacAddress(mac_address), inet=Inet(ip_address), write_community=community)

             # Pre-checks
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                validate_ofdm_exist=True,
                validate_ds_channel_ids_exist=channel_ids,
            ).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(f"[start] Precheck failed for MAC={mac_address}: {msg}")
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)

            group_id, operation_id = await self.loadService(MultiChannelEstimationService,
                                                            cm,
                                                            tftp_servers,
                                                            duration=duration,
                                                            interval=interval,
                                                            interface_parameters=interface_parameters,)
            return MultiChanEstimationStartResponse(mac_address     =   mac_address,
                                                    status          =   OperationState.RUNNING,
                                                    message         =   None,
                                                    group_id        =   group_id,
                                                    operation_id    =   operation_id)


        @self.router.get("/status/{operation_id}",
            response_model=MultiChanEstStatusResponse,
            summary="Get status of a multi-sample ChannelEstimation capture")
        def get_status(operation_id: OperationId) -> MultiChanEstStatusResponse:
            try:
                service: MultiChannelEstimationService = cast(MultiChannelEstimationService, self.getService(operation_id))

            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            status = service.status(operation_id)
            return MultiChanEstStatusResponse(
                mac_address     =   service.cm.get_mac_address.mac_address,
                status          =   "success",
                message         =   None,
                operation       =   MultiChanEstimationResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None))

        @self.router.get("/results/{operation_id}",
            summary="Download a ZIP archive of all ChannelEstimation capture files",
            responses={200: {"content": {"application/zip": {}},
                             "description": "ZIP archive of capture files"}})
        def download_results_zip(operation_id: OperationId) -> StreamingResponse:

            svc: MultiChannelEstimationService = cast(MultiChannelEstimationService, self.getService(operation_id))
            samples = svc.results(operation_id)
            pnm_dir, mac = str(SystemConfigSettings.pnm_dir()), svc.cm.get_mac_address.mac_address
            buf = io.BytesIO()

            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for s in samples:
                    path = os.path.join(pnm_dir, s.filename)

                    try:
                        zf.write(path, arcname=os.path.basename(s.filename))

                    except FileNotFoundError:
                        self.logger.warning(f"[zip] Missing: {path}")

                    except Exception as e:
                        self.logger.warning(f"[zip] Skip {path}: {e}")

            buf.seek(0)
            headers = {"Content-Disposition": f"attachment; filename=multiChannelEstimation_{mac}_{operation_id}.zip"}
            return StreamingResponse(buf, media_type="application/zip", headers=headers)


        @self.router.delete("/stop/{operation_id}",
            response_model=MultiChanEstStatusResponse,
            summary="Stop a running multi-sample ChannelEstimation capture early")
        def stop_capture(operation_id: OperationId) -> MultiChanEstStatusResponse:
            """


            """
            try:
                service: MultiChannelEstimationService = cast(MultiChannelEstimationService, self.getService(operation_id))

            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            service.stop(operation_id)
            status = service.status(operation_id)
            return MultiChanEstStatusResponse(
                mac_address =   service.cm.get_mac_address.mac_address,
                status      =   OperationState.STOPPED,
                message     =   None,
                operation   =   MultiChanEstimationResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None)
            )


        @self.router.post("/analysis",
            response_model=MultiChanEstimationAnalysisResponse,
            summary="Perform signal analysis on a previously executed Multi-ChannelEstimation")
        def analysis(request: MultiChanEstAnalysisRequest) -> MultiChanEstimationAnalysisResponse | FileResponse:
            """
            Perform post-capture analysis on Multi-ChannelEstimation measurement data.

            Supports:
            - MIN_AVG_MAX
            - GROUP_DELAY
            - LTE_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_IFFT
            """
            try:
                capture_group_id: GroupId = OperationManager.get_capture_group(request.operation_id)
                self.logger.info(f"[analysis] operation_id={request.operation_id} capture_group={capture_group_id}")
            except KeyError:
                msg = f"No capture group found for operation {request.operation_id}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address     =   MacAddress.null(),
                    status          =   ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message         =   msg,
                    data            =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Prepare data aggregator
            cda = CaptureDataAggregator(capture_group_id)

            # Parse analysis type
            try:
                atype = MultiChanEstAnalysisType(request.analysis.type)

            except ValueError:
                msg = f"Invalid analysis type: {request.analysis.type}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE,
                    message     =   msg,
                    data        =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Dispatch map for type → analysis engine
            analysis_map: dict[MultiChanEstAnalysisType, Callable[[CaptureDataAggregator], MultiChanEstimationSignalAnalysis]] = {
                MultiChanEstAnalysisType.MIN_AVG_MAX:                lambda agg: MultiChanEstimationSignalAnalysis(agg, MultiChanEstAnalysisType.MIN_AVG_MAX),
                MultiChanEstAnalysisType.GROUP_DELAY:                lambda agg: MultiChanEstimationSignalAnalysis(agg, MultiChanEstAnalysisType.GROUP_DELAY),
                MultiChanEstAnalysisType.LTE_DETECTION_PHASE_SLOPE:  lambda agg: MultiChanEstimationSignalAnalysis(agg, MultiChanEstAnalysisType.LTE_DETECTION_PHASE_SLOPE),
                MultiChanEstAnalysisType.ECHO_DETECTION_IFFT:        lambda agg: MultiChanEstimationSignalAnalysis(agg, MultiChanEstAnalysisType.ECHO_DETECTION_IFFT),
            }

            if atype not in analysis_map:
                msg = f"Unsupported analysis type: {atype}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address     =   MacAddress.null(),
                    status          =   ServiceStatusCode.DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE,
                    message         =   msg,
                    data            =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Determine output type
            output_type:OutputType = request.analysis.output.type
            engine = analysis_map[atype](cda)
            analysis_result = engine.to_model()

            # Handle output formats
            if output_type == OutputType.JSON:
                err = analysis_result.error
                status = ServiceStatusCode.SUCCESS if not err else ServiceStatusCode.FAILURE
                message = err or f"Analysis {analysis_result.analysis_type} completed for group {capture_group_id}"

                data_model = AnalysisDataModel(
                    analysis_type   =   analysis_result.analysis_type,
                    results         =   [r.model_dump() for r in analysis_result.results])

                mac = engine.getMacAddresses()[0].mac_address
                self.logger.info(f"[analysis] type={atype.name} mac={mac} status={status.name} group={capture_group_id}")

                return MultiChanEstimationAnalysisResponse(
                    mac_address =   mac,
                    status      =   status,
                    message     =   message,
                    data        =   data_model)

            elif output_type == OutputType.ARCHIVE:
                try:
                    rpt = engine.build_report()
                    self.logger.info(f"[analysis] Built archive report for group {capture_group_id}")
                    return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

                except Exception as e:
                    msg = f"Archive build failed: {e}"
                    self.logger.error(msg)
                    return MultiChanEstimationAnalysisResponse(
                        mac_address     =   MacAddress.null(),
                        status          =   ServiceStatusCode.FAILURE,
                        message         =   msg,
                        data            =   AnalysisDataModel(analysis_type=atype.name, results=[]))

            # Unsupported output type
            msg = f"Unsupported output type: {output_type}"
            self.logger.error(msg)
            return MultiChanEstimationAnalysisResponse(
                mac_address     =   MacAddress.null(),
                status          =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message         =   msg,
                data            =   AnalysisDataModel(analysis_type=atype.name, results=[]))

    @staticmethod
    def _resolve_interface_parameters(
        channel_ids: list[ChannelId] | None,
    ) -> DownstreamOfdmParameters | None:
        if not channel_ids:
            return None
        return DownstreamOfdmParameters(channel_id=list(channel_ids))

# Auto-register
router = MultiDsChanEstRouter().router


# FILE: src/pypnm/api/routes/advance/multi_us_ofdma_pre_eq/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import io
import logging
import os
import zipfile
from collections.abc import Callable
from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdma_pre_eq_signal_analysis import (
    MultiOfdmaPreEqAnalysisType,
    MultiOfdmaPreEqSignalAnalysis,
)
from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.schemas import (
    AnalysisDataModel,
    MultiUsOfdmaPreEqAnalysisRequest,
    MultiUsOfdmaPreEqAnalysisResponse,
    MultiUsOfdmaPreEqRequest,
    MultiUsOfdmaPreEqResponseStatus,
    MultiUsOfdmaPreEqStartResponse,
    MultiUsOfdmaPreEqStatusResponse,
)
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.service import (
    MultiUsOfdmaPreEqService,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    UpstreamOfdmaParameters,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, GroupId, MacAddressStr, OperationId


class MultiUsOfdmaPreEqRouter(AbstractService):
    """Router for handling Multi-US-OFDMA-Pre-Equalization operations."""

    def __init__(self) -> None:
        super().__init__()
        self.router = APIRouter(prefix="/advance/multi/usOfdmaPreEqualization",
                                tags=["PNM Operations - Multi-US-OFDMA-Pre-Equalization"])
        self.logger = logging.getLogger(self.__class__.__name__)
        self._add_routes()

    # ──────────────────────────────────────────────────────────
    # Routes
    # ──────────────────────────────────────────────────────────
    def _add_routes(self) -> None:

        @self.router.post("/start",
            response_model=MultiUsOfdmaPreEqStartResponse | SnmpResponse,
            summary="Start a multi-sample US OFDMA Pre-Equalization capture")
        async def start_multi_chan_estimation(request: MultiUsOfdmaPreEqRequest) -> MultiUsOfdmaPreEqStartResponse | SnmpResponse:

            duration, interval = request.capture.parameters.measurement_duration, request.capture.parameters.sample_interval
            mac_address: MacAddressStr = request.cable_modem.mac_address
            ip_address: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)
            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            interface_parameters = self._resolve_interface_parameters(channel_ids)


            self.logger.info(f"[start] Multi-US OFDMA Pre-Equalization for MAC={mac_address}, duration={duration}s interval={interval}s")

            cm = CableModem(mac_address=MacAddress(mac_address), inet=Inet(ip_address), write_community=community)

             # Pre-checks
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                validate_ofdma_exist=True,
                validate_us_channel_ids_exist=channel_ids,
            ).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(f"[start] Precheck failed for MAC={mac_address}: {msg}")
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)

            group_id, operation_id = await self.loadService(MultiUsOfdmaPreEqService,
                                                            cm,
                                                            tftp_servers,
                                                            duration=duration,
                                                            interval=interval,
                                                            interface_parameters=interface_parameters,)
            return MultiUsOfdmaPreEqStartResponse(mac_address     =   mac_address,
                                                    status          =   OperationState.RUNNING,
                                                    message         =   None,
                                                    group_id        =   group_id,
                                                    operation_id    =   operation_id)


        @self.router.get("/status/{operation_id}",
            response_model=MultiUsOfdmaPreEqStatusResponse,
            summary="Get status of a multi-sample US OFDMA Pre-Equalization capture")
        def get_status(operation_id: OperationId) -> MultiUsOfdmaPreEqStatusResponse:
            try:
                service: MultiUsOfdmaPreEqService = cast(MultiUsOfdmaPreEqService, self.getService(operation_id))

            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            status = service.status(operation_id)
            return MultiUsOfdmaPreEqStatusResponse(
                mac_address     =   service.cm.get_mac_address.mac_address,
                status          =   "success",
                message         =   None,
                operation       =   MultiUsOfdmaPreEqResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None))

        @self.router.get("/results/{operation_id}",
            summary="Download a ZIP archive of all UsOfdmaPreEqualization capture files",
            responses={200: {"content": {"application/zip": {}},
                             "description": "ZIP archive of capture files"}})
        def download_results_zip(operation_id: OperationId) -> StreamingResponse:

            svc: MultiUsOfdmaPreEqService = cast(MultiUsOfdmaPreEqService, self.getService(operation_id))
            samples = svc.results(operation_id)
            pnm_dir, mac = str(SystemConfigSettings.pnm_dir()), svc.cm.get_mac_address.mac_address
            buf = io.BytesIO()

            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for s in samples:
                    path = os.path.join(pnm_dir, s.filename)

                    try:
                        zf.write(path, arcname=os.path.basename(s.filename))

                    except FileNotFoundError:
                        self.logger.warning(f"[zip] Missing: {path}")

                    except Exception as e:
                        self.logger.warning(f"[zip] Skip {path}: {e}")

            buf.seek(0)
            headers = {"Content-Disposition": f"attachment; filename=multiUsOfdmaPreEqualization_{mac}_{operation_id}.zip"}
            return StreamingResponse(buf, media_type="application/zip", headers=headers)


        @self.router.delete("/stop/{operation_id}",
            response_model=MultiUsOfdmaPreEqStatusResponse,
            summary="Stop a running multi-sample US OFDMA Pre-Equalization capture early")
        def stop_capture(operation_id: OperationId) -> MultiUsOfdmaPreEqStatusResponse:
            """


            """
            try:
                service: MultiUsOfdmaPreEqService = cast(MultiUsOfdmaPreEqService, self.getService(operation_id))

            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            service.stop(operation_id)
            status = service.status(operation_id)
            return MultiUsOfdmaPreEqStatusResponse(
                mac_address =   service.cm.get_mac_address.mac_address,
                status      =   OperationState.STOPPED,
                message     =   None,
                operation   =   MultiUsOfdmaPreEqResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None)
            )


        @self.router.post("/analysis",
            response_model=MultiUsOfdmaPreEqAnalysisResponse,
            summary="Perform signal analysis on a previously executed Multi-US OFDMA Pre-Equalization")
        def analysis(request: MultiUsOfdmaPreEqAnalysisRequest) -> MultiUsOfdmaPreEqAnalysisResponse | FileResponse:
            """
            Perform post-capture analysis on Multi-US OFDMA Pre-Equalization measurement data.

            Supports:
            - MIN_AVG_MAX
            - GROUP_DELAY
            - ECHO_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_IFFT
            """
            try:
                capture_group_id: GroupId = OperationManager.get_capture_group(request.operation_id)
                self.logger.info(f"[analysis] operation_id={request.operation_id} capture_group={capture_group_id}")
            except KeyError:
                msg = f"No capture group found for operation {request.operation_id}"
                self.logger.error(msg)
                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address     =   MacAddress.null(),
                    status          =   ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message         =   msg,
                    data            =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Prepare data aggregator
            cda = CaptureDataAggregator(capture_group_id)

            # Parse analysis type
            try:
                atype = MultiOfdmaPreEqAnalysisType(request.analysis.type)

            except ValueError:
                msg = f"Invalid analysis type: {request.analysis.type}"
                self.logger.error(msg)
                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.US_OFDMA_PRE_EQ_INVALID_ANALYSIS_TYPE,
                    message     =   msg,
                    data        =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Dispatch map for type → analysis engine
            analysis_map: dict[MultiOfdmaPreEqAnalysisType, Callable[[CaptureDataAggregator], MultiOfdmaPreEqSignalAnalysis]] = {
                MultiOfdmaPreEqAnalysisType.MIN_AVG_MAX:         lambda agg: MultiOfdmaPreEqSignalAnalysis(agg, MultiOfdmaPreEqAnalysisType.MIN_AVG_MAX),
                MultiOfdmaPreEqAnalysisType.GROUP_DELAY:         lambda agg: MultiOfdmaPreEqSignalAnalysis(agg, MultiOfdmaPreEqAnalysisType.GROUP_DELAY),
                MultiOfdmaPreEqAnalysisType.ECHO_DETECTION_IFFT: lambda agg: MultiOfdmaPreEqSignalAnalysis(agg, MultiOfdmaPreEqAnalysisType.ECHO_DETECTION_IFFT),
            }

            if atype not in analysis_map:
                msg = f"Unsupported analysis type: {atype}"
                self.logger.error(msg)
                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address     =   MacAddress.null(),
                    status          =   ServiceStatusCode.US_OFDMA_PRE_EQ_INVALID_ANALYSIS_TYPE,
                    message         =   msg,
                    data            =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Determine output type
            output_type:OutputType = request.analysis.output.type
            engine = analysis_map[atype](cda)
            analysis_result = engine.to_model()

            # Handle output formats
            if output_type == OutputType.JSON:
                err = analysis_result.error
                status = ServiceStatusCode.SUCCESS if not err else ServiceStatusCode.FAILURE
                message = err or f"Analysis {analysis_result.analysis_type} completed for group {capture_group_id}"

                data_model = AnalysisDataModel(
                    analysis_type   =   analysis_result.analysis_type,
                    results         =   [r.model_dump() for r in analysis_result.results])

                mac = engine.getMacAddresses()[0].mac_address
                self.logger.info(f"[analysis] type={atype.name} mac={mac} status={status.name} group={capture_group_id}")

                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address =   mac,
                    status      =   status,
                    message     =   message,
                    data        =   data_model)

            elif output_type == OutputType.ARCHIVE:
                try:
                    rpt = engine.build_report()
                    self.logger.info(f"[analysis] Built archive report for group {capture_group_id}")
                    return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

                except Exception as e:
                    msg = f"Archive build failed: {e}"
                    self.logger.error(msg)
                    return MultiUsOfdmaPreEqAnalysisResponse(
                        mac_address     =   MacAddress.null(),
                        status          =   ServiceStatusCode.FAILURE,
                        message         =   msg,
                        data            =   AnalysisDataModel(analysis_type=atype.name, results=[]))

            # Unsupported output type
            msg = f"Unsupported output type: {output_type}"
            self.logger.error(msg)
            return MultiUsOfdmaPreEqAnalysisResponse(
                mac_address     =   MacAddress.null(),
                status          =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message         =   msg,
                data            =   AnalysisDataModel(analysis_type=atype.name, results=[]))

    def _resolve_interface_parameters(self, channel_ids: list[ChannelId] | None) -> UpstreamOfdmaParameters | None:
        if channel_ids is None:
            return None
        if len(channel_ids) == 0:
            return None
        return UpstreamOfdmaParameters(channel_id=channel_ids)

# Auto-register
router = MultiUsOfdmaPreEqRouter().router


# FILE: src/pypnm/api/routes/docs/pnm/ds/ofdm/rxmer/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.rxmer_analysis_rpt import (
    AnalysisRptMatplotConfig,
    RxMerAnalysisReport,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
    PnmSingleCaptureRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.rxmer.service import CmDsOfdmRxMerService
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import DocsPnmCmDsOfdmRxMerEntry
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, InetAddressStr, MacAddressStr


class RxMerRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/ds/ofdm"
        self.base_endpoint = "/rxMer"
        self.router = APIRouter(
            prefix=prefix, tags=["PNM Operations - Downstream OFDM RxMER"])
        self.logger = logging.getLogger(f'RxMerRouter.{self.base_endpoint.strip("/")}')
        self.__routes()

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get RxMER PNM Capture File",
            response_model=None,
            responses=FAST_API_RESPONSE,)
        async def get_capture(request: PnmSingleCaptureRequest) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture Downstream OFDM RxMER Per-Subcarrier Values.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/ofdm/rxmer.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            self.logger.info(f"Starting RxMER measurement for MAC: {mac}, IP: {ip}")

            cm = CableModem(mac_address=MacAddress(mac), inet=Inet(ip), write_community=community)

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                validate_ofdm_exist=True,
                validate_ds_channel_ids_exist=channel_ids,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service: CmDsOfdmRxMerService = CmDsOfdmRxMerService(cm, tftp_servers)
            interface_parameters = self._resolve_interface_parameters(channel_ids)
            msg_rsp: MessageResponse = await service.set_and_go(interface_parameters=interface_parameters)

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete RxMER measurement."
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            measurement_stats:list[DocsPnmCmDsOfdmRxMerEntry] = \
                cast(list[DocsPnmCmDsOfdmRxMerEntry],
                    await service.getPnmMeasurementStatistics(channel_ids=channel_ids))

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())

                # Clean up payload by removing unneeded or redundant sections
                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "modulations", "snr_db_values"])
                primative = msg_rsp.payload_to_dict('primative')
                DictGenerate.pop_keys_recursive(primative, ["device_details", "modulation_statistics"])
                payload.update({str(k): v for k, v in primative.items()})
                payload.update(DictGenerate.models_to_nested_dict(measurement_stats, 'measurement_stats',))

                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   payload,)

            elif request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme = theme)
                analysis_rpt = RxMerAnalysisReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    data        =   {},)

    @staticmethod
    def _resolve_interface_parameters(
        channel_ids: list[ChannelId] | None,
    ) -> DownstreamOfdmParameters | None:
        if not channel_ids:
            return None
        return DownstreamOfdmParameters(channel_id=list(channel_ids))


# Required for dynamic auto-registration
router = RxMerRouter().router


# FILE: src/pypnm/api/routes/docs/pnm/ds/ofdm/chan_est_coeff/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.channel_estimation_analysis_rpt import ChanEstimationReport
from pypnm.api.routes.basic.rxmer_analysis_rpt import AnalysisRptMatplotConfig
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
    PnmSingleCaptureRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.chan_est_coeff.service import (
    CmDsOfdmChanEstCoefService,
)
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.pnm.DocsPnmCmOfdmChanEstCoefEntry import (
    DocsPnmCmOfdmChanEstCoefEntry,
)
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class ChannelEstimationCoefficientRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/ds/ofdm"
        self.base_endpoint = "/channelEstCoeff"
        self.router = APIRouter(
            prefix=prefix, tags=["PNM Operations - Downstream OFDM Channel Estimation Coefficients"])
        self.logger = logging.getLogger(f'ChannelEstimationCoefficientRouter.{self.base_endpoint.strip("/")}')
        self.__routes()

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get Channel Estimation Coefficients PNM Capture File",
            response_model=None,
            responses=FAST_API_RESPONSE,)
        async def get_capture(request: PnmSingleCaptureRequest) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture Downstream OFDM Channel Estimation Coefficients.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/ofdm/channel-estimation.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            self.logger.info(f"Starting Channel Estimation Coefficients measurement for MAC: {mac}, IP: {ip}")

            cm = CableModem(mac_address=MacAddress(mac),
                            inet=Inet(ip),
                            write_community=community)

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                validate_ofdm_exist=True,
                validate_ds_channel_ids_exist=channel_ids,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service: CmDsOfdmChanEstCoefService = CmDsOfdmChanEstCoefService(cm, tftp_servers=tftp_servers)
            interface_parameters = None
            if channel_ids:
                interface_parameters = DownstreamOfdmParameters(channel_id=list(channel_ids))

            msg_rsp: MessageResponse = await service.set_and_go(interface_parameters=interface_parameters)

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Channel Estimation Coefficients measurement."
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            measurement_stats:list[DocsPnmCmOfdmChanEstCoefEntry] = \
                cast(list[DocsPnmCmOfdmChanEstCoefEntry],
                    await service.getPnmMeasurementStatistics(channel_ids=channel_ids))

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis =  Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())

                # Clean up payload by removing unneeded or redundant sections
                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "complex"])
                primative = msg_rsp.payload_to_dict('primative')
                DictGenerate.pop_keys_recursive(primative, ["device_details"])
                payload.update({str(k): v for k, v in primative.items()})
                payload.update(DictGenerate.models_to_nested_dict(measurement_stats, 'measurement_stats',))

                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   payload,)

            elif request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme = theme)
                analysis_rpt = ChanEstimationReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    data        =   {},)


# Required for dynamic auto-registration
router = ChannelEstimationCoefficientRouter().router


# FILE: src/pypnm/api/routes/docs/pnm/ds/ofdm/const_display/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.abstract.analysis_report import Analysis
from pypnm.api.routes.basic.constellation_display_analysis_rpt import (
    ConstDisplayAnalysisRptMatplotConfig,
    ConstellationDisplayReport,
)
from pypnm.api.routes.common.classes.analysis.analysis import AnalysisType
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
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.const_display.schemas import (
    PnmConstellationDisplayAnalysisRequest,
)
from pypnm.api.routes.docs.pnm.ds.ofdm.const_display.service import (
    CmDsOfdmConstDisplayService,
)
from pypnm.api.routes.docs.pnm.files.service import FileType, PnmFileService
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.pnm.DocsPnmCmDsConstDispMeasEntry import (
    DocsPnmCmDsConstDispMeasEntry,
)
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class ConstellationDisplayRouter:
    """
    FastAPI router for Downstream OFDM Constellation Display.

    [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/documentation/api/fast-api/single/ds/ofdm/constellation-display.md)

    """

    def __init__(self) -> None:
        """
        Initialize router with consistent prefix/tags and register routes.
        """
        prefix: str = "/docs/pnm/ds/ofdm"
        self.base_endpoint: str = "/constellationDisplay"
        self.router: APIRouter = APIRouter(prefix=prefix, tags=["PNM Operations - Downstream OFDM Constellation Display"])
        self.logger: logging.Logger = logging.getLogger(f'ConstellationDisplayRouter.{self.base_endpoint.strip("/")}')
        self.__routes()

    def __routes(self) -> None:
        """
        Register FastAPI routes for this router.
        """
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get Constellation Display PNM Capture File",
            response_model=None,
            responses=FAST_API_RESPONSE,
        )

        async def get_capture(request: PnmConstellationDisplayAnalysisRequest) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture Downstream OFDM Constellation Display Samples And Return Analysis Results.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/ofdm/constellation-display.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            self.logger.info(f"Starting Constellation Display capture for MAC: {mac}, IP: {ip}")

            cm = CableModem(mac_address=MacAddress(mac), inet=Inet(ip), write_community=community)

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                validate_ofdm_exist=True,
                validate_ds_channel_ids_exist=channel_ids,
            ).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            modulation_order_offset: int = request.capture_settings.modulation_order_offset
            number_sample_symbol: int = request.capture_settings.number_sample_symbol

            service: CmDsOfdmConstDisplayService = CmDsOfdmConstDisplayService(
                cable_modem             =   cm,
                tftp_servers            =   tftp_servers,
                modulation_order_offset =   modulation_order_offset,
                number_sample_symbol    =   number_sample_symbol,
            )

            interface_parameters = None
            if channel_ids:
                interface_parameters = DownstreamOfdmParameters(channel_id=list(channel_ids))

            msg_rsp: MessageResponse = await service.set_and_go(interface_parameters=interface_parameters)
            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Constellation Display capture."
                self.logger.error(err)
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            measurement_stats:list[DocsPnmCmDsConstDispMeasEntry] = \
                cast(list[DocsPnmCmDsConstDispMeasEntry],
                    await service.getPnmMeasurementStatistics(channel_ids=channel_ids))

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())
                payload.update({k: v for k, v in msg_rsp.payload_to_dict().items() if isinstance(k, str)})

                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "data"])
                primative = msg_rsp.payload_to_dict('primative')
                DictGenerate.pop_keys_recursive(primative, ["device_details"])
                payload.update({k: v for k, v in primative.items() if isinstance(k, str)})
                payload.update(DictGenerate.models_to_nested_dict(measurement_stats, 'measurement_stats',))

                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   payload,)

            elif request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                crosshair = request.analysis.plot.options.display_cross_hair
                plot_config = ConstDisplayAnalysisRptMatplotConfig(theme = theme, display_crosshair=crosshair)
                analysis_rpt = ConstellationDisplayReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    data        =   {},)

# Required for dynamic auto-registration
router = ConstellationDisplayRouter().router


# FILE: src/pypnm/api/routes/docs/pnm/ds/ofdm/fec_summary/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisRptMatplotConfig
from pypnm.api.routes.basic.fec_summary_analysis_rpt import FecSummaryAnalysisReport
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
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
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.fec_summary.schemas import (
    PnmFecSummaryAnalysisRequest,
)
from pypnm.api.routes.docs.pnm.ds.ofdm.fec_summary.service import (
    CmDsOfdmFecSummaryService,
)
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import FecSummaryType
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmFecEntry import DocsPnmCmDsOfdmFecEntry
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class FecSummaryRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/ds/ofdm"
        self.base_endpoint = "/fecSummary"
        self.router = APIRouter(prefix=prefix, tags=["PNM Operations - Downstream OFDM FEC Summary"])
        self.logger = logging.getLogger(f'FecSummaryRouter.{self.base_endpoint.strip("/")}')
        self.__routes()

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get FEC Summary PNM Capture",
            response_model=None,
            responses=FAST_API_RESPONSE,)
        async def get_capture(request: PnmFecSummaryAnalysisRequest) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture Downstream OFDM FEC Summary Statistics.

            Retrieves corrected/uncorrectable codeword counters for the selected FEC
            summary interval (e.g., 10-minute or 24-hour) across active OFDM profiles.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/ofdm/fec-summary.md)
            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)
            self.logger.info(f"Starting FEC Summary capture for MAC: {mac}, IP: {ip}")

            cm = CableModem(mac_address=MacAddress(mac), inet=Inet(ip), write_community=community)

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                validate_ofdm_exist=True,
                validate_ds_channel_ids_exist=channel_ids,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            fec_type:FecSummaryType = request.capture_settings.fec_summary_type
            service = CmDsOfdmFecSummaryService(cable_modem=cm,
                                                fec_summary_type=fec_type,
                                                tftp_servers=tftp_servers)

            interface_parameters = None
            if channel_ids:
                interface_parameters = DownstreamOfdmParameters(channel_id=list(channel_ids))

            msg_rsp: MessageResponse = await service.set_and_go(interface_parameters=interface_parameters)

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete FEC Summary capture."
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            measurement_stats:list[DocsPnmCmDsOfdmFecEntry] = \
                cast(list[DocsPnmCmDsOfdmFecEntry],
                    await service.getPnmMeasurementStatistics(channel_ids=channel_ids))

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())
                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "mac_address"])

                primative = msg_rsp.payload_to_dict('primative')
                DictGenerate.pop_keys_recursive(primative, ["device_details"])
                payload.update(cast(dict[str, Any], msg_rsp.payload_to_dict("primative")))

                payload.update(DictGenerate.models_to_nested_dict(measurement_stats, 'measurement_stats',))

                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   payload)

            elif request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme = theme)
                analysis_rpt = FecSummaryAnalysisReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    data        =   {},)


# Required for dynamic auto-registration
router = FecSummaryRouter().router


# FILE: src/pypnm/api/routes/docs/pnm/ds/ofdm/modulation_profile/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter

from pypnm.api.routes.basic.abstract.analysis_report import AnalysisRptMatplotConfig
from pypnm.api.routes.basic.modulation_profile_analysis_rpt import (
    ModulationProfileReport,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
    PnmSingleCaptureRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.modulation_profile.service import (
    CmDsOfdmModProfileService,
)
from pypnm.api.routes.docs.pnm.files.service import (
    FileResponse,
    FileType,
    PnmFileService,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmModProfEntry import (
    DocsPnmCmDsOfdmModProfEntry,
)
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class ModulationProfileRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/ds/ofdm"
        self.base_endpoint = "/modulationProfile"
        self.router = APIRouter(prefix=prefix, tags=["PNM Operations - Downstream OFDM Modulation Profile"])
        self.logger = logging.getLogger(f'ModulationProfileRouter.{self.base_endpoint.strip("/")}')
        self.__routes()

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            response_model=None,
            summary="Get Modulation Profile PNM Capture File",
            responses=FAST_API_RESPONSE,
        )
        async def get_capture(request: PnmSingleCaptureRequest) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture Downstream OFDM Modulation Profile.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/ofdm/modulation-profile.md)
            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            self.logger.info(f"Starting Modulation Profile measurement for MAC: {mac}, IP: {ip}")

            cm = CableModem(mac_address=MacAddress(mac), inet=Inet(ip), write_community=community)

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                validate_ofdm_exist=True,
                validate_ds_channel_ids_exist=channel_ids,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service: CmDsOfdmModProfileService = CmDsOfdmModProfileService(cm, tftp_servers)
            interface_parameters = None
            if channel_ids:
                interface_parameters = DownstreamOfdmParameters(channel_id=list(channel_ids))

            msg_rsp: MessageResponse = await service.set_and_go(interface_parameters=interface_parameters)

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Modulation Profile measurement."
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            measurement_stats:list[DocsPnmCmDsOfdmModProfEntry] = \
                cast(list[DocsPnmCmDsOfdmModProfEntry],
                    await service.getPnmMeasurementStatistics(channel_ids=channel_ids))

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())

                primative = cast(dict[str, Any], msg_rsp.payload_to_dict('primative'))
                DictGenerate.pop_keys_recursive(primative, ["device_details", "modulation_statistics"])
                payload.update(primative)
                payload.update(DictGenerate.models_to_nested_dict(measurement_stats, 'measurement_stats'))

                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   payload,)

            elif request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme = theme)
                analysis_rpt = ModulationProfileReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return SnmpResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                )


# Required for dynamic auto-registration
router = ModulationProfileRouter().router


# FILE: src/pypnm/api/routes/docs/pnm/us/ofdma/pre_equalization/router.py
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
import logging
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.us_ofdma_pre_eq_analysis_rpt import CmUsOfdmaPreEqReport
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
    PnmSingleCaptureRequest,
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
from pypnm.api.routes.docs.pnm.us.ofdma.pre_equalization.service import (
    CmUsOfdmaPreEqService,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.pnm.DocsPnmCmUsPreEqEntry import DocsPnmCmUsPreEqEntry
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr, Path


class UsOfdmaPreEqualizationRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/us/ofdma"
        self.base_endpoint = "/preEqualization"
        self.router = APIRouter(
            prefix=prefix, tags=["PNM Operations - Upstream OFDMA Pre-Equalization"])
        self.logger = logging.getLogger(f'UsOfdmaPreEqualizationRouter.{self.base_endpoint.strip("/")}')
        self.__routes()

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get Upstream OFDMA Pre-Equalization Capture",
            response_model=None,
            responses=FAST_API_RESPONSE,)
        async def get_capture(request: PnmSingleCaptureRequest) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture Upstream OFDMA Pre-Equalization Coefficients.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/us/ofdma/pre-equalization.md#get-capture)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            self.logger.info(
                f"Starting Upstream OFDMA Pre-Equalization measurement for MAC: {mac}, IP: {ip}")

            cm = CableModem(MacAddress(mac), Inet(ip), write_community=community)

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                validate_ofdma_exist=True,
                validate_us_channel_ids_exist=channel_ids,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service: CmUsOfdmaPreEqService = CmUsOfdmaPreEqService(cm, tftp_servers,)
            msg_rsp: MessageResponse = await service.set_and_go()
            msg_rsp.log_payload()

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete Upstream OFDMA Pre-Equalization measurement."
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            measurement_stats:list[DocsPnmCmUsPreEqEntry] = \
                cast(list[DocsPnmCmUsPreEqEntry],
                    await service.getPnmMeasurementStatistics(channel_ids=channel_ids))

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())

                # Clean up payload by removing unneeded or redundant sections
                primative:dict[Any,Any] = msg_rsp.payload_to_dict('primative')
                DictGenerate.pop_keys_recursive(primative, ["device_details"])
                payload.update(primative)
                payload.update(DictGenerate.models_to_nested_dict(measurement_stats, 'measurement_stats',))

                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   payload,)

            elif request.analysis.output.type == OutputType.ARCHIVE:
                analysis_rpt = CmUsOfdmaPreEqReport(analysis)
                rpt: Path    = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    data        =   {},)


# Required for dynamic auto-registration
router = UsOfdmaPreEqualizationRouter().router


# FILE: tests/test_cable_modem_precheck_channel_ids.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.types import ChannelId, InterfaceIndex


class _FakeCableModem:
    def __init__(
        self,
        ds_stack: list[tuple[InterfaceIndex, ChannelId]],
        us_stack: list[tuple[InterfaceIndex, ChannelId]],
    ) -> None:
        self._ds_stack = ds_stack
        self._us_stack = us_stack

    async def getDocsIf31CmDsOfdmChannelIdIndexStack(self) -> list[tuple[InterfaceIndex, ChannelId]]:
        return list(self._ds_stack)

    async def getDocsIf31CmUsOfdmaChannelIdIndexStack(self) -> list[tuple[InterfaceIndex, ChannelId]]:
        return list(self._us_stack)


@pytest.mark.asyncio
async def test_validate_ds_channel_ids_empty_is_noop() -> None:
    cm = _FakeCableModem(ds_stack=[(InterfaceIndex(1), ChannelId(10))], us_stack=[])
    precheck = CableModemServicePreCheck(cable_modem=cm, validate_pnm_ready_status=False)

    status, _ = await precheck.validate_ds_channel_ids_exist([])

    assert status == ServiceStatusCode.SUCCESS


@pytest.mark.asyncio
async def test_validate_ds_channel_ids_invalid() -> None:
    cm = _FakeCableModem(ds_stack=[(InterfaceIndex(1), ChannelId(10))], us_stack=[])
    precheck = CableModemServicePreCheck(cable_modem=cm, validate_pnm_ready_status=False)

    status, _ = await precheck.validate_ds_channel_ids_exist([ChannelId(10), ChannelId(12)])

    assert status == ServiceStatusCode.INVALID_CHANNEL_ID


@pytest.mark.asyncio
async def test_validate_us_channel_ids_valid() -> None:
    cm = _FakeCableModem(ds_stack=[], us_stack=[(InterfaceIndex(1), ChannelId(20))])
    precheck = CableModemServicePreCheck(cable_modem=cm, validate_pnm_ready_status=False)

    status, _ = await precheck.validate_us_channel_ids_exist([ChannelId(20)])

    assert status == ServiceStatusCode.SUCCESS


