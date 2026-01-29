# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Iterable

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    TftpConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
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
        tftp_config: TftpConfig | None = None,
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
            tftp_config: TFTP server configuration overrides to validate (optional).
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
        self._mac_format_error: str | None = None
        self._inet_format_error: str | None = None
        self._mac_address_raw: MacAddressStr | None = None
        self._inet_address_raw: InetAddressStr | None = None

        if cable_modem:
            self.cm = cable_modem
            self._mac_address_raw = self.cm.get_mac_address.mac_address
            self._inet_address_raw = self.cm.get_inet_address
            self._set_format_errors(self._mac_address_raw, self._inet_address_raw)
        elif mac_address and ip_address:

            if snmp_config is None:
                self.logger.debug("No SNMPConfig provided, using default settings")
                snmp_config = SNMPConfig(snmp_v2c=SNMPv2c(community=None))

            self._mac_address_raw = mac_address
            self._inet_address_raw = ip_address
            self._set_format_errors(mac_address, ip_address)

            safe_mac = MacAddress(MacAddress.null()) if self._mac_format_error else MacAddress(mac_address)
            safe_inet = Inet(InetAddressStr("0.0.0.0")) if self._inet_format_error else Inet(ip_address)

            self.cm = CableModem(
                mac_address     =   safe_mac,
                inet            =   safe_inet,
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
        self._tftp_config               = tftp_config

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

        status, msg = self.validate_mac_address_format()
        if status != ServiceStatusCode.SUCCESS:
            self.logger.error(msg)
            return status, msg

        status, msg = self.validate_inet_address_format()
        if status != ServiceStatusCode.SUCCESS:
            self.logger.error(msg)
            return status, msg

        if self._tftp_config is not None:
            status, msg = self.validate_tftp_servers(self._tftp_config)
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return status, msg

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

    def validate_mac_address_format(self) -> PreCheckStatus:
        """
        Validate MAC address format before running network checks.
        """
        if self._mac_format_error:
            raw = self._mac_address_raw or "Unknown"
            msg = f"Invalid MAC address format: {raw}"
            return ServiceStatusCode.INVALID_MAC_ADDRESS_FORMAT, msg
        return ServiceStatusCode.SUCCESS, "MAC address format valid."

    def validate_inet_address_format(self) -> PreCheckStatus:
        """
        Validate INET address format before running network checks.
        """
        if self._inet_format_error:
            raw = self._inet_address_raw or "Unknown"
            msg = f"Invalid INET address format: {raw}"
            return ServiceStatusCode.INVALID_INET_ADDRESS_FORMAT, msg
        return ServiceStatusCode.SUCCESS, "INET address format valid."

    @staticmethod
    def validate_tftp_servers(tftp_config: TftpConfig) -> PreCheckStatus:
        """
        Validate TFTP IPv4/IPv6 addresses using request overrides and defaults.
        """
        status, msg, _ = RequestDefaultsResolver.resolve_tftp_servers_checked(tftp_config)
        return status, msg

    def _set_format_errors(self, mac_address: MacAddressStr, ip_address: InetAddressStr) -> None:
        try:
            MacAddress(mac_address)
        except Exception as e:
            self._mac_format_error = str(e)

        try:
            Inet(ip_address)
        except Exception as e:
            self._inet_format_error = str(e)
