from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    SNMPConfig,
)
from pypnm.docsis.cable_modem import CableModem, InetAddressStr
from pypnm.docsis.data_type.DocsFddCmFddSystemCfgState import DocsFddCmFddSystemCfgState
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress, MacAddressStr

logger = logging.getLogger(__name__)


class FddDiplexerConfigService:
    """
    Service for retrieving the current DOCSIS 4.0 FDD diplexer configuration
    (i.e., the active upstream/downstream band edge settings) from a cable modem.

    These values are reported in TLVs 5.79, 5.80, and 5.81 as part of modem registration,
    and they represent the configured frequency ranges in MHz for FDD operation.
    """

    MHZ: int = 1_000_000  # Constant for MHz unit conversion (currently unused)

    @staticmethod
    async def fetch_fdd_diplexer_config(
        mac_address: MacAddressStr, ip_address: InetAddressStr, snmp_config: SNMPConfig
    ) -> DocsFddCmFddSystemCfgState:
        """
        Connects to the cable modem using the given MAC and IP address,
        and retrieves its currently configured FDD diplexer band edge settings.

        Args:
            mac_address (str): MAC address of the target cable modem.
            ip_address (str): IP address of the target cable modem.

        Returns:
            DocsFddCmFddSystemCfgState: Object containing the configured upstream and downstream band edges.

        Raises:
            RuntimeError: If no configuration data is retrieved from the modem.
        """
        logger.info(f"Fetching diplexer config for {mac_address}@{ip_address}")

        cm = CableModem(
            mac_address=MacAddress(mac_address),
            inet=Inet(ip_address),
            write_community=snmp_config.snmp_v2c.community,
        )

        state: (
            DocsFddCmFddSystemCfgState | None
        ) = await cm.getDocsFddCmFddSystemCfgState()
        if state is None:
            logger.error("Diplexer configuration returned None")
            raise RuntimeError("Failed to retrieve diplexer configuration")

        return state
