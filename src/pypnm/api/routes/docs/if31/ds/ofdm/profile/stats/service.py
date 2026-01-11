# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    SNMPConfig,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr

logger = logging.getLogger(__name__)


class OfdmProfileStatsService:
    """
    Service for retrieving downstream OFDM profile statistics from a cable modem.

    Methods:
        fetch_profile_stats(mac_address, ip_address):
            Async method to fetch and return OFDM profile statistics.
    """

    @staticmethod
    async def fetch_profile_stats(
        mac_address: MacAddressStr, ip_address: InetAddressStr, snmp_config: SNMPConfig
    ) -> list[dict[str, Any]]:
        """
        Fetches OFDM downstream profile statistics from the cable modem.

        Args:
            mac_address (str): MAC address of the cable modem.
            ip_address (str): IP address of the cable modem.

        Returns:
            List[Dict[str, Any]]: Parsed OFDM profile statistics, one dict per OFDM channel.

        Raises:
            RuntimeError: If the SNMP call fails or no entries are returned.
        """
        logger.info(f"Fetching OFDM profile stats for {mac_address}@{ip_address}")
        try:
            cm = CableModem(
                mac_address=MacAddress(mac_address),
                inet=Inet(ip_address),
                write_community=snmp_config.snmp_v2c.community,
            )
            entries = await cm.getDocsIf31CmDsOfdmProfileStatsEntry()
            stats = [entry.to_dict(nested=False) for entry in entries]
            logger.debug(f"Retrieved {len(stats)} OFDM profile stats entries")
            return stats
        except Exception as e:
            logger.error(f"Error fetching OFDM profile stats: {e}", exc_info=True)
            raise RuntimeError(f"Failed to retrieve OFDM profile stats: {e}") from e
