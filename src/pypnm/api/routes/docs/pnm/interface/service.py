
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr, SnmpCommunity


class InterfaceStatsService:
    """
    Service class for retrieving DOCSIS interface statistics from a cable modem.
    """

    def __init__(self, mac_address: MacAddressStr, ip_address: InetAddressStr, write_community: SnmpCommunity) -> None:
        """
        Initialize the service with a target cable modem's MAC and IP address.

        Args:
            mac_address (str): MAC address of the cable modem.
            ip_address (str): IP address of the cable modem.
        """
        self.cm = CableModem(mac_address=MacAddress(mac_address),
                             inet=Inet(ip_address),
                             write_community=write_community)

    async def get_interface_stat_entries(self) -> dict[str, list[dict]]:
        """
        Fetches interface statistics from the cable modem, grouped by interface type.

        Returns:
            Dict[str, List[Dict]]: A dictionary where each key is the DOCSIS interface type
            name (e.g., 'docsCableDownstream') and the value is a list of corresponding
            interface statistics dictionaries.
        """
        interface_stat: dict[str, list[dict]] = await self.cm.getInterfaceStatistics()
        return interface_stat
