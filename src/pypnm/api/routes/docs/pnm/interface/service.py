
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

    async def get_interface_stat_entries(self) -> dict[str, object]:
        """
        Fetches interface statistics from the cable modem, grouped by interface type.

        Returns:
            Dict[str, object]: Interface payload keyed by interface type, with optional
            `bridge` object when BRIDGE-MIB data is available.
        """
        interface_stat: dict[str, object] = await self.cm.getInterfaceStatistics()
        bridge_stat = await self.cm.getBridgeStatistics()
        if bridge_stat:
            interface_stat["bridge"] = bridge_stat.model_dump()
        return interface_stat
