
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
import logging

from pypnm.config.pnm_config_manager import PnmConfigManager
from pypnm.docsis.cm_snmp_operation import CmSnmpOperation
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.ping import Ping
from pypnm.lib.types import SnmpCommunity


class CableModem(CmSnmpOperation):
    """
    Represents a Cable Modem device that extends SNMP operations.

    Provides access to the modem's MAC and IP addresses, and utility
    functions such as ping-based reachability and SNMP responsiveness checks.
    """

    inet: Inet

    def __init__(self, mac_address: MacAddress,
                 inet: Inet,
                 write_community: SnmpCommunity | None = None) -> None:
        """
        Initialize the CableModem instance.

        Args:
            mac_address (MacAddress): The MAC address of the cable modem.
            inet (Inet): The IP address of the cable modem.
            write_community (SnmpCommunity | None, optional): SNMP write community string.
                Defaults to the configured value when not provided.
        """
        resolved_community = write_community
        if resolved_community is None:
            resolved_community = PnmConfigManager.get_write_community()
        super().__init__(inet=inet, write_community=resolved_community)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._mac_address: MacAddress = mac_address

    @property
    def get_mac_address(self) -> MacAddress:
        """
        Returns the MAC address of the cable modem.

        Returns:
            MacAddress: The cable modem's MAC address.
        """
        return self._mac_address

    @property
    def get_inet_address(self) -> InetAddressStr:
        """
        Returns the IP address of the cable modem as a string.

        Returns:
            str: The cable modem's IP address.
        """
        return InetAddressStr(self._inet.__str__())

    def is_ping_reachable(self) -> bool:
        """
        Checks whether the cable modem is reachable via ICMP ping.

        Returns:
            bool: True if the modem responds to ping, False otherwise.
        """
        return Ping.is_reachable(self.get_inet_address)

    async def is_snmp_reachable(self) -> bool:
        """
        Checks whether the cable modem is reachable via SNMP by requesting sysDescr.

        Returns:
            bool: True if SNMP communication is successful, False otherwise.
        """
        system_description = await self.getSysDescr(timeout=1, retries=1)

        self.logger.debug(f"SNMP.is_snmp_reachable: System Description for {system_description}, is_empty: {system_description.is_empty()}")

        if system_description.is_empty():
            self.logger.debug(f"{self.__repr__()}- SNMP access failed")
            return False

        return True

    async def isCableModemMacCorrect(self) -> bool:
        "Checks to see if mac address is cable modem mac-address (docsCableMaclayer)"
        mac = await self.getIfPhysAddress()
        self.logger.debug(f"CableModem MAC Address: {self.get_mac_address}, SNMP Retrieved MAC Address: {mac}")
        return self.get_mac_address.is_equal(mac)

    def same_inet_version(self, other: Inet) -> bool:
        """
        Determines whether this modem's IP address and another Inet address are the same IP version.

        Args:
            other (Inet): Another Inet instance to compare.

        Returns:
            bool: True if both are either IPv4 or IPv6, False otherwise.

        Raises:
            TypeError: If 'other' is not an instance of Inet.
        """
        if not isinstance(other, Inet):
            raise TypeError(f"Expected 'Inet' instance, got {type(other).__name__}")
        return self._inet.same_inet_version(other)

    def __str__(self) -> str:
        """
        String representation of the cable modem.

        Returns:
            str: MAC and IP address representation.
        """
        return f"{self.get_mac_address}"

    def __repr__(self) -> str:
        """
        String representation of the cable modem.

        Returns:
            str: MAC and IP address representation.
        """
        return f"Mac: {self.__str__()} - Inet: {self.get_inet_address}"

    def __hash__(self) -> int:
        """
        Hash based on the normalized raw MAC address string (12 lowercase hex chars).

        This ensures that any MacAddress instance with the same underlying
        normalized MAC value will be treated as equal in sets and dicts.
        """
        return hash(self._mac_address.mac_address)

    def __eq__(self, other: object) -> bool:
        """
        Equality check based on normalized MAC string.
        """
        return isinstance(other, MacAddress) and self._mac_address == other._mac
