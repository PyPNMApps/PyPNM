# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    SNMPConfig,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr
from pypnm.pnm.data_type.DocsEqualizerData import DocsEqualizerData


class UsScQamChannelService:
    """
    Service for retrieving DOCSIS Upstream SC-QAM channel information and
    pre-equalization data from a cable modem using SNMP.

    Attributes:
        cm (CableModem): An instance of the CableModem class used to perform SNMP operations.
    """

    def __init__(
        self,
        mac_address: MacAddressStr,
        ip_address: InetAddressStr,
        snmp_config: SNMPConfig,
    ) -> None:
        """
        Initializes the service with a MAC and IP address.

        Args:
            mac_address (str): MAC address of the target cable modem.
            ip_address (str): IP address of the target cable modem.
        """
        self.cm = CableModem(
            mac_address=MacAddress(mac_address),
            inet=Inet(ip_address),
            write_community=snmp_config.snmp_v2c.community,
        )

    async def get_upstream_entries(self) -> list[dict]:
        """
        Fetches DOCSIS Upstream SC-QAM channel entries.

        Returns:
            List[dict]: A list of dictionaries representing upstream channel information.
        """
        entries = await self.cm.getDocsIfUpstreamChannelEntry()
        return [entry.model_dump() for entry in entries]

    async def get_upstream_pre_equalizations(self) -> dict[int, dict]:
        """
        Fetches upstream pre-equalization coefficient data.

        Returns:
            List[dict]: A dictionary containing per-channel equalizer data with real, imag,
                        magnitude, and power (dB) for each tap.
        """
        pre_eq_data: DocsEqualizerData = await self.cm.getDocsIf3CmStatusUsEqData()
        return pre_eq_data.to_dict()
