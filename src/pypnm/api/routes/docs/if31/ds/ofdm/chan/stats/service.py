# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    SNMPConfig,
)
from pypnm.docsis.cable_modem import CableModem, InetAddressStr
from pypnm.docsis.data_type.DocsIf31CmDsOfdmChanEntry import (
    DocsIf31CmDsOfdmChanChannelEntry,
)
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress, MacAddressStr


class DsOfdmChannelService:

    def __init__(self, mac_address: MacAddressStr,
                 ip_address: InetAddressStr,
                 snmp_config: SNMPConfig) -> None:

        self.cm = CableModem(MacAddress(mac_address),
                             Inet(ip_address),
                             write_community=snmp_config.snmp_v2c.community)

        self.logger = logging.getLogger("DsOfdmChannelService")

    async def get_ofdm_chan_entries(self) -> list[DocsIf31CmDsOfdmChanChannelEntry]:
        """
        Retrieves and populates all OFDM downstream channel entries.

        Returns:
            list[DocsIf31CmDsOfdmChanChannelEntry]: List of channel entries.
        """
        entries: list[DocsIf31CmDsOfdmChanChannelEntry] = await self.cm.getDocsIf31CmDsOfdmChanEntry()

        if not entries:
            self.logger.warning("No OFDM channel entries retrieved from the cable modem.")
            return []

        return entries
