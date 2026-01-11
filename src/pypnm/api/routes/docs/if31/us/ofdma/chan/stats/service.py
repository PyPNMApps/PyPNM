# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    SNMPConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPv2c,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.DocsIf31CmUsOfdmaChanEntry import DocsIf31CmUsOfdmaChanEntry
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class UsOfdmChannelService:
    def __init__(
        self,
        mac_address: MacAddressStr,
        ip_address: InetAddressStr,
        snmp_config: SNMPConfig | None = None,
    ) -> None:
        if snmp_config is None:
            snmp_config = SNMPConfig(snmp_v2c=SNMPv2c(community=None))
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cm = CableModem(
            mac_address=MacAddress(mac_address),
            inet=Inet(ip_address),
            write_community=snmp_config.snmp_v2c.community,
        )

    async def get_ofdma_chan_entries(self) -> list[dict]:
        """
        Retrieves and populates all OFDMA upstream channel entries.

        Returns:
            List[dict]: List of dictionaries with `index`, `channel_id`, and `entry` keys.
        """
        entries: list[
            DocsIf31CmUsOfdmaChanEntry
        ] = await self.cm.getDocsIf31CmUsOfdmaChanEntry()

        result = []
        try:
            for entry in entries:
                result.append(entry.model_dump())
        except Exception as e:
            self.logger.warning(f"Skipping invalid entry at index {entry.index}: {e}")

        return result
