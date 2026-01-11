# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

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
    def __init__(
        self,
        mac_address: MacAddressStr,
        ip_address: InetAddressStr,
        snmp_config: SNMPConfig,
    ) -> None:
        self.cm = CableModem(
            MacAddress(mac_address),
            Inet(ip_address),
            write_community=snmp_config.snmp_v2c.community,
        )
        self.logger = logging.getLogger("DsOfdmChannelService")

    async def get_ofdm_chan_entries(self) -> list[dict]:
        """
        Retrieves and populates all OFDM downstream channel entries.

        Returns:
            List[dict]: List of dictionaries with `index`, `channel_id`, and `entry` keys.
        """
        entries: list[
            DocsIf31CmDsOfdmChanChannelEntry
        ] = await self.cm.getDocsIf31CmDsOfdmChanEntry()

        if not entries:
            self.logger.warning(
                "No OFDM channel entries retrieved from the cable modem."
            )
            return []

        result = []
        try:
            for entry in entries:
                # Check if entry has required attributes before dumping
                if hasattr(entry, "model_dump") and hasattr(entry, "index"):
                    result.append(entry.model_dump())
                else:
                    self.logger.warning("Skipping entry with missing attributes")
        except (ValueError, AttributeError) as e:
            self.logger.error(f"Error processing OFDM channel entries: {e}")

        if not result:
            self.logger.warning("No valid OFDM channel entries found.")

        return result
