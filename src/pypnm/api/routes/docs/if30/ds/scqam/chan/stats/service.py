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
from pypnm.docsis.data_type.DocsIfDownstreamChannel import DocsIfDownstreamChannelEntry
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class DsScQamChannelService:
    """
    Service class for retrieving SC-QAM (Single Carrier Quadrature Amplitude Modulation)
    downstream channel entries from a DOCSIS cable modem.

    This class encapsulates logic to interact with a cable modem using its MAC and IP address,
    and extract downstream channel metrics such as frequency, power, SNR, and modulation type.
    """

    def __init__(
        self,
        mac_address: MacAddressStr,
        ip_address: InetAddressStr,
        snmp_config: SNMPConfig | None = None,
    ) -> None:
        """
        Initialize the service with a target cable modem's MAC and IP address.

        Args:
            mac_address (str): MAC address of the cable modem.
            ip_address (str): IP address of the cable modem.
            snmp_config (SNMPConfig, optional): SNMP configuration. Defaults to None.
        """
        if snmp_config is None:
            snmp_config = SNMPConfig(snmp_v2c=SNMPv2c(community=None))
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cm = CableModem(
            mac_address=MacAddress(mac_address),
            inet=Inet(ip_address),
            write_community=snmp_config.snmp_v2c.community,
        )

    async def get_scqam_chan_entries(self) -> list[dict]:
        """
        Retrieve and process DOCSIS SC-QAM downstream channel entries.

        Returns:
            List[Dict]: A list of dictionaries representing successfully retrieved
                        and populated SC-QAM downstream channel entries.
        """
        entries: list[
            DocsIfDownstreamChannelEntry
        ] = await self.cm.getDocsIfDownstreamChannel()
        return [entry.model_dump() for entry in entries]

    async def get_scqam_chan_codeword_error_rate(
        self, time_elapse: float = 5
    ) -> list[dict]:
        """
        Retrieve codeword error rate for all downstream SC-QAM channels.
        Args:
            time_elapse (float): Time interval in seconds to wait between two SNMP snapshots.
                                 Default is 5 seconds.
        Returns:
            List[Dict]: A list of dictionaries containing codeword error rate entries for each channel.
        """
        cw_error_rate = await self.cm.getDocsIfDownstreamChannelCwErrorRate(time_elapse)

        self.logger.info(
            f"Retrieved [{len(cw_error_rate)}] SC-QAM channel codeword error rate entries over a sampling interval of {time_elapse} seconds."
        )

        if isinstance(cw_error_rate, list):
            return [entry.model_dump() for entry in cw_error_rate]

        elif isinstance(cw_error_rate, dict):
            return cw_error_rate.get("entries", [])

        else:
            return []
