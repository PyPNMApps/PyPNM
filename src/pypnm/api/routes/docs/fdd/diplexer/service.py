# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    SNMPConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPv2c,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.ClabsDocsisVersion import ClabsDocsisVersion
from pypnm.docsis.data_type.DocsFddCmFddCapabilities import (
    DocsFddCmFddBandEdgeCapabilities,
)
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress, MacAddressStr
from pypnm.lib.types import InetAddressStr


class FddDiplexerBandEdgeCapabilityService:
    """
    Service class for retrieving the diplexer band edge capabilities of a DOCSIS 4.0
    cable modem operating in FDD mode.

    This service fetches the following capabilities via SNMP:
    - Upstream upper band edge capability
    - Downstream lower band edge capability
    - Downstream upper band edge capability

    These values indicate the supported extended frequency spectrum limits as reported
    in the modem's SNMP MIBs (e.g., `docsFddDiplexerUsUpperBandEdgeCapability`, etc.).
    """

    def __init__(
        self,
        mac_address: MacAddressStr,
        ip_address: InetAddressStr,
        snmp_config: SNMPConfig | None = None,
    ) -> None:
        """
        Initialize the service using a modem's MAC and IP address.

        Args:
            mac_address (str): The MAC address of the target cable modem.
            ip_address (str): The IP address of the target cable modem.
        """

        if snmp_config is None:
            snmp_config = SNMPConfig(snmp_v2c=SNMPv2c(community=None))

        self.cm = CableModem(
            mac_address=MacAddress(mac_address),
            inet=Inet(ip_address),
            write_community=snmp_config.snmp_v2c.community,
        )

    def isDocsis40(self) -> bool:
        return self.cm.getDocsisBaseCapability() == ClabsDocsisVersion.DOCSIS_40

    async def getFddDiplexerBandEdgeCapabilityEntries(self) -> list[dict]:
        """
        Retrieve and populate the FDD diplexer band edge capabilities from the modem.

        This method:
        1. Walks the SNMP capability tables to obtain valid indices.
        2. Constructs DocsFddCmFddBandEdgeCapabilities objects for each.
        3. Starts SNMP population of each capability instance.
        4. Returns the structured results as a list of dictionaries.

        Returns:
            List[Dict]: A list of populated band edge capability entries.
        """
        fdd_band_edge_list: (
            list[DocsFddCmFddBandEdgeCapabilities] | None
        ) = await self.cm.getDocsFddCmFddBandEdgeCapabilities(create_and_start=False)

        if fdd_band_edge_list is None:
            return []

        entries = [
            fdd_band_edge.to_dict()
            for fdd_band_edge in fdd_band_edge_list
            if await fdd_band_edge.start()
        ]

        return entries
