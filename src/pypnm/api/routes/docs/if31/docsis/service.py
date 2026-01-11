from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    SNMPConfig,
)
from pypnm.api.routes.docs.if31.docsis.schemas import DocsisBaseCapability
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.ClabsDocsisVersion import ClabsDocsisVersion
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr

logger = logging.getLogger(__name__)


class DocsisBaseCapabilityService:
    """
    Service class for retrieving the DOCSIS Base Capability of a cable modem.

    Queries the modem for its DOCSIS version using the
    `docsIf31DocsisBaseCapability` SNMP OID.
    """

    @staticmethod
    async def fetch_docsis_base_capabilty(
        mac_address: MacAddressStr, ip_address: InetAddressStr, snmp_config: SNMPConfig
    ) -> DocsisBaseCapability:
        """
        Fetch the DOCSIS base capability from a given cable modem.

        Args:
            mac_address (str): The MAC address of the target cable modem.
            ip_address (str): The IP address of the target cable modem.

        Returns:
            DocsisBaseCapability: A Pydantic model containing the DOCSIS version.

        Raises:
            RuntimeError: If SNMP query fails or returns None.
        """
        logger.info(f"Fetching DOCSIS Base Capability for: {mac_address}@{ip_address}")

        cm = CableModem(
            MacAddress(mac_address),
            Inet(ip_address),
            write_community=snmp_config.snmp_v2c.community,
        )

        docsis_cap: ClabsDocsisVersion = await cm.getDocsisBaseCapability()

        if docsis_cap is None:
            logger.error("DOCSIS Base Capability returned None")
            raise RuntimeError("Failed to retrieve DOCSIS Base Capability")

        return DocsisBaseCapability(
            docsis_version=docsis_cap.name, clabs_docsis_version=docsis_cap.value
        )
