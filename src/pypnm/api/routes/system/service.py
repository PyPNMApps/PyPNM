from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging

from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.system.schemas import (
    SysDescrResponse,
    SysRequest,
    SysUpTimeResponse,
)
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress

logger = logging.getLogger(__name__)


class SystemSnmpService:
    """
    Service class for retrieving SNMP system-level information from a cable modem,
    such as sysDescr and sysUpTime.
    """

    @staticmethod
    async def get_sysdescr(request: SysRequest) -> SysDescrResponse:
        """
        Retrieve the sysDescr (system description) from the cable modem.

        Args:
            request (SysRequest): connection params + SNMP config.

        Returns:
            SysDescrResponse:
              - on success: status=SUCCESS, system_description contains OID→description map
              - on failure: status=FAILURE, message=error text, system_description=None
        """
        try:
            logger.info(
                f"Fetching sysDescr for {request.cable_modem.mac_address}@{request.cable_modem.ip_address}"
            )
            cm = CableModem(
                mac_address=MacAddress(request.cable_modem.mac_address),
                inet=Inet(request.cable_modem.ip_address),
            )
            system_description: SystemDescriptor = await cm.getSysDescr()

            return SysDescrResponse(
                mac_address=request.cable_modem.mac_address,
                status=ServiceStatusCode.SUCCESS,
                results={"sysDescr": system_description},
            )

        except Exception as e:
            logger.error(f"Failed to retrieve sysDescr: {e}", exc_info=True)
            return SysDescrResponse(
                mac_address=request.cable_modem.mac_address,
                status=ServiceStatusCode.FAILURE,
                message=str(e),
                results={},
            )

    @staticmethod
    async def get_sys_up_time(request: SysRequest) -> SysUpTimeResponse:
        """
        Retrieve the sysUpTime from the cable modem.

        Args:
            request (SysRequest): connection params + SNMP config.

        Returns:
            SysUpTimeResponse:
              - on success: status=SUCCESS, uptime contains human‐readable string
              - on failure: status=FAILURE, message=error text, uptime=""
        """
        try:
            logger.info(
                f"Fetching sysUpTime for {request.cable_modem.mac_address}@{request.cable_modem.ip_address}"
            )
            cm = CableModem(
                mac_address=MacAddress(request.cable_modem.mac_address),
                inet=Inet(request.cable_modem.ip_address),
            )

            raw_uptime: str = await cm.getSysUpTime()
            logger.debug("sysUpTime raw value: %r", raw_uptime)
            return SysUpTimeResponse(
                mac_address=request.cable_modem.mac_address,
                status=ServiceStatusCode.SUCCESS,
                results={"uptime": raw_uptime},
            )

        except Exception as e:
            logger.error(f"Failed to retrieve sysUpTime: {e}", exc_info=True)
            return SysUpTimeResponse(
                mac_address=request.cable_modem.mac_address,
                status=ServiceStatusCode.FAILURE,
                message=str(e),
                results={"uptime": ""},
            )
