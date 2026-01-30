
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
import logging

from fastapi import APIRouter

from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpRequest,
    SnmpResponse,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.interface.service import InterfaceStatsService
from pypnm.api.routes.docs.pnm.spectrumAnalyzer.router import FAST_API_RESPONSE
from pypnm.lib.types import InetAddressStr, MacAddressStr, SnmpCommunity


class InterfaceStatsRouter:
    """
    FastAPI router for retrieving DOCSIS interface statistics.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/docs/pnm/interface",
            tags=["Interface Statistics"])
        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post("/stats",
                          response_model=SnmpResponse,
                          responses=FAST_API_RESPONSE,)
        async def get_interface_stats(request: SnmpRequest) -> SnmpResponse:
            """
            Retrieve DOCSIS interface statistics grouped by interface type.

            [API Guide - Retrieve DOCSIS Interface Statistics](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/pnm/interface/stats.md)
            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community: SnmpCommunity = request.cable_modem.snmp.snmp_v2c.community
            self.logger.info(f"Retrieving interface statistics for MAC: {mac}, IP: {ip}")

            status, msg = await CableModemServicePreCheck(mac_address   =   mac,
                                                          ip_address    =   ip,
                                                          snmp_config   =   request.cable_modem.snmp).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse( mac_address=mac, status=status, message=msg)

            service = InterfaceStatsService(mac_address=mac, ip_address=ip, write_community=community)
            data: dict[str, list[dict]] = await service.get_interface_stat_entries()

            return SnmpResponse(mac_address=mac,
                                status=ServiceStatusCode.SUCCESS,
                                message="Interface statistics retrieved successfully",
                                results=data)

# Required for dynamic auto-registration
router = InterfaceStatsRouter().router
