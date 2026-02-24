# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

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
from pypnm.api.routes.docs.if31.us.ofdma.chan.stats.service import UsOfdmChannelService
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE


class UsOfdmaChannelRouter:
    """
    Router class for DOCSIS 3.1 Upstream OFDMA Channel Statistics.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/docs/if31/us/ofdma/channel",
            tags=["DOCSIS 3.1 Upstream OFDMA Channel Statistics"])
        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post("/stats",
                          response_model=SnmpResponse,
                          responses=FAST_API_RESPONSE,)
        async def get_us_ofdma_channels(request: SnmpRequest) -> SnmpResponse:
            """
            **Upstream OFDMA Channel Statistics**

            Queries a cable modem for active upstream OFDMA channel configuration and health status.
            This includes subcarrier layout, transmission parameters, and timeout counters related to ranging.

            **Outputs include:**
            - Channel ID, subcarrier count, and frequency range
            - Transmit power and pre-equalization enablement
            - Cyclic prefix, roll-off period, and symbols per frame
            - Ranging timeouts and mute status indicators

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/us/ofdma/stats.md)
            """
            mac = request.cable_modem.mac_address
            ip = request.cable_modem.ip_address
            self.logger.info(f"Retrieving Upstream OFDMA Channel Statistics for MAC: {mac}, IP: {ip}")

            precheck = CableModemServicePreCheck(mac_address=mac,
                                                 ip_address=ip,
                                                 snmp_config=request.cable_modem.snmp,
                                                 validate_ofdma_exist=True)
            status, msg = await precheck.run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(
                    mac_address=mac,
                    status=status,
                    message=msg,
                    system_description=precheck.get_system_description_model(),
                )

            service = UsOfdmChannelService(mac, ip, request.cable_modem.snmp)
            data = await service.get_ofdma_chan_entries()

            return SnmpResponse(mac_address =   mac,
                                status      =   status,
                                message     =   msg,
                                system_description=precheck.get_system_description_model(),
                                results     =   data)

# Required for dynamic auto-registration
router = UsOfdmaChannelRouter().router
