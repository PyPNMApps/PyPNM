
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
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
from pypnm.api.routes.docs.if31.ds.ofdm.chan.stats.service import DsOfdmChannelService
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE


class DsOfdmChannelStatsRouter:
    """
    Router class for DOCSIS 3.1 Downstream OFDM Channel Physical Layer Statistics API.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/docs/if31/ds/ofdm/chan",
            tags=["DOCSIS 3.1 Downstream OFDM Channel", "Physical Layer Statistics"])

        self._add_routes()

    def _add_routes(self) -> None:

        @self.router.post("/stats",
                          response_model=SnmpResponse,
                          responses=FAST_API_RESPONSE,)
        async def get_ds_ofdm_channels(request: SnmpRequest) -> SnmpResponse:
            """
            **Downstream OFDM Modulation Profile Statistics (DOCSIS 3.1)**

            Gathers per-profile traffic and FEC correction metrics from each active downstream OFDM channel.
            Profiles typically include IDs 0-4 and always include profile `255` (NCP).

            **Outputs include:**
            - Total, corrected, and uncorrectable codewords
            - Frame counts (unicast/multicast) and CRC errors
            - Octet counters segmented by profile
            - Support for multiple OFDM channels per modem

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/ofdm/channel-stats.md)
            """
            mac = request.cable_modem.mac_address
            ip = request.cable_modem.ip_address
            self.logger.info(f"Retrieving Downstream OFDM Modulation Profile Statistics for MAC: {mac}, IP: {ip}")

            precheck = CableModemServicePreCheck(mac_address=mac,
                                                 ip_address=ip,
                                                 snmp_config=request.cable_modem.snmp,
                                                 validate_ofdm_exist=True)
            status, msg = await precheck.run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(
                    mac_address=mac,
                    status=status,
                    message=msg,
                    system_description=precheck.get_system_description_model(),
                )

            service = DsOfdmChannelService(mac, ip, snmp_config=request.cable_modem.snmp)
            data = await service.get_ofdm_chan_entries()

            return SnmpResponse(mac_address =   mac,
                                status      =   ServiceStatusCode.SUCCESS,
                                message     =   "Successfully retrieved downstream OFDM channel statistics",
                                system_description=precheck.get_system_description_model(),
                                results     =   data)

# Required for dynamic auto-registration
router = DsOfdmChannelStatsRouter().router
