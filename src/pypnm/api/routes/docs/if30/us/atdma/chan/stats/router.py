
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
from pypnm.api.routes.docs.if30.us.atdma.chan.stats.service import UsScQamChannelService
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE


class UsScQamChannelRouter:
    """
    Router class to handle DOCSIS 3.0 Upstream ATDMA Channel Statistics endpoints.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/docs/if30/us/atdma/chan",
            tags=["DOCSIS 3.0 Upstream ATDMA Channel Statistics"])

        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post("/stats",
                          summary="Get DOCSIS 3.0 Upstream ATDMA Channel Stats",
                          response_model=SnmpResponse,
                          responses=FAST_API_RESPONSE,)
        async def get_us_scqam_upstream_channels(request: SnmpRequest) -> SnmpResponse:
            """
            **DOCSIS 3.0 Upstream ATDMA Channel Stats**

            Retrieves DOCSIS 3.0 Upstream ATDMA channel configuration and operational statistics.

            **The response includes modulation settings:**
            - Frequency parameters
            - Pre-equalization status
            - Transmit power
            - Ranging behavior

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/us/atdma/chan/stats.md)

            """
            mac = request.cable_modem.mac_address
            ip = request.cable_modem.ip_address
            self.logger.info(f"Retrieving DOCSIS 3.0 ATDMA upstream channel stats for MAC: {mac}, IP: {ip}")

            # Pre-check cable modem connectivity and status
            precheck = CableModemServicePreCheck(mac_address=mac, ip_address=ip,
                                                 snmp_config=request.cable_modem.snmp,
                                                 validate_atdma_exist=True)
            status, msg = await precheck.run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(
                    mac_address=mac,
                    status=status,
                    message=msg,
                    system_description=precheck.get_system_description_model(),
                )

            service = UsScQamChannelService(mac_address=mac,
                                            ip_address=ip,
                                            snmp_config=request.cable_modem.snmp)
            data = await service.get_upstream_entries()

            return SnmpResponse(
                mac_address =   mac,
                status      =   ServiceStatusCode.SUCCESS,
                message     =   "Successfully retrieved upstream ATDMA channel statistics",
                system_description=precheck.get_system_description_model(),
                results     =   data)

        @self.router.post("/preEqualization",
                          response_model=SnmpResponse,
                          responses=FAST_API_RESPONSE,)
        async def get_us_scqam_pre_equalizations(request: SnmpRequest) -> SnmpResponse:
            """
            **DOCSIS 3.0 Upstream Pre-Equalization Coefficients**

            Retrieves forward and reverse pre-equalization tap coefficients from a DOCSIS 3.0 ATDMA upstream channel.

            **The output includes:**
            - Main tap location
            - Number of forward and reverse taps
            - Complex tap coefficients with real/imag/magnitude/magnitude_dB

            Used to analyze echo cancellation behavior and upstream plant quality.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/us/atdma/chan/pre-equalization.md)

            """
            mac = request.cable_modem.mac_address
            ip = request.cable_modem.ip_address
            self.logger.info(f"Retrieving DOCSIS 3.0 ATDMA upstream pre-equalization for MAC: {mac}, IP: {ip}")

            precheck = CableModemServicePreCheck(mac_address=mac, ip_address=ip,
                                                 snmp_config=request.cable_modem.snmp,
                                                 validate_atdma_exist=True)
            status, msg = await precheck.run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(
                    mac_address=mac,
                    status=status,
                    message=msg,
                    system_description=precheck.get_system_description_model(),
                )

            service = UsScQamChannelService(mac_address=mac,
                                            ip_address=ip,
                                            snmp_config=request.cable_modem.snmp)
            data = await service.get_upstream_pre_equalizations()

            return SnmpResponse(mac_address =   mac,
                                status      =   ServiceStatusCode.SUCCESS,
                                message     =   "Successfully retrieved upstream pre-equalization coefficients",
                                system_description=precheck.get_system_description_model(),
                                results     =   data)

# Required for dynamic auto-registration
router = UsScQamChannelRouter().router
