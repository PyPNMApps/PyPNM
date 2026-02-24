
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging

from fastapi import APIRouter, HTTPException

from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpRequest,
    SnmpResponse,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.if31.docsis.service import DocsisBaseCapabilityService
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE


class BaseCapabilityRouter:
    """
    DOCSIS 3.1 Base Capability API Router

    Provides an endpoint to retrieve the DOCSIS version capability of a cable modem.
    """

    def __init__(self) -> None:
        self.router = APIRouter(
            prefix="/docs/if31/docsis",
            tags=["DOCSIS 3.1 DOCSIS Base Capability"],
            responses=FAST_API_RESPONSE,)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._register_routes()

    def _register_routes(self) -> None:

        @self.router.post("/baseCapability",
                          response_model=SnmpResponse,
                          responses=FAST_API_RESPONSE,)
        async def base_capability(request: SnmpRequest) -> SnmpResponse:
            """
            **DOCSIS 3.1 Base Capability**

            Retrieves the supported DOCSIS version from the cable modem
            using the `docsIf31DocsisBaseCapability` OID. This value
            indicates the maximum DOCSIS version supported by the device.

            This attribute supersedes `docsIfDocsisBaseCapability` as defined in RFC 4546.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/docsis-base-configuration.md)
            """

            mac = request.cable_modem.mac_address
            ip = request.cable_modem.ip_address
            self.logger.info(f"Retrieving DOCSIS 3.1 Base Capability for MAC: {mac}, IP: {ip}")

            try:
                # Verify modem is reachable
                precheck = CableModemServicePreCheck(mac_address=mac,
                                                     ip_address=ip,
                                                     snmp_config=request.cable_modem.snmp)
                status, msg = await precheck.run_precheck()

                if status != ServiceStatusCode.SUCCESS:
                    self.logger.error(msg)
                    return SnmpResponse(
                        mac_address=mac,
                        status=status,
                        message=msg,
                        system_description=precheck.get_system_description_model(),
                    )

                result = await DocsisBaseCapabilityService.fetch_docsis_base_capabilty(mac_address=mac,
                                                                                       ip_address=ip,
                                                                                       snmp_config=request.cable_modem.snmp)

                return SnmpResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    message     =   "DOCSIS Base Capability retrieved successfully.",
                    system_description=precheck.get_system_description_model(),
                    results     =   result.model_dump())

            except HTTPException:
                raise

            except Exception as exc:
                self.logger.exception("Failed to fetch DOCSIS base capability")
                raise HTTPException(
                    status_code=500,
                    detail=f"Internal error retrieving DOCSIS base capability, reason: {exc}") from exc

# Required for dynamic FastAPI router registration
router = BaseCapabilityRouter().router
