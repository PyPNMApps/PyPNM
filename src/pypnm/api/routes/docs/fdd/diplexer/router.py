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
from pypnm.api.routes.docs.fdd.diplexer.service import (
    FddDiplexerBandEdgeCapabilityService,
)
from pypnm.docsis.data_type.ClabsDocsisVersion import ClabsDocsisVersion
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE


class FddDiplexerBandEdgeCapability:
    """
    FastAPI router class for exposing DOCSIS 4.0 FDD diplexer band edge capability via a REST endpoint.

    This endpoint allows clients to retrieve the upstream and downstream diplexer edge capabilities
    from a cable modem, typically used to validate DOCSIS 4.0 spectrum configuration support.

    """

    def __init__(self) -> None:
        """
        Initialize the router, logger, and register API routes under the /docs/fdd/diplexer prefix.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/docs/fdd/diplexer",
            tags=["DOCSIS 4.0 FDD Diplexer Band Edge Capability"],
        )
        self._add_routes()

    def _add_routes(self) -> None:
        """
        Defines the POST /bandEdgeCapability endpoint and attaches it to the router.
        """

        @self.router.post(
            "/bandEdgeCapability",
            summary="Get DOCSIS 4.0 FDD Diplexer Band Edge Capabilities",
            response_model=SnmpResponse,
            responses=FAST_API_RESPONSE,
        )
        async def get_band_edge_cap(request: SnmpRequest) -> SnmpResponse:
            """
            **DOCSIS 4.0 FDD Diplexer Band Edge Capabilities**

            Queries the cable modem to retrieve all supported diplexer band edge configurations
            for upstream and downstream paths. These capabilities are advertised via TLVs 5.82,
            5.83, and 5.84 during CM registration and reflect the modem's spectrum planning capabilities.

            - Upstream Upper Band Edge Capability (TLV 5.84)
            - Downstream Lower Band Edge Capability (TLV 5.82)
            - Downstream Upper Band Edge Capability (TLV 5.83)

            [API Guide - FDD Diplexer Band Edge Capabilities](https://github.com/PyPNMApps/PyPNM/tree/main/docs/api/fast-api/single/fdd/fdd-diplexer-band-edge-cap.md)
            """
            mac = request.cable_modem.mac_address
            ip = request.cable_modem.ip_address
            self.logger.info(
                f"Retrieving FDD diplexer band edge capabilities for MAC: {mac}, IP: {ip}"
            )

            # Ensure modem is reachable and SNMP is operational
            status, msg = await CableModemServicePreCheck(
                mac_address=mac,
                ip_address=ip,
                snmp_config=request.cable_modem.snmp,
                check_docsis_version=[ClabsDocsisVersion.DOCSIS_40],
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            # Fetch capability data from the cable modem
            service = FddDiplexerBandEdgeCapabilityService(
                mac_address=mac, ip_address=ip, snmp_config=request.cable_modem.snmp
            )

            entry = await service.getFddDiplexerBandEdgeCapabilityEntries()

            return SnmpResponse(
                mac_address=mac,
                status=ServiceStatusCode.SUCCESS,
                message="Successfully retrieved FDD diplexer band edge capabilities",
                results=entry,
            )


# Required for dynamic auto-registration
router = FddDiplexerBandEdgeCapability().router
