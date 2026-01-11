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
from pypnm.api.routes.docs.if30.ds.scqam.chan.stats.schemas import (
    CodewordErrorRateRequest,
)
from pypnm.api.routes.docs.if30.ds.scqam.chan.stats.service import DsScQamChannelService
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE


class DsScQamChannelRouter:
    """
    Router class to handle DOCSIS 3.0 Downstream SC-QAM Channel Statistics endpoints.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/docs/if30/ds/scqam/chan",
            tags=["DOCSIS 3.0 Downstream SC-QAM Channel"],
        )

        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post(
            "/stats",
            response_model=SnmpResponse,
            responses=FAST_API_RESPONSE,
        )
        async def get_scqam_ds_channels(request: SnmpRequest) -> SnmpResponse:
            """
            **DOCSIS 3.0 Downstream SC-QAM Channel Stats**

            Retrieves downstream SC-QAM channel configuration and signal quality metrics
            for a DOCSIS 3.0 modem, including modulation type, frequency, RxMER, power,
            and error counters.

            This endpoint is used for monitoring downstream health and identifying RF impairments
            such high uncorrectable error rates.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/scqam/channel-stats.md)

            """
            mac = request.cable_modem.mac_address
            ip = request.cable_modem.ip_address
            self.logger.info(
                f"Retrieving DOCSIS 3.0 SC-QAM downstream channel stats for MAC: {mac}, IP: {ip}"
            )
            status, msg = await CableModemServicePreCheck(
                mac_address=mac, ip_address=ip, snmp_config=request.cable_modem.snmp
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service = DsScQamChannelService(
                mac_address=mac, ip_address=ip, snmp_config=request.cable_modem.snmp
            )
            data = await service.get_scqam_chan_entries()

            return SnmpResponse(
                mac_address=mac,
                status=ServiceStatusCode.SUCCESS,
                message="Successfully retrieved downstream SC-QAM channel stats",
                results=data,
            )

        @self.router.post(
            "/codewordErrorRate",
            response_model=SnmpResponse,
            responses=FAST_API_RESPONSE,
        )
        async def get_scqam_ds_channels_codeword_error_rate(
            request: CodewordErrorRateRequest,
        ) -> SnmpResponse:
            """
            **Compute per-channel DOCSIS 3.0 SC-QAM codeword error rates over a sampling interval.**

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/scqam/cw-error-rate.md)
            """
            mac = request.cable_modem.mac_address
            ip = request.cable_modem.ip_address

            self.logger.info(
                f"Retrieving DOCSIS 3.0 SC-QAM downstream channel codeword error rate for MAC: {mac}, IP: {ip}"
            )

            status, msg = await CableModemServicePreCheck(
                mac_address=mac,
                ip_address=ip,
                snmp_config=request.cable_modem.snmp,
                validate_scqam_exist=True,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service = DsScQamChannelService(
                mac_address=mac, ip_address=ip, snmp_config=request.cable_modem.snmp
            )
            sample_time_elapsed = float(request.capture_parameters.sample_time_elapsed)
            if sample_time_elapsed <= 0:
                error_msg = "Sample time elapsed must be a positive number."
                self.logger.error(error_msg)
                return SnmpResponse(
                    mac_address=mac,
                    status=ServiceStatusCode.INVALID_CAPTURE_PARAMETERS,
                    message=error_msg,
                )

            cw_error_rate = await service.get_scqam_chan_codeword_error_rate(
                float(request.capture_parameters.sample_time_elapsed)
            )

            return SnmpResponse(
                mac_address=mac,
                status=ServiceStatusCode.SUCCESS,
                message="Successfully retrieved codeword error rate",
                results=cw_error_rate,
            )


# Required for dynamic auto-registration
router = DsScQamChannelRouter().router
