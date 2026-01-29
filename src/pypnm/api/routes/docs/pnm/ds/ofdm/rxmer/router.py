# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter
from starlette.responses import FileResponse

from pypnm.api.routes.basic.rxmer_analysis_rpt import (
    AnalysisRptMatplotConfig,
    RxMerAnalysisReport,
)
from pypnm.api.routes.common.classes.analysis.analysis import Analysis, AnalysisType
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisResponse,
    PnmSingleCaptureRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.extended.common_process_service import CommonProcessService
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.ds.ofdm.rxmer.service import CmDsOfdmRxMerService
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import DocsPnmCmDsOfdmRxMerEntry
from pypnm.lib.dict_utils import DictGenerate
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, InetAddressStr, MacAddressStr


class RxMerRouter:
    def __init__(self) -> None:
        prefix = "/docs/pnm/ds/ofdm"
        self.base_endpoint = "/rxMer"
        self.router = APIRouter(
            prefix=prefix, tags=["PNM Operations - Downstream OFDM RxMER"])
        self.logger = logging.getLogger(f'RxMerRouter.{self.base_endpoint.strip("/")}')
        self.__routes()

    def __routes(self) -> None:
        @self.router.post(
            f"{self.base_endpoint}/getCapture",
            summary="Get RxMER PNM Capture File",
            response_model=None,
            responses=FAST_API_RESPONSE,)
        async def get_capture(request: PnmSingleCaptureRequest) -> SnmpResponse | PnmAnalysisResponse | FileResponse:
            """
            Capture Downstream OFDM RxMER Per-Subcarrier Values.

            [API Guide](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/single/ds/ofdm/rxmer.md)

            """
            mac: MacAddressStr = request.cable_modem.mac_address
            ip: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)

            self.logger.info(f"Starting RxMER measurement for MAC: {mac}, IP: {ip}")

            cm = CableModem(mac_address=MacAddress(mac), inet=Inet(ip), write_community=community)

            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_ofdm_exist=True,
                validate_ds_channel_ids_exist=channel_ids,
            ).run_precheck()

            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac, status=status, message=msg)

            service: CmDsOfdmRxMerService = CmDsOfdmRxMerService(cm, tftp_servers)
            interface_parameters = self._resolve_interface_parameters(channel_ids)
            msg_rsp: MessageResponse = await service.set_and_go(interface_parameters=interface_parameters)

            if msg_rsp.status != ServiceStatusCode.SUCCESS:
                err = "Unable to complete RxMER measurement."
                return SnmpResponse(mac_address=mac, message=err, status=msg_rsp.status)

            measurement_stats:list[DocsPnmCmDsOfdmRxMerEntry] = \
                cast(list[DocsPnmCmDsOfdmRxMerEntry],
                    await service.getPnmMeasurementStatistics(channel_ids=channel_ids))

            cps = CommonProcessService(msg_rsp)
            msg_rsp = cps.process()

            analysis = Analysis(AnalysisType.BASIC, msg_rsp)

            if request.analysis.output.type == OutputType.JSON:
                payload: dict[str, Any] = cast(dict[str, Any], analysis.get_results())

                # Clean up payload by removing unneeded or redundant sections
                DictGenerate.pop_keys_recursive(payload, ["pnm_header", "modulations", "snr_db_values"])
                primative = msg_rsp.payload_to_dict('primative')
                DictGenerate.pop_keys_recursive(primative, ["device_details", "modulation_statistics"])
                payload.update({str(k): v for k, v in primative.items()})
                payload.update(DictGenerate.models_to_nested_dict(measurement_stats, 'measurement_stats',))

                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.SUCCESS,
                    data        =   payload,)

            elif request.analysis.output.type == OutputType.ARCHIVE:
                theme = request.analysis.plot.ui.theme
                plot_config = AnalysisRptMatplotConfig(theme = theme)
                analysis_rpt = RxMerAnalysisReport(analysis, plot_config)
                rpt: Path = cast(Path, analysis_rpt.build_report())
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                return PnmAnalysisResponse(
                    mac_address =   mac,
                    status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    data        =   {},)

    @staticmethod
    def _resolve_interface_parameters(
        channel_ids: list[ChannelId] | None,
    ) -> DownstreamOfdmParameters | None:
        if not channel_ids:
            return None
        return DownstreamOfdmParameters(channel_id=list(channel_ids))


# Required for dynamic auto-registration
router = RxMerRouter().router
