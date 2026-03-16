# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import cast

from fastapi import APIRouter
from fastapi.responses import FileResponse, StreamingResponse

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdma_pre_eq_signal_analysis import (
    MultiOfdmaPreEqAnalysisType,
    MultiOfdmaPreEqSignalAnalysis,
)
from pypnm.api.routes.advance.common.abstract.multi_capture_router import (
    AbstractMultiCaptureRouter,
)
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.operation_kind import MultiCaptureOperation
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.common.schema.common_capture_schema import (
    MultiCaptureOperationIdResponse,
)
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.schemas import (
    AnalysisDataModel,
    MultiUsOfdmaPreEqAnalysisRequest,
    MultiUsOfdmaPreEqAnalysisResponse,
    MultiUsOfdmaPreEqRequest,
    MultiUsOfdmaPreEqResponseStatus,
    MultiUsOfdmaPreEqStartResponse,
    MultiUsOfdmaPreEqStatusResponse,
)
from pypnm.api.routes.advance.multi_us_ofdma_pre_eq.service import (
    MultiUsOfdmaPreEqService,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.file_capture.file_type import FileType
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    UpstreamOfdmaParameters,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, MacAddressStr, OperationId


class MultiUsOfdmaPreEqRouter(AbstractMultiCaptureRouter):
    """Router for handling Multi-US-OFDMA-Pre-Equalization operations."""

    def __init__(self) -> None:
        super().__init__()
        self.router = APIRouter(prefix="/advance/multi/us/ofdmaPreEqualization",
                                tags=["PNM Operations - Multi-US-OFDMA-Pre-Equalization"])
        self.logger = logging.getLogger(self.__class__.__name__)
        self._add_routes()

    # ──────────────────────────────────────────────────────────
    # Routes
    # ──────────────────────────────────────────────────────────
    def _add_routes(self) -> None:

        @self.router.post("/start",
            response_model=MultiUsOfdmaPreEqStartResponse | SnmpResponse,
            summary="Start a multi-sample US OFDMA Pre-Equalization capture")
        async def start_multi_chan_estimation(request: MultiUsOfdmaPreEqRequest) -> MultiUsOfdmaPreEqStartResponse | SnmpResponse:

            duration, interval = request.capture.parameters.measurement_duration, request.capture.parameters.sample_interval
            mac_address: MacAddressStr = request.cable_modem.mac_address
            ip_address: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)
            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            interface_parameters = self._resolve_interface_parameters(channel_ids)


            self.logger.info(f"[start] Multi-US OFDMA Pre-Equalization for MAC={mac_address}, duration={duration}s interval={interval}s")

            cm = CableModem(mac_address=MacAddress(mac_address), inet=Inet(ip_address), write_community=community)

             # Pre-checks
            precheck = CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_ofdma_exist=True,
                validate_us_channel_ids_exist=channel_ids,
            )
            status, msg = await precheck.run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(f"[start] Precheck failed for MAC={mac_address}: {msg}")
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)
            precheck_sys_descr = precheck.get_system_description_model()
            system_description = (
                precheck_sys_descr.model_dump(exclude={"is_empty"})
                if not precheck_sys_descr.is_empty
                else None
            )

            group_id, operation_id = await self.loadService(MultiUsOfdmaPreEqService,
                                                            cm,
                                                            tftp_servers,
                                                            duration=duration,
                                                            interval=interval,
                                                            system_description=system_description,
                                                            interface_parameters=interface_parameters,)
            return MultiUsOfdmaPreEqStartResponse(mac_address     =   mac_address,
                                                    system_description = precheck_sys_descr,
                                                    status          =   OperationState.RUNNING,
                                                    message         =   None,
                                                    group_id        =   group_id,
                                                    operation_id    =   operation_id)


        @self.router.get("/status/{operationId}",
            response_model=MultiUsOfdmaPreEqStatusResponse,
            summary="Get status of a multi-sample US OFDMA Pre-Equalization capture")
        def get_status(operationId: OperationId) -> MultiUsOfdmaPreEqStatusResponse:
            operation_id = operationId
            service: MultiUsOfdmaPreEqService = cast(
                MultiUsOfdmaPreEqService,
                self._get_service_or_404(operation_id),
            )

            status = service.status(operation_id)
            return MultiUsOfdmaPreEqStatusResponse(
                mac_address     =   service.cm.get_mac_address.mac_address,
                system_description = service.get_system_description(),
                status          =   "success",
                message         =   None,
                operation       =   MultiUsOfdmaPreEqResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None))

        @self.router.get("/operationId",
            response_model=MultiCaptureOperationIdResponse,
            summary="List persisted Multi-US-OFDMA-Pre-Equalization operation IDs")
        def get_operation_ids() -> MultiCaptureOperationIdResponse:
            """Return persisted operation records for Multi-US-OFDMA-Pre-Equalization keyed by operation ID."""
            return self._build_operation_id_response(MultiCaptureOperation.MULTI_US_OFDMA_PRE_EQUALIZATION)

        @self.router.get("/results/{operationId}",
            summary="Download a ZIP archive of all OFDMA PreEqualization capture files",
            responses={200: {"content": {"application/zip": {}},
                             "description": "ZIP archive of capture files"}})
        def download_results_zip(operationId: OperationId) -> StreamingResponse:
            operation_id = operationId
            return self._build_results_zip_response(operation_id, "multiOfdmaPreEqualization")


        @self.router.delete("/stop/{operationId}",
            response_model=MultiUsOfdmaPreEqStatusResponse,
            summary="Stop a running multi-sample US OFDMA Pre-Equalization capture early")
        def stop_capture(operationId: OperationId) -> MultiUsOfdmaPreEqStatusResponse:
            """


            """
            operation_id = operationId
            service: MultiUsOfdmaPreEqService = cast(
                MultiUsOfdmaPreEqService,
                self._get_service_or_404(operation_id),
            )

            service.stop(operation_id)
            status = service.status(operation_id)
            return MultiUsOfdmaPreEqStatusResponse(
                mac_address =   service.cm.get_mac_address.mac_address,
                system_description = service.get_system_description(),
                status      =   OperationState.STOPPED,
                message     =   None,
                operation   =   MultiUsOfdmaPreEqResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None)
            )


        @self.router.post("/analysis",
            response_model=MultiUsOfdmaPreEqAnalysisResponse,
            response_model_exclude_none=True,
            summary="Perform signal analysis on a previously executed Multi-US OFDMA Pre-Equalization")
        def analysis(request: MultiUsOfdmaPreEqAnalysisRequest) -> MultiUsOfdmaPreEqAnalysisResponse | FileResponse:
            """
            Perform post-capture analysis on Multi-US OFDMA Pre-Equalization measurement data.

            Supports:
            - MIN_AVG_MAX
            - GROUP_DELAY
            - ECHO_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_IFFT
            """
            capture_group_id = self._get_capture_group_or_none(request.operation_id)
            if capture_group_id is None:
                msg = f"No capture group found for operation {request.operation_id}"
                self.logger.error(msg)
                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address     =   MacAddress.null(),
                    status          =   ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message         =   msg,
                    data            =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))
            self._repair_capture_group_from_service_samples(request.operation_id, capture_group_id)
            self.logger.info(f"[analysis] operation_id={request.operation_id} capture_group={capture_group_id}")

            # Prepare data aggregator
            cda = CaptureDataAggregator(capture_group_id)

            # Parse analysis type
            try:
                atype = MultiOfdmaPreEqAnalysisType(request.analysis.type)

            except ValueError:
                msg = f"Invalid analysis type: {request.analysis.type}"
                self.logger.error(msg)
                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.US_OFDMA_PRE_EQ_INVALID_ANALYSIS_TYPE,
                    message     =   msg,
                    data        =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Dispatch map for type → analysis engine
            analysis_map: dict[MultiOfdmaPreEqAnalysisType, Callable[[CaptureDataAggregator], MultiOfdmaPreEqSignalAnalysis]] = {
                MultiOfdmaPreEqAnalysisType.MIN_AVG_MAX:         lambda agg: MultiOfdmaPreEqSignalAnalysis(agg, MultiOfdmaPreEqAnalysisType.MIN_AVG_MAX),
                MultiOfdmaPreEqAnalysisType.GROUP_DELAY:         lambda agg: MultiOfdmaPreEqSignalAnalysis(agg, MultiOfdmaPreEqAnalysisType.GROUP_DELAY),
                MultiOfdmaPreEqAnalysisType.ECHO_DETECTION_IFFT: lambda agg: MultiOfdmaPreEqSignalAnalysis(agg, MultiOfdmaPreEqAnalysisType.ECHO_DETECTION_IFFT),
            }

            if atype not in analysis_map:
                msg = f"Unsupported analysis type: {atype}"
                self.logger.error(msg)
                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address     =   MacAddress.null(),
                    status          =   ServiceStatusCode.US_OFDMA_PRE_EQ_INVALID_ANALYSIS_TYPE,
                    message         =   msg,
                    data            =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Determine output type
            output_type:OutputType = request.analysis.output.type
            engine = analysis_map[atype](cda)
            analysis_result = engine.to_model()

            # Handle output formats
            if output_type == OutputType.JSON:
                err = analysis_result.error
                status = ServiceStatusCode.SUCCESS if not err else ServiceStatusCode.FAILURE
                message = err or f"Analysis {analysis_result.analysis_type} completed for group {capture_group_id}"

                data_model = AnalysisDataModel(
                    analysis_type   =   analysis_result.analysis_type,
                    results         =   [r.model_dump() for r in analysis_result.results])

                mac = engine.getMacAddresses()[0].mac_address
                self.logger.info(f"[analysis] type={atype.name} mac={mac} status={status.name} group={capture_group_id}")

                response_kwargs: dict[str, object] = {}
                if analysis_result.system_description is not None:
                    response_kwargs["device"] = {
                        "mac_address": mac,
                        "system_description": analysis_result.system_description,
                    }

                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address =   mac,
                    status      =   status,
                    message     =   message,
                    **response_kwargs,
                    data        =   data_model)

            elif output_type == OutputType.ARCHIVE:
                try:
                    rpt = engine.build_report()
                    self.logger.info(f"[analysis] Built archive report for group {capture_group_id}")
                    return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

                except Exception as e:
                    msg = f"Archive build failed: {e}"
                    self.logger.error(msg)
                    return MultiUsOfdmaPreEqAnalysisResponse(
                        mac_address     =   MacAddress.null(),
                        status          =   ServiceStatusCode.FAILURE,
                        message         =   msg,
                        data            =   AnalysisDataModel(analysis_type=atype.name, results=[]))

            # Unsupported output type
            msg = f"Unsupported output type: {output_type}"
            self.logger.error(msg)
            return MultiUsOfdmaPreEqAnalysisResponse(
                mac_address     =   MacAddress.null(),
                status          =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message         =   msg,
                data            =   AnalysisDataModel(analysis_type=atype.name, results=[]))

    def _resolve_interface_parameters(self, channel_ids: list[ChannelId] | None) -> UpstreamOfdmaParameters | None:
        if channel_ids is None:
            return None
        if len(channel_ids) == 0:
            return None
        return UpstreamOfdmaParameters(channel_id=channel_ids)

# Auto-register
router = MultiUsOfdmaPreEqRouter().router
