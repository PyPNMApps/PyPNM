# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import io
import logging
import os
import zipfile
from collections.abc import Callable
from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from pypnm.api.routes.advance.analysis.signal_analysis.multi_chan_est_singnal_analysis import (
    MultiChanEstAnalysisType,
    MultiChanEstimationSignalAnalysis,
)
from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.multi_ds_chan_est.schemas import (
    AnalysisDataModel,
    MultiChanEstAnalysisRequest,
    MultiChanEstimationAnalysisResponse,
    MultiChanEstimationResponseStatus,
    MultiChanEstimationStartResponse,
    MultiChanEstRequest,
    MultiChanEstStatusResponse,
)
from pypnm.api.routes.advance.multi_ds_chan_est.service import (
    MultiChannelEstimationService,
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
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, GroupId, MacAddressStr, OperationId


class MultiDsChanEstRouter(AbstractService):
    """Router for handling Multi-DS-Channel-Estimation operations."""

    def __init__(self) -> None:
        super().__init__()
        self.router = APIRouter(prefix="/advance/multi/ds/channelEstimation",
                                tags=["PNM Operations - Multi-DS-Channel-Estimation"])
        self.logger = logging.getLogger(self.__class__.__name__)
        self._add_routes()

    # ──────────────────────────────────────────────────────────
    # Routes
    # ──────────────────────────────────────────────────────────
    def _add_routes(self) -> None:

        @self.router.post("/start",
            response_model=MultiChanEstimationStartResponse | SnmpResponse,
            summary="Start a multi-sample ChannelEstimation capture")
        async def start_multi_chan_estimation(request: MultiChanEstRequest) -> MultiChanEstimationStartResponse | SnmpResponse:

            duration, interval = request.capture.parameters.measurement_duration, request.capture.parameters.sample_interval
            mac_address: MacAddressStr = request.cable_modem.mac_address
            ip_address: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)
            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            interface_parameters = self._resolve_interface_parameters(channel_ids)


            self.logger.info(f"[start] Multi-ChanEst for MAC={mac_address}, duration={duration}s interval={interval}s")

            cm = CableModem(mac_address=MacAddress(mac_address), inet=Inet(ip_address), write_community=community)

             # Pre-checks
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_ofdm_exist=True,
                validate_ds_channel_ids_exist=channel_ids,
            ).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(f"[start] Precheck failed for MAC={mac_address}: {msg}")
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)

            group_id, operation_id = await self.loadService(MultiChannelEstimationService,
                                                            cm,
                                                            tftp_servers,
                                                            duration=duration,
                                                            interval=interval,
                                                            interface_parameters=interface_parameters,)
            return MultiChanEstimationStartResponse(mac_address     =   mac_address,
                                                    status          =   OperationState.RUNNING,
                                                    message         =   None,
                                                    group_id        =   group_id,
                                                    operation_id    =   operation_id)


        @self.router.get("/status/{operation_id}",
            response_model=MultiChanEstStatusResponse,
            summary="Get status of a multi-sample ChannelEstimation capture")
        def get_status(operation_id: OperationId) -> MultiChanEstStatusResponse:
            try:
                service: MultiChannelEstimationService = cast(MultiChannelEstimationService, self.getService(operation_id))

            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            status = service.status(operation_id)
            return MultiChanEstStatusResponse(
                mac_address     =   service.cm.get_mac_address.mac_address,
                status          =   "success",
                message         =   None,
                operation       =   MultiChanEstimationResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None))

        @self.router.get("/results/{operation_id}",
            summary="Download a ZIP archive of all ChannelEstimation capture files",
            responses={200: {"content": {"application/zip": {}},
                             "description": "ZIP archive of capture files"}})
        def download_results_zip(operation_id: OperationId) -> StreamingResponse:

            svc: MultiChannelEstimationService = cast(MultiChannelEstimationService, self.getService(operation_id))
            samples = svc.results(operation_id)
            pnm_dir, mac = str(SystemConfigSettings.pnm_dir()), svc.cm.get_mac_address.mac_address
            buf = io.BytesIO()

            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for s in samples:
                    path = os.path.join(pnm_dir, s.filename)

                    try:
                        zf.write(path, arcname=os.path.basename(s.filename))

                    except FileNotFoundError:
                        self.logger.warning(f"[zip] Missing: {path}")

                    except Exception as e:
                        self.logger.warning(f"[zip] Skip {path}: {e}")

            buf.seek(0)
            headers = {"Content-Disposition": f"attachment; filename=multiChannelEstimation_{mac}_{operation_id}.zip"}
            return StreamingResponse(buf, media_type="application/zip", headers=headers)


        @self.router.delete("/stop/{operation_id}",
            response_model=MultiChanEstStatusResponse,
            summary="Stop a running multi-sample ChannelEstimation capture early")
        def stop_capture(operation_id: OperationId) -> MultiChanEstStatusResponse:
            """


            """
            try:
                service: MultiChannelEstimationService = cast(MultiChannelEstimationService, self.getService(operation_id))

            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            service.stop(operation_id)
            status = service.status(operation_id)
            return MultiChanEstStatusResponse(
                mac_address =   service.cm.get_mac_address.mac_address,
                status      =   OperationState.STOPPED,
                message     =   None,
                operation   =   MultiChanEstimationResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None)
            )


        @self.router.post("/analysis",
            response_model=MultiChanEstimationAnalysisResponse,
            summary="Perform signal analysis on a previously executed Multi-ChannelEstimation")
        def analysis(request: MultiChanEstAnalysisRequest) -> MultiChanEstimationAnalysisResponse | FileResponse:
            """
            Perform post-capture analysis on Multi-ChannelEstimation measurement data.

            Supports:
            - MIN_AVG_MAX
            - GROUP_DELAY
            - LTE_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_IFFT
            """
            try:
                capture_group_id: GroupId = OperationManager.get_capture_group(request.operation_id)
                self.logger.info(f"[analysis] operation_id={request.operation_id} capture_group={capture_group_id}")
            except KeyError:
                msg = f"No capture group found for operation {request.operation_id}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address     =   MacAddress.null(),
                    status          =   ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message         =   msg,
                    data            =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Prepare data aggregator
            cda = CaptureDataAggregator(capture_group_id)

            # Parse analysis type
            try:
                atype = MultiChanEstAnalysisType(request.analysis.type)

            except ValueError:
                msg = f"Invalid analysis type: {request.analysis.type}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE,
                    message     =   msg,
                    data        =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

            # Dispatch map for type → analysis engine
            analysis_map: dict[MultiChanEstAnalysisType, Callable[[CaptureDataAggregator], MultiChanEstimationSignalAnalysis]] = {
                MultiChanEstAnalysisType.MIN_AVG_MAX:                lambda agg: MultiChanEstimationSignalAnalysis(agg, MultiChanEstAnalysisType.MIN_AVG_MAX),
                MultiChanEstAnalysisType.GROUP_DELAY:                lambda agg: MultiChanEstimationSignalAnalysis(agg, MultiChanEstAnalysisType.GROUP_DELAY),
                MultiChanEstAnalysisType.LTE_DETECTION_PHASE_SLOPE:  lambda agg: MultiChanEstimationSignalAnalysis(agg, MultiChanEstAnalysisType.LTE_DETECTION_PHASE_SLOPE),
                MultiChanEstAnalysisType.ECHO_DETECTION_IFFT:        lambda agg: MultiChanEstimationSignalAnalysis(agg, MultiChanEstAnalysisType.ECHO_DETECTION_IFFT),
            }

            if atype not in analysis_map:
                msg = f"Unsupported analysis type: {atype}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address     =   MacAddress.null(),
                    status          =   ServiceStatusCode.DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE,
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

                return MultiChanEstimationAnalysisResponse(
                    mac_address =   mac,
                    status      =   status,
                    message     =   message,
                    data        =   data_model)

            elif output_type == OutputType.ARCHIVE:
                try:
                    rpt = engine.build_report()
                    self.logger.info(f"[analysis] Built archive report for group {capture_group_id}")
                    return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

                except Exception as e:
                    msg = f"Archive build failed: {e}"
                    self.logger.error(msg)
                    return MultiChanEstimationAnalysisResponse(
                        mac_address     =   MacAddress.null(),
                        status          =   ServiceStatusCode.FAILURE,
                        message         =   msg,
                        data            =   AnalysisDataModel(analysis_type=atype.name, results=[]))

            # Unsupported output type
            msg = f"Unsupported output type: {output_type}"
            self.logger.error(msg)
            return MultiChanEstimationAnalysisResponse(
                mac_address     =   MacAddress.null(),
                status          =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message         =   msg,
                data            =   AnalysisDataModel(analysis_type=atype.name, results=[]))

    @staticmethod
    def _resolve_interface_parameters(
        channel_ids: list[ChannelId] | None,
    ) -> DownstreamOfdmParameters | None:
        if not channel_ids:
            return None
        return DownstreamOfdmParameters(channel_id=list(channel_ids))

# Auto-register
router = MultiDsChanEstRouter().router
