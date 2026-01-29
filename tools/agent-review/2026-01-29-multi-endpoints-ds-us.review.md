## Agent Review Bundle Summary
- Goal: Separate multi endpoints into DS and US groups and rename usOfdmaPreEqualization to ofdmaPreEqualization.
- Changes: Updated DS/US router prefixes, renamed US multi OFDMA Pre-Equalization endpoint path, and refreshed endpoint docs/ZIP naming.
- Files: src/pypnm/api/routes/advance/multi_ds_chan_est/router.py; src/pypnm/api/routes/advance/multi_rxmer/router.py; src/pypnm/api/routes/advance/multi_us_ofdma_pre_eq/router.py; docs/api/fast-api/multi/multi-capture-chan-est.md; docs/api/fast-api/multi/multi-capture-rxmer.md; docs/api/fast-api/multi/multi-capture-us-ofdma-pre-eq.md
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails: would reformat); pytest -q
- Notes: Ruff format check reports repo-wide formatting drift.

# FILE: /home/dev01/Projects/PyPNM/src/pypnm/api/routes/advance/multi_ds_chan_est/router.py
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

# FILE: /home/dev01/Projects/PyPNM/src/pypnm/api/routes/advance/multi_rxmer/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import io
import logging
import os
import zipfile
from typing import cast

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from pypnm.api.routes.advance.analysis.signal_analysis.multi_rxmer_signal_analysis import (
    MultiRxMerAnalysisResult,
    MultiRxMerAnalysisType,
    MultiRxMerSignalAnalysis,
)
from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.multi_rxmer.schemas import (
    MultiRxMerAnalysisRequest,
    MultiRxMerAnalysisResponse,
    MultiRxMerMeasureModes,
    MultiRxMerRequest,
    MultiRxMerResponseStatus,
    MultiRxMerStartResponse,
    MultiRxMerStatusResponse,
)
from pypnm.api.routes.advance.multi_rxmer.service import (
    MultiRxMer_Ofdm_Performance_1_Service,
    MultiRxMerService,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPConfig,
    SNMPv2c,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import FileType, PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, GroupId, MacAddressStr, OperationId


class MultiRxMerRouter(AbstractService):
    """
    Router For Multi-RxMER Capture And Analysis

    Overview
    --------
    Exposes endpoints to:
      • Start a background, periodic RxMER capture on a DOCSIS cable modem
      • Poll capture status (state, collected sample count, time remaining)
      • Download all collected raw RxMER files as a ZIP archive
      • Stop an active capture early
      • Run post-capture analysis on the collected dataset

    Execution Model
    ---------------
    Each capture runs asynchronously under a managed operation. The returned `operation_id`
    is used to query status, fetch results, or trigger analysis. Pre-checks verify PNM-ready
    state and the presence of downstream OFDM.

    Inherits
    --------
    AbstractService
        Provides `loadService(...)` and `getService(...)` for service lifecycle and operation lookup.
    """
    def __init__(self) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/advance/multi/ds/rxMer",
            tags=["PNM Operations - Multi-Downstream OFDM RxMER"],)
        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post("/start",
            response_model=MultiRxMerStartResponse | SnmpResponse,
            summary="Start a Multi-RxMER capture",
            responses=FAST_API_RESPONSE,)
        async def start_multi_rxmer(request: MultiRxMerRequest) -> SnmpResponse | MultiRxMerStartResponse:
            """
            Start Multi-RxMER Capture

            Description
            -----------
            Starts an asynchronous RxMER capture on the target cable modem. Sampling cadence is
            controlled by `capture.parameters.measurement_duration` and `capture.parameters.sample_interval`.

            Modes
            -----
            • `MeasureModes.CONTINUOUS` - Continuous sampling for min/avg/max and heat-map workflows
            • `MeasureModes.OFDM_PERFORMANCE_1` - Performance study pairing RxMER with modulation-profile
              and FEC summary collection

            Returns
            -------
            • `MultiRxMerStartResponse` with `group_id` and `operation_id` on success
            • `SnmpResponse` when modem pre-checks fail (e.g., not PNM-ready or OFDM missing)

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """

            mac_address: MacAddressStr = request.cable_modem.mac_address
            ip_address: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(request.cable_modem.snmp)
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(request.cable_modem.pnm_parameters.tftp)
            duration = request.capture.parameters.measurement_duration
            interval = request.capture.parameters.sample_interval
            channel_ids = request.cable_modem.pnm_parameters.capture.channel_ids
            interface_parameters = self._resolve_interface_parameters(channel_ids)

            measure_modes = request.measure.mode
            msg:str = ""

            self.logger.info(
                f"Starting Multi-RxMER capture for MAC={mac_address} "
                f"(duration={duration}s, interval={interval}s)")

            snmp_config = SNMPConfig(snmp_v2c=SNMPv2c(community=community))
            status, msg = await CableModemServicePreCheck(
                mac_address=mac_address,
                ip_address=ip_address,
                snmp_config=snmp_config,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_ofdm_exist=True,
                validate_ds_channel_ids_exist=channel_ids,
                validate_pnm_ready_status=True,
            ).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)

            cable_modem = CableModem(
                mac_address=MacAddress(mac_address),
                inet=Inet(ip_address),
                write_community=community,
            )

            if measure_modes == MultiRxMerMeasureModes.CONTINUOUS:
                msg=f'Starting Multi-RxMER capture for MAC={mac_address}'
                self.logger.info(f'{msg}')
                group_id, operation_id = await self.loadService(
                    MultiRxMerService,
                    cable_modem,
                    tftp_servers,
                    duration=duration,
                    interval=interval,
                    interface_parameters=interface_parameters,)

            elif measure_modes == MultiRxMerMeasureModes.OFDM_PERFORMANCE_1:
                msg=f'Starting Multi-RxMER-OFDM-Performance-1 capture for MAC={mac_address}'
                self.logger.info(f'{msg}')
                group_id, operation_id = await self.loadService(
                    MultiRxMer_Ofdm_Performance_1_Service,
                    cable_modem,
                    tftp_servers,
                    duration=duration,
                    interval=interval,
                    interface_parameters=interface_parameters,)

            else:
                self.logger.error(f'Invalid Measure Mode Selected: ({measure_modes})')
                return MultiRxMerStartResponse(
                    mac_address =   mac_address,
                    status      =   ServiceStatusCode.MEASURE_MODE_INVALID,
                    message =f"{ServiceStatusCode.MEASURE_MODE_INVALID.name}",
                    group_id="", operation_id="",)

            return MultiRxMerStartResponse(
                mac_address =   mac_address,
                status      =   OperationState.RUNNING,
                message     =   msg,
                group_id    =   group_id,
                operation_id=   operation_id,
            )

        @self.router.get("/status/{operation_id}",
            response_model=MultiRxMerStatusResponse,
            summary="Get status of a Multi-RxMER capture",
            responses=FAST_API_RESPONSE,)
        def get_status(operation_id: OperationId) -> MultiRxMerStatusResponse:
            """
            Check Multi-RxMER Capture Status

            Description
            -----------
            Returns the current state of the capture, number of samples collected, and estimated
            time remaining for the given `operation_id`.

            Path Parameters
            ---------------
            operation_id : OperationId
                Identifier returned by `/start`.

            Returns
            -------
            `MultiRxMerStatusResponse` populated with `operation.state`, `operation.collected`,
            and `operation.time_remaining`.

            Errors
            ------
            404 — Operation not found.

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """
            try:
                service:MultiRxMerService = cast(MultiRxMerService, self.getService(operation_id))

            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            status = service.status(operation_id)

            self.logger.debug(f'OpId: {operation_id} - Status: {status}')

            return MultiRxMerStatusResponse(
                mac_address =   service.cm.get_mac_address.mac_address,
                status      =   "success",
                message     =   None,
                operation   =   MultiRxMerResponseStatus(
                                    operation_id    =   operation_id,
                                    state           =   status["state"],
                                    collected       =   status["collected"],
                                    time_remaining  =   status["time_remaining"],
                                    message         =   None,
                ),
            )

        @self.router.get("/results/{operation_id}",
            summary="Download a ZIP archive of all RxMER capture files",
            responses=FAST_API_RESPONSE,)
        def download_measurements_zip(operation_id: OperationId) -> StreamingResponse:
            """
            Download Captured RxMER Measurements (ZIP)

            Description
            -----------
            Streams a ZIP archive containing all RxMER `.bin` files associated with the specified
            `operation_id`. Useful for offline analysis or archival.

            Content
            -------
            • Media Type: `application/zip`
            • Disposition: `attachment; filename=multiRxMer_<mac>_<operation_id>.zip`

            Path Parameters
            ---------------
            operation_id : OperationId
                Identifier returned by `/start`.

            Returns
            -------
            `StreamingResponse` — Streamed ZIP of all capture files found. Missing files are logged and skipped.

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """
            svc:MultiRxMerService = cast(MultiRxMerService, self.getService(operation_id))
            samples = svc.results(operation_id)

            pnm_dir = str(SystemConfigSettings.pnm_dir())
            mac = svc.cm.get_mac_address.mac_address

            buf = io.BytesIO()
            with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zipf:
                for sample in samples:
                    file_path = os.path.join(pnm_dir, sample.filename)
                    arcname = os.path.basename(sample.filename)
                    try:
                        zipf.write(file_path, arcname=arcname)
                    except FileNotFoundError:
                        self.logger.warning(f"File not found, skipping: {file_path}")
                    except Exception as e:
                        self.logger.warning(f"Skipping {file_path}: {e}")

            buf.seek(0)

            headers = {"Content-Disposition": f"attachment; filename=multiRxMer_{mac}_{operation_id}.zip"}
            return StreamingResponse(buf, media_type="application/zip", headers=headers)

        @self.router.delete("/stop/{operation_id}",
            response_model=MultiRxMerStatusResponse,
            summary="Stop a running Multi-RxMER capture early",
            responses=FAST_API_RESPONSE,)
        def stop_capture(operation_id: OperationId) -> MultiRxMerStatusResponse:
            """
            Stop Multi-RxMER Capture

            Description
            -----------
            Signals the background worker to stop sampling after the current iteration for the
            specified `operation_id`.

            Path Parameters
            ---------------
            operation_id : OperationId
                Identifier returned by `/start`.

            Returns
            -------
            `MultiRxMerStatusResponse` — Finalized state and counters at stop time.

            Errors
            ------
            404 — Operation not found.

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """
            try:
                service:MultiRxMerService = cast(MultiRxMerService, self.getService(operation_id))
            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            service.stop(operation_id)
            status = service.status(operation_id)

            return MultiRxMerStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                status=OperationState.STOPPED,
                message=None,
                operation=MultiRxMerResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None,
                ),
            )

        @self.router.post("/analysis",
            response_model=MultiRxMerAnalysisResponse,
            summary="Perform signal analysis on a previously executed Multi-RxMER captures",
            responses=FAST_API_RESPONSE,)
        def analysis(request: MultiRxMerAnalysisRequest) -> MultiRxMerAnalysisResponse | FileResponse:
            """
            Multi-RxMER Analysis

            Description
            -----------
            Runs post-capture analysis for the dataset associated with `request.operation_id`.
            The capture group is derived internally from the operation.

            Analysis Types
            --------------
            • `MIN_AVG_MAX` — Per-subcarrier min/avg/max over the series
            • `RXMER_HEAT_MAP` — Heat-map oriented dataset for visualization
            • `OFDM_PROFILE_PERFORMANCE_1` — Averages RxMER, compares to modulation profiles,
              and aggregates FEC statistics over time

            Output
            ------
            Controlled by `request.analysis.output.type`:
            • `OutputType.JSON` — Typed JSON payload for UI consumption
            • `OutputType.ARCHIVE` — Generated ZIP report via `PnmFileService`

            Returns
            -------
            • `MultiRxMerAnalysisResponse` (JSON output)
            • `FileResponse` (archive report)

            Errors
            ------
            • Capture group not found for the supplied operation
            • Invalid analysis type or invalid output type

            [API Guide - Results](https://github.com/PyPNMApps/PyPNM/blob/main/docs/api/fast-api/multi/multi-capture-rxmer.md#3-download-measurements)
            """
            try:
                capture_group_id:GroupId = OperationManager.get_capture_group(request.operation_id)
                self.logger.info(f'[analysis] - OperationID: {request.operation_id} -> CaptureGroup: {capture_group_id}')

            except KeyError:
                return MultiRxMerAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message     =   f"No capture group found for operation {request.operation_id}",
                    data        =   {})

            cda = CaptureDataAggregator(capture_group_id)

            try:
                atype = MultiRxMerAnalysisType(request.analysis.type)
            except ValueError:
                msg = f'Invalid Analysis Type, reason: {request.analysis.type}'
                return MultiRxMerAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.DS_OFDM_MULIT_RXMER_ANALYSIS_TYPE,
                    message     =   msg,
                    data        =   {})
            self.logger.info(f'Performing Multi-RxMER Min/Avg/Max Analysis for group: {capture_group_id}')

            if atype == MultiRxMerAnalysisType.MIN_AVG_MAX:
                engine = MultiRxMerSignalAnalysis(cda, atype)
                multi_analysis:MultiRxMerAnalysisResult = engine.to_model()

            elif atype == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
                engine = MultiRxMerSignalAnalysis(cda, MultiRxMerAnalysisType.RXMER_HEAT_MAP)
                multi_analysis = engine.to_model()

            elif atype == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
                '''
                    Operation of this test:
                    -----------------------
                    * Collect a seriers of RxMER
                    * Collect at least 1 Modualtion Profile=
                    * Collect a Fec Summary at:
                        - 1 FecSummary every 10 Min
                        - At end of the test

                    OFDM_PROFILE_MEASUREMENT_1
                    --------------------------
                    * Calculate the Avg RxMER of the series
                    * Calculate Shannon for each subcarrier
                    * Compare each modualtion profile against the RxMER Average
                    * Calculate the percentage of subcarries that are outside a given profile
                    * Provide total FEC Stats for each profile over the time of the capture.
                '''
                engine = MultiRxMerSignalAnalysis(cda, MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1)
                multi_analysis = engine.to_model()

            else:
                msg = f'Invalid Analysis Type {atype}'
                return MultiRxMerAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.DS_OFDM_MULIT_RXMER_ANALYSIS_TYPE,
                    message     =   msg,
                    data        =   {})

            # 4) Map analysis output to response fields
            analysis_name = MultiRxMerAnalysisType(atype).name
            message = f"Analysis {analysis_name} completed for group {capture_group_id}"

            try:
                output_type = request.analysis.output.type
            except ValueError:
                msg = f'Invalid Output Type Selected: ({request.analysis.output.type})'
                return MultiRxMerAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    message     =   msg,
                    data        =   {})

            mac_address = multi_analysis.mac_address

            if output_type == OutputType.JSON:
                data = multi_analysis.model_dump().get("data", {})
                return MultiRxMerAnalysisResponse(
                    mac_address =   mac_address,
                    status      =   ServiceStatusCode.SUCCESS,
                    message     =   message,
                    data        =   data,)

            elif output_type == OutputType.ARCHIVE:
                rpt = engine.build_report()
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:

                # Fallback for unsupported output types
                return MultiRxMerAnalysisResponse(
                    mac_address =   mac_address,
                    status      =   ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    message     =   f"Unsupported output type: {output_type}",
                    data        =   {},)

    @staticmethod
    def _resolve_interface_parameters(
        channel_ids: list[ChannelId] | None,
    ) -> DownstreamOfdmParameters | None:
        if not channel_ids:
            return None
        return DownstreamOfdmParameters(channel_id=list(channel_ids))

# For dynamic auto-registration
router = MultiRxMerRouter().router

# FILE: /home/dev01/Projects/PyPNM/src/pypnm/api/routes/advance/multi_us_ofdma_pre_eq/router.py
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

from pypnm.api.routes.advance.analysis.signal_analysis.multi_ofdma_pre_eq_signal_analysis import (
    MultiOfdmaPreEqAnalysisType,
    MultiOfdmaPreEqSignalAnalysis,
)
from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
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
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, GroupId, MacAddressStr, OperationId


class MultiUsOfdmaPreEqRouter(AbstractService):
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
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_ofdma_exist=True,
                validate_us_channel_ids_exist=channel_ids,
            ).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(f"[start] Precheck failed for MAC={mac_address}: {msg}")
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)

            group_id, operation_id = await self.loadService(MultiUsOfdmaPreEqService,
                                                            cm,
                                                            tftp_servers,
                                                            duration=duration,
                                                            interval=interval,
                                                            interface_parameters=interface_parameters,)
            return MultiUsOfdmaPreEqStartResponse(mac_address     =   mac_address,
                                                    status          =   OperationState.RUNNING,
                                                    message         =   None,
                                                    group_id        =   group_id,
                                                    operation_id    =   operation_id)


        @self.router.get("/status/{operation_id}",
            response_model=MultiUsOfdmaPreEqStatusResponse,
            summary="Get status of a multi-sample US OFDMA Pre-Equalization capture")
        def get_status(operation_id: OperationId) -> MultiUsOfdmaPreEqStatusResponse:
            try:
                service: MultiUsOfdmaPreEqService = cast(MultiUsOfdmaPreEqService, self.getService(operation_id))

            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            status = service.status(operation_id)
            return MultiUsOfdmaPreEqStatusResponse(
                mac_address     =   service.cm.get_mac_address.mac_address,
                status          =   "success",
                message         =   None,
                operation       =   MultiUsOfdmaPreEqResponseStatus(
                    operation_id    =   operation_id,
                    state           =   status["state"],
                    collected       =   status["collected"],
                    time_remaining  =   status["time_remaining"],
                    message         =   None))

        @self.router.get("/results/{operation_id}",
            summary="Download a ZIP archive of all OFDMA PreEqualization capture files",
            responses={200: {"content": {"application/zip": {}},
                             "description": "ZIP archive of capture files"}})
        def download_results_zip(operation_id: OperationId) -> StreamingResponse:

            svc: MultiUsOfdmaPreEqService = cast(MultiUsOfdmaPreEqService, self.getService(operation_id))
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
            headers = {"Content-Disposition": f"attachment; filename=multiOfdmaPreEqualization_{mac}_{operation_id}.zip"}
            return StreamingResponse(buf, media_type="application/zip", headers=headers)


        @self.router.delete("/stop/{operation_id}",
            response_model=MultiUsOfdmaPreEqStatusResponse,
            summary="Stop a running multi-sample US OFDMA Pre-Equalization capture early")
        def stop_capture(operation_id: OperationId) -> MultiUsOfdmaPreEqStatusResponse:
            """


            """
            try:
                service: MultiUsOfdmaPreEqService = cast(MultiUsOfdmaPreEqService, self.getService(operation_id))

            except KeyError as err:
                raise HTTPException(status_code=404, detail="Operation not found") from err

            service.stop(operation_id)
            status = service.status(operation_id)
            return MultiUsOfdmaPreEqStatusResponse(
                mac_address =   service.cm.get_mac_address.mac_address,
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
            try:
                capture_group_id: GroupId = OperationManager.get_capture_group(request.operation_id)
                self.logger.info(f"[analysis] operation_id={request.operation_id} capture_group={capture_group_id}")
            except KeyError:
                msg = f"No capture group found for operation {request.operation_id}"
                self.logger.error(msg)
                return MultiUsOfdmaPreEqAnalysisResponse(
                    mac_address     =   MacAddress.null(),
                    status          =   ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message         =   msg,
                    data            =   AnalysisDataModel(analysis_type="UNKNOWN", results=[]))

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

                return MultiUsOfdmaPreEqAnalysisResponse(
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

# FILE: /home/dev01/Projects/PyPNM/docs/api/fast-api/multi/multi-capture-chan-est.md
# Multi-DS Channel Estimation Capture & Analysis API

A concise, implementation-ready reference for orchestrating downstream OFDM channel-estimation captures, status polling, result retrieval, early termination, and post-capture analysis.

## Contents

* [At a Glance](#at-a-glance)
* [Workflow](#workflow)
* [Endpoints](#endpoints)
  * [1) Start Capture](#1-start-capture)
  * [2) Status Check](#2-status-check)
  * [3) Download Results](#3-download-results)
  * [4) Stop Capture Early](#4-stop-capture-early)
  * [5) Analysis](#5-analysis)
* [Timing & Polling](#timing--polling)
* [Plot Examples](#plot-examples)
  * [Min-Avg-Max Magnitude Plot](#min-avg-max-magnitude-plot)
  * [Group Delay Plot](#group-delay-plot)
  * [Echo Detection - IFFT Impulse Response](#echo-detection--ifft-impulse-response)
* [Response Field Reference](#response-field-reference)
  * [Start / Status / Stop](#start--status--stop)
  * [Download ZIP](#download-zip)
  * [Analysis (JSON)](#analysis-json)
* [Analysis Types](#analysis-types)

## At a Glance

| Step | HTTP   | Path                                                       | Purpose                                        |
| ---: | :----- | :--------------------------------------------------------- | :--------------------------------------------- |
|    1 | POST   | `/advance/multi/ds/channelEstimation/start`                    | Begin a multi-sample ChannelEstimation capture |
|    2 | GET    | `/advance/multi/ds/channelEstimation/status/{operation_id}`    | Poll capture progress                          |
|    3 | GET    | `/advance/multi/ds/channelEstimation/results/{operation_id}`   | Download a ZIP of captured PNM files           |
|    4 | DELETE | `/advance/multi/ds/channelEstimation/stop/{operation_id}`      | Stop the capture after current iteration       |
|    5 | POST   | `/advance/multi/ds/channelEstimation/analysis`                 | Run post-capture signal analysis               |

### Identifiers

* `group_id`: Logical grouping for related operations.
* `operation_id`: Unique handle for one capture session. Use it for status, stop, results, and analysis.

## Workflow

1. **Start Capture** → receive `group_id` and `operation_id`.
2. **Poll Status** until `state ∈ ["completed","stopped"]`.
3. **Download Results** once finished or stopped.
4. **(Optional)** **Stop Early** to end after the current iteration.
5. **Run Analysis** on the finished capture using `operation_id` + analysis type.

## Endpoints

### 1) Start Capture

Starts a background multi-sample ChannelEstimation capture with a fixed duration and sample interval.

**Request** `POST /advance/multi/ds/channelEstimation/start`  
**Body** (`MultiChanEstRequest`):

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
      },
      "capture": {
        "channel_ids": [193, 194]
      }
    },
    "snmp": {
      "snmpV2C": { "community": "public" }
    }
  },
  "capture": {
    "parameters": {
      "measurement_duration": 120,
      "sample_interval": 15
    }
  }
}
```

When `pnm_parameters.capture.channel_ids` is omitted or empty, the capture includes all downstream OFDM channels.

#### Response (MultiChanEstimationStartResponse)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "running",
  "message": null,
  "group_id": "3bd6f7c107ad465b",
  "operation_id": "3df9f479d7a549b7"
}
```

### 2) Status Check

**Request** `GET /advance/multi/ds/channelEstimation/status/{operation_id}`

#### Response (MultiChanEstStatusResponse)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "success",
  "message": null,
  "operation": {
    "operation_id": "3df9f479d7a549b7",
    "state": "running",
    "collected": 3,
    "time_remaining": 105,
    "message": null
  }
}
```

### 3) Download Results

**Request** `GET /advance/multi/ds/channelEstimation/results/{operation_id}`

#### Response

* `Content-Type: application/zip`
* ZIP name: `multiChannelEstimation_<mac>_<operation_id>.zip`
* Contains ChannelEstimation coefficient files, for example:

```text
ds_ofdm_chan_estimate_coef_aabbccddeeff_160_1751762613.bin
ds_ofdm_chan_estimate_coef_aabbccddeeff_160_1751762629.bin
ds_ofdm_chan_estimate_coef_aabbccddeeff_160_1751762645.bin
```

### 4) Stop Capture Early

**Request** `DELETE /advance/multi/ds/channelEstimation/stop/{operation_id}`

#### Response (MultiChanEstStatusResponse)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "stopped",
  "message": null,
  "operation": {
    "operation_id": "3df9f479d7a549b7",
    "state": "stopped",
    "collected": 5,
    "time_remaining": 0,
    "message": null
  }
}
```

### 5) Analysis

**Request** `POST /advance/multi/ds/channelEstimation/analysis`  
**Body** (`MultiChanEstAnalysisRequest` - preferred string enums):

```json
{
  "analysis": {
    "type": "group-delay",
    "output": { "type": "json" }
  },
  "operation_id": "3df9f479d7a549b7"
}
```

## Analysis Types

**Analysis Types** (`analysis.type`)

| Type                        | Description                                                |
| --------------------------- | ---------------------------------------------------------- |
| `min-avg-max`               | Min/avg/max magnitude across captures per subcarrier       |
| `group-delay`               | Per-subcarrier group delay from averaged phase response    |
| `lte-detection-phase-slope` | LTE-like interference from group-delay ripple anomalies    |
| `echo-detection-ifft`       | Echo/impulse response estimation via IFFT                  |

**Output Types** (`analysis.output.type`)

| Value       | Name      | Description                              | Media Type         |
| :---------- | :-------- | :--------------------------------------- | :----------------- |
| `"json"`    | `JSON`    | Structured JSON body                     | `application/json` |
| `"archive"` | `ARCHIVE` | ZIP containing CSV + PNG report bundle   | `application/zip`  |

## Timing & Polling {#timing--polling}

### Capture Timing

* `measurement_duration` *(s)* → total run length. Example: `120` means two minutes.
* `sample_interval` *(s)* → period between samples. Example: `15` over `120` seconds → **8** samples.

### Polling Strategy

* Poll **no more than once per** `sample_interval`.
* Stop polling when `time_remaining == 0` **and** `state == "completed"` or `state == "stopped"`.

### Results Availability

* When `state ∈ ["completed","stopped"]`, the ZIP is immediately available.
* Files are produced at sampling time; the archive is just a bundle step.

### Stop Semantics

1. Current iteration finishes.  
2. Final PNM for that iteration is written.  
3. `state → "stopped"` (remaining time may be > 0 if mid-interval).

## Plot Examples

### Min-Avg-Max Magnitude Plot

| Channel | Plot | Description                                      | Note                                      |
| ------- | ---- | ------------------------------------------------ | ----------------------------------------- |
| 193     | [Min-Avg-Max ](./images/multi-chan-est/193_chan_est_min_avg_max.png)  | Min/Avg/Max channel-estimation magnitude vs f.   | Flat regions may indicate stable response |
| 194     | [Min-Avg-Max](./images/multi-chan-est/194_chan_est_min_avg_max.png)  | Min/Avg/Max channel-estimation magnitude vs f.   | Flat regions may indicate stable response |
| 195     | [Min-Avg-Max](./images/multi-chan-est/195_chan_est_min_avg_max.png)  | Min/Avg/Max channel-estimation magnitude vs f.   | Flat regions may indicate stable response |
| 196     | [Min-Avg-Max](./images/multi-chan-est/196_chan_est_min_avg_max.png)  | Min/Avg/Max channel-estimation magnitude vs f.   | Flat regions may indicate stable response |
| 197     | [Min-Avg-Max](./images/multi-chan-est/197_chan_est_min_avg_max.png)  | Min/Avg/Max channel-estimation magnitude vs f.   | Flat regions may indicate stable response |

### Group Delay Plot

| Channel | Plot | Description                                      | Note                                      |
| ------- | ---- | ------------------------------------------------ | ----------------------------------------- |
| 193     | [Group Delay](./images/multi-chan-est/193_chan_est_group_delay.png) | Per-subcarrier group delay vs frequency. | Spikes can indicate echoes or filter issues. |
| 194     | [Group Delay](./images/multi-chan-est/194_chan_est_group_delay.png) | Per-subcarrier group delay vs frequency. | Spikes can indicate echoes or filter issues. |
| 195     | [Group Delay](./images/multi-chan-est/195_chan_est_group_delay.png) | Per-subcarrier group delay vs frequency. | Spikes can indicate echoes or filter issues. |
| 196     | [Group Delay](./images/multi-chan-est/196_chan_est_group_delay.png) | Per-subcarrier group delay vs frequency. | Spikes can indicate echoes or filter issues. |
| 197     | [Group Delay](./images/multi-chan-est/197_chan_est_group_delay.png) | Per-subcarrier group delay vs frequency. | Spikes can indicate echoes or filter issues. |


### Echo Detection - IFFT Impulse Response {#echo-detection--ifft-impulse-response}

| Channel | Plot | Description                                      | Note                                      |
| ------- | ---- | ------------------------------------------------ | ----------------------------------------- |
| 193     | [Echo IFFT](./images/multi-chan-est/193_chan_est_echo_ifft.png) | Impulse-response magnitude vs time (IFFT).    | Secondary peaks map to echo paths in the HFC. |
| 194     | [Echo IFFT](./images/multi-chan-est/194_chan_est_echo_ifft.png) | Impulse-response magnitude vs time (IFFT).    | Secondary peaks map to echo paths in the HFC. |
| 195     | [Echo IFFT](./images/multi-chan-est/195_chan_est_echo_ifft.png) | Impulse-response magnitude vs time (IFFT).    | Secondary peaks map to echo paths in the HFC. |
| 196     | [Echo IFFT](./images/multi-chan-est/196_chan_est_echo_ifft.png) | Impulse-response magnitude vs time (IFFT).    | Secondary peaks map to echo paths in the HFC. |
| 197     | [Echo IFFT](./images/multi-chan-est/197_chan_est_echo_ifft.png) | Impulse-response magnitude vs time (IFFT).    | Secondary peaks map to echo paths in the HFC. |


## Response Field Reference

### Start / Status / Stop {#start--status--stop}

| Field                       | Type    | Description                                                                 |
| --------------------------- | ------- | --------------------------------------------------------------------------- |
| `mac_address`               | string  | Cable modem MAC address.                                                    |
| `status`                    | string  | Start: `"running"`; Status/Stop: high-level status string.                 |
| `message`                   | string  | Optional detail text.                                                       |
| `group_id`                  | string  | Logical grouping for related operations (Start only).                       |
| `operation_id`              | string  | Unique capture handle used with status/results/stop/analysis.              |
| `operation.state`           | string  | Current state: `running`, `completed`, or `stopped`.                        |
| `operation.collected`       | integer | Number of captured samples.                                                 |
| `operation.time_remaining`  | integer | Estimated seconds left.                                                     |

### Download ZIP

| Aspect               | Value / Format                                                   |
| -------------------- | ---------------------------------------------------------------- |
| `Content-Type`       | `application/zip`                                               |
| ZIP name             | `multiChannelEstimation_<mac>_<operation_id>.zip`               |
| PNM file name format | `ds_ofdm_chan_estimate_coef_<mac>_<channel_id>_<epoch>.bin`     |

### Analysis (JSON)

These keys appear under the `data` object of `MultiChanEstimationAnalysisResponse`. Per-type models differ, but common fields include:

For **Min-Avg-Max**:

[Min-Avg-Max - Theory of Operation](analysis/multi-chanest-min-avg-max.md)

| Field/Path             | Type/Example        | Meaning                                          |
| ---------------------- | ------------------- | ------------------------------------------------ |
| `results[].channel_id` | int                 | Channel identifier.                              |
| `results[].frequency`  | array[int] (Hz)     | Per-subcarrier center frequency.                 |
| `results[].min`        | array[float] (dB)   | Minimum magnitude per subcarrier.                |
| `results[].avg`        | array[float] (dB)   | Average magnitude per subcarrier.                |
| `results[].max`        | array[float] (dB)   | Maximum magnitude per subcarrier.                |

For **Group-Delay**:

[Group-Delay - Theory of Operation](analysis/group-delay-calculator.md)

| Field/Path                 | Type/Example        | Meaning                                        |
| -------------------------- | ------------------- | ---------------------------------------------- |
| `results[].channel_id`     | int                 | Channel identifier.                            |
| `results[].frequency`      | array[int] (Hz)     | Per-subcarrier center frequency.               |
| `results[].group_delay_us` | array[float] (µs)   | Group delay per subcarrier.                    |

For **LTE-Detection (Phase-Slope)**:

| Field/Path                 | Type/Example        | Meaning                                        |
| -------------------------- | ------------------- | ---------------------------------------------- |
| `results[].channel_id`     | int                 | Channel identifier.                            |
| `results[].anomalies`      | array[float]        | LTE-like anomaly metric per segment/bin.       |
| `results[].threshold`      | float               | Threshold used to flag anomalies.              |
| `results[].bin_widths`     | array[float] (Hz)   | Bin widths used for segmentation.              |

For **Echo-Detection (IFFT)**:

[Echo-Detection (IFFT) - Theory of Operation](analysis/ofdm-echo-detection.md)

| Field/Path                    | Type/Example      | Meaning                                        |
| ----------------------------- | ----------------- | ---------------------------------------------- |
| `results[].channel_id`        | int               | Channel identifier.                            |
| `results[].impulse_response`  | array[float]      | Magnitude of impulse response vs sample index. |
| `results[].sample_rate`       | float (Hz)        | Sample rate used for IFFT.                     |

A typical JSON response:

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": "Analysis group-delay completed for group 3bd6f7c107ad465b",
  "data": {
    "analysis_type": "group-delay",
    "results": [
      {
        "channel_id": 194,
        "frequency": [90000000, 90001562, 90003125],
        "group_delay_us": [0.08, 0.07, 0.09]
      }
    ]
  }
}
```

# FILE: /home/dev01/Projects/PyPNM/docs/api/fast-api/multi/multi-capture-rxmer.md
# Multi‑RxMER Capture & Analysis API

A concise, implementation‑ready reference for orchestrating downstream OFDM RxMER captures, status polling, result retrieval,
early termination, and post‑capture analysis.

## Contents

* [At a Glance](#at-a-glance)
* [Workflow](#workflow)
* [Endpoints](#endpoints)
  * [1) Start Capture](#1-start-capture)
  * [2) Status Check](#2-status-check)
  * [3) Download Results](#3-download-results)
  * [4) Stop Capture Early](#4-stop-capture-early)
  * [5) Analysis](#5-analysis)
* [Timing & Polling](#timing--polling)
* [Plot Examples](#plot-examples)
  * [Min‑Avg‑Max Line Plot](#min-avg-max-line-plot)
  * [RxMER Heat Map](#rxmer-heat-map)
  * [OFDM Profile Performance 1 Overlay](#ofdm-profile-performance-1-overlay)
* [Response Field Reference](#response-field-reference)
  * [Start / Status / Stop](#start--status--stop)
  * [Download ZIP](#download-zip)
  * [Analysis (JSON)](#analysis-json)
* [Compatibility Matrix](#compatibility-matrix)

## At a Glance

| Step | HTTP   | Path                                         | Purpose                                  |
| ---: | :----- | :------------------------------------------- | :--------------------------------------- |
|    1 | POST   | `/advance/multi/ds/rxMer/start`                  | Begin a background capture               |
|    2 | GET    | `/advance/multi/ds/rxMer/status/{operation_id}`  | Poll capture progress                    |
|    3 | GET    | `/advance/multi/ds/rxMer/results/{operation_id}` | Download a ZIP of captured PNM files     |
|    4 | DELETE | `/advance/multi/ds/rxMer/stop/{operation_id}`    | Stop the capture after current iteration |
|    5 | POST   | `/advance/multi/ds/rxMer/analysis`               | Run post-capture analytics               |

### Identifiers

* `group_id`: Logical grouping for related operations.
* `operation_id`: Unique handle for one capture session. Use it for status, stop, results, and analysis.

## Workflow

1. **Start Capture** → receive `group_id` and `operation_id`.
2. **Poll Status** until `state ∈ ["completed","stopped"]`.
3. **Download Results** once finished or stopped.
4. **(Optional)** **Stop Early** to end after the current iteration.
5. **Run Analysis** on the finished capture using `operation_id` + analysis type.

## Endpoints

### 1) Start Capture

Starts a background RxMER capture with a fixed duration and sample interval.

**Request** `POST /advance/multi/ds/rxMer/start`  
**Body** (`MultiRxMerRequest`):

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100",
    "pnm_parameters": {
      "tftp": {
        "ipv4": "192.168.0.10",
        "ipv6": "2001:db8::10"
      },
      "capture": {
        "channel_ids": [193, 194]
      }
    },
    "snmp": {
      "snmpV2C": { "community": "public" }
    }
  },
  "capture": {
    "parameters": {
      "measurement_duration": 60,
      "sample_interval": 10
    }
  },
  "measure": { "mode": 1 }
}
```

When `pnm_parameters.capture.channel_ids` is omitted or empty, the capture includes all downstream OFDM channels.

### Channel Scoping

| JSON path                              | Type      | Default | Description                                                        |
| -------------------------------------- | --------- | ------- | ------------------------------------------------------------------ |
| `pnm_parameters.capture.channel_ids`   | array(int)| omitted | Optional OFDM channel IDs to capture; empty or missing means all. |

#### Compatibility Matrix

| Measure Mode        | Suited Analyses                                                | Processes                                |
| ------------------- | -------------------------------------------------------------- | ---------------------------------------- |
|      `0`            | `min-avg-max`, `rxmer-heat-map`                                | RxMER                                    |
|      `1`            | `ofdm-profile-performance-1`, `min-avg-max`, `rxmer-heat-map`  | RxMER + Modulation Profile + FEC Summary |

> Use `mode=1` when you specifically want OFDM performance context; otherwise `mode=0` is recommended for continuous monitoring.

#### Response (MultiRxMerStartResponse)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "running",
  "message": "Starting Multi-RxMER capture for MAC=aa:bb:cc:dd:ee:ff",
  "group_id": "3bd6f7c107ad465b",
  "operation_id": "4aca137c1e9d4eb6"
}
```

### 2) Status Check

**Request** `GET /advance/multi/ds/rxMer/status/{operation_id}`

#### Response (MultiRxMerStatusResponse)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "success",
  "message": null,
  "operation": {
    "operation_id": "4aca137c1e9d4eb6",
    "state": "running",
    "collected": 2,
    "time_remaining": 50,
    "message": null
  }
}
```

### 3) Download Results

**Request** `GET /advance/multi/ds/rxMer/results/{operation_id}`

#### Response

* `Content-Type: application/zip`
* ZIP name: `<mac>_<model>_<ephoc>.zip`
* Contains files like:

```text
ds_ofdm_rxmer_per_subcar_aabbccddeeff_160_1751762613.bin
ds_ofdm_modulation_profile_aabbccddeeff_160_1762980708
ds_ofdm_codeword_error_rate_aabbccddeeff_160_1762980674.bin
aabbccddeeff_lpet3_1762980743_rxmer_min_avg_max_160.csv
aabbccddeeff_lpet3_1762981896_ofdm_profile_perf_1_ch160_pid0.csv
aabbccddeeff_lpet3_1762981556_rxmer_ofdm_heat_map_160.csv
aabbccddeeff_lpet3_1763007607_160_profile_0_ofdm_profile_perf_1.png
aabbccddeeff_lpet3_1763007680_160_rxmer_min_avg_max.png
aabbccddeeff_lpet3_1763007737_160_rxmer_heat_map.png 
```

### 4) Stop Capture Early

**Request** `DELETE /advance/multi/ds/rxMer/stop/{operation_id}`

#### Stop Response (MultiRxMerStatusResponse)

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": "stopped",
  "message": null,
  "operation": {
    "operation_id": "4aca137c1e9d4eb6",
    "state": "stopped",
    "collected": 4,
    "time_remaining": 42,
    "message": null
  }
}
```

### 5) Analysis

**Request** `POST /advance/multi/ds/rxMer/analysis`  
**Body** (`MultiRxMerAnalysisRequest` - preferred string enums):

```json
{
  "analysis": {
    "type": "min-avg-max",
    "output": { "type": "json" }
  },
  "operation_id": "4aca137c1e9d4eb6"
}
```

**Analysis Types** (`analysis.type`)

| Type                         | Description                          | `measure.mode`|
| ---------------------------- | ------------------------------------ | ------------- |
| `min-avg-max`                | Min/Avg/Max RxMER across samples     | `0` or `1`    |
| `rxmer-heat-map`             | Time × Frequency heatmap grid        | `0` or `1`    |
| `ofdm-profile-performance-1` | Per‑subcarrier performance metrics   | `1`           |

**Output Types** (`analysis.output.type`)

| Value      | Name      | Description                              | Media Type         |
| :--------- | :-------- | :--------------------------------------- | :----------------- |
| `"json"`   | `JSON`    | Structured JSON body                     | `application/json` |
| `"archive"`| `ARCHIVE` | ZIP containing multiple artifacts        | `application/zip`  |

## Timing & Polling {#timing--polling}

### Capture Timing

* `measurement_duration` *(s)* → total run length. Example: `60` means one minute.
* `sample_interval` *(s)* → period between samples. Example: `10` over `60` seconds → **6** samples.

### Polling Strategy

* Poll **no more than once per** `sample_interval`.
* Stop polling when `time_remaining == 0` **and** `state == "completed"`.

### Results Availability

* When `state ∈ ["completed","stopped"]`, the ZIP is immediately available.
* Files are produced at sampling time; the archive is just a bundle step.

### Stop Semantics

1. Current iteration finishes.  
2. Final PNM for that iteration is written.  
3. `state → "stopped"` (remaining time may be > 0 if mid‑interval).

## Plot Examples

### Min-Avg-Max Line Plot

| Plot | Description | Note |
| ---- | ----------- | ---- |
| [Min‑Avg‑Max](./images/multi-rxmer/160_rxmer_min_avg_max.png) | Min/Avg/Max RxMER across samples. | Constant line indicates low RxMER @ 750MHz |

### RxMER Heat Map

| Plot | Description | Note |
| ---- | ----------- | ---- |
| [Heat-Map](./images/multi-rxmer/160_rxmer_heat_map.png) | Time × Frequency heatmap grid. | Constant dark Line indicating low RxMER |

### OFDM Profile Performance 1 Overlay

| Plot | Profile | Description |
| ---- | :-----: | ----------- |
| [256‑QAM](./images/multi-rxmer/160_profile_0_ofdm_profile_perf_1.png) | `0` | Avg‑RxMER with modulation profile overlay and FEC summary across sample time. |
| [1K‑QAM](./images/multi-rxmer/160_profile_1_ofdm_profile_perf_1.png)  | `1` | Avg‑RxMER with modulation profile overlay and FEC summary across sample time. |
| [2K‑QAM](./images/multi-rxmer/160_profile_2_ofdm_profile_perf_1.png)  | `2` | Avg‑RxMER with modulation profile overlay and FEC summary across sample time. |
| [4K‑QAM](./images/multi-rxmer/160_profile_3_ofdm_profile_perf_1.png)  | `3` | Avg‑RxMER with modulation profile overlay and FEC summary across sample time. |

## Response Field Reference

### Start / Status / Stop {#start--status--stop}

| Field                       | Type    | Description                                                                 |
| -------------------------- | ------- | --------------------------------------------------------------------------- |
| `mac_address`              | string  | Cable modem MAC address.                                                    |
| `status`                   | string  | Start: `"running"`; Status/Stop: high‑level status string.                |
| `message`                  | string  | Optional detail text.                                                       |
| `group_id`                 | string  | Logical grouping for related operations (Start only).                       |
| `operation_id`             | string  | Unique capture handle used with status/results/stop/analysis.               |
| `operation.state`          | string  | Current state: `running`, `completed`, or `stopped`.                        |
| `operation.collected`      | integer | Number of captured samples.                                                 |
| `operation.time_remaining` | integer | Estimated seconds left.                                                     |

### Download ZIP

| Aspect                | Value / Format                                           |
| -------------------- | --------------------------------------------------------- |
| `Content-Type`       | `application/zip`                                         |
| ZIP name             | `multiRxMer_<mac>_<operation_id>.zip`                     |
| PNM file name format | `ds_ofdm_rxmer_per_subcar_<mac>_<channel_id>_<epoch>.bin` |

### Analysis (JSON)

These keys appear under the `data` object of `MultiRxMerAnalysisResponse`. Per‑type models differ, but common fields include:

| Field/Path                                       | Type/Example             | Meaning                                                                              |
| ------------------------------------------------ | ------------------------ | ------------------------------------------------------------------------------------ |
| `<channel_id>`                                   | string/int key           | Map key representing a single OFDM channel’s results.                                |
| `channel_id`                                     | int                      | Channel identifier repeated in the model.                                            |
| `frequency`                                      | array[int] (Hz)          | Per‑subcarrier center frequency.                                                     |
| `min` / `avg` / `max`                            | array[float] (dB)        | Min/avg/max RxMER per subcarrier (MIN_AVG_MAX).                                      |
| `timestamps`                                     | array[int] (epoch sec)   | Capture timestamps for heat map rows (RXMER_HEAT_MAP).                               |
| `values`                                         | array[array[float]] (dB) | Heat map matrix rows aligned to `timestamps` (RXMER_HEAT_MAP).                       |
| `avg_mer`                                        | array[float] (dB)        | Average MER across captures per subcarrier (OFDM_PROFILE_PERFORMANCE_1).             |
| `mer_shannon_limits`                             | array[float] (dB)        | Derived MER (min SNR) per subcarrier (OFDM_PROFILE_PERFORMANCE_1).                   |
| `profiles[].profile_id`                          | int                      | Modulation profile index.                                                            |
| `profiles[].profile_min_mer`                     | array[float] (dB)        | Minimum MER allowed by the profile per subcarrier.                                   |
| `profiles[].capacity_delta`                      | array[float] (dB)        | `avg_mer - profile_min_mer` per subcarrier.                                          |
| `profiles[].fec_summary.start/end`               | int (epoch sec)          | FEC observation window boundaries.                                                   |
| `profiles[].fec_summary.summary[].summary.total_codewords` | int            | Total FEC codewords counted.                                                         |
| `profiles[].fec_summary.summary[].summary.corrected`       | int            | FEC corrected codewords.                                                             |
| `profiles[].fec_summary.summary[].summary.uncorrectable`   | int            | Uncorrectable codewords.                                                             |

# FILE: /home/dev01/Projects/PyPNM/docs/api/fast-api/multi/multi-capture-us-ofdma-pre-eq.md
# Multi-Capture US OFDMA Pre-Equalization

This API runs periodic upstream OFDMA pre-equalization captures and stores each capture as PNM files. After the
capture window completes, you can download a ZIP of the PNM files or run post-capture signal analysis.

## Endpoints

| # | Method | Path | Description |
| - | ------ | ---- | ----------- |
| 1 | POST | `/advance/multi/us/ofdmaPreEqualization/start` | Begin a multi-sample US OFDMA pre-equalization capture |
| 2 | GET | `/advance/multi/us/ofdmaPreEqualization/status/{operation_id}` | Poll capture progress |
| 3 | GET | `/advance/multi/us/ofdmaPreEqualization/results/{operation_id}` | Download a ZIP of captured PNM files |
| 4 | DELETE | `/advance/multi/us/ofdmaPreEqualization/stop/{operation_id}` | Stop the capture after the current iteration |
| 5 | POST | `/advance/multi/us/ofdmaPreEqualization/analysis` | Run post-capture signal analysis |

## Start capture

**Request** `POST /advance/multi/us/ofdmaPreEqualization/start`

```json
{
  "cable_modem": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.0.100"
  },
  "capture": {
    "parameters": {
      "measurement_duration": 60,
      "sample_interval": 5
    }
  },
  "measure": {
    "mode": 0
  }
}
```

**Response**

```json
{
  "status": 0,
  "message": "Multi capture started",
  "group_id": "group-1",
  "operation_id": "op-1"
}
```

## Status

**Request** `GET /advance/multi/us/ofdmaPreEqualization/status/{operation_id}`

**Response**

```json
{
  "status": 0,
  "message": "OK",
  "operation": {
    "operation_id": "op-1",
    "state": "running",
    "collected": 3,
    "time_remaining": 45,
    "message": null
  }
}
```

## Results

**Request** `GET /advance/multi/us/ofdmaPreEqualization/results/{operation_id}`

Returns a ZIP file containing the captured PNM files for each iteration.

- ZIP name: `multiOfdmaPreEqualization_<mac>_<operation_id>.zip`

## Stop

**Request** `DELETE /advance/multi/us/ofdmaPreEqualization/stop/{operation_id}`

Stops the capture after the current iteration finishes. The `status` endpoint will reflect final state once complete.

## Analysis

**Request** `POST /advance/multi/us/ofdmaPreEqualization/analysis`

```json
{
  "operation_id": "op-1",
  "analysis": {
    "type": "MIN_AVG_MAX",
    "output": {
      "type": "JSON"
    },
    "plot": {
      "enable": false
    }
  }
}
```

Supported analysis types:

- MIN_AVG_MAX
- GROUP_DELAY
- ECHO_DETECTION_IFFT

**Response**

```json
{
  "status": 0,
  "message": "OK",
  "data": {
    "analysis_type": "MIN_AVG_MAX",
    "results": []
  }
}
```
