# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from typing import cast

from fastapi import APIRouter
from fastapi.responses import FileResponse, StreamingResponse

from pypnm.api.routes.advance.analysis.signal_analysis.multi_rxmer_signal_analysis import (
    MultiRxMerAnalysisResult,
    MultiRxMerAnalysisType,
    MultiRxMerSignalAnalysis,
)
from pypnm.api.routes.advance.common.abstract.multi_capture_router import (
    AbstractMultiCaptureRouter,
)
from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
)
from pypnm.api.routes.advance.common.operation_kind import MultiCaptureOperation
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.common.schema.common_capture_schema import (
    MultiCaptureOperationIdResponse,
)
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
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.data_type.sysDescr import SystemDescriptor
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ChannelId, MacAddressStr, OperationId


class MultiRxMerRouter(AbstractMultiCaptureRouter):
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
            precheck = CableModemServicePreCheck(
                mac_address=mac_address,
                ip_address=ip_address,
                snmp_config=snmp_config,
                tftp_config=request.cable_modem.pnm_parameters.tftp,
                validate_ofdm_exist=True,
                validate_ds_channel_ids_exist=channel_ids,
                validate_pnm_ready_status=True,
            )
            status, msg = await precheck.run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)
            precheck_sys_descr = precheck.get_system_description_model()
            system_description = (
                precheck_sys_descr.model_dump(exclude={"is_empty"})
                if not precheck_sys_descr.is_empty
                else None
            )

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
                    system_description=system_description,
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
                    system_description=system_description,
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
                system_description = precheck_sys_descr,
                status      =   OperationState.RUNNING,
                message     =   msg,
                group_id    =   group_id,
                operation_id=   operation_id,
            )

        @self.router.get("/status/{operationId}",
            response_model=MultiRxMerStatusResponse,
            summary="Get status of a Multi-RxMER capture",
            responses=FAST_API_RESPONSE,)
        def get_status(operationId: OperationId) -> MultiRxMerStatusResponse:
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
            operation_id = operationId
            service:MultiRxMerService = cast(MultiRxMerService, self._get_service_or_404(operation_id))

            status = service.status(operation_id)

            self.logger.debug(f'OpId: {operation_id} - Status: {status}')

            return MultiRxMerStatusResponse(
                mac_address =   service.cm.get_mac_address.mac_address,
                system_description = service.get_system_description(),
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

        @self.router.get("/operationId",
            response_model=MultiCaptureOperationIdResponse,
            summary="List persisted Multi-RxMER operation IDs",
            responses=FAST_API_RESPONSE,)
        def get_operation_ids() -> MultiCaptureOperationIdResponse:
            """Return persisted operation records for Multi-RxMER captures keyed by operation ID."""
            return self._build_operation_id_response(MultiCaptureOperation.MULTI_RXMER)

        @self.router.get("/results/{operationId}",
            summary="Download a ZIP archive of all RxMER capture files",
            responses=FAST_API_RESPONSE,)
        def download_measurements_zip(operationId: OperationId) -> StreamingResponse:
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
            operation_id = operationId
            return self._build_results_zip_response(operation_id, "multiRxMer")

        @self.router.delete("/stop/{operationId}",
            response_model=MultiRxMerStatusResponse,
            summary="Stop a running Multi-RxMER capture early",
            responses=FAST_API_RESPONSE,)
        def stop_capture(operationId: OperationId) -> MultiRxMerStatusResponse:
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
            operation_id = operationId
            service:MultiRxMerService = cast(MultiRxMerService, self._get_service_or_404(operation_id))

            service.stop(operation_id)
            status = service.status(operation_id)
            self._release_operation_memory(operation_id)

            return MultiRxMerStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                system_description=service.get_system_description(),
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
            response_model_exclude_none=True,
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
            capture_group_id = self._get_capture_group_or_none(request.operation_id)
            if capture_group_id is None:
                return MultiRxMerAnalysisResponse(
                    mac_address =   MacAddress.null(),
                    status      =   ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message     =   f"No capture group found for operation {request.operation_id}",
                    data        =   {})
            self._repair_capture_group_from_service_samples(request.operation_id, capture_group_id)
            self.logger.info(f'[analysis] - OperationID: {request.operation_id} -> CaptureGroup: {capture_group_id}')

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

            elif atype == MultiRxMerAnalysisType.ECHO_REFLECTION_1:
                engine = MultiRxMerSignalAnalysis(cda, MultiRxMerAnalysisType.ECHO_REFLECTION_1)
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
            fallback_mac = MacAddress.null()
            fallback_system_description = None
            try:
                service_for_context = cast(MultiRxMerService, self.getService(request.operation_id))
                fallback_mac = service_for_context.cm.get_mac_address.mac_address
                service_sd = service_for_context.get_system_description()
                if any(str(service_sd.get(k, "")).strip() for k in ("HW_REV", "VENDOR", "BOOTR", "SW_REV", "MODEL")):
                    fallback_system_description = SystemDescriptor.load_from_dict(service_sd).to_model()
            except Exception:
                op_rec = OperationManager.get_operation_record(request.operation_id)
                if isinstance(op_rec, dict):
                    metadata = op_rec.get("metadata")
                    if isinstance(metadata, dict):
                        md_mac = metadata.get("mac_address")
                        if isinstance(md_mac, str) and md_mac.strip():
                            fallback_mac = md_mac
                        md_sd = metadata.get("system_description")
                        if isinstance(md_sd, dict) and any(str(md_sd.get(k, "")).strip() for k in ("HW_REV", "VENDOR", "BOOTR", "SW_REV", "MODEL")):
                            fallback_system_description = SystemDescriptor.load_from_dict(md_sd).to_model()

            if mac_address == MacAddress.null():
                mac_address = fallback_mac

            response_system_description = multi_analysis.system_description or fallback_system_description

            if output_type == OutputType.JSON:
                err = multi_analysis.error
                status_code = ServiceStatusCode.SUCCESS if not err else ServiceStatusCode.FAILURE
                response_message = err or message
                data = multi_analysis.model_dump().get("data", {})
                if err:
                    try:
                        svc_for_err = cast(MultiRxMerService, self.getService(request.operation_id))
                        samples_for_err = svc_for_err.results(request.operation_id)
                        sample_errors = [str(s.error) for s in samples_for_err if getattr(s, "error", None)]
                        if sample_errors:
                            response_message = f"{response_message} Last capture error: {sample_errors[-1]}"
                    except Exception:
                        pass
                response_kwargs: dict[str, object] = {}
                if response_system_description is not None:
                    response_kwargs["device"] = {
                        "mac_address": mac_address,
                        "system_description": response_system_description,
                    }
                self._release_operation_memory(request.operation_id)
                return MultiRxMerAnalysisResponse(
                    mac_address =   mac_address,
                    status      =   status_code,
                    message     =   response_message,
                    **response_kwargs,
                    data        =   data,)

            elif output_type == OutputType.ARCHIVE:
                rpt = engine.build_report()
                self._release_operation_memory(request.operation_id)
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
