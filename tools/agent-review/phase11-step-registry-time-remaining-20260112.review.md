## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

### Summary
Aligned multi-RxMER and multi-ChannelEstimation registry status endpoints with the shared time_remaining contract, including safe coercion to the default when missing. Added unit tests for both endpoints to validate service-provided and default time_remaining behavior.

### Modified Files
- src/pypnm/api/routes/advance/multi_rxmer/router.py
- src/pypnm/api/routes/advance/multi_ds_chan_est/router.py
- tests/test_multi_channel_estimation_start_and_analysis.py
- tests/test_multi_rxmer_registry_status_time_remaining.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass
- `pytest -q` → pass (577 passed, 4 skipped)

### Tests
- `pytest -q` → pass (577 passed, 4 skipped)
- `ruff` → pass (`ruff check .`)

### Notes / Warnings
- `pytest` skipped SNMPv2 integration tests (PNM_CM_IT not set) and optional Postgres schema init (PYPNM_DB_POSTGRES_DSN not set).

### Remaining TODOs / Follow-Ups
- None
# FILE: src/pypnm/api/routes/advance/multi_rxmer/router.py
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
from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.common.operation_workflow_schemas import (
    OperationCancelResponse,
    OperationRequest,
    OperationResultResponse,
    OperationStatusResponse,
)
from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
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
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import FileType, PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import GroupId, MacAddressStr, OperationId


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

    _DEFAULT_TIME_REMAINING: int = 0

    def __init__(self) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/advance/multiRxMer",
            tags=["PNM Operations - Multi-Downstream OFDM RxMER"],
        )
        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post(
            "/start",
            response_model=MultiRxMerStartResponse | SnmpResponse,
            summary="Start a Multi-RxMER capture",
            responses=FAST_API_RESPONSE,
        )
        async def start_multi_rxmer(
            request: MultiRxMerRequest,
        ) -> SnmpResponse | MultiRxMerStartResponse:
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
            community = RequestDefaultsResolver.resolve_snmp_community(
                request.cable_modem.snmp
            )
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(
                request.cable_modem.pnm_parameters.tftp
            )
            duration = request.capture.parameters.measurement_duration
            interval = request.capture.parameters.sample_interval

            measure_modes = request.measure.mode
            msg: str = ""

            self.logger.info(
                f"Starting Multi-RxMER capture for MAC={mac_address} "
                f"(duration={duration}s, interval={interval}s)"
            )

            cable_modem = CableModem(
                mac_address=MacAddress(mac_address),
                inet=Inet(ip_address),
                write_community=community,
            )

            status, msg = await CableModemServicePreCheck(
                cable_modem=cable_modem,
                validate_ofdm_exist=True,
                validate_pnm_ready_status=True,
            ).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(msg)
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)

            if measure_modes == MultiRxMerMeasureModes.CONTINUOUS:
                msg = f"Starting Multi-RxMER capture for MAC={mac_address}"
                self.logger.info(f"{msg}")
                group_id, operation_id = await self.loadService(
                    MultiRxMerService,
                    cable_modem,
                    tftp_servers,
                    duration=duration,
                    interval=interval,
                )

            elif measure_modes == MultiRxMerMeasureModes.OFDM_PERFORMANCE_1:
                msg = f"Starting Multi-RxMER-OFDM-Performance-1 capture for MAC={mac_address}"
                self.logger.info(f"{msg}")
                group_id, operation_id = await self.loadService(
                    MultiRxMer_Ofdm_Performance_1_Service,
                    cable_modem,
                    tftp_servers,
                    duration=duration,
                    interval=interval,
                )

            else:
                self.logger.error(f"Invalid Measure Mode Selected: ({measure_modes})")
                return MultiRxMerStartResponse(
                    mac_address=mac_address,
                    status=ServiceStatusCode.MEASURE_MODE_INVALID,
                    message=f"{ServiceStatusCode.MEASURE_MODE_INVALID.name}",
                    group_id="",
                    operation_id="",
                )

            return MultiRxMerStartResponse(
                mac_address=mac_address,
                status=OperationState.RUNNING,
                message=msg,
                group_id=group_id,
                operation_id=operation_id,
            )

        @self.router.get(
            "/status/{operation_id}",
            response_model=MultiRxMerStatusResponse,
            summary="Get status of a Multi-RxMER capture",
            responses=FAST_API_RESPONSE,
        )
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
                service: MultiRxMerService = cast(
                    MultiRxMerService, self.getService(operation_id)
                )

            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err

            status = service.status(operation_id)

            self.logger.debug(f"OpId: {operation_id} - Status: {status}")

            return MultiRxMerStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                status="success",
                message=None,
                operation=MultiRxMerResponseStatus(
                    operation_id=operation_id,
                    state=status["state"],
                    collected=status["collected"],
                    time_remaining=status["time_remaining"],
                    message=None,
                ),
            )

        @self.router.post(
            "/status",
            response_model=OperationStatusResponse,
            summary="Get status of a Multi-RxMER capture (operation registry)",
            responses=FAST_API_RESPONSE,
        )
        def get_status_post(request: OperationRequest) -> OperationStatusResponse:
            try:
                status = OperationWorkflowService.get_status(request.operation_id)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            time_remaining = self._DEFAULT_TIME_REMAINING
            service = OperationRegistry.get(request.operation_id)
            if service is not None:
                op_status = service.status(request.operation_id)
                try:
                    time_remaining = int(
                        op_status.get("time_remaining", time_remaining)
                    )
                except (TypeError, ValueError):
                    time_remaining = self._DEFAULT_TIME_REMAINING
            return OperationStatusResponse(
                status="success",
                message=None,
                operation=status,
                time_remaining=time_remaining,
            )

        @self.router.get(
            "/results/{operation_id}",
            summary="Download a ZIP archive of all RxMER capture files",
            responses=FAST_API_RESPONSE,
        )
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
            svc: MultiRxMerService = cast(
                MultiRxMerService, self.getService(operation_id)
            )
            samples = svc.results(operation_id)

            pnm_dir = str(SystemConfigSettings.pnm_dir())
            mac = svc.cm.get_mac_address.mac_address

            buf = io.BytesIO()
            with zipfile.ZipFile(
                buf, mode="w", compression=zipfile.ZIP_DEFLATED
            ) as zipf:
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

            headers = {
                "Content-Disposition": f"attachment; filename=multiRxMer_{mac}_{operation_id}.zip"
            }
            return StreamingResponse(buf, media_type="application/zip", headers=headers)

        @self.router.delete(
            "/stop/{operation_id}",
            response_model=MultiRxMerStatusResponse,
            summary="Stop a running Multi-RxMER capture early",
            responses=FAST_API_RESPONSE,
        )
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
                service: MultiRxMerService = cast(
                    MultiRxMerService, self.getService(operation_id)
                )
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err

            service.stop(operation_id)
            status = service.status(operation_id)

            return MultiRxMerStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                status=OperationState.STOPPED,
                message=None,
                operation=MultiRxMerResponseStatus(
                    operation_id=operation_id,
                    state=status["state"],
                    collected=status["collected"],
                    time_remaining=status["time_remaining"],
                    message=None,
                ),
            )

        @self.router.post(
            "/cancel",
            response_model=OperationCancelResponse,
            summary="Cancel a running Multi-RxMER capture",
            responses=FAST_API_RESPONSE,
        )
        def cancel_capture(request: OperationRequest) -> OperationCancelResponse:
            try:
                service: AbstractCaptureService = self.getService(request.operation_id)
            except KeyError:
                service = None
            try:
                status = OperationWorkflowService.cancel(request.operation_id, service)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            return OperationCancelResponse(
                status="success",
                message=None,
                operation=status,
            )

        @self.router.post(
            "/result",
            response_model=OperationResultResponse,
            summary="Get Multi-RxMER results once the operation completes",
            responses=FAST_API_RESPONSE,
        )
        def get_result(request: OperationRequest) -> OperationResultResponse:
            try:
                status = OperationWorkflowService.get_result(request.operation_id)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            except ValueError as err:
                raise HTTPException(status_code=409, detail=str(err)) from err
            return OperationResultResponse(
                status="success",
                message=None,
                operation=status,
            )

        @self.router.post(
            "/analysis",
            response_model=MultiRxMerAnalysisResponse,
            summary="Perform signal analysis on a previously executed Multi-RxMER captures",
            responses=FAST_API_RESPONSE,
        )
        def analysis(
            request: MultiRxMerAnalysisRequest,
        ) -> MultiRxMerAnalysisResponse | FileResponse:
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
                capture_group_id: GroupId = OperationManager.get_capture_group(
                    request.operation_id
                )
                self.logger.info(
                    f"[analysis] - OperationID: {request.operation_id} -> CaptureGroup: {capture_group_id}"
                )

            except KeyError:
                return MultiRxMerAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message=f"No capture group found for operation {request.operation_id}",
                    data={},
                )

            cda = CaptureDataAggregator(capture_group_id)

            try:
                atype = MultiRxMerAnalysisType(request.analysis.type)
            except ValueError:
                msg = f"Invalid Analysis Type, reason: {request.analysis.type}"
                return MultiRxMerAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.DS_OFDM_MULIT_RXMER_ANALYSIS_TYPE,
                    message=msg,
                    data={},
                )
            self.logger.info(
                f"Performing Multi-RxMER Min/Avg/Max Analysis for group: {capture_group_id}"
            )

            if atype == MultiRxMerAnalysisType.MIN_AVG_MAX:
                engine = MultiRxMerSignalAnalysis(cda, atype)
                multi_analysis: MultiRxMerAnalysisResult = engine.to_model()

            elif atype == MultiRxMerAnalysisType.RXMER_HEAT_MAP:
                engine = MultiRxMerSignalAnalysis(
                    cda, MultiRxMerAnalysisType.RXMER_HEAT_MAP
                )
                multi_analysis = engine.to_model()

            elif atype == MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1:
                """
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
                """
                engine = MultiRxMerSignalAnalysis(
                    cda, MultiRxMerAnalysisType.OFDM_PROFILE_PERFORMANCE_1
                )
                multi_analysis = engine.to_model()

            else:
                msg = f"Invalid Analysis Type {atype}"
                return MultiRxMerAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.DS_OFDM_MULIT_RXMER_ANALYSIS_TYPE,
                    message=msg,
                    data={},
                )

            # 4) Map analysis output to response fields
            analysis_name = MultiRxMerAnalysisType(atype).name
            message = f"Analysis {analysis_name} completed for group {capture_group_id}"

            try:
                output_type = request.analysis.output.type
            except ValueError:
                msg = f"Invalid Output Type Selected: ({request.analysis.output.type})"
                return MultiRxMerAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    message=msg,
                    data={},
                )

            mac_address = multi_analysis.mac_address

            if output_type == OutputType.JSON:
                data = multi_analysis.model_dump().get("data", {})
                return MultiRxMerAnalysisResponse(
                    mac_address=mac_address,
                    status=ServiceStatusCode.SUCCESS,
                    message=message,
                    data=data,
                )

            elif output_type == OutputType.ARCHIVE:
                rpt = engine.build_report()
                return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

            else:
                # Fallback for unsupported output types
                return MultiRxMerAnalysisResponse(
                    mac_address=mac_address,
                    status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                    message=f"Unsupported output type: {output_type}",
                    data={},
                )


# For dynamic auto-registration
router = MultiRxMerRouter().router

# FILE: src/pypnm/api/routes/advance/multi_ds_chan_est/router.py
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
from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.advance.common.operation_workflow_schemas import (
    OperationCancelResponse,
    OperationRequest,
    OperationStatusResponse,
)
from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.advance.multi_ds_chan_est.schemas import (
    AnalysisDataModel,
    MultiChanEstAnalysisRequest,
    MultiChanEstimationAnalysisResponse,
    MultiChanEstimationResponseStatus,
    MultiChanEstimationResultResponse,
    MultiChanEstimationStartResponse,
    MultiChanEstRequest,
    MultiChanEstStatusResponse,
)
from pypnm.api.routes.advance.multi_ds_chan_est.service import (
    MultiChannelEstimationService,
)
from pypnm.api.routes.advance.multi_ds_chan_est.workflow_service import (
    MultiChanEstimationWorkflowService,
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
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.docs.pnm.files.service import PnmFileService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE
from pypnm.lib.inet import Inet, InetAddressStr
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import MacAddressStr, OperationId


class MultiDsChanEstRouter(AbstractService):
    """Router for handling Multi-DS-Channel-Estimation operations."""

    _DEFAULT_TIME_REMAINING: int = 0

    def __init__(self) -> None:
        super().__init__()
        self.router = APIRouter(
            prefix="/advance/multiChannelEstimation",
            tags=["PNM Operations - Multi-DS-Channel-Estimation"],
        )
        self.logger = logging.getLogger(self.__class__.__name__)
        self._workflow_service = MultiChanEstimationWorkflowService()
        self._add_routes()

    # ──────────────────────────────────────────────────────────
    # Routes
    # ──────────────────────────────────────────────────────────
    def _add_routes(self) -> None:
        @self.router.post(
            "/start",
            response_model=MultiChanEstimationStartResponse | SnmpResponse,
            summary="Start a multi-sample ChannelEstimation capture",
        )
        async def start_multi_chan_estimation(
            request: MultiChanEstRequest,
        ) -> MultiChanEstimationStartResponse | SnmpResponse:
            duration, interval = (
                request.capture.parameters.measurement_duration,
                request.capture.parameters.sample_interval,
            )
            mac_address: MacAddressStr = request.cable_modem.mac_address
            ip_address: InetAddressStr = request.cable_modem.ip_address
            community = RequestDefaultsResolver.resolve_snmp_community(
                request.cable_modem.snmp
            )
            tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(
                request.cable_modem.pnm_parameters.tftp
            )

            self.logger.info(
                f"[start] Multi-ChanEst for MAC={mac_address}, duration={duration}s interval={interval}s"
            )

            cm = CableModem(
                mac_address=MacAddress(mac_address),
                inet=Inet(ip_address),
                write_community=community,
            )

            # Pre-checks
            status, msg = await CableModemServicePreCheck(
                cable_modem=cm, validate_ofdm_exist=True
            ).run_precheck()
            if status != ServiceStatusCode.SUCCESS:
                self.logger.error(
                    f"[start] Precheck failed for MAC={mac_address}: {msg}"
                )
                return SnmpResponse(mac_address=mac_address, status=status, message=msg)

            group_id, operation_id = await self.loadService(
                MultiChannelEstimationService,
                cm,
                tftp_servers,
                duration=duration,
                interval=interval,
            )
            return MultiChanEstimationStartResponse(
                mac_address=mac_address,
                status=ServiceStatusCode.SUCCESS,
                message=None,
                group_id=group_id,
                capture_group_id=group_id,
                operation_id=operation_id,
                operation_state=OperationState.RUNNING,
            )

        @self.router.get(
            "/status/{operation_id}",
            response_model=MultiChanEstStatusResponse,
            summary="Get status of a multi-sample ChannelEstimation capture",
        )
        def get_status(operation_id: OperationId) -> MultiChanEstStatusResponse:
            try:
                service: MultiChannelEstimationService = cast(
                    MultiChannelEstimationService, self.getService(operation_id)
                )

            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err

            status = service.status(operation_id)
            return MultiChanEstStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                status=ServiceStatusCode.SUCCESS,
                message=None,
                operation=MultiChanEstimationResponseStatus(
                    operation_id=operation_id,
                    state=status["state"],
                    collected=status["collected"],
                    time_remaining=status["time_remaining"],
                    message=None,
                ),
            )

        @self.router.post(
            "/status",
            response_model=OperationStatusResponse,
            summary="Get status of a multi-sample ChannelEstimation capture (operation registry)",
            responses=FAST_API_RESPONSE,
        )
        def get_status_post(request: OperationRequest) -> OperationStatusResponse:
            try:
                status = OperationWorkflowService.get_status(request.operation_id)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            time_remaining = self._DEFAULT_TIME_REMAINING
            service = OperationRegistry.get(request.operation_id)
            if service is not None:
                op_status = service.status(request.operation_id)
                try:
                    time_remaining = int(
                        op_status.get("time_remaining", time_remaining)
                    )
                except (TypeError, ValueError):
                    time_remaining = self._DEFAULT_TIME_REMAINING
            return OperationStatusResponse(
                status="success",
                service_status=ServiceStatusCode.SUCCESS,
                message=None,
                operation=status,
                time_remaining=time_remaining,
            )

        @self.router.get(
            "/results/{operation_id}",
            summary="Download a ZIP archive of all ChannelEstimation capture files",
            responses={
                200: {
                    "content": {"application/zip": {}},
                    "description": "ZIP archive of capture files",
                }
            },
        )
        def download_results_zip(operation_id: OperationId) -> StreamingResponse:
            svc: MultiChannelEstimationService = cast(
                MultiChannelEstimationService, self.getService(operation_id)
            )
            samples = svc.results(operation_id)
            pnm_dir, mac = (
                str(SystemConfigSettings.pnm_dir()),
                svc.cm.get_mac_address.mac_address,
            )
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
            headers = {
                "Content-Disposition": f"attachment; filename=multiChannelEstimation_{mac}_{operation_id}.zip"
            }
            return StreamingResponse(buf, media_type="application/zip", headers=headers)

        @self.router.delete(
            "/stop/{operation_id}",
            response_model=MultiChanEstStatusResponse,
            summary="Stop a running multi-sample ChannelEstimation capture early",
        )
        def stop_capture(operation_id: OperationId) -> MultiChanEstStatusResponse:
            """ """
            try:
                service: MultiChannelEstimationService = cast(
                    MultiChannelEstimationService, self.getService(operation_id)
                )

            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err

            service.stop(operation_id)
            status = service.status(operation_id)
            return MultiChanEstStatusResponse(
                mac_address=service.cm.get_mac_address.mac_address,
                status=ServiceStatusCode.SUCCESS,
                message=None,
                operation=MultiChanEstimationResponseStatus(
                    operation_id=operation_id,
                    state=status["state"],
                    collected=status["collected"],
                    time_remaining=status["time_remaining"],
                    message=None,
                ),
            )

        @self.router.post(
            "/cancel",
            response_model=OperationCancelResponse,
            summary="Cancel a running multi-sample ChannelEstimation capture",
            responses=FAST_API_RESPONSE,
        )
        def cancel_capture(request: OperationRequest) -> OperationCancelResponse:
            try:
                service: AbstractCaptureService = self.getService(request.operation_id)
            except KeyError:
                service = None
            try:
                status = OperationWorkflowService.cancel(request.operation_id, service)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            return OperationCancelResponse(
                status="success",
                service_status=ServiceStatusCode.SUCCESS,
                message=None,
                operation=status,
            )

        @self.router.post(
            "/result",
            response_model=MultiChanEstimationResultResponse,
            summary="Get ChannelEstimation results once the operation completes",
            responses=FAST_API_RESPONSE,
        )
        def get_result(request: OperationRequest) -> MultiChanEstimationResultResponse:
            try:
                return self._workflow_service.result(request.operation_id)
            except KeyError as err:
                detail = err.args[0] if err.args else "Operation not found"
                raise HTTPException(status_code=404, detail=detail) from err
            except ValueError as err:
                raise HTTPException(status_code=400, detail=str(err)) from err

        @self.router.post(
            "/analysis",
            response_model=MultiChanEstimationAnalysisResponse,
            summary="Perform signal analysis on a previously executed Multi-ChannelEstimation",
        )
        def analysis(
            request: MultiChanEstAnalysisRequest,
        ) -> MultiChanEstimationAnalysisResponse | FileResponse:
            """
            Perform post-capture analysis on Multi-ChannelEstimation measurement data.

            Supports:
            - MIN_AVG_MAX
            - GROUP_DELAY
            - LTE_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_PHASE_SLOPE
            - ECHO_DETECTION_IFFT
            """
            capture_group_id = OperationManager.get_capture_group(request.operation_id)
            if not capture_group_id:
                msg = f"No capture group found for operation {request.operation_id}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message=msg,
                    data=AnalysisDataModel(analysis_type="UNKNOWN", results=[]),
                )
            self.logger.info(
                f"[analysis] operation_id={request.operation_id} capture_group={capture_group_id}"
            )

            # Prepare data aggregator
            cda = CaptureDataAggregator(capture_group_id)

            # Parse analysis type
            try:
                atype = MultiChanEstAnalysisType(request.analysis.type)

            except ValueError:
                msg = f"Invalid analysis type: {request.analysis.type}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE,
                    message=msg,
                    data=AnalysisDataModel(analysis_type="UNKNOWN", results=[]),
                )

            # Dispatch map for type → analysis engine
            analysis_map: dict[
                MultiChanEstAnalysisType,
                Callable[[CaptureDataAggregator], MultiChanEstimationSignalAnalysis],
            ] = {
                MultiChanEstAnalysisType.MIN_AVG_MAX: lambda agg: MultiChanEstimationSignalAnalysis(
                    agg, MultiChanEstAnalysisType.MIN_AVG_MAX
                ),
                MultiChanEstAnalysisType.GROUP_DELAY: lambda agg: MultiChanEstimationSignalAnalysis(
                    agg, MultiChanEstAnalysisType.GROUP_DELAY
                ),
                MultiChanEstAnalysisType.LTE_DETECTION_PHASE_SLOPE: lambda agg: MultiChanEstimationSignalAnalysis(
                    agg, MultiChanEstAnalysisType.LTE_DETECTION_PHASE_SLOPE
                ),
                MultiChanEstAnalysisType.ECHO_DETECTION_IFFT: lambda agg: MultiChanEstimationSignalAnalysis(
                    agg, MultiChanEstAnalysisType.ECHO_DETECTION_IFFT
                ),
            }

            if atype not in analysis_map:
                msg = f"Unsupported analysis type: {atype}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.DS_OFDM_CHAN_EST_INVALID_ANALYSIS_TYPE,
                    message=msg,
                    data=AnalysisDataModel(analysis_type="UNKNOWN", results=[]),
                )

            # Determine output type
            output_type: OutputType = request.analysis.output.type
            engine = analysis_map[atype](cda)
            analysis_result = engine.to_model()

            # Handle output formats
            if output_type == OutputType.JSON:
                err = analysis_result.error
                status = (
                    ServiceStatusCode.SUCCESS if not err else ServiceStatusCode.FAILURE
                )
                message = (
                    err
                    or f"Analysis {analysis_result.analysis_type} completed for group {capture_group_id}"
                )

                data_model = AnalysisDataModel(
                    analysis_type=analysis_result.analysis_type,
                    results=[r.model_dump() for r in analysis_result.results],
                )

                mac = engine.getMacAddresses()[0].mac_address
                self.logger.info(
                    f"[analysis] type={atype.name} mac={mac} status={status.name} group={capture_group_id}"
                )

                return MultiChanEstimationAnalysisResponse(
                    mac_address=mac, status=status, message=message, data=data_model
                )

            elif output_type == OutputType.ARCHIVE:
                try:
                    rpt = engine.build_report()
                    self.logger.info(
                        f"[analysis] Built archive report for group {capture_group_id}"
                    )
                    return PnmFileService().get_file(FileType.ARCHIVE, rpt.name)

                except Exception as e:
                    msg = f"Archive build failed: {e}"
                    self.logger.error(msg)
                    return MultiChanEstimationAnalysisResponse(
                        mac_address=MacAddress.null(),
                        status=ServiceStatusCode.FAILURE,
                        message=msg,
                        data=AnalysisDataModel(analysis_type=atype.name, results=[]),
                    )

            # Unsupported output type
            msg = f"Unsupported output type: {output_type}"
            self.logger.error(msg)
            return MultiChanEstimationAnalysisResponse(
                mac_address=MacAddress.null(),
                status=ServiceStatusCode.INVALID_OUTPUT_TYPE,
                message=msg,
                data=AnalysisDataModel(analysis_type=atype.name, results=[]),
            )


# Auto-register
router = MultiDsChanEstRouter().router

# FILE: tests/test_multi_channel_estimation_start_and_analysis.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import pypnm.api.routes.advance.multi_ds_chan_est.router as ds_router
from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.multi_ds_chan_est.router import router
from pypnm.api.routes.advance.multi_ds_chan_est.service import (
    MultiChannelEstimationService,
)
from pypnm.api.routes.common.classes.operation.cable_modem_precheck import (
    CableModemServicePreCheck,
)
from pypnm.api.routes.common.extended.common_messaging_service import MessageResponse
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import OperationId

_TEST_TIME_REMAINING: int = 123


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _configure_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"
    transaction_db = db_dir / "transactions.json"

    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(capture_group_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "operation_db",
        classmethod(lambda cls: str(operation_db)),
    )
    monkeypatch.setattr(
        SystemConfigSettings,
        "transaction_db",
        classmethod(lambda cls: str(transaction_db)),
    )


def _start_request_payload() -> dict[str, object]:
    return {
        "cable_modem": {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "192.168.0.100",
            "pnm_parameters": {
                "tftp": {
                    "ipv4": None,
                    "ipv6": None,
                },
                "capture": {
                    "channel_ids": None,
                },
            },
            "snmp": {
                "snmp_v2c": {
                    "community": "public",
                }
            },
        },
        "capture": {
            "parameters": {
                "measurement_duration": 1,
                "sample_interval": 1,
            }
        },
    }


@pytest.mark.asyncio
async def test_start_returns_success_status_and_group_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    async def _fake_precheck(
        self: CableModemServicePreCheck,
    ) -> tuple[ServiceStatusCode, str]:
        return ServiceStatusCode.SUCCESS, "ok"

    async def _fake_capture(self: MultiChannelEstimationService) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])

    monkeypatch.setattr(CableModemServicePreCheck, "run_precheck", _fake_precheck)
    monkeypatch.setattr(
        MultiChannelEstimationService, "_capture_message_response", _fake_capture
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/start",
        json=_start_request_payload(),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.SUCCESS
    assert payload["operation_id"]
    assert payload["capture_group_id"]
    assert payload["group_id"] == payload["capture_group_id"]
    assert payload["operation_state"] == "running"
    OperationRegistry.unregister(OperationId(payload["operation_id"]))


def test_analysis_returns_capture_group_not_found_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    db_path = Path(SystemConfigSettings.operation_db())
    db_path.write_text(json.dumps({}), encoding="utf-8")

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/analysis",
        json={"operation_id": "op-missing"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND
    assert "No capture group found for operation" in payload["message"]


class _StubMac:
    mac_address = "aa:bb:cc:dd:ee:ff"


class _StubCm:
    get_mac_address = _StubMac()


class _StubService:
    def __init__(self) -> None:
        self.cm = _StubCm()
        self._state = "running"

    def status(self, operation_id: OperationId) -> dict[str, object]:
        return {
            "state": self._state,
            "collected": 0,
            "time_remaining": 0,
        }

    def stop(self, operation_id: OperationId) -> None:
        self._state = "stopped"


def test_status_endpoint_uses_service_status_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    stub = _StubService()
    monkeypatch.setattr(
        ds_router.MultiDsChanEstRouter,
        "getService",
        lambda self, operation_id: stub,
    )

    client = TestClient(_build_app())
    response = client.get("/advance/multiChannelEstimation/status/op-500")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.SUCCESS
    assert payload["operation"]["operation_id"] == "op-500"


def test_stop_endpoint_uses_service_status_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)
    stub = _StubService()
    monkeypatch.setattr(
        ds_router.MultiDsChanEstRouter,
        "getService",
        lambda self, operation_id: stub,
    )

    client = TestClient(_build_app())
    response = client.delete("/advance/multiChannelEstimation/stop/op-501")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == ServiceStatusCode.SUCCESS
    assert payload["operation"]["state"] == "stopped"


def test_registry_status_endpoint_returns_dual_status_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/status",
        json={"operation_id": "op-600"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS


def test_registry_status_endpoint_uses_service_time_remaining(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    class _StubService:
        def status(self, operation_id: OperationId) -> dict[str, int]:
            return {"time_remaining": _TEST_TIME_REMAINING}

    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )
    monkeypatch.setattr(
        OperationRegistry,
        "get",
        staticmethod(lambda operation_id: _StubService()),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/status",
        json={"operation_id": "op-602"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["time_remaining"] == _TEST_TIME_REMAINING


def test_registry_status_endpoint_uses_default_time_remaining_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )
    monkeypatch.setattr(
        OperationRegistry,
        "get",
        staticmethod(lambda operation_id: None),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/status",
        json={"operation_id": "op-603"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert (
        payload["time_remaining"]
        == ds_router.MultiDsChanEstRouter._DEFAULT_TIME_REMAINING
    )


def test_registry_cancel_endpoint_returns_dual_status_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    def _fake_cancel(
        operation_id: OperationId, service: object | None = None
    ) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "canceled",
            "created_ts": 1,
            "updated_ts": 2,
            "progress_current": 1,
            "progress_total": 1,
            "message": "Operation canceled",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        ds_router.OperationWorkflowService,
        "cancel",
        staticmethod(_fake_cancel),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiChannelEstimation/cancel",
        json={"operation_id": "op-601"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS

# FILE: tests/test_multi_rxmer_registry_status_time_remaining.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import pypnm.api.routes.advance.multi_rxmer.router as rxmer_router
from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.multi_rxmer.router import router
from pypnm.lib.types import OperationId

_TEST_TIME_REMAINING: int = 123


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def test_registry_status_endpoint_uses_service_time_remaining(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StubService:
        def status(self, operation_id: OperationId) -> dict[str, int]:
            return {"time_remaining": _TEST_TIME_REMAINING}

    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        rxmer_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )
    monkeypatch.setattr(
        OperationRegistry,
        "get",
        staticmethod(lambda operation_id: _StubService()),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiRxMer/status",
        json={"operation_id": "op-800"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["time_remaining"] == _TEST_TIME_REMAINING


def test_registry_status_endpoint_uses_default_time_remaining_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fake_status(operation_id: OperationId) -> object:
        return {
            "operation_id": str(operation_id),
            "state": "running",
            "created_ts": 1,
            "updated_ts": 1,
            "progress_current": 0,
            "progress_total": 1,
            "message": "Operation running",
            "error": None,
            "artifact_paths": None,
        }

    monkeypatch.setattr(
        rxmer_router.OperationWorkflowService,
        "get_status",
        staticmethod(_fake_status),
    )
    monkeypatch.setattr(
        OperationRegistry,
        "get",
        staticmethod(lambda operation_id: None),
    )

    client = TestClient(_build_app())
    response = client.post(
        "/advance/multiRxMer/status",
        json={"operation_id": "op-801"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert (
        payload["time_remaining"]
        == rxmer_router.MultiRxMerRouter._DEFAULT_TIME_REMAINING
    )

