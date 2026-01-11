### Summary
Added dual-status support for operation start responses, centralized workflow schemas via re-exports, and aligned registry status responses with the shared time_remaining contract; updated docs and tests to reflect the unified payload shape.

### Modified Files
- src/pypnm/api/routes/advance/common/operation_workflow_schemas.py
- src/pypnm/api/routes/advance/common/operation_workflow_router.py
- src/pypnm/api/routes/advance/common/schema/operation_schema.py
- src/pypnm/api/routes/advance/multi_rxmer/router.py
- src/pypnm/api/routes/advance/multi_ds_chan_est/router.py
- docs/api/fast-api/multi/capture-operation.md
- tests/test_operation_registry_dual_status.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass
- `pytest -q` → pass (573 passed, 4 skipped)

### Tests
- `pytest` → pass (573 passed, 4 skipped)
- `ruff` → pass (`ruff check .`)

### Notes / Warnings
- `pytest` skipped SNMPv2 integration tests (PNM_CM_IT not set) and optional Postgres schema init (PYPNM_DB_POSTGRES_DSN not set).

### Remaining TODOs / Follow-Ups
- None
# FILE: src/pypnm/api/routes/advance/common/operation_workflow_schemas.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonResponse,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.operations.operation_models import OperationStatusModel
from pypnm.lib.types import OperationId


class OperationStartRequest(BaseModel):
    """
    Request body for creating a generic operation entry.
    """

    progress_total: int = Field(..., ge=1, description="Total expected work units.")
    message: str | None = Field(
        default=None, description="Optional message for operation creation."
    )


class OperationRequest(BaseModel):
    """
    Request body carrying an operation identifier.
    """

    operation_id: OperationId = Field(
        ..., description="Operation ID for status/cancel/result calls."
    )


class OperationStartResponse(CommonResponse):
    """
    Response returned after creating a generic operation entry.
    """

    service_status: ServiceStatusCode = Field(
        default=ServiceStatusCode.SUCCESS,
        description="Canonical ServiceStatusCode for this response.",
    )
    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )
    time_remaining: int = Field(
        ..., description="Seconds remaining for the operation (0 when unknown)."
    )


class OperationStatusResponse(CommonResponse):
    """
    Response containing the latest operation status record.
    """

    service_status: ServiceStatusCode = Field(
        default=ServiceStatusCode.SUCCESS,
        description="Canonical ServiceStatusCode for this response.",
    )
    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )
    time_remaining: int = Field(
        ..., description="Seconds remaining for the operation (0 when unknown)."
    )


class OperationCancelResponse(CommonResponse):
    """
    Response returned after a cancel request.
    """

    service_status: ServiceStatusCode = Field(
        default=ServiceStatusCode.SUCCESS,
        description="Canonical ServiceStatusCode for this response.",
    )
    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )


class OperationResultResponse(CommonResponse):
    """
    Response returned for result requests.
    """

    service_status: ServiceStatusCode = Field(
        default=ServiceStatusCode.SUCCESS,
        description="Canonical ServiceStatusCode for this response.",
    )
    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )


__all__ = [
    "OperationStartRequest",
    "OperationRequest",
    "OperationStartResponse",
    "OperationStatusResponse",
    "OperationCancelResponse",
    "OperationResultResponse",
]

# FILE: src/pypnm/api/routes/advance/common/operation_workflow_router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.common.operation_workflow_schemas import (
    OperationCancelResponse,
    OperationRequest,
    OperationResultResponse,
    OperationStartRequest,
    OperationStartResponse,
    OperationStatusResponse,
)
from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE


class OperationWorkflowRouter(AbstractService):
    """
    Generic operation workflow endpoints (start/status/result/cancel).
    """

    _DEFAULT_TIME_REMAINING: int = 0

    def __init__(self) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/advance/operation",
            tags=["PNM Operations - Workflow"],
        )
        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post(
            "/start",
            response_model=OperationStartResponse,
            summary="Create a generic operation entry",
            responses=FAST_API_RESPONSE,
        )
        def start_operation(request: OperationStartRequest) -> OperationStartResponse:
            status = OperationWorkflowService.start(
                progress_total=request.progress_total,
                message=request.message,
            )
            return OperationStartResponse(
                status="success",
                service_status=ServiceStatusCode.SUCCESS,
                message=None,
                operation=status,
                time_remaining=self._DEFAULT_TIME_REMAINING,
            )

        @self.router.post(
            "/status",
            response_model=OperationStatusResponse,
            summary="Get status for an operation ID",
            responses=FAST_API_RESPONSE,
        )
        def get_status(request: OperationRequest) -> OperationStatusResponse:
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
                time_remaining = int(op_status.get("time_remaining", time_remaining))
            return OperationStatusResponse(
                status="success",
                service_status=ServiceStatusCode.SUCCESS,
                message=None,
                operation=status,
                time_remaining=time_remaining,
            )

        @self.router.post(
            "/result",
            response_model=OperationResultResponse,
            summary="Get the final result for an operation ID",
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
                raise HTTPException(status_code=400, detail=str(err)) from err
            return OperationResultResponse(
                status="success",
                service_status=ServiceStatusCode.SUCCESS,
                message=None,
                operation=status,
            )

        @self.router.post(
            "/cancel",
            response_model=OperationCancelResponse,
            summary="Cancel an operation by ID",
            responses=FAST_API_RESPONSE,
        )
        def cancel(request: OperationRequest) -> OperationCancelResponse:
            service = OperationRegistry.get(request.operation_id)
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


router = OperationWorkflowRouter().router


__all__ = ["OperationWorkflowRouter", "router"]

# FILE: src/pypnm/api/routes/advance/common/schema/operation_schema.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.common.operation_workflow_schemas import (
    OperationCancelResponse,
    OperationRequest,
    OperationResultResponse,
    OperationStatusResponse,
)

__all__ = [
    "OperationRequest",
    "OperationStatusResponse",
    "OperationCancelResponse",
    "OperationResultResponse",
]

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
            return OperationStatusResponse(
                status="success",
                message=None,
                operation=status,
                time_remaining=self._DEFAULT_TIME_REMAINING,
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
            return OperationStatusResponse(
                status="success",
                service_status=ServiceStatusCode.SUCCESS,
                message=None,
                operation=status,
                time_remaining=self._DEFAULT_TIME_REMAINING,
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

# FILE: docs/api/fast-api/multi/capture-operation.md
# Multi‑Capture Operation Overview

When you initiate a **multi-capture** session (e.g., Multi‑RxMER or Multi‑DS‑Channel‑Estimation), PyPNM maintains a lightweight file‑based tracking system and stages resulting PNM binaries for downstream workflows.

**Directory Layout**:

```text
.data/
├── db/
│   ├── operation_capture.json      # Maps operations to capture groups
│   ├── capture_group.json          # Records capture groups
│   └── transactions.json           # Lists each staged file transaction
├── operations/
│   └── <operation_id>.json         # Status + progress for async operations
└── pnm/
    └── <.bin files>                # Raw PNM captures retrieved via TFTP
```

## 1. Operation Status Registry (`operations/<operation_id>.json`)

Each operation has its own status file to support `status`, `result`, and `cancel` endpoints.

**Example**:

```json
{
  "operation_id": "f6afb2d7df2c4a5c",
  "state": "running",
  "created_ts": 1730000000,
  "updated_ts": 1730000010,
  "progress_current": 1,
  "progress_total": 6,
  "message": "Operation running",
  "error": null,
  "artifact_paths": [
    "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_160_1730000000.bin"
  ]
}
```

## 2. Operation Database (`operation_capture.json`)

Records each background **operation** and its connection to a capture group.

**Example**:

```json
{
  "f6afb2d7df2c4a5c": {
    "capture_group_id": "10b6ea239641487c",
    "created": 1748280293
  }
}
```

* **Key**: `operation_id` (e.g., `f6afb2d7df2c4a5c`).
* **capture\_group\_id**: Associated `capture_group_id`.
* **created**: Unix timestamp when the operation started.
* **legacy**: Older records may use `capture_group` and are still read for compatibility.

## 3. Capture Group Database (`capture_group.json`)

Tracks each high‑level invocation as a distinct **capture group**.

**Example**:

```json
{
  "10b6ea239641487c": {
    "created": 1748280293,
    "transactions": [
      "2ee6138bbc1b3c3d",
      "65c04a28d0add931",
      "df4d2b3e3146ef30",
      "6773c9ebc097a579"
    ]
  }
}
```

* **Key**: `capture_group_id` (e.g., `10b6ea239641487c`).
* **created**: Unix timestamp when the group was created.
* **transactions**: List of associated `transaction_id`s (one per file).

## 4. Transactions Manifest (`transactions.json`)

A detailed manifest of every PNM file moved into `.data/pnm/` during the capture.

**Example**:

```json
{
  "2ee6138bbc1b3c3d": {
      "timestamp": 1748280294,
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
      "filename": "ds_ofdm_rxmer_per_subcar_aa:bb:cc:dd:ee:ff_34_1748280294.bin",
      "device_details": {
          "system_description": {
              "HW_REV": "1.0",
              "VENDOR": "LANCity",
              "BOOTR": "NONE",
              "SW_REV": "1.0.0",
              "MODEL": "LCPET-3"
          }
      }
  }
}
```

* **Key**: `transaction_id` (e.g., `2ee6138bbc1b3c3d`).
* **timestamp**: Unix epoch when the file was staged.
* **mac\_address**: Sanitized MAC of the target modem.
* **pnm\_test\_type**: Identifier of the PNM capture type.
* **filename**: Name of the `.bin` file in `.data/pnm/`.
* **device\_details.system\_description**: Snapshot of modem metadata at capture time.

Transaction IDs must be non-empty. Blank or whitespace-only IDs are dropped with a warning and are never persisted.
The `mac_address` field is intentionally stored in `transaction_records` (it is not treated as redundant in the SQL-backed schema direction).

## 5. Operation Workflow Endpoints (POST)

Generic workflow endpoints provide a consistent interface for operation status, result, and cancellation.
These endpoints rely on an in-memory OperationRegistry for live stop/status hooks and a filesystem-backed
OperationStore for authoritative state. Cancel requests are best-effort in-process; the OperationStore
status remains authoritative across restarts.

**Request** `POST /advance/operation/start`

```json
{
  "progress_total": 6,
  "message": "Operation created"
}
```

**Response** (start includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "running",
    "created_ts": 1730000000,
    "updated_ts": 1730000000,
    "progress_current": 0,
    "progress_total": 6,
    "message": "Operation created",
    "error": null,
    "artifact_paths": []
  },
  "time_remaining": 0
}
```

**Request** `POST /advance/operation/status`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Response** (registry status includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "running",
    "created_ts": 1730000000,
    "updated_ts": 1730000010,
    "progress_current": 1,
    "progress_total": 6,
    "message": "Operation running",
    "error": null,
    "artifact_paths": []
  },
  "time_remaining": 0
}
```

**Request** `POST /advance/operation/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Response** (registry result includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "completed",
    "created_ts": 1730000000,
    "updated_ts": 1730000030,
    "progress_current": 6,
    "progress_total": 6,
    "message": "Operation completed",
    "error": null,
    "artifact_paths": []
  }
}
```

**Request** `POST /advance/operation/cancel`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Response** (registry cancel includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null,
  "operation": {
    "operation_id": "f6afb2d7df2c4a5c",
    "state": "canceled",
    "created_ts": 1730000000,
    "updated_ts": 1730000020,
    "progress_current": 2,
    "progress_total": 6,
    "message": "Operation canceled",
    "error": null,
    "artifact_paths": []
  }
}
```

## 6. Multi-RxMER Workflow Endpoints (POST)

**Request** `POST /advance/ds/ofdm/rxmer/multi/start`

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.0.100",
  "duration": 60,
  "interval": 5
}
```

**Request** `POST /advance/ds/ofdm/rxmer/multi/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

## 7. Multi-ChannelEstimation Workflow Endpoints (POST)

**Request** `POST /advance/multiChannelEstimation/start`

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
  }
}
```

Note: The legacy `measure` payload is currently ignored and will be removed in a future release.

**Request** `POST /advance/multiChannelEstimation/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

Result behavior:
- Missing transaction records are skipped with warnings.
- If no transaction records resolve, the endpoint returns HTTP 404.

Start response fields:
- capture_group_id is canonical.
- group_id is legacy and will be deprecated.
- status is ServiceStatusCode.SUCCESS when the operation starts; operation_state indicates RUNNING.
Status semantics:
- Top-level status is always a ServiceStatusCode value.
- operation.state carries running/stopped/completed semantics.
- Registry endpoints return legacy status string plus service_status as the canonical ServiceStatusCode.

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and appends a JSON entry.
4. **Database Updates**: Timestamps and transaction lists are updated in both `operation_capture.json` and `capture_group.json`.
5. **Completion**: After the capture ends, the three JSON tables fully describe what was captured, when, and for which operation/group.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.

# FILE: tests/test_operation_registry_dual_status.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import pypnm.api.routes.advance.common.operation_workflow_router as workflow_router
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.types import OperationId


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(workflow_router.router)
    return app


def _fake_status(operation_id: OperationId) -> dict[str, object]:
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


def _fake_cancel(
    operation_id: OperationId, service: object | None = None
) -> dict[str, object]:
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


def _fake_result(operation_id: OperationId) -> dict[str, object]:
    return {
        "operation_id": str(operation_id),
        "state": "completed",
        "created_ts": 1,
        "updated_ts": 2,
        "progress_current": 1,
        "progress_total": 1,
        "message": "Operation completed",
        "error": None,
        "artifact_paths": None,
    }


def _fake_start(progress_total: int, message: str | None) -> dict[str, object]:
    return {
        "operation_id": "op-start-1",
        "state": "running",
        "created_ts": 1,
        "updated_ts": 1,
        "progress_current": 0,
        "progress_total": progress_total,
        "message": message,
        "error": None,
        "artifact_paths": None,
    }


def _patch_service(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    func: Callable[..., dict[str, object]],
) -> None:
    monkeypatch.setattr(
        workflow_router.OperationWorkflowService,
        name,
        staticmethod(func),
    )
    monkeypatch.setattr(
        workflow_router.OperationRegistry,
        "get",
        staticmethod(lambda operation_id: None),
    )


def test_operation_status_returns_dual_status_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_service(monkeypatch, "get_status", _fake_status)
    client = TestClient(_build_app())
    response = client.post(
        "/advance/operation/status",
        json={"operation_id": "op-700"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS


def test_operation_start_returns_dual_status_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_service(monkeypatch, "start", _fake_start)
    client = TestClient(_build_app())
    response = client.post(
        "/advance/operation/start",
        json={"progress_total": 1, "message": "Operation created"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS
    assert "operation" in payload
    assert "time_remaining" in payload


def test_operation_cancel_returns_dual_status_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_service(monkeypatch, "cancel", _fake_cancel)
    client = TestClient(_build_app())
    response = client.post(
        "/advance/operation/cancel",
        json={"operation_id": "op-701"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS


def test_operation_result_returns_dual_status_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_service(monkeypatch, "get_result", _fake_result)
    client = TestClient(_build_app())
    response = client.post(
        "/advance/operation/result",
        json={"operation_id": "op-702"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["service_status"] == ServiceStatusCode.SUCCESS

