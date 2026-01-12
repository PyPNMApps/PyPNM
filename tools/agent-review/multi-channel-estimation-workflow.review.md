## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

### Summary
Wired multi-ChannelEstimation result resolution to the hardened workflow path with capture-group mapping, missing-record filtering, and 404 when no transactions resolve, while keeping existing capture service usage intact. Updated start responses to include capture_group_id and documented the result behavior with new regression tests.

### Modified Files
- src/pypnm/api/routes/advance/multi_ds_chan_est/router.py
- src/pypnm/api/routes/advance/multi_ds_chan_est/schemas.py
- src/pypnm/api/routes/advance/multi_ds_chan_est/workflow_service.py
- docs/api/fast-api/multi/capture-operation.md
- tests/test_multi_channel_estimation_result.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass
- `pytest -q` → pass (563 passed, 4 skipped)

### Tests
- `pytest` → pass (563 passed, 4 skipped)
- `ruff` → pass
- `python3 -m compileall src` → pass

### Notes / Warnings
- Pytest logs include expected warnings from existing tests; no deprecation warnings observed.

### Remaining TODOs / Follow-Ups
- None

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
from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.advance.common.schema.operation_schema import (
    OperationCancelResponse,
    OperationRequest,
    OperationStatusResponse,
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
from pypnm.lib.types import GroupId, MacAddressStr, OperationId


class MultiDsChanEstRouter(AbstractService):
    """Router for handling Multi-DS-Channel-Estimation operations."""

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
                status=OperationState.RUNNING,
                message=None,
                group_id=group_id,
                capture_group_id=group_id,
                operation_id=operation_id,
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
                status="success",
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
                message=None,
                operation=status,
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
                status=OperationState.STOPPED,
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
            try:
                capture_group_id: GroupId = OperationManager.get_capture_group(
                    request.operation_id
                )
                self.logger.info(
                    f"[analysis] operation_id={request.operation_id} capture_group={capture_group_id}"
                )
            except KeyError:
                msg = f"No capture group found for operation {request.operation_id}"
                self.logger.error(msg)
                return MultiChanEstimationAnalysisResponse(
                    mac_address=MacAddress.null(),
                    status=ServiceStatusCode.CAPTURE_GROUP_NOT_FOUND,
                    message=msg,
                    data=AnalysisDataModel(analysis_type="UNKNOWN", results=[]),
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

# FILE: src/pypnm/api/routes/advance/multi_ds_chan_est/schemas.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from pypnm.api.routes.advance.analysis.signal_analysis.multi_chan_est_singnal_analysis import (
    MultiChanEstAnalysisType,
)
from pypnm.api.routes.advance.common.schema.common_capture_schema import (
    MultiCaptureParametersResponse,
    MultiCaptureRequest,
)
from pypnm.api.routes.advance.multi_rxmer.schemas import ChanEstMeasureParameters
from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonAnalysisResponse,
    CommonMatPlotConfigRequest,
    CommonOutput,
    CommonResponse,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.lib.operations.operation_models import OperationStatusModel
from pypnm.lib.types import GroupId, OperationId, PathArray


################################# HELPER MODEL ############################
class AnalysisDataModel(BaseModel):
    """Typed container for analysis output."""

    analysis_type: str = Field(..., description="Executed analysis type name.")
    results: list[dict[str, Any]] = Field(
        ...,
        description="List of per-channel analysis results (min/avg/max, group delay, anomalies, etc.).",
    )


class MultiChanEstAnalysisContainerModel(BaseModel):
    """Model for Multi-ChannelEstimation analysis types."""

    type: MultiChanEstAnalysisType = Field(
        default=MultiChanEstAnalysisType.MIN_AVG_MAX,
        description="Analysis type to perform, implementation-specific integer value",
    )
    output: CommonOutput = Field(
        default=CommonOutput(), description="Output type control: json or archive"
    )
    plot: CommonMatPlotConfigRequest = Field(
        default=CommonMatPlotConfigRequest(),
        description="Plot configuration for multi-ChannelEstimation analysis",
    )


class MultiChanEstAnalysisModel(BaseModel):
    """Request schema for performing signal analysis on a completed Multi-ChannelEstimation capture."""

    analysis: MultiChanEstAnalysisContainerModel = Field(
        default=MultiChanEstAnalysisContainerModel(),
        description="Analysis type to perform, implementation-specific integer value",
    )


################################# REQUEST #################################


class MultiChanEstAnalysisRequest(BaseModel):
    """Request schema for performing signal analysis on a completed Multi-ChannelEstimation capture."""

    analysis: MultiChanEstAnalysisContainerModel = Field(
        default=MultiChanEstAnalysisContainerModel(),
        description="Analysis type to perform, implementation-specific integer value",
    )
    operation_id: OperationId = Field(
        ..., description="Operation ID to query status/results."
    )


################################# RESPONSE #################################


class MultiChanEstRequest(MultiCaptureRequest):
    """Request schema for initiating a Multi-ChannelEstimation operation."""

    measure: ChanEstMeasureParameters = Field(
        ...,
        description="Measurement parameters for the Multi-ChannelEstimation operation.",
    )


class MultiChanEstimationResponseStatus(MultiCaptureParametersResponse):
    """Status details about a Multi-ChannelEstimation capture operation."""

    pass


class MultiChanEstimationStartResponse(CommonResponse):
    """Response returned when a multi-ChannelEstimation capture is kicked off."""

    group_id: GroupId = Field(..., description="Capture group ID for this session")
    capture_group_id: GroupId = Field(
        ..., description="Capture group ID for this session"
    )
    operation_id: OperationId = Field(
        ..., description="Operation ID to query status/results"
    )


class MultiChanEstStatusResponse(CommonResponse):
    """Response schema for checking the status of a Multi-ChannelEstimation capture operation."""

    operation: MultiChanEstimationResponseStatus = Field(
        ...,
        description="Detailed operation-level state and sample count (operation_id, state, collected, time_remaining, message).",
    )


class MultiChanEstimationAnalysisResponse(CommonAnalysisResponse):
    """Response schema for Multi-ChannelEstimation signal analysis."""

    data: AnalysisDataModel = Field(
        ...,
        description="Structured analysis result container including the analysis_type and its corresponding per-channel results.",
    )


class MultiChanEstimationResultResponse(CommonResponse):
    """Response schema for completed Multi-ChannelEstimation capture results."""

    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )
    capture_group_id: GroupId = Field(..., description="Capture group identifier.")
    transactions: list[TransactionRecordModel] = Field(
        ..., description="Resolved transaction record models."
    )
    artifact_paths: PathArray | None = Field(
        None, description="Optional artifact paths persisted for the operation."
    )

# FILE: src/pypnm/api/routes/advance/multi_ds_chan_est/workflow_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.advance.multi_ds_chan_est.schemas import (
    MultiChanEstimationResultResponse,
)
from pypnm.api.routes.common.classes.file_capture.pnm_file_opearation import (
    OperationCaptureGroupResolver,
)
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import OperationId


class MultiChanEstimationWorkflowService:
    """
    Result helpers for multi-ChannelEstimation capture workflows.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

    def result(self, operation_id: OperationId) -> MultiChanEstimationResultResponse:
        status = OperationWorkflowService.get_result(operation_id)
        resolver = OperationCaptureGroupResolver()
        capture_group_id = resolver.get_capture_group_id(operation_id)
        if not capture_group_id:
            raise KeyError(f"Capture group not found for operation: {operation_id}")
        txn_ids = resolver.get_transaction_ids_for_capture_group(capture_group_id)
        txn_store = PnmFileTransaction()
        transactions: list[TransactionRecordModel] = []
        for txn_id in txn_ids:
            model = txn_store.getRecordModel(txn_id)
            tx_id = str(getattr(model, "transaction_id", "")).strip()
            if tx_id:
                transactions.append(model)
                continue
            self.logger.warning(
                "Missing transaction record for transaction_id=%s", txn_id
            )
        if not transactions:
            raise KeyError(
                f"No transaction records found for capture_group_id={capture_group_id}"
            )
        return MultiChanEstimationResultResponse(
            mac_address=MacAddress.null(),
            status=ServiceStatusCode.SUCCESS,
            message=None,
            operation=status,
            capture_group_id=capture_group_id,
            transactions=transactions,
            artifact_paths=status.artifact_paths,
        )


__all__ = ["MultiChanEstimationWorkflowService"]

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

**Request** `POST /advance/operation/status`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Request** `POST /advance/operation/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

**Request** `POST /advance/operation/cancel`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
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
  },
  "measure": {
    "channel_estimation": {
      "cm_interface": {
        "docs_if3_interface_idx": 1
      },
      "ds_ofdm": {
        "ofdm_downstream_channel_id": 0,
        "timeout": 90,
        "modem_time_out": 100
      }
    }
  }
}
```

**Request** `POST /advance/multiChannelEstimation/result`

```json
{
  "operation_id": "f6afb2d7df2c4a5c"
}
```

Result behavior:
- Missing transaction records are skipped with warnings.
- If no transaction records resolve, the endpoint returns HTTP 404.

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and appends a JSON entry.
4. **Database Updates**: Timestamps and transaction lists are updated in both `operation_capture.json` and `capture_group.json`.
5. **Completion**: After the capture ends, the three JSON tables fully describe what was captured, when, and for which operation/group.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.

# FILE: tests/test_multi_channel_estimation_result.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.multi_ds_chan_est.router import router
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import OperationId


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _configure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Path]:
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

    return {
        "capture_group_db": capture_group_db,
        "operation_db": operation_db,
        "transaction_db": transaction_db,
    }


def _seed_operation(
    operation_id: OperationId, capture_group_id: str, paths: dict[str, Path]
) -> None:
    paths["operation_db"].write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group_id": capture_group_id,
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )


def _seed_transaction_db(transaction_id: str, paths: dict[str, Path]) -> None:
    paths["transaction_db"].write_text(
        json.dumps(
            {
                transaction_id: {
                    "timestamp": 1,
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                    "pnm_test_type": "DS_OFDM_CHAN_EST_COEF",
                    "filename": "chan_est.bin",
                    "device_details": {
                        "system_description": {
                            "HW_REV": "1.0",
                            "VENDOR": "LANCity",
                            "BOOTR": "NONE",
                            "SW_REV": "1.0.0",
                            "MODEL": "LCPET-3",
                        }
                    },
                }
            }
        ),
        encoding="utf-8",
    )


def _seed_capture_group(
    capture_group_id: str, transaction_ids: list[str], paths: dict[str, Path]
) -> None:
    paths["capture_group_db"].write_text(
        json.dumps(
            {
                capture_group_id: {
                    "created": 1,
                    "transactions": transaction_ids,
                }
            }
        ),
        encoding="utf-8",
    )


def _complete_operation(operation_id: OperationId) -> None:
    store = OperationStore()
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )


def test_multi_channel_estimation_result_skips_missing_records_and_returns_200(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())
    caplog.set_level("WARNING")

    operation_id = OperationId("op-300")
    capture_group_id = "group-300"
    txn_ok = "txn-ok"
    txn_missing = "txn-missing"

    _seed_operation(operation_id, capture_group_id, paths)
    _seed_capture_group(capture_group_id, [txn_ok, txn_missing], paths)
    _seed_transaction_db(txn_ok, paths)
    _complete_operation(operation_id)

    response = client.post(
        "/advance/multiChannelEstimation/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert len(payload["transactions"]) == 1
    assert payload["transactions"][0]["transaction_id"] == txn_ok
    assert "Missing transaction record for transaction_id" in caplog.text


def test_multi_channel_estimation_result_returns_404_when_none_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-301")
    capture_group_id = "group-301"
    txn_missing = "txn-missing"

    _seed_operation(operation_id, capture_group_id, paths)
    _seed_capture_group(capture_group_id, [txn_missing], paths)
    paths["transaction_db"].write_text(json.dumps({}), encoding="utf-8")
    _complete_operation(operation_id)

    response = client.post(
        "/advance/multiChannelEstimation/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 404
    assert "No transaction records found" in response.json()["detail"]


def test_multi_channel_estimation_result_accepts_legacy_capture_group_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-302")
    capture_group_id = "group-302"
    txn_ok = "txn-ok-302"

    paths["operation_db"].write_text(
        json.dumps(
            {
                str(operation_id): {
                    "capture_group": capture_group_id,
                    "created": 1,
                }
            }
        ),
        encoding="utf-8",
    )
    _seed_capture_group(capture_group_id, [txn_ok], paths)
    _seed_transaction_db(txn_ok, paths)
    _complete_operation(operation_id)

    response = client.post(
        "/advance/multiChannelEstimation/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert payload["transactions"][0]["transaction_id"] == txn_ok
