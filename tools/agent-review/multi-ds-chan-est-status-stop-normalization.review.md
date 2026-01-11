### Summary
Normalized multi-ChannelEstimation status/stop responses to use ServiceStatusCode at the top level and removed exception-based capture-group resolution in /analysis, then added tests to lock the status semantics and stop state behavior. Updated docs to clarify top-level status vs operation.state.

### Modified Files
- src/pypnm/api/routes/advance/multi_ds_chan_est/router.py
- docs/api/fast-api/multi/capture-operation.md
- tests/test_multi_channel_estimation_start_and_analysis.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass
- `pytest -q` → pass (567 passed, 4 skipped)

### Tests
- `pytest` → pass (567 passed, 4 skipped)
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
from pypnm.lib.types import MacAddressStr, OperationId


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

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and appends a JSON entry.
4. **Database Updates**: Timestamps and transaction lists are updated in both `operation_capture.json` and `capture_group.json`.
5. **Completion**: After the capture ends, the three JSON tables fully describe what was captured, when, and for which operation/group.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.

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
