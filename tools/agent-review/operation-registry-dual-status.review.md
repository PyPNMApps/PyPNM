## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

### Summary
Added service_status to generic operation registry responses (status/cancel/result) while preserving legacy status strings, updated the generic operation workflow router to emit both fields, and documented the dual-status behavior. Added tests covering the three generic operation registry endpoints.

### Modified Files
- src/pypnm/api/routes/advance/common/operation_workflow_schemas.py
- src/pypnm/api/routes/advance/common/operation_workflow_router.py
- docs/api/fast-api/multi/capture-operation.md
- tests/test_operation_registry_dual_status.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass
- `pytest -q` → pass (572 passed, 4 skipped)

### Tests
- `pytest` → pass (572 passed, 4 skipped)
- `ruff` → pass
- `python3 -m compileall src` → pass

### Notes / Warnings
- Pytest logs include expected warnings from existing tests; no deprecation warnings observed.

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

**Response** (registry status includes legacy + canonical status)

```json
{
  "status": "success",
  "service_status": 0,
  "message": null
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
  "message": null
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
  "message": null
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
