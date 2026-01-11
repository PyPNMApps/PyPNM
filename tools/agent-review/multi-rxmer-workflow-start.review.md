### Summary
Added a multi-RxMER workflow start/result API under the DS/OFDM path, introduced protocol-typed operation registry entries, and wired result resolution through capture-group records. Added tests for start and result endpoints and documented the new routes and registry behavior.

### Modified Files
- src/pypnm/api/routes/advance/common/operation_registry.py
- src/pypnm/api/routes/advance/common/operation_workflow_service.py
- src/pypnm/api/routes/advance/ds/ofdm/rxmer/multi/router.py
- src/pypnm/api/routes/advance/ds/ofdm/rxmer/multi/service.py
- src/pypnm/api/routes/advance/ds/ofdm/rxmer/multi/schemas.py
- docs/api/fast-api/multi/capture-operation.md
- tests/test_multi_rxmer_start_returns_operation_and_group.py
- tests/test_multi_rxmer_result_resolves_transactions.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass (365 files already formatted)
- `pytest -q` → pass (554 passed, 4 skipped)

### Tests
- `pytest -q` → pass (554 passed, 4 skipped)
- `ruff check .` → pass
- `ruff format --check .` → pass
- `python3 -m compileall src` → pass

### Notes / Warnings
- pytest emitted expected warning logs from existing tests and integrations.

### Remaining TODOs / Follow-Ups
- None

# FILE: src/pypnm/api/routes/advance/common/operation_registry.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import threading
from typing import Protocol

from pypnm.lib.types import OperationId


class OperationServiceProtocol(Protocol):
    def stop(self, operation_id: OperationId) -> None: ...

    def status(self, operation_id: OperationId) -> dict[str, object]: ...


class OperationRegistry:
    """
    In-memory registry mapping operation IDs to running capture services.
    """

    _lock = threading.Lock()
    _services: dict[OperationId, OperationServiceProtocol] = {}

    @classmethod
    def register(
        cls, operation_id: OperationId, service: OperationServiceProtocol
    ) -> None:
        logger = logging.getLogger(cls.__name__)
        with cls._lock:
            cls._services[operation_id] = service
        logger.debug("Registered operation service for operation_id=%s", operation_id)

    @classmethod
    def get(cls, operation_id: OperationId) -> OperationServiceProtocol | None:
        with cls._lock:
            return cls._services.get(operation_id)

    @classmethod
    def unregister(cls, operation_id: OperationId) -> None:
        logger = logging.getLogger(cls.__name__)
        with cls._lock:
            removed = cls._services.pop(operation_id, None)
        if removed is not None:
            logger.debug(
                "Unregistered operation service for operation_id=%s", operation_id
            )


__all__ = ["OperationRegistry", "OperationServiceProtocol"]

# FILE: src/pypnm/api/routes/advance/common/operation_workflow_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.common.operation_registry import OperationServiceProtocol
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_models import OperationStatusModel
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import OperationId
from pypnm.lib.utils import Generate


class OperationWorkflowService:
    """
    Shared workflow helpers for status, cancel, and result endpoints.
    """

    _DEFAULT_PROGRESS_TOTAL: int = 1
    _DEFAULT_START_MESSAGE: str = "Operation created"
    _RUNNING_MESSAGE: str = "Operation running"
    _DEFAULT_OPERATION_ID_LENGTH: int = 16

    @staticmethod
    def start(progress_total: int, message: str | None = None) -> OperationStatusModel:
        store = OperationStore()
        operation_id = OperationId(
            str(
                Generate.operation_id(
                    length=OperationWorkflowService._DEFAULT_OPERATION_ID_LENGTH
                )
            )
        )
        total = max(OperationWorkflowService._DEFAULT_PROGRESS_TOTAL, progress_total)
        created = store.create_operation(
            operation_id=operation_id,
            progress_total=total,
            message=message or OperationWorkflowService._DEFAULT_START_MESSAGE,
        )
        return store.update_operation(
            operation_id=operation_id,
            state=OperationExecutionState.RUNNING,
            progress_current=0,
            progress_total=total,
            message=OperationWorkflowService._RUNNING_MESSAGE,
            error=created.error,
            artifact_paths=created.artifact_paths,
        )

    @staticmethod
    def get_status(operation_id: OperationId) -> OperationStatusModel:
        store = OperationStore()
        status = store.get_operation(operation_id)
        if status is None:
            raise KeyError(f"Operation not found: {operation_id}")
        return status

    @staticmethod
    def cancel(
        operation_id: OperationId, service: OperationServiceProtocol | None = None
    ) -> OperationStatusModel:
        store = OperationStore()
        status = store.mark_canceled(operation_id, "Operation canceled")
        if status is None:
            raise KeyError(f"Operation not found: {operation_id}")
        if service is not None:
            service.stop(operation_id)
        return status

    @staticmethod
    def get_result(operation_id: OperationId) -> OperationStatusModel:
        store = OperationStore()
        status = store.get_operation(operation_id)
        if status is None:
            raise KeyError(f"Operation not found: {operation_id}")
        if status.state not in {
            OperationExecutionState.COMPLETED,
            OperationExecutionState.CANCELED,
        }:
            raise ValueError("Operation not completed")
        return status


__all__ = ["OperationWorkflowService"]

# FILE: src/pypnm/api/routes/advance/ds/ofdm/rxmer/multi/router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.schemas import (
    MultiRxMerResultRequest,
    MultiRxMerResultResponse,
    MultiRxMerStartRequest,
    MultiRxMerStartResponse,
)
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.service import (
    MultiRxMerWorkflowService,
)
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE


class MultiRxMerWorkflowRouter(AbstractService):
    """
    Router for multi-RxMER workflow start/result endpoints.
    """

    def __init__(self) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/advance/ds/ofdm/rxmer/multi",
            tags=["PNM Operations - Multi-RxMER"],
        )
        self._service = MultiRxMerWorkflowService()
        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post(
            "/start",
            response_model=MultiRxMerStartResponse,
            summary="Start a Multi-RxMER capture workflow",
            responses=FAST_API_RESPONSE,
        )
        async def start_capture(
            request: MultiRxMerStartRequest,
        ) -> MultiRxMerStartResponse:
            return await self._service.start(request)

        @self.router.post(
            "/result",
            response_model=MultiRxMerResultResponse,
            summary="Get Multi-RxMER capture results by operation ID",
            responses=FAST_API_RESPONSE,
        )
        def get_result(
            request: MultiRxMerResultRequest,
        ) -> MultiRxMerResultResponse:
            try:
                return self._service.result(request)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            except ValueError as err:
                raise HTTPException(status_code=400, detail=str(err)) from err


router = MultiRxMerWorkflowRouter().router


__all__ = ["MultiRxMerWorkflowRouter", "router"]

# FILE: src/pypnm/api/routes/advance/ds/ofdm/rxmer/multi/service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.schemas import (
    MultiRxMerResultRequest,
    MultiRxMerResultResponse,
    MultiRxMerStartRequest,
    MultiRxMerStartResponse,
)
from pypnm.api.routes.advance.multi_rxmer.service import MultiRxMerService
from pypnm.api.routes.common.classes.file_capture.pnm_file_opearation import (
    OperationCaptureGroupResolver,
)
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress


class MultiRxMerWorkflowService:
    """
    Start and result helpers for multi-RxMER capture workflows.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

    async def start(self, request: MultiRxMerStartRequest) -> MultiRxMerStartResponse:
        cm = CableModem(
            mac_address=MacAddress(request.mac_address),
            inet=Inet(request.ip_address),
        )
        service = MultiRxMerService(
            cm=cm,
            duration=request.duration,
            interval=request.interval,
        )
        group_id, operation_id = await service.start()
        return MultiRxMerStartResponse(
            mac_address=request.mac_address,
            status=ServiceStatusCode.SUCCESS,
            message="Operation started",
            operation_id=operation_id,
            capture_group_id=group_id,
        )

    def result(self, request: MultiRxMerResultRequest) -> MultiRxMerResultResponse:
        status = OperationWorkflowService.get_result(request.operation_id)
        resolver = OperationCaptureGroupResolver()
        capture_group_id = resolver.get_capture_group_id(request.operation_id)
        if not capture_group_id:
            raise KeyError(
                f"Capture group not found for operation: {request.operation_id}"
            )
        txn_ids = resolver.get_transaction_ids_for_capture_group(capture_group_id)
        txn_store = PnmFileTransaction()
        transactions: list[TransactionRecordModel] = [
            txn_store.getRecordModel(txn_id) for txn_id in txn_ids
        ]
        return MultiRxMerResultResponse(
            mac_address=MacAddress.null(),
            status=ServiceStatusCode.SUCCESS,
            message=None,
            operation=status,
            capture_group_id=capture_group_id,
            transactions=transactions,
            artifact_paths=status.artifact_paths,
        )


__all__ = ["MultiRxMerWorkflowService"]

# FILE: src/pypnm/api/routes/advance/ds/ofdm/rxmer/multi/schemas.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonResponse,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.lib.operations.operation_models import OperationStatusModel
from pypnm.lib.types import (
    GroupId,
    InetAddressStr,
    MacAddressStr,
    OperationId,
    PathArray,
)


class MultiRxMerStartRequest(BaseModel):
    mac_address: MacAddressStr = Field(..., description="Cable modem MAC address")
    ip_address: InetAddressStr = Field(..., description="Cable modem IP address")
    duration: float = Field(..., ge=0, description="Capture duration in seconds")
    interval: float = Field(..., ge=0, description="Capture interval in seconds")


class MultiRxMerStartResponse(CommonResponse):
    operation_id: OperationId = Field(
        ..., description="Operation ID for status/result/cancel calls"
    )
    capture_group_id: GroupId = Field(..., description="Capture group identifier")


class MultiRxMerResultRequest(BaseModel):
    operation_id: OperationId = Field(..., description="Operation ID for result lookup")


class MultiRxMerResultResponse(CommonResponse):
    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )
    capture_group_id: GroupId = Field(..., description="Capture group identifier")
    transactions: list[TransactionRecordModel] = Field(
        ..., description="Resolved transaction record models."
    )
    artifact_paths: PathArray | None = Field(
        None, description="Resolved artifact paths from the operation."
    )


__all__ = [
    "MultiRxMerStartRequest",
    "MultiRxMerStartResponse",
    "MultiRxMerResultRequest",
    "MultiRxMerResultResponse",
]

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
    "capture_group": "10b6ea239641487c",
    "created": 1748280293
  }
}
```

* **Key**: `operation_id` (e.g., `f6afb2d7df2c4a5c`).
* **capture\_group**: Associated `capture_group_id`.
* **created**: Unix timestamp when the operation started.

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
          "sys_descr": {
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
* **device\_details.sys\_descr**: Snapshot of modem metadata at capture time.

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

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and appends a JSON entry.
4. **Database Updates**: Timestamps and transaction lists are updated in both `operation_capture.json` and `capture_group.json`.
5. **Completion**: After the capture ends, the three JSON tables fully describe what was captured, when, and for which operation/group.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.

# FILE: tests/test_multi_rxmer_start_returns_operation_and_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.router import router
from pypnm.api.routes.advance.multi_rxmer.service import MultiRxMerService
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


@pytest.mark.asyncio
async def test_start_returns_operation_and_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_paths(tmp_path, monkeypatch)

    async def _fake_capture(self: MultiRxMerService) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])

    monkeypatch.setattr(MultiRxMerService, "_capture_message_response", _fake_capture)

    client = TestClient(_build_app())
    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/start",
        json={
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "192.168.0.100",
            "duration": 0,
            "interval": 0,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["operation_id"]
    assert payload["capture_group_id"]
    OperationRegistry.unregister(OperationId(payload["operation_id"]))

# FILE: tests/test_multi_rxmer_result_resolves_transactions.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.router import router
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


def test_result_resolves_transactions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-123")
    capture_group_id = "group-123"
    transaction_id = "txn123"

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
    paths["capture_group_db"].write_text(
        json.dumps(
            {
                capture_group_id: {
                    "created": 1,
                    "transactions": [transaction_id],
                }
            }
        ),
        encoding="utf-8",
    )
    paths["transaction_db"].write_text(
        json.dumps(
            {
                transaction_id: {
                    "timestamp": 1,
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                    "pnm_test_type": "DS_OFDM_RXMER_PER_SUBCAR",
                    "filename": "rxmer.bin",
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

    response = client.post(
        "/advance/ds/ofdm/rxmer/multi/result",
        json={"operation_id": str(operation_id)},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_group_id"] == capture_group_id
    assert payload["transactions"]
    assert payload["transactions"][0]["transaction_id"] == transaction_id
    OperationRegistry.unregister(operation_id)
