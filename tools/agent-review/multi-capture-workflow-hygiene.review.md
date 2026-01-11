### Summary
Normalized operation capture records to use capture_group_id with legacy read support, and hardened multi-RxMER result resolution to skip missing transaction records while returning a clear 404 when none resolve. Updated multi-capture docs to match canonical field names and added tests covering legacy keys, missing records, and operation manager writes.

### Modified Files
- src/pypnm/api/routes/common/classes/file_capture/pnm_file_opearation.py
- src/pypnm/api/routes/advance/common/operation_manager.py
- src/pypnm/api/routes/advance/ds/ofdm/rxmer/multi/service.py
- src/pypnm/api/routes/advance/ds/ofdm/rxmer/multi/router.py
- docs/api/fast-api/multi/capture-operation.md
- tests/test_multi_rxmer_result_resolves_transactions.py
- tests/test_operation_manager_capture_group_id.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass
- `pytest -q` → pass (557 passed, 4 skipped)

### Tests
- `pytest` → pass (557 passed, 4 skipped)
- `ruff` → pass
- `python3 -m compileall src` → pass

### Notes / Warnings
- Pytest logs include expected warnings from existing tests; no deprecation warnings observed.

### Remaining TODOs / Follow-Ups
- None

# FILE: src/pypnm/api/routes/common/classes/file_capture/pnm_file_opearation.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import json
import logging
from pathlib import Path

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import GroupId, OperationId, TransactionId


class OperationCaptureGroupResolver:
    """
    Resolve Operation IDs Into Capture Groups And Transaction Records.

    This helper class ties together three JSON-backed datasets:

    1) Operation Database
       - Path: SystemConfigSettings.operation_db
       - Shape:
         {
           "<operation_id>": {
             "capture_group_id": "<capture_group_id>",
             "created": <epoch>
           },
           ...
         }

    2) Capture Group Database
       - Path: SystemConfigSettings.capture_group_db
       - Shape:
         {
           "<capture_group_id>": {
             "created": <epoch>,
             "transactions": [
               "<txn_id_1>",
               "<txn_id_2>",
               ...
             ]
           },
           ...
         }

    3) Transaction Database (PnmFileTransaction.transaction_db)
       - Already managed by PnmFileTransaction.

    Public APIs:
      - get_capture_group_id(operation_id)
      - get_transaction_ids_for_operation(operation_id)
      - get_transaction_models_for_operation(operation_id)
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.operation_db_path = Path(SystemConfigSettings.operation_db())
        self.capture_group_db_path = Path(SystemConfigSettings.capture_group_db())

        self.operation_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.capture_group_db_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.operation_db_path.exists():
            self.operation_db_path.write_text(json.dumps({}))
        if not self.capture_group_db_path.exists():
            self.capture_group_db_path.write_text(json.dumps({}))

    # ------------------------------------------------------------------ #
    # Internal JSON helpers
    # ------------------------------------------------------------------ #
    def _load_json(self, path: Path) -> dict[str, dict]:
        try:
            with path.open("r") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                self.logger.warning("Expected dict at %s, got %s", path, type(data))
                return {}
            return data
        except json.JSONDecodeError:
            self.logger.error("Failed to parse JSON database at %s", path)
            return {}
        except FileNotFoundError:
            self.logger.warning("JSON database not found at %s", path)
            return {}

    # ------------------------------------------------------------------ #
    # Resolution helpers
    # ------------------------------------------------------------------ #
    def get_capture_group_id(self, operation_id: OperationId) -> GroupId | None:
        """
        Resolve A Capture Group Identifier From An Operation ID.

        Returns the associated capture_group_id string when present in the
        operation database; otherwise returns None.
        """
        op_db = self._load_json(self.operation_db_path)
        rec = op_db.get(operation_id)
        if not rec:
            self.logger.info(
                "No operation record found for operation_id=%s", operation_id
            )
            return None

        capture_group_id = rec.get("capture_group_id")
        if not capture_group_id:
            legacy_capture_group = rec.get("capture_group")
            if legacy_capture_group:
                self.logger.warning(
                    "Operation record for %s uses legacy 'capture_group' field",
                    operation_id,
                )
                return GroupId(str(legacy_capture_group))
            self.logger.warning(
                "Operation record for %s is missing 'capture_group_id' field",
                operation_id,
            )
            return None

        return GroupId(str(capture_group_id))

    def get_transaction_ids_for_capture_group(
        self, capture_group_id: GroupId
    ) -> list[TransactionId]:
        """
        Resolve All Transaction IDs Belonging To A Capture Group.

        Returns an ordered list of TransactionId values, or an empty list if
        the capture group is unknown or has no associated transactions.
        """
        cg_db = self._load_json(self.capture_group_db_path)
        rec = cg_db.get(capture_group_id)
        if not rec:
            self.logger.info(
                "No capture group record found for capture_group_id=%s",
                capture_group_id,
            )
            return []

        txns = rec.get("transactions") or []
        if not isinstance(txns, list):
            self.logger.warning(
                "Capture group %s has non-list 'transactions' field: %r",
                capture_group_id,
                type(txns),
            )
            return []

        transaction_ids: list[TransactionId] = []
        for tid in txns:
            tx_id = str(tid)
            if not tx_id.strip():
                self.logger.warning(
                    "Skipping empty transaction_id in capture_group_db for capture_group_id=%s",
                    capture_group_id,
                )
                continue
            transaction_ids.append(TransactionId(tx_id))
        return transaction_ids

    def get_transaction_ids_for_operation(
        self, operation_id: OperationId
    ) -> list[TransactionId]:
        """
        Resolve All Transaction IDs Associated With An Operation ID.

        This is a convenience wrapper that:
          1) Finds the capture_group_id for the supplied operation_id.
          2) Returns the list of TransactionId values for that capture group.
        """
        capture_group_id = self.get_capture_group_id(operation_id)
        if not capture_group_id:
            return []
        return self.get_transaction_ids_for_capture_group(capture_group_id)

    def get_transaction_models_for_operation(
        self, operation_id: OperationId
    ) -> list[TransactionRecordModel]:
        """
        Resolve TransactionRecordModel Instances For An Operation ID.

        For each transaction id mapped to the given operation, this method
        constructs a canonical TransactionRecordModel via PnmFileTransaction.

        Missing records are skipped; only models with a non-empty transaction_id
        field are returned.
        """
        txn_ids = self.get_transaction_ids_for_operation(operation_id)
        if not txn_ids:
            self.logger.info(
                "No transaction IDs found for operation_id=%s", operation_id
            )
            return []

        txn_store = PnmFileTransaction()
        models: list[TransactionRecordModel] = []

        for tid in txn_ids:
            model = txn_store.getRecordModel(tid)
            # Assuming TransactionRecordModel.null() sets transaction_id to an empty string.
            tx_id = str(getattr(model, "transaction_id", "")).strip()
            if tx_id:
                models.append(model)
            else:
                self.logger.warning(
                    "TransactionRecordModel for tid=%s is null/empty and will be skipped",
                    tid,
                )

        return models

# FILE: src/pypnm/api/routes/advance/common/operation_manager.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import cast
from pypnm.lib.types import GroupId, OperationId


class OperationManager:
    """
    Manager for mapping background capture operations to their capture group IDs.

    Each operation is assigned a unique operation_id and linked to a
    capture_group_id. Mappings are persisted in a JSON file so that
    captures can be looked up later by operation ID.

    JSON schema:
    {
        "<operation_id>": {
            "capture_group_id": "<group_id>",
            "created": <unix_epoch_seconds>
        },
        ...
    }
    """

    def __init__(self, capture_group_id: GroupId, db_path: Path | None = None) -> None:
        """
        Initialize a new operation manager for a given capture group.

        Args:
            capture_group_id: The ID of the capture group to associate.
            db_path: Optional path to the operations DB file; if None,
                     retrieves from ConfigManager under
                     [PnmFileRetrieval].operation_db.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.capture_group_id: GroupId = capture_group_id
        self.operation_id: OperationId = cast(OperationId, uuid.uuid4().hex[:16])

        # Resolve DB file path
        if db_path:
            self.db_path = db_path
        else:
            db_str = SystemConfigSettings.operation_db()
            self.db_path = Path(db_str)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Ensure DB exists
        if not self.db_path.exists():
            self._atomic_write({})

    def _load(self) -> dict[str, Any]:
        """
        Load the operations DB from disk.

        Returns:
            Dict of operation mappings, or empty dict on parse error.
        """
        try:
            with self.db_path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            self.logger.warning(f"Failed to load operation DB, resetting: {e}")
            return {}

    def _atomic_write(self, data: dict[str, Any]) -> None:
        """
        Atomically write the given data to the DB file.
        """
        temp = self.db_path.with_suffix(".tmp")
        with temp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        temp.replace(self.db_path)

    def _save(self, data: dict[str, Any]) -> None:
        """
        Persist the given operations dict to disk with atomic write.
        """
        try:
            self._atomic_write(data)
        except Exception as e:
            self.logger.error(f"Failed to save operation DB: {e}")

    def register(self) -> OperationId:
        """
        Register this operation with its capture group ID in the DB.

        Verifies that the associated capture group exists before registration.

        Returns:
            The operation_id assigned.

        Raises:
            ValueError: If the capture_group_id is not present in the CaptureGroup database.
        """
        # Verify that the capture group exists, or fail hard
        from pypnm.api.routes.common.classes.file_capture.capture_group import (
            CaptureGroup,
        )

        cg = CaptureGroup(group_id=self.capture_group_id)
        if self.capture_group_id not in cg.list_groups():
            raise ValueError(f"CaptureGroup '{self.capture_group_id}' does not exist")

        db = self._load()
        db[self.operation_id] = {
            "capture_group_id": self.capture_group_id,
            "created": int(time.time()),
        }
        self._save(db)
        self.logger.info(
            f"Registered operation {self.operation_id} for group {self.capture_group_id}"
        )
        return self.operation_id

    @classmethod
    def get_capture_group(
        cls, operation_id: OperationId, db_path: Path | None = None
    ) -> GroupId:
        """
        Retrieve the capture_group_id for a given operation_id.

        Args:
            operation_id: The operation ID to look up.
            db_path: Optional override for the operations DB file.

        Returns:
            capture_group_id if found, otherwise None.
            Exception thrown
        """

        if not db_path:
            db_str = SystemConfigSettings.operation_db()
            db_path = Path(db_str)
        try:
            with db_path.open("r", encoding="utf-8") as f:
                db = json.load(f)
            rec = db.get(operation_id)
            if isinstance(rec, dict):
                capture_group_id = rec.get("capture_group_id")
                if capture_group_id:
                    return capture_group_id
                legacy_capture_group = rec.get("capture_group")
                if legacy_capture_group:
                    cls.logger = logging.getLogger(cls.__name__)
                    cls.logger.warning(
                        "Operation record for %s uses legacy 'capture_group' field",
                        operation_id,
                    )
                    return legacy_capture_group
            return None
        except Exception as e:
            cls.logger = logging.getLogger(cls.__name__)
            cls.logger.error(f"Error retrieving capture group for {operation_id}: {e}")
            return ""

    @classmethod
    def list_operations(cls, db_path: Path | None = None) -> list[str]:
        """
        List all registered operation IDs.

        Args:
            db_path: Optional override for the operations DB file.

        Returns:
            List of operation_id strings.
        """
        if not db_path:
            db_str = SystemConfigSettings.operation_db()
            db_path = Path(db_str)
        try:
            with db_path.open("r", encoding="utf-8") as f:
                return list(json.load(f).keys())
        except Exception as e:
            logging.getLogger(cls.__name__).error(f"Error listing operations: {e}")
            return []

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
                detail = err.args[0] if err.args else "Operation not found"
                raise HTTPException(status_code=404, detail=detail) from err
            except ValueError as err:
                raise HTTPException(status_code=400, detail=str(err)) from err


router = MultiRxMerWorkflowRouter().router


__all__ = ["MultiRxMerWorkflowRouter", "router"]

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

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and appends a JSON entry.
4. **Database Updates**: Timestamps and transaction lists are updated in both `operation_capture.json` and `capture_group.json`.
5. **Completion**: After the capture ends, the three JSON tables fully describe what was captured, when, and for which operation/group.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.

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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())
    caplog.set_level("WARNING")

    operation_id = OperationId("op-123")
    capture_group_id = "group-123"
    transaction_id = "txn123"
    missing_transaction_id = "txn-missing"

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
                    "transactions": [transaction_id, missing_transaction_id],
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
    assert "Missing transaction record for transaction_id" in caplog.text
    OperationRegistry.unregister(operation_id)


def test_result_rejects_when_no_transactions_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-124")
    capture_group_id = "group-124"
    transaction_id = "txn-missing"

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
    paths["transaction_db"].write_text(json.dumps({}), encoding="utf-8")

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

    assert response.status_code == 404
    assert "No transaction records found" in response.json()["detail"]


def test_result_resolves_transactions_with_legacy_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _configure_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    operation_id = OperationId("op-125")
    capture_group_id = "group-125"
    transaction_id = "txn125"

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
    assert payload["transactions"][0]["transaction_id"] == transaction_id

# FILE: tests/test_operation_manager_capture_group_id.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.config.system_config_settings import SystemConfigSettings


def _configure_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base_dir = tmp_path / ".data"
    db_dir = base_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"

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

    return operation_db


def test_operation_manager_writes_capture_group_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_db = _configure_paths(tmp_path, monkeypatch)
    group = CaptureGroup()
    group_id = group.create_group()

    manager = OperationManager(capture_group_id=group_id)
    operation_id = manager.register()

    data = json.loads(operation_db.read_text(encoding="utf-8"))
    record = data[str(operation_id)]
    assert "capture_group_id" in record
    assert "capture_group" not in record
