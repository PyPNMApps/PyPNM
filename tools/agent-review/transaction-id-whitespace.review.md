### Summary
Normalized whitespace-only transaction_id and filename handling in capture parsing, tightened resolver filtering for empty IDs, and added tests to cover whitespace variants in capture linking, collection adds, and file-generator mapping.

### Modified Files
- src/pypnm/api/routes/advance/common/capture_service.py
- src/pypnm/api/routes/common/classes/file_capture/pnm_file_opearation.py
- tests/test_operation_workflow.py
- tests/test_common_measure_service_empty_transaction_id.py
- tests/test_transaction_collection_empty_transaction_id.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass (355 files already formatted)
- `pytest -q` → pass (548 passed, 4 skipped)
- `pytest --collect-only -q` → pass
- `pytest -q -ra` → pass (548 passed, 4 skipped)
- `pytest --markers` → pass

### Tests
- `pytest -q` → pass (548 passed, 4 skipped)
- `pytest --collect-only -q` → pass
- `pytest -q -ra` → pass (548 passed, 4 skipped)
- `pytest --markers` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass
- `python3 -m compileall src` → pass

### Notes / Warnings
- pytest emitted expected warning logs for empty/whitespace transaction_id handling and other existing warnings.

### Remaining TODOs / Follow-Ups
- None

# FILE: src/pypnm/api/routes/advance/common/capture_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, cast

from pypnm.api.routes.advance.common.operation_manager import OperationManager
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.api.routes.common.classes.file_capture.capture_sample import CaptureSample
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    MessageResponse,
    MessageResponseType,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import GroupId, OperationId, TimeStamp
from pypnm.lib.utils import Generate


class AbstractCaptureService(ABC):
    """
    Abstract base for periodic background capture services with capture-group support.

    Responsibilities:
        - Create a new capture session (group + operation ID)
        - Periodically fetch raw MessageResponse objects (_capture_message_response)
        - Parse responses into CaptureSample objects (_process_captures)
        - Store samples in memory and persist transaction IDs via CaptureGroup
        - Provide status, results, and stop functionality

    Attributes:
        duration (float): Total runtime for captures, in seconds.
        interval (float): Delay between successive capture iterations, in seconds.
        _ops (Dict[str, Dict[str, Any]]): In-memory state for active operations.
        _cap_group (CaptureGroup): Persistence for transaction IDs across restarts.
        logger (logging.Logger): Logger for operational messages.
    """

    def __init__(self, duration: float, interval: float) -> None:
        """
        Initialize the capture service framework.

        Args:
            duration: Total duration (seconds) for which to run captures.
            interval: Interval (seconds) between capture iterations.

        Raises:
            OSError: If the capture-group database cannot be initialized.
        """
        self.duration = duration
        self.interval = interval
        self.time_remaining: int = 0
        self._ops: dict[str, dict[str, Any]] = {}
        self.logger = logging.getLogger(self.__class__.__name__)
        try:
            self._cap_group = CaptureGroup()
        except Exception as exc:
            self.logger.error(
                f"Failed to initialize CaptureGroup, reason={exc}", exc_info=True
            )
            raise

        self._capture_group_id: GroupId = GroupId("")
        self._operation_id: OperationId = OperationId("")
        self._operation_store = OperationStore()

    async def start(self) -> tuple[GroupId, OperationId]:
        """
        Create a new capture group and operation, then schedule the background runner.

        Returns:
            A tuple of (group_id, operation_id):
            - group_id: 16-character ID for grouping transactions.
            - operation_id: 16-character unique ID for this capture run.

        Side Effects:
            - Registers a new entry in the CaptureGroup database.
            - Launches an asyncio background task that performs captures.

        Raises:
            Exception: Propagates errors from CaptureGroup creation or task scheduling.
        """
        try:
            group_id = self._cap_group.create_group()
        except Exception as exc:
            self.logger.error(
                f"Failed to create capture group, reason={exc}", exc_info=True
            )
            raise

        try:
            om = OperationManager(capture_group_id=group_id)
            operation_id: OperationId = om.register()
        except Exception as exc:
            self.logger.error(
                f"Failed to create operation manager, reason={exc}", exc_info=True
            )
            raise

        start_time = time.time()
        progress_total = OperationStore.estimate_progress_total(
            self.duration, self.interval
        )
        self._ops[operation_id] = {
            "group_id": group_id,
            "state": OperationState.RUNNING,
            "start_time": start_time,
            "duration": self.duration,
            "interval": self.interval,
            "time_remaining": self.time_remaining,
            "samples": [],
            "progress_total": progress_total,
        }

        self.setOperationFinalInvocation(operation_id, False)
        self._operation_store.create_operation(
            operation_id=operation_id,
            progress_total=progress_total,
            message="Operation created",
        )
        self._operation_store.update_operation(
            operation_id=operation_id,
            state=OperationExecutionState.RUNNING,
            progress_current=0,
            progress_total=progress_total,
            message="Operation running",
            error=None,
            artifact_paths=None,
        )

        self.logger.info(
            f"CaptureGroup={group_id} / Operation={operation_id} started "
            f"({self.duration}s @ {self.interval}s interval)"
        )

        async def _runner() -> None:
            end_time = start_time + self.duration
            progress_current = 0

            while (time.time() < end_time) and self._ops[operation_id][
                "state"
            ] == OperationState.RUNNING:
                if self._operation_store.is_canceled(operation_id):
                    self._ops[operation_id]["state"] = OperationState.STOPPED
                    self._operation_store.update_operation(
                        operation_id=operation_id,
                        state=OperationExecutionState.CANCELED,
                        progress_current=progress_current,
                        progress_total=progress_total,
                        message="Operation canceled",
                        error=None,
                        artifact_paths=self._artifact_paths(operation_id),
                    )
                    return
                now = time.time()
                remaining = max(0, int(end_time - now))
                self._ops[operation_id]["time_remaining"] = remaining
                iteration_ts = Generate.time_stamp()

                # Add a waitup front so that it can goto the next function
                await asyncio.sleep(self.interval)

                try:
                    msg_rsp = await self._capture_message_response()
                    samples = self._process_captures(msg_rsp)
                    for sample in samples:
                        self._ops[operation_id]["samples"].append(sample)
                        tx_id = str(sample.transaction_id)
                        if not tx_id.strip():
                            self.logger.warning(
                                "[%s] Skipping capture_group link for empty transaction_id",
                                operation_id,
                            )
                            continue
                        self._cap_group.add_transaction(sample.transaction_id)
                        self.logger.debug(
                            f"[{operation_id}] Captured sample txn={sample.transaction_id}"
                        )
                    progress_current += 1
                    self._operation_store.update_operation(
                        operation_id=operation_id,
                        state=OperationExecutionState.RUNNING,
                        progress_current=progress_current,
                        progress_total=progress_total,
                        message="Operation running",
                        error=None,
                        artifact_paths=self._artifact_paths(operation_id),
                    )

                except Exception as exc:
                    error_msg = str(exc)
                    self.logger.error(
                        f"[{operation_id}] Capture error: {error_msg}", exc_info=True
                    )
                    self._ops[operation_id]["samples"].append(
                        CaptureSample(
                            timestamp=cast(TimeStamp, iteration_ts),
                            transaction_id="",
                            filename="",
                            error=error_msg,
                        )
                    )
                    progress_current += 1
                    self._operation_store.update_operation(
                        operation_id=operation_id,
                        state=OperationExecutionState.RUNNING,
                        progress_current=progress_current,
                        progress_total=progress_total,
                        message="Operation running with errors",
                        error=error_msg,
                        artifact_paths=self._artifact_paths(operation_id),
                    )

            # Complete if still running
            if self._ops[operation_id]["state"] == OperationState.RUNNING:
                self._ops[operation_id]["state"] = OperationState.COMPLETED
                iteration_ts = time.time()

                try:
                    self.logger.info(
                        f"Runner ended, Final Invocation , One Last Cycle before ending"
                        f"state={self._ops[operation_id]['state']}"
                        f"time-remaining={self._ops[operation_id]['time_remaining']}"
                    )

                    self.setOperationFinalInvocation(operation_id, True)
                    msg_rsp: MessageResponse = await self._capture_message_response()

                    # This is here to before any last operation at the time of the completion of the task
                    if msg_rsp.status == ServiceStatusCode.SKIP_MESSAGE_RESPONSE:
                        self.logger.info("Skipping last _capture_message_response()")
                    else:
                        samples = self._process_captures(msg_rsp)
                        for sample in samples:
                            self._ops[operation_id]["samples"].append(sample)
                            tx_id = str(sample.transaction_id)
                            if not tx_id.strip():
                                self.logger.warning(
                                    "[%s] Skipping capture_group link for empty transaction_id",
                                    operation_id,
                                )
                                continue
                            self._cap_group.add_transaction(sample.transaction_id)
                            self.logger.info(
                                f"[{operation_id}] Captured sample txn={sample.transaction_id}"
                            )
                        progress_current += 1

                except Exception as exc:
                    error_msg = str(exc)
                    self.logger.error(
                        f"[{operation_id}] Capture error: {error_msg}", exc_info=True
                    )
                    self._ops[operation_id]["samples"].append(
                        CaptureSample(
                            timestamp=cast(TimeStamp, iteration_ts),
                            transaction_id="",
                            filename="",
                            error=error_msg,
                        )
                    )
                    progress_current += 1
                    self._operation_store.update_operation(
                        operation_id=operation_id,
                        state=OperationExecutionState.RUNNING,
                        progress_current=progress_current,
                        progress_total=progress_total,
                        message="Operation running with errors",
                        error=error_msg,
                        artifact_paths=self._artifact_paths(operation_id),
                    )

            self.logger.info(
                f"[{operation_id}] Capture session ended with state={self._ops[operation_id]['state']}"
            )
            final_state = (
                OperationExecutionState.CANCELED
                if self._ops[operation_id]["state"] == OperationState.STOPPED
                else OperationExecutionState.COMPLETED
            )
            self._operation_store.update_operation(
                operation_id=operation_id,
                state=final_state,
                progress_current=max(progress_current, progress_total),
                progress_total=progress_total,
                message=f"Operation {final_state.value}",
                error=None,
                artifact_paths=self._artifact_paths(operation_id),
            )

            ###############
            # Main RUNNER #
            ###############

        try:
            asyncio.create_task(_runner())
        except Exception as exc:
            self.logger.error(
                f"Failed to schedule capture runner task, reason={exc}", exc_info=True
            )
            raise

        self._capture_group_id = group_id
        self._operation_id = operation_id

        return group_id, operation_id

    def getCaptureGroupID(self) -> GroupId:
        return self._capture_group_id

    def getOperationID(self) -> OperationId:
        return self._operation_id

    def getOperation(self, operation_id: OperationId) -> dict[str, dict[str, Any]]:
        return self._ops[operation_id]

    def getOperationState(self, operation_id: OperationId) -> OperationState:
        return self._ops[operation_id]["state"]

    def setOperationFinalInvocation(
        self, operation_id: OperationId, state: bool
    ) -> None:
        "Indicate that Runner is done, and invocate any final operations"
        self._ops[operation_id]["final_invocation"] = state

    def getOperationFinalInvocation(self, operation_id: OperationId) -> bool:
        return self._ops[operation_id]["final_invocation"]

    def status(self, operation_id: OperationId) -> dict[str, Any]:
        """
        Get the current state and sample count for a capture operation.

        Args:
            operation_id: The ID of the capture operation.

        Returns:
            A dict containing:
                - state (OperationState): Current operation state.
                - collected (int): Number of samples collected.
        """
        op = self._ops.get(operation_id)
        if not op:
            return {"state": OperationState.UNKNOWN, "collected": 0}

        return {
            "state": op["state"],
            "collected": len(op["samples"]),
            "time_remaining": op.get("time_remaining", 0),
        }

    def results(self, operation_id: OperationId) -> list[CaptureSample]:
        """
        Retrieve all CaptureSample objects collected for the operation.

        Args:
            operation_id: The ID of the capture operation.

        Returns:
            A list of CaptureSample. Empty if operation not found.
        """
        op = self._ops.get(operation_id)
        return op["samples"] if op else []

    def stop(self, operation_id: OperationId) -> None:
        """
        Signal the background runner to stop after the current iteration.

        Args:
            operation_id: The ID of the capture operation.

        Effects:
            Sets the operation state to STOPPED if it was RUNNING.
            Idempotent if called multiple times.
        """
        op = self._ops.get(operation_id)
        if op and op["state"] == OperationState.RUNNING:
            op["state"] = OperationState.STOPPED
            self._operation_store.mark_canceled(operation_id, "Operation canceled")
            self.logger.info(f"[{operation_id}] Stopped by user")

    def _process_captures(self, msg_rsp: MessageResponse) -> list[CaptureSample]:
        """
        Parse a raw MessageResponse into a list of CaptureSample objects.

        Args:
            msg_rsp: MessageResponse from _capture_message_response.

        Returns:
            A list of CaptureSample. On payload/type/parsing errors, returns
            a list with a single CaptureSample indicating the error.
        """
        ts = cast(TimeStamp, Generate.time_stamp())
        payload = msg_rsp.payload
        if not isinstance(payload, list):
            err = f"Unexpected payload type: {type(payload).__name__}"
            self.logger.error(err)
            return [
                CaptureSample(timestamp=ts, transaction_id="", filename="", error=err)
            ]

        samples: list[CaptureSample] = []
        for idx, entry in enumerate(payload):
            try:
                status_str, msg_type, body = MessageResponse.get_payload_msg(entry)  # type: ignore

            except Exception as exc:
                err = f"Failed to parse payload entry {idx}: {exc}"
                self.logger.error(err, exc_info=True)
                samples.append(
                    CaptureSample(
                        timestamp=ts, transaction_id="", filename="", error=err
                    )
                )
                continue

            if status_str != ServiceStatusCode.SUCCESS.name:
                err = f"Payload entry {idx} returned status {status_str}"
                self.logger.error(err)
                samples.append(
                    CaptureSample(
                        timestamp=ts, transaction_id="", filename="", error=err
                    )
                )
                continue

            if msg_type != MessageResponseType.PNM_FILE_TRANSACTION.name:
                # skip non-transaction messages
                continue

            txn_id_raw = body.get("transaction_id", "")
            filename_raw = body.get("filename", "")
            txn_id = str(txn_id_raw).strip()
            filename = str(filename_raw).strip()
            if not txn_id or not filename:
                err = f"Missing txn_id or filename in entry {idx}"
                self.logger.warning(f"{err}: {body}")
                samples.append(
                    CaptureSample(
                        timestamp=ts,
                        transaction_id=txn_id,
                        filename=filename,
                        error="missing-txn-or-filename",
                    )
                )
                continue

            try:
                rec = PnmFileTransaction().get_record(txn_id)
            except Exception as exc:
                err = f"DB fetch error for txn {txn_id}: {exc}"
                self.logger.error(err, exc_info=True)
                samples.append(
                    CaptureSample(
                        timestamp=ts,
                        transaction_id=txn_id,
                        filename=filename,
                        error="db-fetch-error",
                    )
                )
                continue

            if rec is None:
                err = f"No DB record found for txn {txn_id}"
                self.logger.warning(err)
                samples.append(
                    CaptureSample(
                        timestamp=ts,
                        transaction_id=txn_id,
                        filename=filename,
                        error="no-db-record",
                    )
                )
            else:
                samples.append(
                    CaptureSample(
                        timestamp=ts,
                        transaction_id=txn_id,
                        filename=filename,
                        error=None,
                    )
                )

        if not samples:
            err = "No valid transactions found in payload"
            self.logger.warning(err)
            return [
                CaptureSample(
                    timestamp=ts,
                    transaction_id="",
                    filename="",
                    error="no-transactions",
                )
            ]

        return samples

    def _artifact_paths(self, operation_id: OperationId) -> list[str]:
        samples = self._ops.get(operation_id, {}).get("samples", [])
        return [sample.filename for sample in samples if sample.filename]

    @abstractmethod
    async def _capture_message_response(self) -> MessageResponse:
        """
        Perform one capture iteration and return its raw response.

        This method is called by the runner each cycle. Subclasses must
        implement the actual SNMP/TFTP logic and always return a
        `MessageResponse`, even on errors.

        Returns
        -------
        MessageResponse
            The raw capture response. Its `.status` field indicates success,
            failure, or a special skip code.

        Notes
        -----
        - On internal exception, catch it and return a failure response, e.g.:
          `MessageResponse(ServiceStatusCode.YOUR_ERROR_CODE)`.
        - To indicate “no PNM file needed right now” (e.g. final cleanup),
          return a `MessageResponse` with
          ``status == ServiceStatusCode.SKIP_MESSAGE_RESPONSE``.
        """
        ...

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

# FILE: tests/test_operation_workflow.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    MessageResponse,
    MessageResponseType,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import OperationId


class _FakeCaptureService(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=[])


class _FakeCaptureServiceEmptyTxn(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        payload = [
            {
                "status": ServiceStatusCode.SUCCESS.name,
                "message_type": MessageResponseType.PNM_FILE_TRANSACTION.name,
                "message": {
                    "transaction_id": "",
                    "filename": "rxmer.bin",
                },
            }
        ]
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=payload)


class _FakeCaptureServiceWhitespaceTxn(AbstractCaptureService):
    async def _capture_message_response(self) -> MessageResponse:
        payload = [
            {
                "status": ServiceStatusCode.SUCCESS.name,
                "message_type": MessageResponseType.PNM_FILE_TRANSACTION.name,
                "message": {
                    "transaction_id": "   ",
                    "filename": "rxmer.bin",
                },
            }
        ]
        return MessageResponse(ServiceStatusCode.SUCCESS, payload=payload)


def _configure_operation_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base_dir = tmp_path / ".data"
    pnm_dir = base_dir / "pnm"
    db_dir = base_dir / "db"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)

    capture_group_db = db_dir / "capture_group.json"
    operation_db = db_dir / "operation_capture.json"

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


@pytest.mark.asyncio
async def test_start_creates_running_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    service = _FakeCaptureService(duration=0, interval=1)
    _, operation_id = await service.start()

    store = OperationStore()
    status = store.get_operation(operation_id)
    assert status is not None
    assert status.state == OperationExecutionState.RUNNING

    await asyncio.sleep(0)
    completed = store.get_operation(operation_id)
    assert completed is not None
    assert completed.state == OperationExecutionState.COMPLETED
    assert completed.progress_current >= 1


@pytest.mark.asyncio
async def test_cancel_marks_canceled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    service = _FakeCaptureService(duration=1, interval=0)
    _, operation_id = await service.start()

    canceled = OperationWorkflowService.cancel(operation_id, service)
    assert canceled.state == OperationExecutionState.CANCELED

    await asyncio.sleep(0)
    store = OperationStore()
    status = store.get_operation(operation_id)
    assert status is not None
    assert status.state == OperationExecutionState.CANCELED


def test_result_requires_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    store = OperationStore()
    operation_id = OperationId("op-test-1")
    store.create_operation(operation_id, progress_total=1, message="Operation created")
    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.RUNNING,
        progress_current=0,
        progress_total=1,
        message="Operation running",
        error=None,
        artifact_paths=None,
    )

    with pytest.raises(ValueError):
        OperationWorkflowService.get_result(operation_id)

    store.update_operation(
        operation_id=operation_id,
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )
    status = OperationWorkflowService.get_result(operation_id)
    assert status.state == OperationExecutionState.COMPLETED


@pytest.mark.asyncio
async def test_capture_service_skips_empty_transaction_id_linking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    service = _FakeCaptureServiceEmptyTxn(duration=0, interval=0)
    group_id, _ = await service.start()

    await asyncio.sleep(0)

    db_path = Path(SystemConfigSettings.capture_group_db())
    with db_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    assert data[group_id]["transactions"] == []
    assert "Skipping capture_group link for empty transaction_id" in caplog.text


@pytest.mark.asyncio
async def test_capture_service_skips_whitespace_transaction_id_linking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    service = _FakeCaptureServiceWhitespaceTxn(duration=0, interval=0)
    group_id, _ = await service.start()

    await asyncio.sleep(0)

    db_path = Path(SystemConfigSettings.capture_group_db())
    with db_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    assert data[group_id]["transactions"] == []
    assert "Skipping capture_group link for empty transaction_id" in caplog.text

# FILE: tests/test_common_measure_service_empty_transaction_id.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import TransactionId
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


def _configure_pnm_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pnm_dir = tmp_path / "pnm"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )


@pytest.mark.asyncio
async def test_pnm_file_generator_skips_empty_transaction_id_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_pnm_dir(tmp_path, monkeypatch)
    caplog.set_level("WARNING")

    async def _fake_insert(
        self: PnmFileTransaction,
        cable_modem: CableModem,
        pnm_test_type: DocsPnmCmCtlTest,
        filename: str,
    ) -> TransactionId:
        return TransactionId("")

    monkeypatch.setattr(PnmFileTransaction, "insert", _fake_insert)

    cm = CableModem(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        inet=Inet("192.168.0.100"),
        write_community="public",
    )
    service = CommonMeasureService(
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        cable_modem=cm,
        tftp_servers=(Inet("192.168.0.100"), Inet("::1")),
    )

    filename = await service._pnm_file_generator(
        DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR
    )

    assert filename
    assert service._transactionId_pnmFile == {}
    assert "Skipping transaction mapping for empty transaction_id" in caplog.text


@pytest.mark.asyncio
async def test_pnm_file_generator_skips_whitespace_transaction_id_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure_pnm_dir(tmp_path, monkeypatch)
    caplog.set_level("WARNING")

    async def _fake_insert(
        self: PnmFileTransaction,
        cable_modem: CableModem,
        pnm_test_type: DocsPnmCmCtlTest,
        filename: str,
    ) -> TransactionId:
        return TransactionId("   ")

    monkeypatch.setattr(PnmFileTransaction, "insert", _fake_insert)

    cm = CableModem(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        inet=Inet("192.168.0.100"),
        write_community="public",
    )
    service = CommonMeasureService(
        pnm_test_type=DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        cable_modem=cm,
        tftp_servers=(Inet("192.168.0.100"), Inet("::1")),
    )

    filename = await service._pnm_file_generator(
        DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR
    )

    assert filename
    assert service._transactionId_pnmFile == {}
    assert "Skipping transaction mapping for empty transaction_id" in caplog.text

# FILE: tests/test_transaction_collection_empty_transaction_id.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.api.routes.advance.common.transactionsCollection import TransactionCollection
from pypnm.api.routes.common.classes.file_capture.types import (
    DeviceDetailsModel,
    TransactionRecordModel,
)
from pypnm.docsis.cm_snmp_operation import SystemDescriptor
from pypnm.lib.types import FileName, MacAddressStr, TimestampSec, TransactionId


def test_transaction_collection_skips_empty_transaction_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("WARNING")
    collection = TransactionCollection()
    record = TransactionRecordModel(
        transaction_id=TransactionId(""),
        timestamp=TimestampSec(1),
        mac_address=MacAddressStr("aa:bb:cc:dd:ee:ff"),
        pnm_test_type="DS_OFDM_RXMER_PER_SUBCAR",
        filename=FileName("rxmer.bin"),
        device_details=DeviceDetailsModel(
            system_description=SystemDescriptor.empty().to_model()
        ),
    )

    added = collection.add(record, b"payload")

    assert added is False
    assert collection.length() == 0
    assert "Skipping TransactionCollection add for empty transaction_id" in caplog.text


def test_transaction_collection_skips_whitespace_transaction_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("WARNING")
    collection = TransactionCollection()
    record = TransactionRecordModel(
        transaction_id=TransactionId("   "),
        timestamp=TimestampSec(1),
        mac_address=MacAddressStr("aa:bb:cc:dd:ee:ff"),
        pnm_test_type="DS_OFDM_RXMER_PER_SUBCAR",
        filename=FileName("rxmer.bin"),
        device_details=DeviceDetailsModel(
            system_description=SystemDescriptor.empty().to_model()
        ),
    )

    added = collection.add(record, b"payload")

    assert added is False
    assert collection.length() == 0
    assert "Skipping TransactionCollection add for empty transaction_id" in caplog.text
