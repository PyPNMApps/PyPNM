## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:

### Summary
Added a generic operation workflow router with start/status/result/cancel endpoints, an in-memory operation registry for cancellation hooks, and updated capture-service registration/unregistration. Extended workflow service start/result logic, added router tests, and documented the new POST endpoints.

### Modified Files
- src/pypnm/api/routes/advance/common/capture_service.py
- src/pypnm/api/routes/advance/common/operation_registry.py
- src/pypnm/api/routes/advance/common/operation_workflow_service.py
- src/pypnm/api/routes/advance/common/operation_workflow_schemas.py
- src/pypnm/api/routes/advance/common/operation_workflow_router.py
- docs/api/fast-api/multi/capture-operation.md
- tests/test_operation_workflow_router.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass (360 files already formatted)
- `pytest -q` → pass (552 passed, 4 skipped)

### Tests
- `pytest -q` → pass (552 passed, 4 skipped)
- `ruff check .` → pass
- `ruff format --check .` → pass
- `python3 -m compileall src` → pass

### Notes / Warnings
- pytest emitted expected warning logs from existing tests and integrations.

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
from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
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
        OperationRegistry.register(operation_id, self)

        self.logger.info(
            f"CaptureGroup={group_id} / Operation={operation_id} started "
            f"({self.duration}s @ {self.interval}s interval)"
        )

        async def _runner() -> None:
            try:
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
                            self._link_capture_group_transaction(
                                operation_id, sample.transaction_id
                            )
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
                            f"[{operation_id}] Capture error: {error_msg}",
                            exc_info=True,
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
                    iteration_ts = Generate.time_stamp()

                    try:
                        self.logger.info(
                            f"Runner ended, Final Invocation , One Last Cycle before ending"
                            f"state={self._ops[operation_id]['state']}"
                            f"time-remaining={self._ops[operation_id]['time_remaining']}"
                        )

                        self.setOperationFinalInvocation(operation_id, True)
                        msg_rsp: MessageResponse = (
                            await self._capture_message_response()
                        )

                        # This is here to before any last operation at the time of the completion of the task
                        if msg_rsp.status == ServiceStatusCode.SKIP_MESSAGE_RESPONSE:
                            self.logger.info(
                                "Skipping last _capture_message_response()"
                            )
                        else:
                            samples = self._process_captures(msg_rsp)
                            for sample in samples:
                                self._ops[operation_id]["samples"].append(sample)
                                self._link_capture_group_transaction(
                                    operation_id, sample.transaction_id
                                )
                                self.logger.info(
                                    f"[{operation_id}] Captured sample txn={sample.transaction_id}"
                                )
                            progress_current += 1

                    except Exception as exc:
                        error_msg = str(exc)
                        self.logger.error(
                            f"[{operation_id}] Capture error: {error_msg}",
                            exc_info=True,
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
            finally:
                OperationRegistry.unregister(operation_id)

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

    def _link_capture_group_transaction(
        self, operation_id: OperationId, transaction_id: str
    ) -> None:
        tx_id = str(transaction_id).strip()
        if not tx_id:
            self.logger.warning(
                "[%s] Skipping capture_group link for empty transaction_id",
                operation_id,
            )
            return
        self._cap_group.add_transaction(tx_id)

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

# FILE: src/pypnm/api/routes/advance/common/operation_registry.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

from pypnm.lib.types import OperationId

if TYPE_CHECKING:
    from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService


class OperationRegistry:
    """
    In-memory registry mapping operation IDs to running capture services.
    """

    _lock = threading.Lock()
    _services: dict[OperationId, AbstractCaptureService] = {}

    @classmethod
    def register(
        cls, operation_id: OperationId, service: AbstractCaptureService
    ) -> None:
        logger = logging.getLogger(cls.__name__)
        with cls._lock:
            cls._services[operation_id] = service
        logger.debug("Registered operation service for operation_id=%s", operation_id)

    @classmethod
    def get(cls, operation_id: OperationId) -> AbstractCaptureService | None:
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


__all__ = ["OperationRegistry"]

# FILE: src/pypnm/api/routes/advance/common/operation_workflow_service.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
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
        operation_id: OperationId, service: AbstractCaptureService | None = None
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

# FILE: src/pypnm/api/routes/advance/common/operation_workflow_schemas.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonResponse,
)
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

    operation: OperationStatusModel = Field(
        ..., description="Filesystem-backed operation status."
    )


class OperationResultResponse(CommonResponse):
    """
    Response returned for result requests.
    """

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

## Workflow Summary

1. **Start Multi‑Capture**: System generates a new `operation_id` linked to a new `capture_group_id`.
2. **Periodic Triggers**: SNMP instructs the modem to TFTP-upload the PNM blob.
3. **File Staging**: PyPNM copies each `.bin` into `.data/pnm/` and appends a JSON entry.
4. **Database Updates**: Timestamps and transaction lists are updated in both `operation_capture.json` and `capture_group.json`.
5. **Completion**: After the capture ends, the three JSON tables fully describe what was captured, when, and for which operation/group.

> Downstream tools can monitor `transactions.json` as a manifest to automatically discover and process new PNM files—no manual polling required.

# FILE: tests/test_operation_workflow_router.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.common.operation_workflow_router import router
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import OperationId


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def _configure_operation_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pnm_dir = tmp_path / ".data" / "pnm"
    pnm_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        SystemConfigSettings,
        "pnm_dir",
        classmethod(lambda cls: str(pnm_dir)),
    )


def test_operation_status_and_result_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    start_resp = client.post("/advance/operation/start", json={"progress_total": 1})
    assert start_resp.status_code == 200
    operation_id = start_resp.json()["operation"]["operation_id"]
    assert start_resp.json()["operation"]["state"] == OperationExecutionState.RUNNING

    status_resp = client.post(
        "/advance/operation/status", json={"operation_id": operation_id}
    )
    assert status_resp.status_code == 200
    assert status_resp.json()["operation"]["operation_id"] == operation_id

    result_resp = client.post(
        "/advance/operation/result", json={"operation_id": operation_id}
    )
    assert result_resp.status_code == 400

    store = OperationStore()
    store.update_operation(
        operation_id=OperationId(operation_id),
        state=OperationExecutionState.COMPLETED,
        progress_current=1,
        progress_total=1,
        message="Operation completed",
        error=None,
        artifact_paths=None,
    )

    result_ok = client.post(
        "/advance/operation/result", json={"operation_id": operation_id}
    )
    assert result_ok.status_code == 200
    assert result_ok.json()["operation"]["state"] == OperationExecutionState.COMPLETED


def test_operation_cancel_invokes_registry_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure_operation_paths(tmp_path, monkeypatch)
    client = TestClient(_build_app())

    start_resp = client.post("/advance/operation/start", json={"progress_total": 1})
    assert start_resp.status_code == 200
    operation_id = start_resp.json()["operation"]["operation_id"]

    class _FakeService:
        def __init__(self) -> None:
            self.stopped = False

        def stop(self, _operation_id: OperationId) -> None:
            self.stopped = True

    service = _FakeService()
    OperationRegistry.register(OperationId(operation_id), service)

    cancel_resp = client.post(
        "/advance/operation/cancel", json={"operation_id": operation_id}
    )
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["operation"]["state"] == OperationExecutionState.CANCELED
    assert service.stopped is True
    OperationRegistry.unregister(OperationId(operation_id))
