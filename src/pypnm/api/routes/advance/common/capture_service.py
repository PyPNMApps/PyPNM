# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, cast

from pypnm.api.routes.advance.common.operation_kind import (
    MultiCaptureOperation,
    MultiCaptureOperationModel,
)
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
from pypnm.lib.memory import ProcessMemory
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

    OPERATION_NAME: MultiCaptureOperation = MultiCaptureOperation.MULTI_RXMER
    MEASURE_MODE: str = "standard"

    def __init__(
        self,
        duration: float,
        interval: float,
        system_description: dict[str, str] | None = None,
    ) -> None:
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
        self.time_remaining:int = 0
        self._ops: dict[str, dict[str, Any]] = {}
        self.logger = logging.getLogger(self.__class__.__name__)
        try:
            self._cap_group = CaptureGroup()
        except Exception as exc:
            self.logger.error(f"Failed to initialize CaptureGroup, reason={exc}", exc_info=True)
            raise

        self._capture_group_id: GroupId = GroupId("")
        self._operation_id: OperationId = OperationId("")
        self._system_description: dict[str, str] = self._normalize_system_description(system_description)

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
            self.logger.error(f"Failed to create capture group, reason={exc}", exc_info=True)
            raise

        operation_metadata: dict[str, Any] = {}
        cm = getattr(self, "cm", None)
        mac_obj = getattr(cm, "get_mac_address", None)
        mac_str = getattr(mac_obj, "mac_address", None)
        if mac_str:
            operation_metadata["mac_address"] = str(mac_str)
        if self._has_populated_system_description(self._system_description):
            operation_metadata["system_description"] = dict(self._system_description)
        operation = self.get_operation_model()

        try:
            om = OperationManager(capture_group_id=group_id)
            operation_id:OperationId = om.register(operation=operation, metadata=operation_metadata)
        except Exception as exc:
            self.logger.error(f"Failed to create operation manager, reason={exc}", exc_info=True)
            raise

        start_time = time.time()
        self._ops[operation_id] = {
            "group_id":         group_id,
            "state":            OperationState.RUNNING,
            "start_time":       start_time,
            "duration":         self.duration,
            "interval":         self.interval,
            "time_remaining":   self.time_remaining,
            "collected":        0,
            "samples":          [],
            "task":             None,
        }

        self.setOperationFinalInvocation(operation_id, False)

        self.logger.info(
            f"CaptureGroup={group_id} / Operation={operation_id} started "
            f"({self.duration}s @ {self.interval}s interval)")

        async def _runner() -> None:
            try:
                end_time = start_time + self.duration

                while (time.time() < end_time) and self._ops[operation_id]["state"] == OperationState.RUNNING:

                    now = time.time()
                    remaining = max(0, int(end_time - now))
                    self._ops[operation_id]["time_remaining"] = remaining
                    iteration_ts = Generate.time_stamp()

                    # Add a waitup front so that it can goto the next function
                    await asyncio.sleep(self.interval)

                    try:
                        msg_rsp = await self._capture_message_response()
                        if msg_rsp.status == ServiceStatusCode.SKIP_MESSAGE_RESPONSE:
                            self.logger.info(f"[{operation_id}] Capture iteration skipped by service status.")
                            continue

                        if isinstance(msg_rsp.payload, list):
                            samples = self._process_captures(msg_rsp)
                            for sample in samples:
                                self._append_operation_sample(operation_id, sample)
                                self.logger.debug(f"[{operation_id}] Captured sample txn={sample.transaction_id}")
                        else:
                            status_name = msg_rsp.status.name if isinstance(msg_rsp.status, ServiceStatusCode) else str(msg_rsp.status)
                            err = f"Capture response returned no transaction payload (status={status_name})"
                            self.logger.warning(f"[{operation_id}] {err}")
                            self._append_operation_sample(
                                operation_id,
                                CaptureSample(
                                    timestamp=cast(TimeStamp, iteration_ts),
                                    transaction_id="",
                                    filename="",
                                    error=err,
                                ),
                            )

                    except Exception as exc:
                        error_msg = str(exc)
                        self.logger.error(f"[{operation_id}] Capture error: {error_msg}", exc_info=True)
                        self._append_operation_sample(
                            operation_id,
                            CaptureSample(timestamp=cast(TimeStamp, iteration_ts), transaction_id="", filename="", error=error_msg),
                        )

                # Complete if still running
                if self._ops[operation_id]["state"] == OperationState.RUNNING:

                    self._ops[operation_id]["state"] = OperationState.COMPLETED
                    iteration_ts = Generate.time_stamp()

                    try:

                        self.logger.debug(f'Runner ended, Final Invocation , One Last Cycle before ending'
                                        f'state={self._ops[operation_id]["state"]}'
                                        f'time-remaining={self._ops[operation_id]["time_remaining"]}')

                        self.setOperationFinalInvocation(operation_id, True)
                        msg_rsp:MessageResponse = await self._capture_message_response()

                        # This is here to before any last operation at the time of the completion of the task
                        if msg_rsp.status == ServiceStatusCode.SKIP_MESSAGE_RESPONSE:
                            self.logger.info('Skipping last _capture_message_response()')
                        else:
                            if isinstance(msg_rsp.payload, list):
                                samples = self._process_captures(msg_rsp)
                                for sample in samples:
                                    self._append_operation_sample(operation_id, sample)
                                    self.logger.info(f"[{operation_id}] Captured sample txn={sample.transaction_id}")
                            else:
                                status_name = msg_rsp.status.name if isinstance(msg_rsp.status, ServiceStatusCode) else str(msg_rsp.status)
                                err = f"Final capture response returned no transaction payload (status={status_name})"
                                self.logger.warning(f"[{operation_id}] {err}")
                                self._append_operation_sample(
                                    operation_id,
                                    CaptureSample(
                                        timestamp=cast(TimeStamp, iteration_ts),
                                        transaction_id="",
                                        filename="",
                                        error=err,
                                    ),
                                )

                    except Exception as exc:
                        error_msg = str(exc)
                        self.logger.error(f"[{operation_id}] Capture error: {error_msg}", exc_info=True)
                        self._append_operation_sample(
                            operation_id,
                            CaptureSample(timestamp=cast(TimeStamp, iteration_ts), transaction_id="", filename="", error=error_msg),
                        )
            except asyncio.CancelledError:
                if operation_id in self._ops and self._ops[operation_id]["state"] == OperationState.RUNNING:
                    self._ops[operation_id]["state"] = OperationState.CANCELLED
                self.logger.info(f"[{operation_id}] Capture session cancelled")
                raise
            finally:
                if operation_id in self._ops:
                    self.logger.info(
                        f"[{operation_id}] Capture session ended with state={self._ops[operation_id]['state']}",
                    )

                                            ###############
                                            # Main RUNNER #
                                            ###############
        def _on_runner_done(task: asyncio.Task[None]) -> None:
            op = self._ops.get(operation_id)
            if op is None:
                return
            if task.cancelled() and op.get("state") in (OperationState.RUNNING, None):
                op["state"] = OperationState.CANCELLED
                self.logger.info(f"[{operation_id}] Capture session marked cancelled by task callback")

        try:
            task = asyncio.create_task(_runner())
            self._ops[operation_id]["task"] = task
            task.add_done_callback(_on_runner_done)
        except Exception as exc:
            self.logger.error(f"Failed to schedule capture runner task, reason={exc}", exc_info=True)
            raise

        self._capture_group_id = group_id
        self._operation_id = operation_id

        return group_id, operation_id

    def getCaptureGroupID(self) -> GroupId:
        return self._capture_group_id

    def getOperationID(self) -> OperationId:
        return self._operation_id

    def getOperation(self, operation_id:OperationId) -> dict[str, dict[str, Any]]:
        return self._ops[operation_id]

    def _append_operation_sample(self, operation_id: OperationId, sample: CaptureSample) -> None:
        """
        Append a capture sample and update operation-level counters.

        Args:
            operation_id: Operation receiving the sample.
            sample: Parsed capture sample to retain.
        """
        op = self._ops[operation_id]
        op["samples"].append(sample)
        op["collected"] = int(op.get("collected", 0)) + 1
        if sample.transaction_id:
            self._cap_group.add_transaction(sample.transaction_id)

    def getOperationState(self,operation_id:OperationId) -> OperationState:
        return self._ops[operation_id]["state"]

    def setOperationFinalInvocation(self, operation_id:OperationId, state:bool) -> None:
            "Indicate that Runner is done, and invocate any final operations"
            self._ops[operation_id]["final_invocation"] = state

    def getOperationFinalInvocation(self, operation_id:OperationId) -> bool:
            return self._ops[operation_id]["final_invocation"]

    def get_system_description(self) -> dict[str, str]:
        """Return the cached session-level sysDescr payload used for multi-capture metadata."""
        return dict(self._system_description)

    def get_operation_model(self) -> MultiCaptureOperationModel:
        """Return the persisted operation block associated with this capture service."""
        return MultiCaptureOperationModel(name=self.OPERATION_NAME, measure_mode=self._normalize_measure_mode(self.MEASURE_MODE))

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
            "collected": int(op.get("collected", 0)),
            "time_remaining": op.get("time_remaining", 0)
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

    def release_operation_memory(self, operation_id: OperationId) -> None:
        """
        Drop retained in-memory samples and task references for an operation.

        Args:
            operation_id: Operation whose transient in-memory state should be released.
        """
        op = self._ops.get(operation_id)
        if not op:
            return

        released_samples = len(op["samples"])
        op["samples"] = []
        op["task"] = None

        if released_samples > 0:
            self.logger.info("[%s] Released %d retained samples from memory", operation_id, released_samples)

        ProcessMemory.release_unused_memory()

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
            task = op.get("task")
            if isinstance(task, asyncio.Task) and not task.done():
                task.cancel()
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
            return [CaptureSample(timestamp         =   ts,
                                  transaction_id    =   "",
                                  filename          =   "",
                                  error             =   err)]

        samples: list[CaptureSample] = []
        for idx, entry in enumerate(payload):
            try:
                status_str, msg_type, body = MessageResponse.get_payload_msg(entry)

            except Exception as exc:
                err = f"Failed to parse payload entry {idx}: {exc}"
                self.logger.error(err, exc_info=True)
                samples.append(CaptureSample(timestamp      =   ts,
                                             transaction_id =   "",
                                             filename       =   "",
                                             error          =   err))
                continue

            if status_str != ServiceStatusCode.SUCCESS.name:
                err = f"Payload entry {idx} returned status {status_str}"
                self.logger.error(err)
                samples.append(CaptureSample(timestamp      =   ts,
                                             transaction_id =   "",
                                             filename       =   "",
                                             error          =   err))
                continue

            if msg_type != MessageResponseType.PNM_FILE_TRANSACTION.name:
                # skip non-transaction messages
                continue

            txn_id = body.get("transaction_id", "")
            filename = body.get("filename", "")
            if not txn_id or not filename:
                err = f"Missing txn_id or filename in entry {idx}"
                self.logger.warning(f"{err}: {body}")
                samples.append(CaptureSample(timestamp      =   ts,
                                             transaction_id =   txn_id,
                                             filename       =   filename,
                                             error          =   "missing-txn-or-filename"))
                continue

            try:
                rec = PnmFileTransaction().get_record(txn_id)
            except Exception as exc:
                err = f"DB fetch error for txn {txn_id}: {exc}"
                self.logger.error(err, exc_info=True)
                samples.append(CaptureSample(timestamp      =   ts,
                                             transaction_id =   txn_id,
                                             filename       =   filename,
                                             error          =   "db-fetch-error"))
                continue

            if rec is None:
                err = f"No DB record found for txn {txn_id}"
                self.logger.warning(err)
                samples.append(CaptureSample(timestamp      =   ts,
                                             transaction_id =   txn_id,
                                             filename       =   filename,
                                             error          =   "no-db-record"))
            else:
                if not self._ensure_transaction_system_description(txn_id, rec):
                    samples.append(CaptureSample(timestamp      =   ts,
                                                 transaction_id =   txn_id,
                                                 filename       =   filename,
                                                 error          =   "missing-system-description"))
                    continue
                samples.append(CaptureSample(timestamp      =   ts,
                                             transaction_id =   txn_id,
                                             filename       =   filename,
                                             error          =   None))

        if not samples:
            err = "No valid transactions found in payload"
            self.logger.warning(err)
            return [CaptureSample(timestamp         =   ts,
                                  transaction_id    =   "",
                                  filename          =   "",
                                  error             =   "no-transactions")]

        return samples

    @staticmethod
    def _normalize_measure_mode(measure_mode: Enum | str) -> str:
        """Normalize enum or string measure-mode values for persistence."""
        if isinstance(measure_mode, Enum):
            return measure_mode.name.lower()
        return str(measure_mode).strip().lower()

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

    @staticmethod
    def _normalize_system_description(system_description: dict[str, Any] | None) -> dict[str, str]:
        if not isinstance(system_description, dict):
            return {}
        normalized: dict[str, str] = {}
        for key in ("HW_REV", "VENDOR", "BOOTR", "SW_REV", "MODEL"):
            value = system_description.get(key, "")
            normalized[key] = str(value) if value is not None else ""
        return normalized

    @staticmethod
    def _has_populated_system_description(system_description: dict[str, Any] | None) -> bool:
        if not isinstance(system_description, dict):
            return False
        return any(str(system_description.get(k, "")).strip() for k in ("HW_REV", "VENDOR", "BOOTR", "SW_REV", "MODEL"))

    @staticmethod
    def _extract_record_system_description(record: dict[str, Any]) -> dict[str, Any] | None:
        device_details = record.get("device_details")
        if not isinstance(device_details, dict):
            return None
        system_description = device_details.get("system_description")
        if not isinstance(system_description, dict):
            return None
        return system_description

    def _ensure_transaction_system_description(self, txn_id: str, record: dict[str, Any]) -> bool:
        current = self._extract_record_system_description(record)
        if self._has_populated_system_description(current):
            if not self._has_populated_system_description(self._system_description):
                self._system_description = self._normalize_system_description(current)
            return True

        if not self._has_populated_system_description(self._system_description):
            self.logger.warning("Transaction %s missing system_description and no session fallback is available.", txn_id)
            return False

        try:
            updated = PnmFileTransaction().update_record_system_description(
                txn_id,
                self._system_description,
            )
        except Exception as exc:
            self.logger.error("Failed to update system_description for txn %s: %s", txn_id, exc, exc_info=True)
            return False

        if not updated:
            self.logger.warning("Unable to persist system_description for txn %s", txn_id)
            return False

        record.setdefault("device_details", {})
        if isinstance(record["device_details"], dict):
            record["device_details"]["system_description"] = dict(self._system_description)

        return True
