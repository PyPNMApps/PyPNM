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

        try:
            om = OperationManager(capture_group_id=group_id)
            operation_id:OperationId = om.register()
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
            "samples":          []
        }

        self.setOperationFinalInvocation(operation_id, False)

        self.logger.info(
            f"CaptureGroup={group_id} / Operation={operation_id} started "
            f"({self.duration}s @ {self.interval}s interval)")

        async def _runner() -> None:

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
                    samples = self._process_captures(msg_rsp)
                    for sample in samples:
                        self._ops[operation_id]["samples"].append(sample)
                        self._cap_group.add_transaction(sample.transaction_id)
                        self.logger.debug(f"[{operation_id}] Captured sample txn={sample.transaction_id}")

                except Exception as exc:
                    error_msg = str(exc)
                    self.logger.error(f"[{operation_id}] Capture error: {error_msg}", exc_info=True)
                    self._ops[operation_id]["samples"].append(CaptureSample(timestamp       =   cast(TimeStamp, iteration_ts),
                                                                            transaction_id  =   "",
                                                                            filename        =   "",
                                                                            error           =   error_msg))

            # Complete if still running
            if self._ops[operation_id]["state"] == OperationState.RUNNING:

                self._ops[operation_id]["state"] = OperationState.COMPLETED
                iteration_ts = time.time()

                try:

                    self.logger.info(f'Runner ended, Final Invocation , One Last Cycle before ending'
                                    f'state={self._ops[operation_id]["state"]}'
                                    f'time-remaining={self._ops[operation_id]["time_remaining"]}')

                    self.setOperationFinalInvocation(operation_id, True)
                    msg_rsp:MessageResponse = await self._capture_message_response()

                    # This is here to before any last operation at the time of the completion of the task
                    if msg_rsp.status == ServiceStatusCode.SKIP_MESSAGE_RESPONSE:
                        self.logger.info('Skipping last _capture_message_response()')
                    else:
                        samples = self._process_captures(msg_rsp)
                        for sample in samples:
                            self._ops[operation_id]["samples"].append(sample)
                            self._cap_group.add_transaction(sample.transaction_id)
                            self.logger.info(f"[{operation_id}] Captured sample txn={sample.transaction_id}")

                except Exception as exc:
                    error_msg = str(exc)
                    self.logger.error(f"[{operation_id}] Capture error: {error_msg}", exc_info=True)
                    self._ops[operation_id]["samples"].append(
                        CaptureSample(timestamp         =   cast(TimeStamp, iteration_ts),
                                      transaction_id    =   "",
                                      filename          =   "",
                                      error             =error_msg))

            self.logger.info(f"[{operation_id}] Capture session ended with state={self._ops[operation_id]['state']}")

                                            ###############
                                            # Main RUNNER #
                                            ###############
        try:
            asyncio.create_task(_runner())
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

    def getOperationState(self,operation_id:OperationId) -> OperationState:
        return self._ops[operation_id]["state"]

    def setOperationFinalInvocation(self, operation_id:OperationId, state:bool) -> None:
            "Indicate that Runner is done, and invocate any final operations"
            self._ops[operation_id]["final_invocation"] = state

    def getOperationFinalInvocation(self, operation_id:OperationId) -> bool:
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
