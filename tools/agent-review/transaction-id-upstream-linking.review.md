### Summary
Added upstream guards to skip empty/whitespace transaction_id linking in capture workflows and in-memory collections, plus safe filtering when reading capture-group transactions. Added focused tests for empty-transaction handling at capture service, collection, and filename mapping layers.

### Modified Files
- src/pypnm/api/routes/advance/common/capture_service.py
- src/pypnm/api/routes/advance/common/transactionsCollection.py
- src/pypnm/api/routes/common/extended/common_measure_service.py
- src/pypnm/api/routes/common/classes/file_capture/pnm_file_opearation.py
- tests/test_operation_workflow.py
- tests/test_common_measure_service_empty_transaction_id.py
- tests/test_transaction_collection_empty_transaction_id.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass (355 files already formatted)
- `pytest -k "transaction_id and (linking or operation or multi)" -q` → pass (2 passed, 547 deselected)

### Tests
- `pytest` → pass (2 passed, 547 deselected; warning logs emitted in test)
- `ruff` → pass
- `ruff format --check .` → pass
- `python3 -m compileall src` → pass

### Notes / Warnings
- pytest emitted expected WARNING logs for empty transaction_id handling during test execution.

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

            txn_id = body.get("transaction_id", "")
            filename = body.get("filename", "")
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

# FILE: src/pypnm/api/routes/advance/common/transactionsCollection.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from pydantic import Field

from pypnm.api.routes.advance.common.types.types import Sort
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import ByteArray, TransactionId


class TransactionCollectionModel(TransactionRecordModel):
    """
    Extended transaction record model that includes raw file bytes.

    Attributes
    ----------
    data : bytes
        Capture data payload for the associated transaction file.
    """

    data: bytes = Field(..., description="(PNM/PNN/LDD) file bytes")


class TransactionCollection:
    """
    Collection container for handling transaction records, supporting sorting,
    retrieval by ID, and bulk operations.
    """

    def __init__(self) -> None:
        """
        Initialize internal storage for transaction records and indices.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self._records: list[TransactionCollectionModel] = []
        self._transaction_ids: list[TransactionId] = []
        self._transaction_models: list[TransactionCollectionModel] = []
        self._transaction_tm: dict[TransactionId, TransactionCollectionModel] = {}
        self._tranaction_tm = self._transaction_tm  # alias
        self._mac_addresses: set[MacAddress] = set()

    def add(self, record: TransactionRecordModel, bytes: bytes) -> bool:
        """
        Add a new transaction record and its associated data payload.

        Parameters
        ----------
        record : TransactionRecordModel
            Metadata describing the transaction.
        bytes : bytes
            Raw file contents.

        Returns
        -------
        bool
            True if added successfully.
        """
        tx_id = str(record.transaction_id)
        if not tx_id.strip():
            self.logger.warning(
                "Skipping TransactionCollection add for empty transaction_id"
            )
            return False

        tcm = TransactionCollectionModel(
            transaction_id=record.transaction_id,
            timestamp=record.timestamp,
            mac_address=record.mac_address,
            pnm_test_type=record.pnm_test_type,
            filename=record.filename,
            device_details=record.device_details,
            data=bytes,
        )
        self._records.append(tcm)
        self._transaction_tm[record.transaction_id] = tcm
        self._transaction_models.append(tcm)
        self._transaction_ids.append(record.transaction_id)
        self._mac_addresses.add(MacAddress(record.mac_address))
        return True

    def length(self) -> int:
        """
        Get the total number of transaction records in the collection.

        Returns
        -------
        int
            Count of records.
        """
        return len(self._records)

    def getTransactionIds(
        self, sorts: list[Sort] | None = None, reverse: bool = False
    ) -> list[TransactionId]:
        """
        Retrieve transaction IDs, optionally sorted.

        Parameters
        ----------
        sorts : list of Sort, optional
            Sorting priorities in order. If None, insertion order is used.
        reverse : bool
            If True, reverse the sorting order.

        Returns
        -------
        list of TransactionId
            Sorted list of transaction IDs.

        Raises
        ------
        ValueError
            If Sort.CHANNEL_ID is included in sorts.
        """
        if not sorts:
            return list(self._transaction_ids)
        sorted_records = self._sorted_records(sorts, reverse)
        return [r.transaction_id for r in sorted_records]

    def getTransactionCollectionModel(
        self,
        transaction_id: TransactionId = "",
        sorts: list[Sort] | None = None,
        reverse: bool = False,
    ) -> list[TransactionCollectionModel]:
        """
        Retrieve transaction models by ID or sorted collection.

        Parameters
        ----------
        transaction_id : TransactionId, optional
            Specific transaction ID to retrieve. Returns all if empty.
        sorts : list of Sort, optional
            Sorting priorities in order.
        reverse : bool
            If True, reverse the sorting order.

        Returns
        -------
        list of TransactionCollectionModel
            Matching transaction models.
        """
        if transaction_id:
            model = self._transaction_tm.get(transaction_id)
            return [model] if model else []
        if not sorts:
            return list(self._transaction_models)
        return self._sorted_records(sorts, reverse)

    def getTransactionBytes(
        self,
        transaction_id: TransactionId = "",
        sorts: list[Sort] | None = None,
        reverse: bool = False,
    ) -> ByteArray:
        """
        Retrieve raw data bytes from transactions.

        Parameters
        ----------
        transaction_id : TransactionId, optional
            Specific transaction ID to retrieve. Returns all if empty.
        sorts : list of Sort, optional
            Sorting priorities in order.
        reverse : bool
            If True, reverse the sorting order.

        Returns
        -------
        ByteArray
            List of raw data bytes from the matching transactions.
        """
        ba: ByteArray = []

        if transaction_id:
            tcm = self._transaction_tm.get(transaction_id)
            if tcm:
                ba.append(tcm.data)
            return ba

        records = (
            self._sorted_records(sorts, reverse) if sorts else self._transaction_models
        )
        for tcm in records:
            ba.append(tcm.data)
        return ba

    def getMacAddresses(self) -> list[MacAddress]:
        return list(self._mac_addresses)

    def _sorted_records(
        self, sorts: list[Sort], reverse: bool
    ) -> list[TransactionCollectionModel]:
        """
        Internal helper to sort records based on provided sort keys.

        Parameters
        ----------
        sorts : list of Sort
            Sorting priorities in order.
        reverse : bool
            If True, reverse the sorting order.

        Returns
        -------
        list of TransactionCollectionModel
            Sorted records.

        Raises
        ------
        ValueError
            If Sort.CHANNEL_ID is included in sorts.
        """
        if Sort.CHANNEL_ID in sorts:
            raise ValueError("Sorting by CHANNEL_ID is not supported.")

        key_fn = self._composite_key_for_sorts(sorts)
        return sorted(self._records, key=key_fn, reverse=reverse)

    def _composite_key_for_sorts(
        self, sorts: list[Sort]
    ) -> Callable[..., tuple[object, ...]]:
        """
        Build a composite key function for multi-level sorting.

        Parameters
        ----------
        sorts : list of Sort
            Sorting priorities in order.

        Returns
        -------
        callable
            A key function for sorting.
        """

        def key(r: TransactionCollectionModel) -> tuple[object, ...]:
            parts: list[object] = []

            for s in sorts:
                if s == Sort.ASCEND_EPOCH:
                    parts.append(r.timestamp)
                elif s == Sort.MAC_ADDRESS:
                    parts.append(r.mac_address)
                elif s == Sort.PNM_FILE_TYPE:
                    parts.append(self._file_ext(r.filename))

            parts.append(r.transaction_id)
            return tuple(parts)

        return key

    @staticmethod
    def _file_ext(filename: str) -> str:
        """
        Extract file extension in lowercase without the leading dot.

        Parameters
        ----------
        filename : str
            Name of the file.

        Returns
        -------
        str
            File extension or empty string if none found.
        """
        return Path(filename).suffix.lower().lstrip(".")

# FILE: src/pypnm/api/routes/common/extended/common_measure_service.py
# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
import math
import os
import shutil
import time
from enum import Enum, auto
from pathlib import Path
from typing import TypeAlias, cast

from pypnm.api.routes.common.classes.analysis.analysis import SpecAnCapturePara
from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.extended.common_measure_schema import (
    DownstreamOfdmParameters,
    UpstreamOfdmaParameters,
)
from pypnm.api.routes.common.extended.common_messaging_service import (
    CommonMessagingService,
    MessageResponse,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_config_manager import PnmConfigManager
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.docsis.cm_snmp_operation import (
    DocsPnmBulkFileUploadStatus,
    DocsPnmCmCtlStatus,
    FecSummaryType,
)
from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.docsis.data_type.pnm.DocsIf3CmSpectrumAnalysisEntry import (
    DocsIf3CmSpectrumAnalysisEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsConstDispMeasEntry import (
    DocsPnmCmDsConstDispMeasEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsHistEntry import DocsPnmCmDsHistEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmFecEntry import DocsPnmCmDsOfdmFecEntry
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmModProfEntry import (
    DocsPnmCmDsOfdmModProfEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmDsOfdmRxMerEntry import (
    DocsPnmCmDsOfdmRxMerEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmOfdmChanEstCoefEntry import (
    DocsPnmCmOfdmChanEstCoefEntry,
)
from pypnm.docsis.data_type.pnm.DocsPnmCmUsPreEqEntry import DocsPnmCmUsPreEqEntry
from pypnm.lib.file_processor import FileProcessor
from pypnm.lib.ftp.ftp_connector import FTPConnector
from pypnm.lib.host_endpoint import HostEndpoint
from pypnm.lib.inet import Inet
from pypnm.lib.ping import Ping
from pypnm.lib.ssh.ssh_connector import SSHConnector
from pypnm.lib.tftp.tftp_connector import TFTPConnector
from pypnm.lib.types import ChannelId, FileNameStr, InterfaceIndex, TransactionId, HostNameStr
from pypnm.lib.utils import Generate
from pypnm.pnm.data_type.DocsIf3CmSpectrumAnalysisCtrlCmd import (
    DocsIf3CmSpectrumAnalysisCtrlCmd,
    SpectrumRetrievalType,
    WindowFunction,
)
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest
from pypnm.snmp.modules import DocsisIfType
from pypnm.snmp.snmp_v2c import Snmp_v2c


class MeasureServiceReturnTypes(Enum):
    BASE_MODEL = auto()
    DICT = auto()

MeasurementEntry: TypeAlias =   DocsPnmCmOfdmChanEstCoefEntry   | \
                                DocsPnmCmDsConstDispMeasEntry   | \
                                DocsPnmCmDsOfdmRxMerEntry       | \
                                DocsPnmCmUsPreEqEntry           | \
                                DocsPnmCmDsHistEntry            | \
                                DocsPnmCmDsOfdmFecEntry         | \
                                DocsPnmCmDsOfdmModProfEntry     | \
                                DocsIf3CmSpectrumAnalysisEntry

class CommonMeasureService(CommonMessagingService):
    """
    Base service class for executing common Proactive Network Maintenance (PNM) measurement tests.

    Parameters:
        pnm_test_type (DocsPnmCmCtlTest): The type of PNM test to execute.
        cable_modem (CableModem): The cable modem instance used for the test.
        tftp_servers (Inet,Inet): (IPv4,IPv6)
        tftp_path (str, optional): The path on the TFTP server where test result files are stored. Default is an empty string.
        snmp_write_community (str, optional): The SNMP community string for write access. Default is "private".
        **extra_options (dict, optional): Additional keyword arguments specific to the test type, such as:
            - fec_summary_type (FecSummaryType): Required for tests involving FEC summary metrics.
            - Other parameters based on the test type.

    Notes:
        This class serves as a base for test-specific measurement operations. Subclasses should implement
        specific tests such as:
        - Downstream OFDM codeword error rate
        - RXMER per subcarrier
        - FEC statistics, etc.

        It is expected that subclasses will extend this service and provide the necessary implementations for
        executing and processing PNM measurements based on the test type and parameters.
    """
    def __init__(self, pnm_test_type:DocsPnmCmCtlTest,
                 cable_modem: CableModem,
                 tftp_servers: tuple[Inet,Inet],
                 tftp_path: str = "",
                 snmp_write_community: str = "private",
                 **extra_options) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.propagate = True

        self.pnm_filename:list[str]

        self._transactionId_pnmFile: dict[str, str] = {}
        self.pnm_test_type:DocsPnmCmCtlTest         = pnm_test_type
        self.cm:CableModem                          = cable_modem
        self.tftp_servers:tuple[Inet,Inet]          = tftp_servers
        self.tftp_path:str                          = tftp_path
        self.snmp_write_community:str               = snmp_write_community
        self.extra_options                          = extra_options
        self.config_mgr:ConfigManager               = ConfigManager()
        self.log_prefix:str                         = f"MAC: {self.cm.get_mac_address} - INET: {self.cm.get_inet_address}"
        self.pnm_dir                                = PnmConfigManager.get_save_dir()
        self.pnm_local_dir                          = SystemConfigSettings.pnm_dir
        self._capture_parameter:SpecAnCapturePara   = SpecAnCapturePara()

        # Initialize default spectrum capture parameters
        self._capture_parameter.spectrum_retrieval_type = SpectrumRetrievalType.UNKNOWN

        if self.extra_options:
            self.logger.info(f"{self.log_prefix} - OPTIONS: {self.extra_options}")
            self._preload_interface_parameters()

        self._precheck()

    def _precheck(self) -> None:
        """
        Perform pre-check and ensure the save directory exists.
        """
        self.logger.debug(f'PreCheck: SaveDir: {self.pnm_dir}')
        save_path = Path(self.pnm_dir)
        save_path.mkdir(parents=True, exist_ok=True)

    def _preload_interface_parameters(self) -> None:
        """
        Load optional interface parameters from extra_options dictionary.
        If not present, sets interface_parameters to None.
        """
        self.interface_parameters = self.extra_options.get("interface_parameters", None)

    def setSpectrumCaptureParameters(self, capture_parameter:SpecAnCapturePara) -> None:
        """
        Set the spectrum capture parameters for the measurement.

        TODO: This method may be deprecated in favor of passing parameters directly during initialization.

        Args:
            capture_parameter (SpecAnCapturePara): The spectrum capture parameters.
        """
        self._capture_parameter = capture_parameter

    def getSpectrumCaptureParameters(self) -> SpecAnCapturePara:
        """
        Get the current spectrum capture parameters.

        Returns:
            SpecAnCapturePara: The current spectrum capture parameters.
        """
        return self._capture_parameter

    async def set_and_go(self, interface_parameters: DownstreamOfdmParameters | UpstreamOfdmaParameters | None = None ,
                         max_wait_count: int = 5,) -> MessageResponse:
        """
        Trigger PNM file capture and retrieval based on direction-specific parameters.

        Args:
            interface_parameters (InterfaceParameters, optional):
                The configuration specifying the direction of capture:
                - `DownstreamOfdmParameters`: For OFDM downstream channels.
                - `UpstreamOfdmaParameters`: For OFDMA upstream channels.
                If `None` (default), all channels will be captured.

            max_wait_count (int, optional):
                Maximum seconds to wait for measurement readiness. Default is 5.

        Returns:
            MessageResponse: Result indicating success or failure of the operation.
        """

        ##########################################################
        # Verify that we can connect to the CM via Ping and SNMP
        ##########################################################

        if not self.is_ping_reachable():
            self.logger.error(f"{self.log_prefix} - Unreachable via PING")
            return self.build_send_msg(ServiceStatusCode.UNREACHABLE_PING)

        if not await self.is_snmp_ready():
            self.logger.error(f"{self.log_prefix} - Unreachable via SNMP")
            return self.build_send_msg(ServiceStatusCode.UNREACHABLE_SNMP)

        #########################################################################
        #                   Spectrum Analysis SNMP Return                       #
        #########################################################################

        if self.getSpectrumCaptureParameters().spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.debug(f"{self.log_prefix} - Performing Spectrum Analysis SNMP Amplitude Data")

            #Set Spectrum Analyzer
            __status = await self._generic_spectrum_analyzer_operation()

            if __status[0] != ServiceStatusCode.SUCCESS:
               self.logger.error(f"{self.log_prefix} - Unable to set Spectrum Analyzer Settings")
               return self.build_send_msg(ServiceStatusCode.SPEC_ANALYZER_SET_CONFIG_ERROR)

            # This is a blocking method, it will return SUCCESS or wait till timeout to return an ERROR
            status = await self._check_spectrum_amplitude_data_status()

            if status == ServiceStatusCode.SUCCESS:
                self.logger.info(f"{self.log_prefix} - Spectrum Amplitude Data is READY, collecting amplitude data, may take a while...")
                amp_data: bytes = await self.cm.getSpectrumAmplitudeData()
                self.logger.info(f"{self.log_prefix} - Spectrum Amplitude Data collection COMPLETE, total bytes: {len(amp_data)}.")
                #################################################################################################
                # Build binary filename and save file - START
                #################################################################################################
                filename = await self._pnm_file_generator(DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA)
                tx_id = self._get_transaction_id_by_filename(filename)
                if not tx_id:
                    self.logger.error(f"{self.log_prefix} - Unable to find Transaction ID for PNM filename: {filename}")
                    return self.build_send_msg(ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND)

                pnm_dir = SystemConfigSettings.pnm_dir()
                fpath = f"{pnm_dir}/{filename}"
                self.logger.debug(f'SpectrumAmplitudeData: - FNAME: {filename} - Length:{len(amp_data)} - TransactionID: {tx_id}')

                FileProcessor(fpath).write_file(amp_data)
                #################################################################################################
                # Build binary filename and save file - END
                #################################################################################################

                self.build_transaction_msg(tx_id, filename)

            return self.build_send_msg(status)

        #########################################################################
        # Ensure CM Inet and TFTP server address use the same IP version
        #
        # The TFTP server address must match the IP version (IPv4 or IPv6) used
        # by the Cable Modem (CM). By default, we assume IPv4.
        #
        # If the CM's IP address is IPv6 and matches the version of the
        # secondary TFTP server entry, we switch to using the IPv6 TFTP server.
        #
        # TODO: Enhance this logic to support dual-stack (dual-home) cable modems,
        # where both IPv4 and IPv6 may be valid simultaneously.
        #########################################################################

        self.logger.info(f'{self.log_prefix} - TFTP-SERVERS: ({self.tftp_servers[0]} | {self.tftp_servers[1].inet})')

        # Default to using the IPv4 TFTP server
        tftp_server: Inet = self.tftp_servers[0]

        # Switch to IPv6 TFTP server if CM uses IPv6
        if self.cm.same_inet_version(self.tftp_servers[1]):
            tftp_server = self.tftp_servers[1]

        # Attempt to configure the CM with the selected TFTP server and path
        if not await self.cm.setDocsPnmBulk(tftp_server.inet, self.tftp_path):
            self.logger.error(
                f"{self.log_prefix} - Unable to set TFTP server {tftp_server.inet} "
                f"or TFTP path: {self.tftp_path}")
            return self.build_send_msg(ServiceStatusCode.TFTP_SERVER_PATH_SET_FAIL)

        ##############################################################################################
        # This section is determine by the direction due to which interface and type we are accessing
        ##############################################################################################

        status_index_channelId = await self._get_indexes_via_pnm_test_type(interface_parameters)
        self.logger.info(f'{self.log_prefix} - Index/ChannelID List: {status_index_channelId[1]}')
        if status_index_channelId[0] != ServiceStatusCode.SUCCESS or status_index_channelId[1] is None:
            self.logger.error(f'{self.log_prefix} - Unable to aquire index from ChannelID, reason: {status_index_channelId[0]}')
            return self.build_send_msg(status_index_channelId[0])

        ##############################################################################################
        # This section runs through all the indexes, build PNM file, run measurement and check status
        ##############################################################################################
        index_channelId: list[tuple[InterfaceIndex, ChannelId]] = status_index_channelId[1]
        return self.build_send_msg(await self._pnm_measure_status_and_pnm_file_transfer(index_channelId, max_wait_count))

    def getInterfaceParameters(self,
        interface_type: DocsisIfType) -> DownstreamOfdmParameters | UpstreamOfdmaParameters:
        """
        Instantiate and return the PNM test parameters for the specified DOCSIS interface.

        Args:
            interface_type (DocsisIfType):
                The DOCSIS interface type:
                - `DocsisIfType.docsOfdmDownstream` → returns DownstreamOfdmParameters
                - `DocsisIfType.docsOfdmaUpstream`  → returns UpstreamOfdmaParameters

        Returns:
            Union[DownstreamOfdmParameters, UpstreamOfdmaParameters]:
                A parameters object tailored to the requested interface.

        Raises:
            ValueError: If `interface_type` is not OFDM downstream or OFDMA upstream.
        """
        if interface_type == DocsisIfType.docsOfdmDownstream:
            return DownstreamOfdmParameters()
        if interface_type == DocsisIfType.docsOfdmaUpstream:
            return UpstreamOfdmaParameters()

        raise ValueError(
            f"Unsupported interface type: {interface_type!r}. "
            "Expected docsOfdmDownstream or docsOfdmaUpstream."
        )

    def is_ping_reachable(self) -> bool:
        """
        Check if the cable modem is reachable via ICMP ping.

        Returns:
            bool: True if the modem responds to ping, False otherwise.
        """
        return self.cm.is_ping_reachable()

    async def is_snmp_ready(self) -> bool:
        """
        Asynchronously check if the cable modem is accessible via SNMP.

        Returns:
            bool: True if the modem responds to SNMP queries, False otherwise.
        """
        return await self.cm.is_snmp_reachable()

    async def _filter_measurement_entries(
        self,
        entries: list[MeasurementEntry],
        channel_ids: list[ChannelId] | None,
    ) -> list[MeasurementEntry]:
        if not channel_ids:
            return entries

        channel_id_set = {int(channel_id) for channel_id in channel_ids}
        index_set: set[int] = set()

        if self.pnm_test_type in (
            DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
            DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF,
            DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
            DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
            DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR,
        ):
            idx_channel_id = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()
            index_set = {int(idx) for idx, channel_id in idx_channel_id if int(channel_id) in channel_id_set}

        elif self.pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:
            idx_channel_id = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
            index_set = {int(idx) for idx, channel_id in idx_channel_id if int(channel_id) in channel_id_set}

        filtered: list[MeasurementEntry] = []
        for entry in entries:
            if isinstance(entry, (DocsPnmCmDsHistEntry, DocsIf3CmSpectrumAnalysisEntry)):
                continue
            if index_set:
                if int(entry.index) in index_set:
                    filtered.append(entry)
                continue
            if not hasattr(entry, "channel_id"):
                continue
            if int(entry.channel_id) in channel_id_set:
                filtered.append(entry)
        return filtered

    async def getPnmMeasurementStatistics(
        self,
        channel_ids: list[ChannelId] | None = None,
    ) -> list[MeasurementEntry]:
        """
        Retrieve PNM measurement entries for the currently configured `pnm_test_type`.

        Returns
        -------
        List[MeasurementEntry]
            A (possibly empty) list of model instances corresponding to the active
            test type:

            - DS_OFDM_CHAN_EST_COEF             → List[DocsPnmCmOfdmChanEstCoefEntry]
            - DS_CONSTELLATION_DISP             → List[DocsPnmCmDsConstDispMeasEntry]
            - DS_OFDM_RXMER_PER_SUBCAR          → List[DocsPnmCmDsOfdmRxMerEntry]
            - US_PRE_EQUALIZER_COEF             → List[DocsPnmCmUsPreEqEntry]
            - DS_HISTOGRAM                      → List[DocsPnmCmDsHistEntry]
            - DS_OFDM_FEC_SUMMARY               → List[DocsPnmCmDsOfdmFecEntry]
            - DS_OFDM_MODULATION_PROFILE        → List[DocsPnmCmDsOfdmModProfEntry]
            - SPECTRUM_ANALYZER                 → List[DocsIf3CmSpectrumAnalysisEntry]
            - SPECTRUM_ANALYZER_SNMP_AMP_DATA   → List[DocsIf3CmSpectrumAnalysisEntry]

            For other (stub/unsupported) test types, an empty list is returned.

        Notes
        -----
        - This method performs no aggregation; it returns the raw per-entry models
          fetched from the cable modem for the selected measurement type.
        - For strict typing, concrete lists are cast to `List[MeasurementEntry]`
          at return points (because `List` is invariant in the type system).
        - If `channel_ids` is provided and not empty, results are filtered to only
          include entries whose `channel_id` is in the list.
        """
        entries: list[MeasurementEntry] = []

        if self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            self.logger.debug(f"{self.log_prefix} - Running SPECTRUM_ANALYZER")
            concrete = await self.cm.getDocsIf3CmSpectrumAnalysisEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF:
            self.logger.debug(f"{self.log_prefix} - Running OFDM Channel Estimation Coefficient collection")
            concrete = await self.cm.getDocsPnmCmOfdmChanEstCoefEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP:
            self.logger.debug(f"{self.log_prefix} - Running OFDM Constellation Display collection")
            concrete = await self.cm.getDocsPnmCmDsConstDispMeasEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR:
            self.logger.debug(f"{self.log_prefix} - Running RXMER entry collection")
            concrete = await self.cm.getDocsPnmCmDsOfdmRxMerEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE:
            self.logger.debug(f"{self.log_prefix} - Running DS_OFDM_CODEWORD_ERROR_RATE")
            concrete = await self.cm.getDocsPnmCmDsOfdmFecEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM:
            self.logger.debug(f"{self.log_prefix} - Running DS_HISTOGRAM")
            concrete = await self.cm.getDocsPnmCmDsHistEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:
            self.logger.debug(f"{self.log_prefix} - Running Upstream Pre-Equalization entry collection")
            concrete = await self.cm.getDocsPnmCmUsPreEqEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE:
            self.logger.debug(f"{self.log_prefix} - Running DS_OFDM_MODULATION_PROFILE")
            concrete = await self.cm.getDocsPnmCmDsOfdmModProfEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA:
            self.logger.debug(f"{self.log_prefix} - Running SPECTRUM_ANALYZER_SNMP_AMP_DATA")
            concrete = await self.cm.getDocsIf3CmSpectrumAnalysisEntry()
            entries = cast(list[MeasurementEntry], concrete)
            return await self._filter_measurement_entries(entries, channel_ids)

        elif self.pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_SYMBOL_CAPTURE:
            self.logger.warning(f"{self.log_prefix} - Stub handler: DS_OFDM_SYMBOL_CAPTURE")

        elif self.pnm_test_type == DocsPnmCmCtlTest.LATENCY_REPORT:
            self.logger.warning(f"{self.log_prefix} - Stub handler: LATENCY_REPORT")

        else:
            self.logger.warning(f"{self.log_prefix} - Unknown PNM test type: {self.pnm_test_type}")

        return entries

    ###################
    # Private Methods #
    ###################

    async def _get_and_move_pnm_file(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Retrieves and moves the specified PNM file based on the configured retrieval method.

        This method delegates the file retrieval operation to a protocol-specific handler method
        depending on the configuration defined under `PnmFileRetrieval.method`. 
        Supported methods include: "local", "tftp", "sftp"
        # TODO: Need to implement, not sure if we need to: "ftp", "http", and "https".

        Configuration keys used:
            - PnmFileRetrieval.method: The file retrieval method to use (e.g., "local", "tftp", etc.).
            - PnmFileRetrieval.retries: Optional number of retries for retrieval attempts (currently unused here).

        Args:
            pnm_file_name (str): The name of the file to retrieve and move.

        Returns:
            bool: True if the file was successfully retrieved and moved; False otherwise.
        """
        method = SystemConfigSettings.retrieval_method()
        self.logger.info(f"{self.log_prefix} - Retrieval method: {method}")

        try:
            if method == "local":
                return await self._handle_local_fetch(pnm_file_name)
            elif method == "tftp":
                return self._handle_tftp_fetch(pnm_file_name)
            elif method == "ftp":
                return self._handle_ftp_fetch(pnm_file_name)
            elif method == "sftp":
                return self._handle_sftp_fetch(pnm_file_name)
            elif method == "http":
                return self._handle_http_fetch(pnm_file_name)
            elif method == "https":
                return self._handle_https_fetch(pnm_file_name)
            else:
                self.logger.error(f"{self.log_prefix} - Unsupported retrieval method: {method}")
                return ServiceStatusCode.FILE_RETRIEVAL_TYPE_INVALID

        except Exception as e:
            self.logger.exception(f"{self.log_prefix} - File retrieval failed: {e}")
            return ServiceStatusCode.PNM_FILE_RETRIEVAL_ERROR

    async def _get_indexes_via_pnm_test_type(self, ifParameters: DownstreamOfdmParameters | UpstreamOfdmaParameters | None = None
                                             ) -> tuple[ServiceStatusCode, list[tuple[InterfaceIndex, ChannelId]] | None]:
        """
        Determines the appropriate interface indexes and channel IDs to target for a given PNM test type.

        Depending on the configured PNM test type, this method selects the relevant interface and filters the index/ChannelID
        tuples based on user-specified parameters.

        Args:
            interface_parameters (Optional[InterfaceParameters]): Parameters specifying interface type ("ofdm" or "ofdma")
                and optionally a list of channel IDs to filter. If not provided, default parameters are selected based on test type.

        Returns:
            Tuple[ServiceStatusCode, Optional[List[Tuple[int, int]]]]:
                A status code indicating success or reason for failure, and a list of (index, channelId) tuples.
        """

        if ifParameters is None:
            ifParameters = DownstreamOfdmParameters()

        if not ifParameters:
            ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmDownstream)

        if self.pnm_test_type in (DocsPnmCmCtlTest.DS_HISTOGRAM, DocsPnmCmCtlTest.LATENCY_REPORT):
            idx:list[InterfaceIndex] = await self.cm.getIfTypeIndex(DocsisIfType.docsCableMaclayer)
            return ServiceStatusCode.SUCCESS, [(idx[0], ChannelId(0))]

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
            return ServiceStatusCode.SUCCESS, [(InterfaceIndex(0), ChannelId(0))]

        elif self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA:
            return ServiceStatusCode.SUCCESS, [(InterfaceIndex(0), ChannelId(0))]

        elif self.pnm_test_type in (DocsPnmCmCtlTest.DS_CONSTELLATION_DISP,
                                    DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF,
                                    DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE,
                                    DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE,
                                    DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR):

            if not ifParameters:
                ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmDownstream)

        elif self.pnm_test_type in (DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF,):
            ifParameters = self.getInterfaceParameters(DocsisIfType.docsOfdmaUpstream)
            self.logger.info(f'{DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF} Measurement - IfParameters: {ifParameters.model_dump()}')

        '''
        There is redundant code, but incase I may need to change due to
        change of requiments depending on Downstream vs. Upstream

        TODO: lol, I am sure I will not revisit, but OK for now.
        '''
        if ifParameters.type == "ofdm":
            channel_id_list = ifParameters.channel_id
            idx_channelId = await self.cm.getDocsIf31CmDsOfdmChannelIdIndexStack()

            if not idx_channelId:
                self.logger.warning("No OFDM channel data found.")
                return ServiceStatusCode.NO_OFDMA_CHAN_ID_INDEX_FOUND, []

            if channel_id_list:
                filtered = [tpl for tpl in idx_channelId if tpl[1] in channel_id_list]
                self.logger.info(f'Downstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
                return ServiceStatusCode.SUCCESS, filtered

            self.logger.info(f'Downstream: {ifParameters.type} -> IDX,CHAN_ID: {idx_channelId}')

            return ServiceStatusCode.SUCCESS, idx_channelId

        elif ifParameters.type == "ofdma":
            channel_id_list = ifParameters.channel_id
            idx_channelId = await self.cm.getDocsIf31CmUsOfdmaChannelIdIndexStack()
            if not idx_channelId:
                self.logger.warning("No OFDMA channel found.")
                return ServiceStatusCode.NO_OFDMA_CHAN_ID_INDEX_FOUND, []

            if channel_id_list:
                filtered = [tpl for tpl in idx_channelId if tpl[1] in channel_id_list]
                self.logger.info(f'Upstream: {ifParameters.type} -> ChanID(s): {channel_id_list} -> Filtered: {filtered}')
                return ServiceStatusCode.SUCCESS, filtered

            self.logger.info(f'Upstream: {ifParameters.type} -> IDX,CHAN_ID: {idx_channelId}')

        return ServiceStatusCode.SUCCESS, idx_channelId

    async def _pnm_measure_status_and_pnm_file_transfer(self, idx_channelId:list[tuple[InterfaceIndex, ChannelId]], max_wait_count:int) -> ServiceStatusCode:
        """
        Set and monitor the OFDM measurement test for specified (index, PLC) tuples.

        For each (index, PLC) pair:
            - Initiates the PNM test using SNMP.
            - Waits for the test status to reach READY.
            - Monitors for the measurement status to become SAMPLE_READY.
            - Retrieves the resulting PNM file and stores it locally.

        Args:
            idx_channelId (Tuple[int, int]): A list of tuples where each tuple consists of
                the SNMP interface index and the corresponding PLC (center frequency).
            max_wait_count (int): Maximum number of seconds to wait for SAMPLE_READY status.

        Returns:
            ServiceStatusCode: SUCCESS if all steps completed successfully,
                otherwise a specific error status (e.g., if the file couldn't be retrieved
                or the measurement status did not become SAMPLE_READY).
        """
        for interface_index, channel_id in idx_channelId:

            #######################################################################
            # This sets the Measurement Table/Row for the specific PNM Measurement
            #######################################################################
            ctl_measure_status:tuple[ServiceStatusCode, list[FileNameStr]] = \
                await self._setDocsPnmCmMeasureTest(self.pnm_test_type, interface_index, channel_id)
            
            if ctl_measure_status[0] != ServiceStatusCode.SUCCESS:
                return ctl_measure_status[0]

            pnm_filenames = ctl_measure_status[1]
            self.logger.info(f'{self.log_prefix} - PNM File(s) -> {pnm_filenames}')

            count=1
            while True:
                cm_ctl_status:DocsPnmCmCtlStatus = await self.cm.getDocsPnmCmCtlStatus()
                self.logger.info(f"{self.log_prefix} - PNM status: {str(cm_ctl_status).upper()} - count: {count}")
                if cm_ctl_status == DocsPnmCmCtlStatus.TEST_IN_PROGRESS:
                    count += 1
                    await asyncio.sleep(1)
                    continue

                if cm_ctl_status == DocsPnmCmCtlStatus.READY:
                    break

                if cm_ctl_status == DocsPnmCmCtlStatus.TEMP_REJECT:
                    break

                if cm_ctl_status == DocsPnmCmCtlStatus.SNMP_ERROR:
                    break

            self.logger.debug(f"{self.log_prefix} - Checking Measurement Status for {self.pnm_test_type} @ IDX: {interface_index}")

            wait_count = 0
            def extract_idx(idx):
                return idx[0] if isinstance(idx, list) and idx else idx

            while wait_count < max_wait_count:
                meas_status = await self.cm.getPnmMeasurementStatus(self.pnm_test_type, extract_idx(interface_index))
                self.logger.info(f"{self.log_prefix} - MeasureStatus: {meas_status.name}")
                if meas_status == MeasStatusType.SAMPLE_READY:
                    break
                await asyncio.sleep(1)
                wait_count += 1

            else:
                self.logger.error(f"{self.log_prefix} - SAMPLE_READY not reached for ChannelID {channel_id}")
                return ServiceStatusCode.NOT_READY_AFTER_FILE_CAPTURE

            #Multiple PNM files for special cases
            for pnm_fname in pnm_filenames:

                status:ServiceStatusCode = await self._check_and_wait_for_tftp_upload(FileNameStr(pnm_fname))

                if status != ServiceStatusCode.SUCCESS:
                    self.logger.error(f"{self.log_prefix} - Unable to Upload PNM File to TFTP({status})")
                    return status

                # Get and copy PNM file to local data directory
                retrieval_status = await self._get_and_move_pnm_file(FileNameStr(pnm_fname))
                if retrieval_status != ServiceStatusCode.SUCCESS:
                    self.logger.error(
                        f"{self.log_prefix} - Unable to copy PNM file to local {self.pnm_dir} dir "
                        f"(status={retrieval_status})")
                    return retrieval_status

                # Find Transaction ID via filename
                trans_id = self._get_transaction_id_by_filename(pnm_fname)
                if not trans_id:
                    self.logger.error(f"{self.log_prefix} - Unable to find Transaction ID for PNM filename: {pnm_fname}")
                    return ServiceStatusCode.PNM_FILE_TRANSACTION_ID_NOT_FOUND
                
                self.logger.debug(f'{self.log_prefix} - TransID: {trans_id} -> Filename: {pnm_fname}')
                self.build_transaction_msg(trans_id, pnm_fname)

        return ServiceStatusCode.SUCCESS

    async def _check_and_wait_for_tftp_upload(self, filename: str, max_wait_count: int = 5) -> ServiceStatusCode:
        """
        Waits for a PNM file to be uploaded via TFTP by polling the upload status.

        Args:
            filename (str): The name of the file being uploaded.
            max_wait_count (int): Maximum number of seconds to wait before timing out.

        Returns:
            ServiceStatusCode: SUCCESS if upload completed, failure code otherwise.
        """
        wait_count = 0

        while wait_count < max_wait_count:
            try:
                status = await self.cm.getBulkFileUploadStatus(filename)
            except Exception as e:
                self.logger.error(f"{self.log_prefix} - Error checking upload status for '{filename}': {e}")
                return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

            if status == DocsPnmBulkFileUploadStatus.UPLOAD_COMPLETED:
                self.logger.info(f"{self.log_prefix} - File '{filename}' uploaded successfully.")
                return ServiceStatusCode.SUCCESS

            if status == DocsPnmBulkFileUploadStatus.ERROR:
                self.logger.error(f"{self.log_prefix} - Device reported ERROR for file upload '{filename}'.")
                return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

            self.logger.debug(
                f"{self.log_prefix} - Waiting for file '{filename}' to upload "
                f"(status={status.name}, wait_count={wait_count})"
            )

            await asyncio.sleep(1)
            wait_count += 1

        self.logger.error(f"{self.log_prefix} - TFTP file '{filename}' upload timed out after {max_wait_count} seconds.")
        return ServiceStatusCode.TFTP_PNM_FILE_UPLOAD_FAILURE

    async def _setDocsPnmCmMeasureTest(self, pnm_test_type:DocsPnmCmCtlTest,
                                       interface_index:int, channel_id:ChannelId) -> tuple[ServiceStatusCode, list[FileNameStr]]:
        """
        Configure and trigger a specific PNM (Proactive Network Maintenance) measurement
        test on a cable modem based on the test type.

        Depending on the `pnm_test_type`, this method:
        - Generates appropriate output file names.
        - Uses SNMP to set the modem to collect specific diagnostic data.
        - Handles various DOCSIS downstream and upstream tests, including:
            - US Pre-Equalizer Coefficients (requires two files per interface: pre-eq and last pre-eq)
            - DS OFDM RxMER per Subcarrier
            - DS OFDM Codeword Error Rate
            - DS OFDM Channel Estimation Coefficients
            - DS Constellation Display
            - DS Histogram
            - DS OFDM Modulation Profile
            - Spectrum Analyzer Scan

        Parameters:
            pnm_test_type (DocsPnmCmCtlTest): Enum value indicating the PNM test to perform.
            interface_index (int): The SNMP index for the OFDM channel (usually the interface index).
            channel_id (int): The channel ID associated with the modem interface.

        Returns:
            Tuple[ServiceStatusCode, List[str]]: Status of the operation and list of generated file names.
        """
        pnm_files: list[FileNameStr] = []

        if pnm_test_type == DocsPnmCmCtlTest.US_PRE_EQUALIZER_COEF:

            # Pre-Eq and Last Pre-EQ (2 files)
            pre_eq_filename         = await self._pnm_file_generator(self.pnm_test_type, str(channel_id))
            last_pre_eq_filename    = await self._pnm_file_generator(self.pnm_test_type, f'last_pre-eq_{str(channel_id)}')

            self.logger.info(f'{self.log_prefix} - Setting {self.pnm_test_type} for ChannelID: {channel_id} "'
                             f'@ IDX: {interface_index} -> FN(): {pre_eq_filename}, FN(last): {last_pre_eq_filename}')

            self.logger.info(f'{self.log_prefix} - Performing US_PRE_EQUALIZER_COEF measurement on IDX: ({interface_index})')
            if not await self.cm.setDocsPnmCmUsPreEq(ofdma_idx              =   interface_index,
                                                     filename               =   pre_eq_filename,
                                                     last_pre_eq_filename   =   last_pre_eq_filename):
                self.logger.error(f"{self.log_prefix} - Upstream OFDMA Pre-Equalization is Not Avalaible")
                return ServiceStatusCode.FILE_SET_FAIL, []

            #Append files for later fetching
            pnm_files.extend([pre_eq_filename, last_pre_eq_filename])

        else:
            #The remaining PNM Measuresurement are single PNM file
            pnm_filename = await self._pnm_file_generator(self.pnm_test_type, str(channel_id))
            self.logger.debug(f'{self.log_prefix} - Setting {self.pnm_test_type} for ChannelID: {channel_id} @ IDX: {interface_index} -> FN: {pnm_filename}')
            pnm_files.append(pnm_filename)

            if pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR:

                if not await self.cm.setDocsPnmCmDsOfdmRxMer(ofdm_idx=interface_index, rxmer_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CODEWORD_ERROR_RATE:

                fst = self.extra_options.get("fec_summary_type", FecSummaryType.TEN_MIN)

                if not await self.cm.setDocsPnmCmDsOfdmFecSum(ofdm_idx=interface_index, fec_sum_file_name=pnm_filename, fec_sum_type=fst):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_CHAN_EST_COEF:

                if not await self.cm.setDocsPnmCmOfdmChEstCoef(ofdm_idx=interface_index, chan_est_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_CONSTELLATION_DISP:
                # OFDM Downstream Constellation Display setup
                # Extra SNMP options may include:
                #   - modulation_offset: Optional[int]
                #   - num_sample_symb: Optional[int]
                if not await self.cm.setDocsPnmCmDsConstDisp(
                    ofdm_idx                =   interface_index,
                    const_disp_name         =   pnm_filename,
                    modulation_order_offset =   self.extra_options.get('modulation_order_offset', 0),
                    number_sample_symbol    =   self.extra_options.get('number_sample_symbol', 0)
                ):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_HISTOGRAM:
                sample_duration = self.extra_options.get("histogram_sample_duration", 10)
                if not await self.cm.setDocsPnmCmDsHist(ds_histogram_file_name=pnm_filename, timeout=sample_duration):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.DS_OFDM_MODULATION_PROFILE:

                if not await self.cm.setDocsPnmCmDsOfdmModProf(ofdm_idx=interface_index, mod_prof_file_name=pnm_filename):
                    self.logger.error(f"{self.log_prefix} - Failed to set PNM filename: {pnm_filename}")
                    return ServiceStatusCode.FILE_SET_FAIL, []

            elif pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER:
                #Created generic to be used for PNM File and SNMP Return data
                 __status = await self._generic_spectrum_analyzer_operation(filename=pnm_filename)
                 if __status[0] != ServiceStatusCode.SUCCESS:
                    return __status

        return ServiceStatusCode.SUCCESS, pnm_files

    async def _check_spectrum_amplitude_data_status(self, timeout_seconds: int = 300) -> ServiceStatusCode:
        """
        Polls the cable modem for spectrum amplitude data availability within a timeout period.

        This method repeatedly checks if `docsIf3CmSpectrumAnalysisMeasAmplitudeData` is present
        on the modem, and returns a success or timeout status accordingly.

        Args:
            timeout_seconds (int): Maximum number of seconds to wait before timing out. Default is 300.

        Returns:
            ServiceStatusCode:
                - SUCCESS if data becomes available within the timeout period.
                - SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT if the timeout is exceeded.
        """
        t_start = time.time()

        while True:
            if await self.cm.isAmplitudeDataPresent():
                return ServiceStatusCode.SUCCESS
            now:int = math.floor(time.time() - t_start)

            if now >= timeout_seconds:
                self.logger.warning(f'{self.log_prefix} - Timeout for Amplitude Data ({now} of {timeout_seconds} seconds)')
                return ServiceStatusCode.SPEC_ANALYZER_AMPLITUDE_DATA_TIMEOUT

            self.logger.info(f'{self.log_prefix} - Waiting for Amplitude Data ({now} of {timeout_seconds})')

            await asyncio.sleep(1)

    async def _handle_local_fetch(self, pnm_file_name: str) -> ServiceStatusCode:
        """
        Handles copying a specified PNM file from a local source directory to a configured save directory.

        This method looks up the source and destination paths from the application's system configuration
        (under the "PnmFileRetrieval" section) and attempts to copy the file named `pnm_file_name`
        from the source directory to the save directory.

        Configuration keys used:
            - PnmFileRetrieval.local.src_dir: Source directory where the PNM file resides.
            - PnmFileRetrieval.save_dir: Destination directory where the file should be saved.

        Args:
            pnm_file_name (str): The name of the file to copy.

        Returns:
            bool: True if the file was successfully copied; False otherwise.
        """

        src_dir = SystemConfigSettings.local_src_dir()

        self.logger.info(
            f'{self.log_prefix} - Local Copy - SRC: {src_dir} - SAVE: {self.pnm_dir} - FN: {pnm_file_name}'
        )

        if not os.path.isdir(src_dir) or not os.path.isdir(self.pnm_dir):
            self.logger.error(f"{self.log_prefix} - Invalid source or destination directory")
            return ServiceStatusCode.LOCAL_FETCH_FAILURE

        while True:
            await asyncio.sleep(1)
            file_found = False
            for filename in os.listdir(src_dir):
                if filename == pnm_file_name:
                    file_found = True
                    src_path = os.path.join(src_dir, filename)
                    dest_path = os.path.join(self.pnm_dir, filename)
                    try:
                        shutil.copy2(src_path, dest_path)
                        self.logger.debug(f"{self.log_prefix} - Copied {filename} to {self.pnm_dir}")
                        return ServiceStatusCode.SUCCESS
                    except Exception as e:
                        self.logger.error(f"{self.log_prefix} - Copy failed for {filename}: {e}")
                        return ServiceStatusCode.LOCAL_FETCH_FAILURE

            if not file_found:
                self.logger.warning(f"{self.log_prefix} - File not found in source directory: {pnm_file_name}")

            return ServiceStatusCode.LOCAL_FETCH_FAILURE

    def _handle_sftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch a file from remote SFTP server.

        Args:
            pnm_file_name: Name of the file to fetch from remote server

        Returns:
            bool: True if file transfer successful, False otherwise
        """
        sys_config = SystemConfigSettings()

        self.logger.debug(f"{self.log_prefix} - SFTP: Connecting to: {sys_config.sftp_host()}")

        if self._ping_pnm_file_server(HostNameStr(sys_config.sftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for SFTP host: {sys_config.sftp_host()}")
            return ServiceStatusCode.SFTP_HOST_UNREACHABLE

        sftp = SSHConnector(
            hostname        =   sys_config.sftp_host(),
            username        =   sys_config.sftp_user(),
            port            =   sys_config.sftp_port())

        password_enc     = sys_config.sftp_password()
        private_key_path = sys_config.sftp_private_key_path()

        try:
            if not sftp.connect(password_enc     =   password_enc,
                                private_key_path =   private_key_path):
                self.logger.error(f'{self.log_prefix} - SFTP Connect Failure: Host: {sys_config.sftp_host()}')
                return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

            remote_file_path = f'{sys_config.sftp_remote_dir()}/{pnm_file_name}'
            if not sftp.receive_file(remote_path =   remote_file_path,
                                     local_path  =   sys_config.pnm_dir()):
                self.logger.error(
                    f'{self.log_prefix} - SFTP Receive File Error '
                    f'(SRC:{remote_file_path} DST: {sys_config.pnm_dir()})'
                )
                return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

            self.logger.info(f'{self.log_prefix} - Successfully fetched file: {pnm_file_name}')
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f'{self.log_prefix} - SFTP Fetch Exception: {e}')
            return ServiceStatusCode.SFTP_PNM_FILE_FETCH_ERROR

        finally:
            sftp.disconnect()

    def _handle_tftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch the specified PNM file via TFTP.

        Assumes the following attributes on self:
        - self.pnm_local_dir (str)    # local directory to save the downloaded file
        - self.log_prefix (str)       # used for consistent logging

        TFTP settings are read from SystemConfigCommonSettings:
        - tftp_host (str)
        - tftp_port (int)
        - tftp_timeout (int)
        - tftp_remote_dir (str)   # remote directory where PNM files live (if applicable)
        """

        if self._ping_pnm_file_server(HostNameStr(SystemConfigSettings.tftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for TFTP host: {SystemConfigSettings.tftp_host()}")
            return ServiceStatusCode.TFTP_HOST_UNREACHABLE  

        try:
            connector = TFTPConnector(
                host    =   Inet(SystemConfigSettings.tftp_host()),
                port    =   int(str(SystemConfigSettings.tftp_port())))

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during TFTP connecting: {e}")
            return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

        try:

            self.logger.info(
                f"{self.log_prefix} - Starting TFTP download from "
                f"{SystemConfigSettings.tftp_host()}:{SystemConfigSettings.tftp_port()}"
            )

            # Build remote filename (some tftp servers require just the basename)
            remote_name = (
                f"{SystemConfigSettings.tftp_remote_dir().rstrip('/')}/{pnm_file_name}"
                if SystemConfigSettings.tftp_remote_dir() else
                pnm_file_name
            )
            local_path = os.path.join(SystemConfigSettings.pnm_dir(), pnm_file_name)

            success = connector.download_file(remote_name, local_path)

            if not success:
                self.logger.error(
                    f"{self.log_prefix} - TFTP download failed for '{remote_name}'"
                )
                return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

            self.logger.info(
                f"{self.log_prefix} - Successfully fetched '{pnm_file_name}' via TFTP"
            )
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during TFTP downloading: {e}")
            return ServiceStatusCode.TFTP_PNM_FILE_FETCH_ERROR

    def _handle_ftp_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        """
        Fetch the specified PNM file via FTP.

        Assumes the following attributes exist on self:
        - self.pnm_local_dir (str)    # local directory to save the downloaded file
        - self.log_prefix (str)       # used for consistent logging

        All FTP-specific settings are read from SystemConfigCommonSettings:
        - ftp_host (str)
        - ftp_port (int)
        - ftp_user (str)
        - ftp_password (str)
        - ftp_use_tls (bool)
        - ftp_timeout (int)
        - ftp_remote_dir (str)   # remote directory where PNM files live
        """
        sys_config = SystemConfigSettings()

        if self._ping_pnm_file_server(HostNameStr(SystemConfigSettings.ftp_host())) != ServiceStatusCode.SUCCESS:
            self.logger.error(f"{self.log_prefix} - Ping failed for FTP host: {SystemConfigSettings.ftp_host()}")
            return ServiceStatusCode.FTP_HOST_UNREACHABLE  

        try:
            connector = FTPConnector(
                host        =   str(sys_config.ftp_host()),
                port        =   int(str(sys_config.ftp_port())),
                username    =   str(sys_config.ftp_user()),
                password    =   str(sys_config.ftp_password()),
                use_tls     =   bool(sys_config.ftp_use_tls()),
                timeout     =   int(str(sys_config.ftp_timeout()))
            )

            self.logger.debug(
                f"{self.log_prefix} - Connecting to FTP server "
                f"{sys_config.ftp_host}:{sys_config.ftp_port}"
            )
            if not connector.connect():
                self.logger.error(f"{self.log_prefix} - FTP connection failed")
                return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

            # Build remote and local paths
            remote_base = sys_config.ftp_remote_dir.rstrip("/") if sys_config.ftp_remote_dir else ""
            remote_path = f"{remote_base}/{pnm_file_name}" if remote_base else pnm_file_name

            local_path = os.path.join(self.pnm_local_dir, pnm_file_name)

            self.logger.debug(
                f"{self.log_prefix} - Downloading '{remote_path}' to '{local_path}'"
            )
            success = connector.download_file(remote_path, local_path)
            connector.disconnect()

            if not success:
                self.logger.error(
                    f"{self.log_prefix} - FTP download failed for '{remote_path}'"
                )
                return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

            self.logger.info(
                f"{self.log_prefix} - Successfully fetched '{pnm_file_name}' via FTP"
            )
            return ServiceStatusCode.SUCCESS

        except Exception as e:
            self.logger.error(f"{self.log_prefix} - Exception during FTP fetch: {e}")
            return ServiceStatusCode.FTP_PNM_FILE_FETCH_ERROR

    def _handle_http_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        # TODO: implement HTTP file fetch logic
        self.logger.debug(f"{self.log_prefix} - HTTP fetch not yet implemented")
        return ServiceStatusCode.HTTP_PNM_FILE_FETCH_ERROR

    def _handle_https_fetch(self, pnm_file_name: FileNameStr) -> ServiceStatusCode:
        # TODO: implement HTTPS file fetch logic
        self.logger.debug(f"{self.log_prefix} - HTTPS fetch not yet implemented")
        return ServiceStatusCode.SHTTP_PNM_FILE_FETCH_ERROR
    
    async def _pnm_file_generator(self, test_type: DocsPnmCmCtlTest, suffix: str = "", ext: str = ".bin") -> FileNameStr:
        """
        Generates the PNM file name based on the provided DocsPnmCmCtlTest, with optional suffix and extension.

        Args:
            test_type (DocsPnmCmCtlTest): The type of the test to generate the prefix.
            suffix (str, optional): A suffix added to the file name. Defaults to an empty string.
            ext (str, optional): The file extension. Defaults to ".bin".

        Returns:
            str: The generated PNM file name.
        """
        test_prefix = test_type.name.lower()

        if suffix:
            suffix = f'_{suffix}'

        file_name:FileNameStr = FileNameStr(f"{test_prefix}_{self.cm.get_mac_address.to_mac_format()}{suffix}_{Generate.time_stamp()}{ext}")

        transaction_id = await PnmFileTransaction().insert(self.cm, test_type, file_name)

        self.logger.debug(f"Generated PNM file name: {file_name} -> TransID: {transaction_id}")

        tx_id = str(transaction_id)
        if not tx_id.strip():
            self.logger.warning(
                "%s - Skipping transaction mapping for empty transaction_id (filename=%s)",
                self.log_prefix,
                file_name,
            )
            return file_name

        self._transactionId_pnmFile[transaction_id] = file_name

        return file_name

    def _get_transaction_id_by_filename(self, file_name: str) -> TransactionId | None:
        """
        Return the transaction ID associated with the given file name.
        Assumes file names are unique. Returns None if not found.
        """
        for transaction_id, name in self._transactionId_pnmFile.items():
            if name == file_name:
                return TransactionId(transaction_id)
        return None

    async def _generic_spectrum_analyzer_operation(self, filename:str="") -> tuple[ServiceStatusCode, list[str]]:
        """
        Perform a generic spectrum-analyzer operation on the cable modem, supporting two retrieval modes:
        1. SNMP-based amplitude data return (AmplitudeData textual convention)
        2. PNM file return (download via TFTP once the CM writes the file)

        The same set of control parameters (frequency range, bin count, windowing, etc.) is used
        in both cases—avoiding duplicate “control-command” logic (DRY). Downstream, a separate helper
        method is called based on `spectrum_retrieval_type`.

        Extra options (from self.extra_options):
            • inactivity_timeout             (int, default=100)
                - Maximum seconds to wait for the CM to complete the measurement
            • first_segment_center_freq      (int, default=300_000_000)
                - Starting center frequency in Hz
            • last_segment_center_freq       (int, default=900_000_000)
                - Ending center frequency in Hz
            • segment_freq_span              (int, default=7_500_000)
                - Frequency span per segment in Hz
            • num_bins_per_segment           (int, default=256)
                - Number of bins (samples) per segment
            • noise_bw                       (int, default=110)
                - Equivalent noise bandwidth in Hz
            • window_function                (WindowFunction, default=WindowFunction.HANN)
                - Window function to apply to each segment
            • num_averages                   (int, default=1)
                - Number of averages to take
            • spectrum_retrieval_type        (SpectrumRetrievalType, default=SpectrumRetrievalType.FILE)
                - FILE: write to PNM file via TFTP (requires pnm_filename)
                - SNMP: return amplitude data directly via SNMP (no file write)

        Returns:
            Tuple[ServiceStatusCode, List[str]]:
                • On success: (ServiceStatusCode.SUCCESS, [<PNM filename>]) for FILE mode,
                  or (ServiceStatusCode.SUCCESS, []) for SNMP mode.
                • On failure: (ServiceStatusCode.SPEC_ANALYZER_NOT_AVAILABLE, []).

        Raises:
            None directly—errors are mapped to a failure status code.
        """
        self.logger.info(f"{self.log_prefix} - Entering into SPECTRUM-ANALYZER Mode (filename: {filename})")

        # Default: only SNMP control-command, no file write
        ctl_cmd_filename = Snmp_v2c.TRUE

        if (self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER or \
            self.pnm_test_type == DocsPnmCmCtlTest.SPECTRUM_ANALYZER_SNMP_AMP_DATA) and \
            (not self.getSpectrumCaptureParameters()):

            self.logger.error('No Spectrum Parameters Found, did you set: setSpectrumCaptureParameters()')

            return  ServiceStatusCode.NO_SPECTRUM_CAPTURE_PARAMETERS, []

        capture_parameter = self.getSpectrumCaptureParameters()

        if not capture_parameter:

            capture_parameter = SpecAnCapturePara (
                inactivity_timeout          = self.extra_options.get("inactivity_timeout", 100),
                first_segment_center_freq   = self.extra_options.get("first_segment_center_freq", 300_000_000),
                last_segment_center_freq    = self.extra_options.get("last_segment_center_freq", 993_000_000),
                segment_freq_span           = self.extra_options.get("segment_freq_span", 1_000_000),
                num_bins_per_segment        = self.extra_options.get("num_bins_per_segment", 256),
                noise_bw                    = self.extra_options.get("noise_bw", 110),
                window_function             = self.extra_options.get("window_function", WindowFunction.HANN),
                num_averages                = self.extra_options.get("num_averages", 1),
                spectrum_retrieval_type     = self.extra_options.get("spectrum_retrieval_type",SpectrumRetrievalType.FILE),
            )

        if capture_parameter.spectrum_retrieval_type == SpectrumRetrievalType.SNMP:
            self.logger.info(f"{self.log_prefix} - SPECTRUM-ANALYZER - SNMP-AMPLITUDE-DATA-RETURN")
            ctl_cmd_filename = Snmp_v2c.FALSE

        else:
            if not filename:
                self.logger.error(f"{self.log_prefix} - Missing 'filename' for FILE retrieval mode")
                return ServiceStatusCode.MISSING_PNM_FILENAME, []

        spectrum_cmd = DocsIf3CmSpectrumAnalysisCtrlCmd(
            docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout           =   capture_parameter.inactivity_timeout,
            docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency =   capture_parameter.first_segment_center_freq,
            docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency  =   capture_parameter.last_segment_center_freq,
            docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan        =   capture_parameter.segment_freq_span,
            docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment           =   capture_parameter.num_bins_per_segment,
            docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth    =   capture_parameter.noise_bw,
            docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction              =   capture_parameter.window_function,
            docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages            =   capture_parameter.num_averages,
            docsIf3CmSpectrumAnalysisCtrlCmdEnable                      =   Snmp_v2c.TRUE,
            docsIf3CmSpectrumAnalysisCtrlCmdFileName                    =   filename,
            docsIf3CmSpectrumAnalysisCtrlCmdFileEnable                  =   ctl_cmd_filename,)

        # Issue the SNMP SET for the control-command. The downstream logic
        # (not shown here) will branch to either:
        #   • SNMP:  set FileEnable = FALSE → wait for measurement → walk AmplitudeData
        #   • FILE:  set FileEnable = TRUE  → wait for measurement status → TFTP download
        if not await self.cm.setDocsIf3CmSpectrumAnalysisCtrlCmd(spectrum_cmd,
                                                                 capture_parameter.spectrum_retrieval_type):
            self.logger.error(f"{self.log_prefix} - Spectrum Analyzer is Not Available")
            return ServiceStatusCode.SPEC_ANALYZER_NOT_AVAILABLE, []

        # On success, return the filename (if FILE mode) or an empty list (SNMP mode)
        if capture_parameter.spectrum_retrieval_type == SpectrumRetrievalType.FILE:
            return ServiceStatusCode.SUCCESS, [filename]
        else:
            return ServiceStatusCode.SUCCESS, []

    def _ping_pnm_file_server(self, host: HostNameStr) -> ServiceStatusCode:
        """
        Ping The PNM File Server To Check Its Availability.

        This helper first attempts DNS resolution of the host. If the host
        resolves only to loopback addresses (for example "127.0.0.1" or "::1"),
        ICMP ping is bypassed and the host is treated as reachable so that
        local SCP/SFTP/TFTP retrieval is not blocked by loopback
        misconfiguration.

        If DNS resolution fails entirely, the ping pre-check is skipped and the
        method returns SUCCESS while logging the condition at debug level,
        allowing the subsequent transfer step to provide a more precise error.

        For non-loopback addresses that resolve successfully, a standard ICMP
        ping is issued via HostEndpoint. If the ping fails, PING_FAILED is
        returned.
        """
        endpoint  = HostEndpoint(host)
        addresses = endpoint.resolve()

        if not addresses:
            self.logger.debug(
                f"{self.log_prefix} - DNS lookup failed for host: {host}; "
                "skipping ping pre-check"
            )
            return ServiceStatusCode.SUCCESS

        for addr in addresses:
            if addr.startswith("127.") or addr == "::1":
                self.logger.debug(
                    f"{self.log_prefix} - Host {host} resolved to loopback ({addr}); "
                    "skipping ping pre-check"
                )
                return ServiceStatusCode.SUCCESS

        if endpoint.ping():
            return ServiceStatusCode.SUCCESS

        self.logger.debug(f"{self.log_prefix} - Ping failed for host: {host}")
        return ServiceStatusCode.PING_FAILED

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

        return capture_group_id

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
            if getattr(model, "transaction_id", ""):
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
